package probe

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Push-mode durability.
//
// The spool is the push agent's authority for two things that used to be
// either memory-only or split apart: the result backlog hz has not
// acknowledged, and the target-set cache. They share one file and one
// atomic-replace lifecycle on purpose: the targets decide what gets probed
// while hz is unreachable, and the backlog is what those probes produce —
// losing one while keeping the other makes a restart report either nonsense
// targets or an unrecoverable-looking hole.
//
// The commit rule is the whole point of this type: results are persisted
// before they can be acknowledged, and an acknowledgement only removes what
// it names, after that removal is itself persisted. A crash anywhere leaves
// an intact prefix of unacknowledged work, which the next process resumes
// from. hz dedupes the retried overlap, so durability here never becomes
// double counting there.

// maxSpoolBytes is the payload backstop to maxBuffered's count cap. A flood
// of verbose failures cannot turn the state file into an unbounded disk
// claim just because every entry is small enough to fit the count.
const maxSpoolBytes = 4 << 20

// spoolDoc is the on-disk state. It is a superset of the old targets-only
// file: a state written by an older agent decodes with empty backlog fields.
type spoolDoc struct {
	Targets      TargetSet  `json:"targets"`
	Pending      []Result   `json:"pending,omitempty"`
	DroppedTotal int64      `json:"dropped_total,omitempty"`
	LastDropAt   *time.Time `json:"last_drop_at,omitempty"`
}

// spool is an ordered, durable FIFO of unacknowledged results plus the cached
// target set. The zero value is not usable; construct with newSpool.
type spool struct {
	path string // empty means stateless: everything stays in memory

	mu       sync.Mutex
	targets  TargetSet
	pending  []Result
	dropped  int64
	lastDrop *time.Time
	state    string // "", ok, degraded, corrupt
}

// newSpool loads the durable state at path. An empty path selects stateless
// mode: no file is ever touched and stats report no durability state.
//
// A missing file is a normal first start. An unreadable file is not: it is
// quarantined, the agent starts empty, and the condition rides along in
// SpoolStats so hz can show it — silently pretending the backlog never
// existed would be the "delivered" illusion this design forbids.
func newSpool(path string) *spool {
	s := &spool{path: path}
	if path == "" {
		return s
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.state = SpoolStateOK
		} else {
			slog.Error("probe: state file unreadable; running without a backlog until it can be rewritten",
				"path", path, "error", err)
			s.state = SpoolStateDegraded
		}
		return s
	}

	var doc spoolDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		backup := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		if renErr := os.Rename(path, backup); renErr != nil {
			// Keep going in memory even if the quarantine rename fails; a
			// later save overwrites the bad file outright.
			slog.Error("probe: state file is corrupt and could not be quarantined",
				"path", path, "backup", backup, "error", renErr)
		} else {
			slog.Error("probe: state file was corrupt; quarantined and starting with an empty backlog",
				"path", path, "backup", backup)
		}
		s.state = SpoolStateCorrupt
		return s
	}

	s.targets = doc.Targets
	s.pending = doc.Pending
	s.dropped = doc.DroppedTotal
	s.lastDrop = doc.LastDropAt
	s.state = SpoolStateOK
	slog.Info("probe: restored push state",
		"path", path, "targets", len(doc.Targets.Targets), "pending", len(doc.Pending))
	return s
}

// Targets returns the cached target set.
func (s *spool) Targets() TargetSet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.targets
}

// SetTargets installs a target set durably. A failed write leaves the set in
// memory — probes should follow it this run — but marks the spool degraded.
func (s *spool) SetTargets(ts TargetSet) error {
	if ts.Version == "" {
		ts.Version = ts.ComputeVersion()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets = ts
	return s.persistLocked()
}

// Append records produced results, assigning IDs to any that lack them, then
// enforces retention deterministically: when the entry or byte cap is
// exceeded the OLDEST unacknowledged results are the ones that go — a
// monitoring agent's newest observation is worth most, and blocking probes
// would make it blind for the rest of the outage.
//
// The in-memory append survives a failed write so a live process still
// delivers while the disk is ill; the spool is flagged degraded so nobody
// mistakes that for durability.
func (s *spool) Append(rs []Result) error {
	if len(rs) == 0 {
		return nil
	}
	for i := range rs {
		if rs[i].ID == "" {
			rs[i].ID = newResultID()
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pending = append(s.pending, rs...)
	s.trimLocked()
	return s.persistLocked()
}

// trimLocked enforces both caps, oldest first, accounting for what it drops.
func (s *spool) trimLocked() {
	if len(s.pending) == 0 {
		return
	}
	drop := 0

	if excess := len(s.pending) - maxBuffered; excess > 0 {
		drop = excess
	}

	// One pass of per-entry sizes lets the byte cap drop an exact prefix
	// instead of repeatedly re-marshalling the whole backlog.
	if size := pendingSize(s.pending); size > maxSpoolBytes {
		sizes := make([]int, len(s.pending))
		var total int
		for i, r := range s.pending {
			b, _ := json.Marshal(r)
			sizes[i] = len(b)
			total += sizes[i]
		}
		// An entry that individually exceeds the cap can never be retained;
		// the prefix loop below would otherwise keep dropping past it
		// forever. It counts as a dropped result like any other.
		for total > maxSpoolBytes && drop < len(s.pending) {
			total -= sizes[drop]
			drop++
		}
	}

	if drop == 0 {
		return
	}
	now := time.Now().UTC()
	s.lastDrop = &now
	s.dropped += int64(drop)
	s.pending = s.pending[drop:]
	slog.Warn("probe: backlog over capacity; dropped oldest unacknowledged results",
		"dropped", drop, "dropped_total", s.dropped, "kept", len(s.pending))
}

// pendingSize is the encoded size of a backlog, used for the byte cap.
func pendingSize(rs []Result) int {
	b, err := json.Marshal(rs)
	if err != nil {
		return 0
	}
	return len(b)
}

// Batch returns the oldest up to limit pending results (a copy), whether more
// remain behind them, and the spool's current stats — all from one snapshot.
func (s *spool) Batch(limit int) ([]Result, bool, SpoolStats) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > maxBuffered {
		limit = maxBuffered
	}
	out := make([]Result, 0, min(limit, len(s.pending)))
	end := min(limit, len(s.pending))
	out = append(out, s.pending[:end]...)
	more := end < len(s.pending)
	return out, more, s.statsLocked()
}

// Pending reports how many results await acknowledgement.
func (s *spool) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// Stats snapshots the observable backlog state.
func (s *spool) Stats() SpoolStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statsLocked()
}

func (s *spool) statsLocked() SpoolStats {
	st := SpoolStats{
		Pending:      len(s.pending),
		Cap:          maxBuffered,
		DroppedTotal: s.dropped,
		State:        s.state,
	}
	if len(s.pending) > 0 {
		oldest := s.pending[0].At
		st.OldestAt = &oldest
	}
	return st
}

// Ack removes precisely the identities hz named that are actually in the
// spool. IDs from another batch, another agent, or a duplicate ack are
// harmless: they match nothing.
//
// Persistence is committed BEFORE the in-memory removal. If the write fails
// nothing is removed, the error is returned, and the caller reports the
// batch again — hz already holds those results and dedupes the retry, so the
// only cost of this caution is one redundant delivery. Removing from memory
// without a durable commit would be the false "delivered" signal on a crash.
func (s *spool) Ack(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id != "" {
			want[id] = true
		}
	}
	next := make([]Result, 0, len(s.pending))
	for _, r := range s.pending {
		if !want[r.ID] {
			next = append(next, r)
		}
	}
	if len(next) == len(s.pending) {
		return nil // nothing to commit
	}
	if err := s.writeLocked(s.docWithLocked(next)); err != nil {
		s.markDegradedLocked()
		return err
	}
	s.pending = next
	if s.path != "" {
		s.state = SpoolStateOK
	}
	return nil
}

// AckPrefix is the fallback for an older hz that answers with a count rather
// than identities: drop the oldest n, which is the prefix that count names.
// Same persist-before-commit rule as Ack.
func (s *spool) AckPrefix(n int) error {
	if n <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if n >= len(s.pending) {
		n = len(s.pending)
	}
	next := s.pending[n:]
	if err := s.writeLocked(s.docWithLocked(next)); err != nil {
		s.markDegradedLocked()
		return err
	}
	s.pending = next
	if s.path != "" {
		s.state = SpoolStateOK
	}
	return nil
}

func (s *spool) docWithLocked(pending []Result) spoolDoc {
	return spoolDoc{
		Targets:      s.targets,
		Pending:      pending,
		DroppedTotal: s.dropped,
		LastDropAt:   s.lastDrop,
	}
}

// persistLocked writes the current memory state. Callers hold mu.
func (s *spool) persistLocked() error {
	if s.path == "" {
		return nil // stateless: nothing to degrade or heal
	}
	if err := s.writeLocked(s.docWithLocked(s.pending)); err != nil {
		s.markDegradedLocked()
		return err
	}
	s.state = SpoolStateOK
	return nil
}

// markDegradedLocked records a failed write without mutating anything else:
// the in-memory truth is still the best this process has.
func (s *spool) markDegradedLocked() {
	if s.state == SpoolStateCorrupt {
		// A successful write is what clears corrupt; a failure changes
		// nothing about the diagnosis.
		return
	}
	if s.state != SpoolStateDegraded {
		slog.Error("probe: backlog state is not being persisted; results survive only until this process exits",
			"path", s.path)
	}
	s.state = SpoolStateDegraded
}

// writeLocked atomically replaces the state file: tmp, fsync, rename, fsync
// directory. Stateless mode is a no-op. Callers hold mu, so concurrent saves
// can neither reorder nor interleave their tmp/rename pairs.
func (s *spool) writeLocked(doc spoolDoc) error {
	if s.path == "" {
		return nil
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return err
	}
	// The rename itself must be durable, or a crash immediately after can
	// still expose the old directory entry.
	if df, err := os.Open(dir); err != nil {
		slog.Warn("probe: state dir not opened for fsync; state rename durability unconfirmed",
			"dir", dir, "error", err)
	} else {
		if err := df.Sync(); err != nil {
			slog.Warn("probe: state dir fsync failed; state rename durability unconfirmed",
				"dir", dir, "error", err)
		}
		_ = df.Close()
	}
	return nil
}
