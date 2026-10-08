package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Durable de-duplication of pushed results.
//
// The agent side guarantees nothing is dropped without an acknowledgement;
// this journal is what makes that safe. It records, per vantage, the
// identity of every result hz has committed to hold. A report whose answer
// was lost is re-sent verbatim: the re-send finds its identities here and is
// folded into checks, history and alerts zero times instead of a second
// time. The record survives an hz restart by living on disk, because "the
// process happened to stay up" is not a property anyone builds on.
//
// The commit order in ReceivePush is the contract this file exists to
// enforce: identities land here (fsync) BEFORE any result folds into a
// check, and only identities present here afterwards are acknowledged. A
// crash between the write and the fold therefore loses at most that
// in-flight batch's samples — rows rebuild on the next probe round — and can
// never produce a duplicate on the retry.

const (
	// pushJournalHorizon bounds how long an identity is remembered. It only
	// has to outlive the longest time an agent can still be holding a result
	// unacknowledged — its spool is capped at 5000 entries — with a wide
	// margin; two weeks is comfortably past any realistic retry life.
	pushJournalHorizon = 14 * 24 * time.Hour

	// pushJournalMaxEntries is the backstop per vantage for fleets that probe
	// very many names. Oldest are trimmed first. 20k identities is roughly a
	// megabyte.
	pushJournalMaxEntries = 20000

	pushJournalVersion = 1
)

// journalEntry is one delivered identity and the gateway-local time it was
// received. No result payload is stored: the journal's job is to recognise
// a retry, not to reconstruct history after a restart (check state is an
// in-memory view like every local check's).
type journalEntry struct {
	ID     string    `json:"id"`
	RecvAt time.Time `json:"recv_at"`
}

type journalDoc struct {
	Version   int            `json:"version"`
	Delivered []journalEntry `json:"delivered"`
}

// pushJournal is the set of per-vantage delivery records. An empty root
// selects in-memory behaviour: de-dup works for the life of the process
// (tests, dry-run) but, honestly, no further.
type pushJournal struct {
	root     string
	mu       sync.Mutex
	vantages map[string]*vantageJournal
}

func newPushJournal(root string) *pushJournal {
	return &pushJournal{root: root, vantages: make(map[string]*vantageJournal)}
}

// vantageJournal serialises all commits for one vantage and holds its
// delivered set in both insertion order (for age/count trimming) and map
// form (for O(1) recognition).
type vantageJournal struct {
	mu      sync.Mutex
	entries []journalEntry
	index   map[string]int
	loaded  bool
	notice  string // one-shot, delivered on the first successful commit
}

// commitResult reports what one report became.
type commitResult struct {
	// Fresh is the identities that were not previously held and therefore
	// must now be folded, in the order they were submitted.
	Fresh []string

	// Held is every submitted identity now durably recorded — fresh plus
	// already-known. It is what the agent may delete: the whole batch is
	// delivered, including the overlap whose answer was lost.
	Held []string

	// Notice carries a non-routine condition the agent should log for its
	// operator — currently: its journal was found corrupt and reset.
	Notice string
}

// Commit records the submitted identities for one vantage before the caller
// folds anything. Fresh names are returned in submission order. A write
// failure rolls back the in-memory additions so a later retry cannot be
// misread as an already-folded duplicate; nothing is acknowledged on error.
func (j *pushJournal) Commit(vantage string, ids []string) (commitResult, error) {
	// Hold the registry lock until the vantage lock is taken, so a Rename
	// cannot repoint the vantage away from a commit that already resolved it.
	// Rename acquires the same vantage locks while holding this registry
	// lock, so neither side can observe a half-migrated vantage.
	j.mu.Lock()
	v := j.vantageForLocked(vantage)
	v.mu.Lock()
	j.mu.Unlock()
	defer v.mu.Unlock()

	if err := j.loadLocked(vantage, v); err != nil {
		return commitResult{}, err
	}

	// Dedupe within the batch itself, preserving first-seen order.
	uniq := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		uniq = append(uniq, id)
	}

	res := commitResult{}
	now := time.Now()
	added := make([]string, 0, len(uniq))
	for _, id := range uniq {
		if _, known := v.index[id]; known {
			continue
		}
		res.Fresh = append(res.Fresh, id)
		added = append(added, id)
	}

	// Snapshot before any mutation so a failed write can restore EVERYTHING,
	// including entries GC is about to drop — otherwise a 14-day-old identity
	// retried in the same process could fold twice after a write blip.
	prevEntries := v.entries

	// Apply, then persist; on failure roll back so memory never claims more
	// than the disk holds.
	for _, id := range added {
		v.index[id] = len(v.entries)
		v.entries = append(v.entries, journalEntry{ID: id, RecvAt: now})
	}
	j.gcLocked(v, now)

	if j.root != "" {
		if err := j.writeLocked(vantage, v); err != nil {
			v.entries = prevEntries
			reindex(v)
			slog.Error("probe: delivery journal write failed; report not acknowledged",
				"vantage", vantage, "error", err)
			return commitResult{}, err
		}
	}

	res.Held = uniq
	if v.notice != "" {
		res.Notice = v.notice
		v.notice = ""
	}
	return res, nil
}

// gcLocked trims by age then by count, oldest first. Entries are kept in
// insertion order, so each trim drops a prefix.
func (j *pushJournal) gcLocked(v *vantageJournal, now time.Time) {
	cut := 0
	for cut < len(v.entries) && now.Sub(v.entries[cut].RecvAt) > pushJournalHorizon {
		cut++
	}
	if excess := len(v.entries) - cut - pushJournalMaxEntries; excess > 0 {
		cut += excess
	}
	if cut == 0 {
		return
	}
	for _, e := range v.entries[:cut] {
		delete(v.index, e.ID)
	}
	v.entries = v.entries[cut:]
	reindex(v)
}

func reindex(v *vantageJournal) {
	v.index = make(map[string]int, len(v.entries))
	for i, e := range v.entries {
		v.index[e.ID] = i
	}
}

// vantageForLocked returns the per-vantage record, creating the in-memory
// shell. Callers must hold j.mu. Loading from disk happens lazily on commit.
func (j *pushJournal) vantageForLocked(name string) *vantageJournal {
	if j.vantages == nil {
		j.vantages = make(map[string]*vantageJournal)
	}
	v := j.vantages[name]
	if v == nil {
		v = &vantageJournal{}
		j.vantages[name] = v
	}
	return v
}

// loadLocked reads the vantage's file once. A corrupt file is quarantined
// rather than silently dropped: the operator gets a log line, the agent gets
// a one-shot notice, and a single overlapping batch may fold twice — the
// bounded, announced alternative to pretending either side knew the truth.
func (j *pushJournal) loadLocked(name string, v *vantageJournal) error {
	if v.index == nil {
		v.index = make(map[string]int)
	}
	if v.loaded || j.root == "" {
		v.loaded = true
		return nil
	}
	v.loaded = true

	path := j.pathFor(name)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		// Unreadable for another reason: treat like corrupt — quarantine the
		// path if possible and start fresh.
		slog.Error("probe: delivery journal unreadable; starting a new one",
			"vantage", name, "path", path, "error", err)
		v.notice = journalResetNotice
		return nil
	}

	var doc journalDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		backup := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		if renErr := os.Rename(path, backup); renErr != nil {
			slog.Error("probe: delivery journal corrupt and could not be quarantined",
				"vantage", name, "path", path, "backup", backup, "error", renErr)
		} else {
			slog.Error("probe: delivery journal was corrupt; quarantined and reset",
				"vantage", name, "path", path, "backup", backup)
		}
		v.notice = journalResetNotice
		return nil
	}

	// Defensive: sort by receipt time so prefix trims are meaningful no
	// matter what wrote the file.
	entries := doc.Delivered
	sort.SliceStable(entries, func(i, k int) bool {
		return entries[i].RecvAt.Before(entries[k].RecvAt)
	})
	v.entries = entries
	reindex(v)
	return nil
}

const journalResetNotice = "hz's delivery journal for this vantage was unreadable and has been reset; " +
	"one in-flight batch may appear duplicated"

// writeLocked atomically replaces the vantage's journal file.
func (j *pushJournal) writeLocked(name string, v *vantageJournal) error {
	return j.writePathLocked(j.pathFor(name), v)
}

// writePathLocked atomically replaces an explicit journal path.
func (j *pushJournal) writePathLocked(path string, v *vantageJournal) error {
	if err := os.MkdirAll(j.root, 0o700); err != nil {
		return err
	}
	doc := journalDoc{Version: pushJournalVersion, Delivered: v.entries}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(j.root, ".journal-*")
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
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	// The rename itself must be durable, or a crash immediately after can
	// still expose the old directory entry.
	if df, err := os.Open(j.root); err != nil {
		slog.Warn("probe: delivery journal dir not opened for fsync; rename durability unconfirmed",
			"dir", j.root, "error", err)
	} else {
		if err := df.Sync(); err != nil {
			slog.Warn("probe: delivery journal dir fsync failed; rename durability unconfirmed",
				"dir", j.root, "error", err)
		}
		_ = df.Close()
	}
	return nil
}

// Remove forgets a vantage entirely, including its file. Called when the
// vantage is deleted from config — an edit or a token rotation keeps the
// journal, because the results' identities outlive those changes.
func (j *pushJournal) Remove(name string) {
	j.mu.Lock()
	delete(j.vantages, name)
	root := j.root
	j.mu.Unlock()

	if root == "" {
		return
	}
	if err := os.Remove(j.pathFor(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("probe: could not remove delivery journal", "vantage", name, "error", err)
	}
}

// Rename migrates a vantage's journal — in-memory record and file — when the
// vantage itself is renamed. It runs wholly inside the registry lock and
// takes the affected vantage locks in the same critical section, so it cannot
// interleave with a commit that resolved the old or the new name: either a
// report finished entirely before the rename sees it, or it lands entirely on
// the migrated record afterwards. A report that raced ahead under the new
// name created a shell whose identities are merged rather than clobbered.
func (j *pushJournal) Rename(oldName, newName string) {
	if oldName == "" || oldName == newName {
		return
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	v := j.vantages[oldName]
	shell := j.vantages[newName]
	if shell != nil {
		shell.mu.Lock()
		defer shell.mu.Unlock()
	}
	if v != nil && v != shell {
		v.mu.Lock()
		defer v.mu.Unlock()
	}
	delete(j.vantages, oldName)

	if j.root == "" {
		if v != nil {
			j.vantages[newName] = v
		}
		return
	}
	oldPath, newPath := j.pathFor(oldName), j.pathFor(newName)

	switch {
	case v != nil:
		// Bring in anything the old name committed in an earlier process life
		// too, then absorb a same-process new-name shell.
		if err := j.loadLocked(oldName, v); err != nil {
			slog.Warn("probe: unreadable old delivery journal on rename; migrating what is in memory",
				"vantage", oldName, "error", err)
		}
		if shell != nil && shell != v {
			mergeEntries(v, shell.entries)
		}
		j.vantages[newName] = v
		shellExisted := shell != nil && len(shell.entries) > 0
		j.moveJournalFile(oldPath, newPath, newName, v, shellExisted)

	case shell != nil:
		// No in-memory old-name record this process, but an earlier process
		// may have left a file behind: merge it into the shell rather than
		// overwriting the shell's newer state.
		if entries, ok := readJournalFile(oldPath); ok {
			mergeEntries(shell, entries)
			_ = os.Remove(oldPath)
		}
		if err := j.writePathLocked(newPath, shell); err != nil {
			slog.Warn("probe: could not persist merged delivery journal on rename",
				"vantage", newName, "error", err)
		}

	default:
		// Nothing in memory under either name: move whatever file is there.
		if err := os.Rename(oldPath, newPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("probe: could not migrate delivery journal on rename",
				"from", oldName, "to", newName, "error", err)
		}
	}
}

// moveJournalFile moves oldPath to newPath and, when the destination could
// already hold shell-only state, rewrites it so nothing is lost. Caller holds
// j.mu and the target vantage lock.
func (j *pushJournal) moveJournalFile(oldPath, newPath, newName string, v *vantageJournal, shellExisted bool) {
	renErr := os.Rename(oldPath, newPath)
	switch {
	case renErr == nil && shellExisted:
		if err := j.writePathLocked(newPath, v); err != nil {
			slog.Warn("probe: migrated delivery journal but merge was not persisted",
				"vantage", newName, "error", err)
		}
	case errors.Is(renErr, os.ErrNotExist):
		if err := j.writePathLocked(newPath, v); err != nil {
			slog.Warn("probe: could not write migrated delivery journal",
				"vantage", newName, "error", err)
		}
	case renErr != nil:
		slog.Warn("probe: could not migrate delivery journal on rename",
			"path", oldPath, "error", renErr)
	}
}

// mergeEntries unions extra into v's entry set, oldest-first, rebuilding the
// index. Caller holds the vantage lock.
func mergeEntries(v *vantageJournal, extra []journalEntry) {
	if len(extra) == 0 {
		return
	}
	have := make(map[string]bool, len(v.entries)+len(extra))
	for _, e := range v.entries {
		have[e.ID] = true
	}
	grew := false
	for _, e := range extra {
		if !have[e.ID] {
			have[e.ID] = true
			v.entries = append(v.entries, e)
			grew = true
		}
	}
	if grew {
		sort.SliceStable(v.entries, func(i, k int) bool {
			return v.entries[i].RecvAt.Before(v.entries[k].RecvAt)
		})
		reindex(v)
	}
}

// readJournalFile loads entries from an arbitrary journal path. A missing or
// unreadable file yields ok=false without touching anything.
func readJournalFile(path string) ([]journalEntry, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var doc journalDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, false
	}
	return doc.Delivered, true
}

// pathFor maps a vantage name to a safe file name. Names are validated on
// input (no colons or whitespace) but never trusted as a path component:
// QueryEscape neutralises separators and dot traversal.
func (j *pushJournal) pathFor(name string) string {
	return filepath.Join(j.root, url.QueryEscape(name)+".json")
}
