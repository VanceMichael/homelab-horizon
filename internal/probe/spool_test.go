package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mkResults(n int, start time.Time, big ...int) []Result {
	out := make([]Result, n)
	for i := 0; i < n; i++ {
		out[i] = Result{
			Target: "t", Host: "h.example", Kind: KindDNS,
			At: start.Add(time.Duration(i) * time.Second), Status: StatusOK,
		}
	}
	return out
}

// The backlog and the targets ride the same file across a restart, in order.
func TestSpoolRestoresPendingAndTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := testSet("a.example.com")
	base := time.Now().UTC().Truncate(time.Second)

	s := newSpool(path)
	if err := s.SetTargets(want); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(mkResults(5, base)); err != nil {
		t.Fatal(err)
	}
	got, more, stats := s.Batch(10)
	if len(got) != 5 || more {
		t.Fatalf("batch = %d, more=%v", len(got), more)
	}
	if stats.State != SpoolStateOK || stats.Pending != 5 || !stats.OldestAt.Equal(base) {
		t.Fatalf("stats = %+v", stats)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file perms = %v, %v", fi.Mode().Perm(), err)
	}

	restarted := newSpool(path)
	if ts := restarted.Targets(); ts.Version != want.Version || len(ts.Targets) != 1 {
		t.Fatalf("targets lost across restart: %+v", ts)
	}
	got2, _, _ := restarted.Batch(10)
	if len(got2) != 5 {
		t.Fatalf("pending restored = %d, want 5", len(got2))
	}
	for i := range got2 {
		if got2[i].ID != got[i].ID || !got2[i].At.Equal(got[i].At) {
			t.Fatalf("entry %d changed across restart:\n%+v\n%+v", i, got[i], got2[i])
		}
	}
}

// Only named, actually-held identities leave the spool; a partial ack leaves
// an intact prefix of work, and that survives a restart too.
func TestSpoolAckExactPartialForeign(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := newSpool(path)
	base := time.Now().UTC().Truncate(time.Second)
	if err := s.Append(mkResults(5, base)); err != nil {
		t.Fatal(err)
	}
	batch, _, _ := s.Batch(10)

	// Ack entries 1 and 3 (subset), plus a stranger's ID and a duplicate.
	if err := s.Ack([]string{batch[1].ID, "foreign-id", batch[3].ID, batch[3].ID}); err != nil {
		t.Fatal(err)
	}
	if s.Pending() != 3 {
		t.Fatalf("pending = %d, want 3", s.Pending())
	}
	got, _, _ := s.Batch(10)
	wantIDs := []string{batch[0].ID, batch[2].ID, batch[4].ID}
	for i, id := range wantIDs {
		if got[i].ID != id {
			t.Fatalf("remaining %d = %s, want %s (order/identity mismatch)", i, got[i].ID, id)
		}
	}

	restarted := newSpool(path)
	if restarted.Pending() != 3 {
		t.Fatalf("partial ack must survive restart, pending = %d", restarted.Pending())
	}

	// Acking nothing or an empty list changes nothing.
	if err := s.Ack(nil); err != nil {
		t.Fatal(err)
	}
	if s.Pending() != 3 {
		t.Fatal("an empty ack must not touch the backlog")
	}
}

// The count fallback an older hz uses removes the oldest prefix.
func TestSpoolAckPrefix(t *testing.T) {
	s := newSpool("")
	base := time.Now().UTC().Truncate(time.Second)
	if err := s.Append(mkResults(5, base)); err != nil {
		t.Fatal(err)
	}
	batch, _, _ := s.Batch(10)
	if err := s.AckPrefix(2); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Batch(10)
	if len(got) != 3 || got[0].ID != batch[2].ID {
		t.Fatalf("prefix ack left %+v", got)
	}
	if err := s.AckPrefix(100); err != nil || s.Pending() != 0 {
		t.Fatalf("over-large prefix must drain the spool")
	}
}

// If the removal cannot be persisted, nothing is removed: an acknowledged but
// unrecorded removal is exactly the false-delivery signal the spool exists to
// prevent. Recovery drains once writes work again. The failure is injected by
// replacing the state directory with a regular file, which blocks MkdirAll no
// matter what uid the test runs as.
func TestSpoolAckWriteFailureRollsBack(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "lib")
	path := filepath.Join(dir, "state.json")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newSpool(path)
	base := time.Now().UTC().Truncate(time.Second)
	if err := s.Append(mkResults(3, base)); err != nil {
		t.Fatal(err)
	}
	batch, _, _ := s.Batch(10)

	// Move the real directory aside and put a file where MkdirAll expects a
	// directory.
	realDir := filepath.Join(parent, "lib-real")
	if err := os.Rename(dir, realDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := s.Ack([]string{batch[0].ID}); err == nil {
		t.Fatal("an ack that cannot be persisted must fail")
	}
	if s.Pending() != 3 {
		t.Fatalf("pending = %d, want 3: failed ack removed data", s.Pending())
	}
	if st := s.Stats(); st.State != SpoolStateDegraded {
		t.Fatalf("state = %q, want degraded", st.State)
	}

	// Recovery: the file gives way and the real directory comes back.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(realDir, dir); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack([]string{batch[0].ID}); err != nil {
		t.Fatalf("ack after recovery: %v", err)
	}
	if s.Pending() != 2 || s.Stats().State != SpoolStateOK {
		t.Fatalf("recovery should drain and heal, pending=%d state=%s", s.Pending(), s.Stats().State)
	}
}

// Entry cap: oldest out, newest kept, counter persisted with the spool.
func TestSpoolEntryCapDropsOldest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := newSpool(path)
	base := time.Now().UTC().Truncate(time.Hour)

	var first, last []Result
	for i := 0; i < 51; i++ {
		rs := mkResults(100, base.Add(time.Duration(i*100)*time.Second))
		if i == 0 {
			first = rs
		}
		if i == 50 {
			last = rs
		}
		if err := s.Append(rs); err != nil {
			t.Fatal(err)
		}
	}
	if s.Pending() != maxBuffered {
		t.Fatalf("pending = %d, want cap %d", s.Pending(), maxBuffered)
	}
	if st := s.Stats(); st.DroppedTotal != 100 || st.State != SpoolStateOK {
		t.Fatalf("stats = %+v, want dropped 100", st)
	}
	got, _, _ := s.Batch(maxBuffered + 500)
	if got[0].ID == first[0].ID {
		t.Fatal("the oldest results should have been dropped")
	}
	if got[len(got)-1].ID != last[99].ID {
		t.Fatal("the newest results should be retained")
	}

	restarted := newSpool(path)
	if st := restarted.Stats(); st.DroppedTotal != 100 || restarted.Pending() != maxBuffered {
		t.Fatalf("drop accounting did not survive restart: %+v", st)
	}
}

// Byte cap: verbose results cannot grow the file without bound; the trim is
// still oldest-first and still leaves a conforming backlog.
func TestSpoolByteCapDropsOldest(t *testing.T) {
	s := newSpool("")
	base := time.Now().UTC().Truncate(time.Hour)
	rs := make([]Result, 12)
	for i := range rs {
		r := mkResults(1, base.Add(time.Duration(i)*time.Second))[0]
		r.Error = strings.Repeat("x", 500_000) // ~0.5 MB each
		rs[i] = r
	}
	if err := s.Append(rs); err != nil {
		t.Fatal(err)
	}
	got, _, st := s.Batch(maxBuffered)
	if size := pendingSize(got); size > maxSpoolBytes {
		t.Fatalf("backlog %d bytes exceeds %d cap", size, maxSpoolBytes)
	}
	if st.DroppedTotal == 0 || len(got) == 0 {
		t.Fatalf("byte cap should drop oldest: %+v", st)
	}
	if got[0].At != rs[12-len(got)].At {
		t.Fatal("byte cap must drop an oldest prefix, not newest data")
	}
}

// A corrupt file is quarantined, starts empty and degraded in reporting
// terms, then heals on the first successful write.
func TestSpoolCorruptQuarantinedAndHeals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := newSpool(path)
	if st := s.Stats(); st.State != SpoolStateCorrupt {
		t.Fatalf("state = %q, want corrupt", st.State)
	}
	backups, _ := filepath.Glob(filepath.Join(dir, "state.json.corrupt-*"))
	if len(backups) != 1 {
		t.Fatalf("expected one quarantine backup, got %v", backups)
	}
	if s.Pending() != 0 {
		t.Fatal("a corrupt spool must start empty")
	}

	if err := s.Append(mkResults(2, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.State != SpoolStateOK || st.Pending != 2 {
		t.Fatalf("state after first write = %+v, want ok/2", st)
	}
	restarted := newSpool(path)
	if restarted.Pending() != 2 || restarted.Stats().State != SpoolStateOK {
		t.Fatalf("healed spool did not survive restart: %+v", restarted.Stats())
	}
}

// Drain walks the backlog oldest-first in bounded batches, reports what
// remains, and ends empty — the loop a long outage exercises.
func TestSpoolDrainBatchesOldestFirst(t *testing.T) {
	s := newSpool(filepath.Join(t.TempDir(), "state.json"))
	base := time.Now().UTC().Truncate(time.Second)
	if err := s.Append(mkResults(5, base)); err != nil {
		t.Fatal(err)
	}

	var sent []string
	for {
		batch, more, st := s.Batch(2)
		if len(batch) == 0 {
			t.Fatal("empty batch before the spool drained")
		}
		if st.Pending != 5-len(sent) {
			t.Fatalf("stats pending = %d, want %d", st.Pending, 5-len(sent))
		}
		for _, r := range batch {
			if len(sent) > 0 && r.At.Before(base.Add(time.Duration(len(sent))*time.Second)) {
				t.Fatal("batches must walk oldest-first without overlap")
			}
			sent = append(sent, r.ID)
		}
		// Pretend hz acknowledged exactly this batch.
		ids := make([]string, len(batch))
		for i, r := range batch {
			ids[i] = r.ID
		}
		if err := s.Ack(ids); err != nil {
			t.Fatal(err)
		}
		if len(sent) < 5 {
			if !more {
				t.Fatalf("batch %d should report more remaining", len(sent))
			}
			continue
		}
		if more {
			t.Fatal("the final batch must not report a remainder")
		}
		break
	}
	if s.Pending() != 0 || s.Stats().Pending != 0 {
		t.Fatal("a fully acknowledged backlog must be empty")
	}
}

// No state path: exactly the old in-memory behaviour, and the agent must not
// claim durability it does not have.
func TestSpoolStatelessMode(t *testing.T) {
	s := newSpool("")
	if err := s.Append(mkResults(3, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if got, more, st := s.Batch(2); len(got) != 2 || !more {
		t.Fatalf("stateless batch wrong: %d %v", len(got), more)
	} else if st.State != "" || st.Cap != maxBuffered {
		t.Fatalf("stateless stats must not claim a state: %+v", st)
	}
	if err := s.AckPrefix(3); err != nil || s.Pending() != 0 {
		t.Fatal("stateless ack failed")
	}
}
