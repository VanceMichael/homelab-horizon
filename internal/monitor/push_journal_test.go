package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The point of the journal: a retried identity folds nothing twice, and that
// memory survives hz itself restarting.
func TestPushJournalDedupAcrossRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "push")
	j := newPushJournal(root)

	res, err := j.Commit("v1", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fresh) != 2 || len(res.Held) != 2 {
		t.Fatalf("first commit fresh=%v held=%v", res.Fresh, res.Held)
	}

	// Overlapping retry plus a new result.
	res, err = j.Commit("v1", []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fresh) != 1 || res.Fresh[0] != "c" {
		t.Fatalf("only the unseen result should be fresh, got %v", res.Fresh)
	}
	if len(res.Held) != 3 {
		t.Fatalf("all three submitted identities are now held, got %v", res.Held)
	}

	// A duplicate id inside one batch is held once, in first-seen order.
	res, err = j.Commit("v1", []string{"c", "c", "d"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fresh) != 1 || res.Fresh[0] != "d" || len(res.Held) != 2 {
		t.Fatalf("in-batch duplicate handled wrong: %+v", res)
	}

	// Simulate an hz restart: new process, same directory.
	j2 := newPushJournal(root)
	res, err = j2.Commit("v1", []string{"a", "b", "c", "d", "e"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fresh) != 1 || res.Fresh[0] != "e" {
		t.Fatalf("after restart only e is new, got %v", res.Fresh)
	}
	if fi, err := os.Stat(filepath.Join(root, "v1.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("journal perms = %v, %v", fi.Mode().Perm(), err)
	}
}

// Vantages never share a de-dup scope: the same identity from two agents is
// two different results.
func TestPushJournalVantageIsolation(t *testing.T) {
	j := newPushJournal(filepath.Join(t.TempDir(), "push"))

	if _, err := j.Commit("a", []string{"x"}); err != nil {
		t.Fatal(err)
	}
	res, err := j.Commit("b", []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fresh) != 1 {
		t.Fatal("the same identity at a different vantage must be fresh")
	}
	if n := countFiles(t, j.root); n != 2 {
		t.Fatalf("expected two journal files, got %d", n)
	}
}

// Age then count: both trim an oldest prefix deterministically.
func TestPushJournalGCTrimsOldest(t *testing.T) {
	v := &vantageJournal{index: make(map[string]int)}
	now := time.Now()
	// Five entries older than the horizon, then 25,000 fresh ones.
	for i := 0; i < 5; i++ {
		v.entries = append(v.entries, journalEntry{
			ID: "old" + string(rune('a'+i)), RecvAt: now.Add(-pushJournalHorizon - time.Hour),
		})
	}
	for i := 0; i < 25000; i++ {
		v.entries = append(v.entries, journalEntry{
			ID: "new", RecvAt: now.Add(-time.Minute),
		})
	}
	// Distinguish the newest entries so the survivors are identifiable.
	for i := 24990; i < 25000; i++ {
		v.entries[5+i].ID = "latest" + string(rune('0'+i-24990))
	}

	j := newPushJournal("")
	j.gcLocked(v, now)

	if len(v.entries) != pushJournalMaxEntries {
		t.Fatalf("entries after GC = %d, want %d", len(v.entries), pushJournalMaxEntries)
	}
	if v.entries[0].ID != "new" {
		t.Fatal("GC must drop an oldest prefix")
	}
	for i := 0; i < 10; i++ {
		want := "latest" + string(rune('0'+i))
		if v.entries[len(v.entries)-10+i].ID != want {
			t.Fatalf("newest entries must survive, position %d = %s", i, v.entries[len(v.entries)-10+i].ID)
		}
	}
	// Index stays consistent with the slice.
	if v.index["latest0"] != pushJournalMaxEntries-10 {
		t.Fatalf("index not rebuilt after trim: %d", v.index["latest0"])
	}
}

// A corrupt journal is quarantined, announced once, and replaced by a working
// one — never silently merged or ignored.
func TestPushJournalCorruptQuarantineAndNotice(t *testing.T) {
	root := filepath.Join(t.TempDir(), "push")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "v1.json")
	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}

	j := newPushJournal(root)
	res, err := j.Commit("v1", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Notice == "" {
		t.Fatal("the first successful commit after corruption must carry a notice")
	}
	if len(res.Fresh) != 1 {
		t.Fatal("the reset journal must accept the batch as fresh")
	}
	if n := countFilesWithSuffix(t, root, ".corrupt-"); n == 0 {
		t.Fatal("the corrupt journal was not quarantined")
	}

	// Notice is one-shot; the file is now valid and remembers the batch.
	res, err = j.Commit("v1", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Notice != "" || len(res.Fresh) != 0 {
		t.Fatalf("notice=%q fresh=%v after heal", res.Notice, res.Fresh)
	}
}

// When the write fails nothing is acknowledged and the in-memory state does
// not outrun the disk: the batch stays fresh for a retry after recovery. The
// failure is injected with the journal root occupied by a regular file, which
// blocks MkdirAll under any uid.
func TestPushJournalWriteFailureRollsBack(t *testing.T) {
	root := filepath.Join(t.TempDir(), "push")
	if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	j := newPushJournal(root)

	if _, err := j.Commit("v1", []string{"a", "b"}); err == nil {
		t.Fatal("a commit that cannot persist must fail")
	}
	// Same process, after the disk recovers: identities are still fresh —
	// the failed attempt neither folded nor acknowledged them.
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := j.Commit("v1", []string{"a", "b"})
	if err != nil {
		t.Fatalf("commit after recovery: %v", err)
	}
	if len(res.Fresh) != 2 {
		t.Fatalf("rolled-back identities must be fresh again, got %v", res.Fresh)
	}
}

// Deleting a vantage removes its journal; a same-named re-registration starts
// a new identity scope.
func TestPushJournalRemove(t *testing.T) {
	root := filepath.Join(t.TempDir(), "push")
	j := newPushJournal(root)
	if _, err := j.Commit("v1", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "v1.json")); err != nil {
		t.Fatalf("journal should exist: %v", err)
	}

	j.Remove("v1")
	if _, err := os.Stat(filepath.Join(root, "v1.json")); !os.IsNotExist(err) {
		t.Fatalf("journal should be gone, err=%v", err)
	}

	res, err := j.Commit("v1", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fresh) != 1 {
		t.Fatal("a re-registered vantage must get an empty journal")
	}
}

// A rename carries the file and the in-memory record; the renamed vantage
// still recognises results it committed under the old name.
func TestPushJournalRenameMigrates(t *testing.T) {
	root := filepath.Join(t.TempDir(), "push")
	j := newPushJournal(root)
	if _, err := j.Commit("old", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	j.Rename("old", "new")

	if _, err := os.Stat(filepath.Join(root, "old.json")); !os.IsNotExist(err) {
		t.Fatalf("old journal should be gone, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "new.json")); err != nil {
		t.Fatalf("renamed journal should exist: %v", err)
	}
	// Simulated reload: the old name now looks removed — it must not delete
	// the migrated file.
	j.Remove("old")
	if _, err := os.Stat(filepath.Join(root, "new.json")); err != nil {
		t.Fatalf("reload must not remove the migrated journal: %v", err)
	}
	if res, err := j.Commit("new", []string{"a", "b"}); err != nil || len(res.Fresh) != 1 {
		t.Fatalf("identity memory did not survive rename: %+v, %v", res, err)
	}
}

// A report arriving under the new name between the config swap and the
// migration must not lose its identities: rename merges the two records.
func TestPushJournalRenameMergesConcurrentShell(t *testing.T) {
	root := filepath.Join(t.TempDir(), "push")
	j := newPushJournal(root)

	if _, err := j.Commit("old", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	// As if a report raced ahead under the new name before the rename ran.
	if _, err := j.Commit("new", []string{"b"}); err != nil {
		t.Fatal(err)
	}
	j.Rename("old", "new")

	// Both identities survive, deduplicated; the old file is gone.
	if _, err := os.Stat(filepath.Join(root, "old.json")); !os.IsNotExist(err) {
		t.Fatal("old journal should be gone")
	}
	res, err := j.Commit("new", []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fresh) != 1 || res.Fresh[0] != "c" {
		t.Fatalf("merged journal should know a and b, fresh=%v", res.Fresh)
	}

	// And it holds across a restart too.
	reopened := newPushJournal(root)
	res, err = reopened.Commit("new", []string{"a", "b"})
	if err != nil || len(res.Fresh) != 0 {
		t.Fatalf("merged identities must persist across restart: %+v %v", res, err)
	}
}

// The old name's only record lives in a file from a previous process, while
// the new name already has a same-process shell: rename merges the file in
// instead of letting the rename clobber the shell.
func TestPushJournalRenameMergesPriorProcessFileIntoShell(t *testing.T) {
	root := filepath.Join(t.TempDir(), "push")
	if _, err := newPushJournal(root).Commit("old", []string{"a"}); err != nil {
		t.Fatal(err)
	}

	// Fresh process: no in-memory old-name record, but a first report already
	// raced ahead under the new name.
	j := newPushJournal(root)
	if _, err := j.Commit("new", []string{"b"}); err != nil {
		t.Fatal(err)
	}
	j.Rename("old", "new")

	if _, err := os.Stat(filepath.Join(root, "old.json")); !os.IsNotExist(err) {
		t.Fatal("old journal file should be gone")
	}
	res, err := j.Commit("new", []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fresh) != 1 || res.Fresh[0] != "c" {
		t.Fatalf("prior-process identity must survive the rename, fresh=%v", res.Fresh)
	}

	// And hold on disk for the next process.
	if res, _ := newPushJournal(root).Commit("new", []string{"a", "b"}); len(res.Fresh) != 0 {
		t.Fatalf("merged identities must survive restart, fresh=%v", res.Fresh)
	}
}

func TestPushJournalMemoryMode(t *testing.T) {
	dir := t.TempDir()
	j := newPushJournal("")
	if _, err := j.Commit("v1", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if res, _ := j.Commit("v1", []string{"a"}); len(res.Fresh) != 0 {
		t.Fatal("in-memory dedup should hold for the process life")
	}
	if n := countFiles(t, dir); n != 0 {
		t.Fatalf("memory mode must not touch disk, found %d files", n)
	}
}

// A vantage name never becomes a path traversal.
func TestPushJournalPathIsEscaped(t *testing.T) {
	j := newPushJournal("/var/lib/h")
	p := j.pathFor("../../etc/passwd")
	if filepath.Base(p) != "..%2F..%2Fetc%2Fpasswd.json" {
		t.Fatalf("unsafe journal path: %s", p)
	}
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func countFilesWithSuffix(t *testing.T, dir, suffix string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && contains(e.Name(), suffix) {
			n++
		}
	}
	return n
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
