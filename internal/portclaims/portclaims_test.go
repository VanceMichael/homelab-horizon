package portclaims

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iodesystems/homelab-horizon/internal/system"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "portclaims.json")
	s, err := Open(system.RealFileSystem{}, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s, path
}

func noListener(context.Context, int, int) ([]int, error) { return nil, nil }

func allocReq(host string, observe func(context.Context, int, int) ([]int, error)) AllocRequest {
	return AllocRequest{
		Host:     host,
		Proto:    "tcp",
		From:     20000,
		Count:    1,
		TTL:      time.Minute,
		Formal:   map[int]bool{},
		Excluded: func(int) bool { return false },
		Observe:  observe,
	}
}

func TestAllocateBasic(t *testing.T) {
	s, _ := newTestStore(t)
	c, err := s.Allocate(context.Background(), allocReq("10.0.0.1", noListener))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if c.From != 20000 || c.To != 20000 || c.Host != "10.0.0.1" || c.Proto != "tcp" {
		t.Fatalf("unexpected claim: %+v", c)
	}
	if !strings.HasPrefix(c.ID, idPrefix) || c.Token == "" {
		t.Fatalf("missing credential: id=%q token=%q", c.ID, c.Token)
	}
}

// Two sequential allocations under the same store lock must never return the
// same range — the whole point of the claim protocol.
func TestAllocateClaimsBlockEachOther(t *testing.T) {
	s, _ := newTestStore(t)
	first, err := s.Allocate(context.Background(), allocReq("10.0.0.1", noListener))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := s.Allocate(context.Background(), allocReq("10.0.0.1", noListener))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.From == second.From {
		t.Fatalf("both claims landed on %d", first.From)
	}

	// A different host is a different scope: it may reuse the number.
	other, err := s.Allocate(context.Background(), allocReq("10.0.0.2", noListener))
	if err != nil {
		t.Fatalf("other host: %v", err)
	}
	if other.From != first.From {
		t.Fatalf("other host should be free to use %d, got %d", first.From, other.From)
	}
}

func TestAllocateCountIsContiguous(t *testing.T) {
	s, _ := newTestStore(t)
	req := allocReq("h", noListener)
	req.Count = 3
	c, err := s.Allocate(context.Background(), req)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if c.To-c.From+1 != 3 {
		t.Fatalf("want 3-port span, got %d-%d", c.From, c.To)
	}
	next, err := s.Allocate(context.Background(), allocReq("h", noListener))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if next.From != c.To+1 {
		t.Fatalf("next claim %d should follow %d", next.From, c.To)
	}
}

func TestAllocateAvoidsFormalAndExcluded(t *testing.T) {
	s, _ := newTestStore(t)
	req := allocReq("h", noListener)
	req.Formal[20000] = true
	req.Excluded = func(p int) bool { return p == 20001 }
	c, err := s.Allocate(context.Background(), req)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if c.From != 20002 {
		t.Fatalf("want 20002 past formal+excluded, got %d", c.From)
	}
}

// A listening candidate is rejected and the search resumes past it.
func TestAllocateRetriesPastLiveListener(t *testing.T) {
	s, _ := newTestStore(t)
	calls := 0
	observe := func(_ context.Context, from, to int) ([]int, error) {
		calls++
		if calls == 1 {
			return []int{from}, nil // the first candidate is actually busy
		}
		return nil, nil
	}
	c, err := s.Allocate(context.Background(), allocReq("h", observe))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if calls != 2 || c.From != 20001 {
		t.Fatalf("want second candidate 20001 after %d scans, got %d", calls, c.From)
	}
}

func TestAllocateScanErrorMintsNothing(t *testing.T) {
	s, _ := newTestStore(t)
	req := allocReq("h", func(context.Context, int, int) ([]int, error) {
		return nil, errors.New("host unreachable")
	})
	if _, err := s.Allocate(context.Background(), req); !errors.Is(err, ErrScanFailed) {
		t.Fatalf("want ErrScanFailed, got %v", err)
	}
	if len(s.Active()) != 0 {
		t.Fatalf("no claim may exist after a failed scan: %+v", s.Active())
	}
}

func TestAllocateContextCancelMintsNothing(t *testing.T) {
	s, _ := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Allocate(ctx, allocReq("h", noListener)); !errors.Is(err, ErrScanFailed) {
		t.Fatalf("canceled ctx must fail with ErrScanFailed, got %v", err)
	}
	if len(s.Active()) != 0 {
		t.Fatal("no claim may survive a disconnected client")
	}
}

func TestAllocateNoFreeRange(t *testing.T) {
	s, _ := newTestStore(t)
	req := allocReq("h", noListener)
	req.From = 65535
	req.Count = 2
	if _, err := s.Allocate(context.Background(), req); !errors.Is(err, ErrNoFreeRange) {
		t.Fatalf("want ErrNoFreeRange, got %v", err)
	}
}

func TestActiveNeverExposesToken(t *testing.T) {
	s, _ := newTestStore(t)
	c, err := s.Allocate(context.Background(), allocReq("h", noListener))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range s.Active() {
		if a.Token != "" {
			t.Fatalf("listing leaked token: %+v", a)
		}
		if a.ID != c.ID {
			t.Fatalf("unexpected claim in listing: %+v", a)
		}
	}
}

func TestReleaseFlow(t *testing.T) {
	s, _ := newTestStore(t)
	c, err := s.Allocate(context.Background(), allocReq("h", noListener))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Release(c.ID, "wrong-token"); !errors.Is(err, ErrWrongToken) {
		t.Fatalf("wrong token: want ErrWrongToken, got %v", err)
	}
	if len(s.Active()) != 1 {
		t.Fatal("failed release must retain the claim")
	}
	released, err := s.Release(c.ID, c.Token)
	if err != nil || !released {
		t.Fatalf("release: %v %v", released, err)
	}
	// Idempotent: releasing again is not an error.
	released, err = s.Release(c.ID, c.Token)
	if err != nil || released {
		t.Fatalf("second release: %v %v", released, err)
	}
}

func TestClaimSurvivesReopen(t *testing.T) {
	s, path := newTestStore(t)
	c, err := s.Allocate(context.Background(), allocReq("h", noListener))
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(system.RealFileSystem{}, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got := reopened.Active()
	if len(got) != 1 || got[0].ID != c.ID || got[0].From != c.From {
		t.Fatalf("claim did not survive restart: %+v", got)
	}
}

func TestExpiredClaimDroppedOnLoadAndSweep(t *testing.T) {
	s, path := newTestStore(t)
	clock := time.Unix(1_700_000_000, 0)
	s.SetNow(func() time.Time { return clock })
	c, err := s.Allocate(context.Background(), allocReq("h", noListener))
	if err != nil {
		t.Fatal(err)
	}
	// Advance past TTL in memory: reads filter, sweep persists.
	clock = clock.Add(2 * time.Minute)
	if len(s.Active()) != 0 {
		t.Fatal("expired claim must not be listed")
	}
	n, err := s.Sweep()
	if err != nil || n != 1 {
		t.Fatalf("sweep: n=%d err=%v", n, err)
	}
	reopened, err := Open(system.RealFileSystem{}, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if len(reopened.Active()) != 0 {
		t.Fatalf("expired claim %s survived in file", c.ID)
	}
}

// Config adopting a leased range completes the takeover: the ghost claim is
// reaped. An unrelated claim stays.
func TestReapAdoptedRanges(t *testing.T) {
	s, _ := newTestStore(t)
	a, err := s.Allocate(context.Background(), allocReq("h", noListener)) // 20000
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Allocate(context.Background(), allocReq("h", noListener)) // 20001
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Reap(func(host, proto string) map[int]bool {
		if host == "h" && proto == "tcp" {
			return map[int]bool{a.From: true} // service config took claim a's port
		}
		return map[int]bool{}
	})
	if err != nil || n != 1 {
		t.Fatalf("reap n=%d err=%v", n, err)
	}
	active := s.Active()
	if len(active) != 1 || active[0].ID != b.ID {
		t.Fatalf("only the adopted claim should be gone: %+v", active)
	}
}

// A save failure during mint must leave nothing behind, in memory or on disk.
func TestSaveFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portclaims.json")
	fs := &failWriteFS{FileSystem: system.RealFileSystem{}}
	s, err := Open(fs, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Allocate(context.Background(), allocReq("h", noListener)); err == nil {
		t.Fatal("want persistence error, got nil")
	}
	if len(s.Active()) != 0 {
		t.Fatal("claim visible after failed save")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("no state file should exist after failed save, stat err=%v", err)
	}
}

// A corrupt file is quarantined and the store opens empty rather than
// inventing claims or crashing startup.
func TestCorruptFileIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portclaims.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(system.RealFileSystem{}, path)
	if err != nil {
		t.Fatalf("corrupt file should not fail open: %v", err)
	}
	if len(s.Active()) != 0 {
		t.Fatal("store must be empty after corrupt load")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "portclaims.json.corrupt-*"))
	if len(matches) != 1 {
		t.Fatalf("want one quarantined file, got %v", matches)
	}
}

// failWriteFS fails every WriteFile, to exercise persistence-failure paths.
type failWriteFS struct {
	system.FileSystem
}

func (f *failWriteFS) WriteFile(string, []byte, os.FileMode) error {
	return errors.New("disk full")
}
