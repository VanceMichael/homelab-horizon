package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingHz is a stand-in gateway: it records every report and answers per
// a caller-supplied policy.
type recordingHz struct {
	mu       sync.Mutex
	requests []PushRequest
	answer   func(nth int, req PushRequest) PushResponse
}

func (h *recordingHz) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PushRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.requests = append(h.requests, req)
		n := len(h.requests)
		resp := h.answer(n, req)
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (h *recordingHz) snapshot() []PushRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]PushRequest, len(h.requests))
	copy(out, h.requests)
	return out
}

// runPushLoop drives one agent loop for a short time.
func runPushLoop(t *testing.T, agent *Agent, hz *httptest.Server, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	agent.PushLoop(ctx, &Pusher{URL: hz.URL, Token: "t", Timeout: 2 * time.Second}, 20*time.Millisecond)
}

// After a restart the first report resumes at the oldest unacknowledged
// record, identity-based acks drain the spool, and every report carries the
// spool's stats.
func TestPushLoopResumesFromSpoolAndAcksByID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	base := time.Now().UTC().Truncate(time.Second)

	// A previous process produced results and died before hearing back.
	func() {
		a := NewAgent("vps", "v1", "t", path)
		a.EnablePushSpool()
		if err := a.pushSpool.SetTargets(testSet("a.example.com")); err != nil {
			t.Fatal(err)
		}
		if err := a.pushSpool.Append(mkResults(3, base)); err != nil {
			t.Fatal(err)
		}
	}()

	restarted := NewAgent("vps", "v1", "t", path)
	restarted.EnablePushSpool()
	if st := restarted.SpoolStats(); st.Pending != 3 || st.State != SpoolStateOK {
		t.Fatalf("restart did not recover the backlog: %+v", st)
	}

	hz2 := &recordingHz{answer: func(_ int, req PushRequest) PushResponse {
		ids := make([]string, len(req.Results))
		for i, r := range req.Results {
			ids[i] = r.ID
		}
		return PushResponse{Accepted: len(ids), AckIDs: ids, Interval: 1}
	}}
	srv := httptest.NewServer(hz2.handler())
	defer srv.Close()

	runPushLoop(t, restarted, srv, 300*time.Millisecond)

	if st := restarted.SpoolStats(); st.Pending != 0 {
		t.Fatalf("backlog did not drain: %+v", st)
	}
	reqs := hz2.snapshot()
	if len(reqs) == 0 {
		t.Fatal("the agent never reported")
	}
	first := reqs[0]
	if len(first.Results) != 3 {
		t.Fatalf("first report after restart = %d results, want 3", len(first.Results))
	}
	if first.Results[0].At != base {
		t.Fatalf("resume must start at the oldest uncommitted record, got %s", first.Results[0].At)
	}
	if first.Spool == nil || first.Spool.Pending != 3 || first.Spool.State != SpoolStateOK {
		t.Fatalf("first report must carry durable spool stats: %+v", first.Spool)
	}
	if first.Spool.OldestAt == nil || !first.Spool.OldestAt.Equal(base) {
		t.Fatalf("spool oldest_at = %v, want %s", first.Spool.OldestAt, base)
	}
}

// A partial ack leaves the rest for the next report; an old-hz answer without
// ack_ids falls back to the accepted prefix. Both must converge to drained.
func TestPushLoopPartialAckAndCountFallback(t *testing.T) {
	t.Run("partial identity ack", func(t *testing.T) {
		a := NewAgent("vps", "v1", "t", filepath.Join(t.TempDir(), "state.json"))
		a.EnablePushSpool()
		base := time.Now().UTC().Truncate(time.Second)
		if err := a.pushSpool.Append(mkResults(3, base)); err != nil {
			t.Fatal(err)
		}

		hz2 := &recordingHz{answer: func(nth int, req PushRequest) PushResponse {
			if nth == 1 {
				if len(req.Results) != 3 {
					t.Errorf("first report should hold all three, got %d", len(req.Results))
				}
				// Acknowledge only the oldest; hz must not be trusted to ack
				// in lockstep with the batch. No interval override: the loop's
				// short test cadence lets the retry arrive within the window.
				return PushResponse{Accepted: 1, AckIDs: []string{req.Results[0].ID}}
			}
			ids := make([]string, len(req.Results))
			for i, r := range req.Results {
				ids[i] = r.ID
			}
			return PushResponse{Accepted: len(ids), AckIDs: ids}
		}}
		srv := httptest.NewServer(hz2.handler())
		defer srv.Close()

		runPushLoop(t, a, srv, 400*time.Millisecond)

		reqs := hz2.snapshot()
		if len(reqs) < 2 || len(reqs[1].Results) != 2 {
			t.Fatalf("the unacknowledged two should form the next report, got %+v", reqs)
		}
		if reqs[1].Results[0].At != base.Add(time.Second) {
			t.Fatal("the retry must keep its unacknowledged boundary")
		}
		if a.SpoolStats().Pending != 0 {
			t.Fatal("partial ack should still drain to zero")
		}
	})

	t.Run("accepted count fallback (older hz)", func(t *testing.T) {
		// Stateless spool: an agent with no --state file, talking to an hz
		// that answers only with a count.
		a := NewAgent("vps", "v1", "t", "")
		a.EnablePushSpool()
		base := time.Now().UTC().Truncate(time.Second)
		if err := a.pushSpool.Append(mkResults(2, base)); err != nil {
			t.Fatal(err)
		}

		hz2 := &recordingHz{answer: func(_ int, req PushRequest) PushResponse {
			// Deliberately no AckIDs: the old-wire contract. No interval
			// override either, so the test's short cadence produces an
			// empty-backlog report inside the window.
			return PushResponse{Accepted: len(req.Results)}
		}}
		srv := httptest.NewServer(hz2.handler())
		defer srv.Close()

		runPushLoop(t, a, srv, 300*time.Millisecond)

		if a.SpoolStats().Pending != 0 {
			t.Fatal("the count fallback must drain the backlog")
		}
		reqs := hz2.snapshot()
		for _, req := range reqs {
			if req.Spool != nil && req.Spool.State != "" {
				t.Fatalf("a stateless agent must not claim a durability state: %+v", req.Spool)
			}
		}
		// Once empty, the wire must not carry a year-zero timestamp.
		last := reqs[len(reqs)-1]
		if last.Spool == nil || last.Spool.Pending != 0 || last.Spool.OldestAt != nil {
			t.Fatalf("drained report should carry an empty, clean spool block: %+v", last.Spool)
		}
		b, _ := json.Marshal(last)
		if strings.Contains(string(b), "oldest_at") {
			t.Fatalf("an empty backlog must not serialise oldest_at: %s", b)
		}
	})
}
