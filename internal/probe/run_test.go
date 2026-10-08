package probe

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunUnknownKindIsAResultNotACrash(t *testing.T) {
	got := Run(context.Background(), TargetSet{Timeout: 1}, Target{
		Name: "x", Host: "127.0.0.1", Kinds: []string{"telepathy"},
	})
	if len(got) != 1 || got[0].Status != StatusFailed {
		t.Fatalf("unknown kind should produce one failed result, got %+v", got)
	}
	if !strings.Contains(got[0].Error, "telepathy") {
		t.Fatalf("the error should name the kind, got %q", got[0].Error)
	}
}

// A result's ID is its identity across retries and restarts: present at
// production, and unique without any coordination.
func TestResultsGetUniqueIDs(t *testing.T) {
	got := Run(context.Background(), TargetSet{Timeout: 1}, Target{
		Name: "x", Host: "127.0.0.1", Kinds: []string{"unknown", "telepathy"},
	})
	if len(got) != 2 {
		t.Fatalf("expected two results, got %d", len(got))
	}
	seen := make(map[string]bool, 1000)
	for i := 0; i < 500; i++ {
		rs := Run(context.Background(), TargetSet{Timeout: 1}, Target{
			Name: "x", Host: "127.0.0.1", Kinds: []string{"telepathy"},
		})
		if rs[0].ID == "" {
			t.Fatal("a produced result must carry an ID")
		}
		if seen[rs[0].ID] {
			t.Fatalf("result ID %q was minted twice", rs[0].ID)
		}
		seen[rs[0].ID] = true
	}
}

// An older agent sends results without IDs. hz must still tell a retried
// result from a new one, by hashing exactly the wire contents.
func TestResultIdentityFallsBackToStableContentHash(t *testing.T) {
	base := Result{
		Target: "a", Host: "a.example", Kind: KindDNS,
		At:        time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
		Status:    StatusOK,
		LatencyMS: 12,
	}
	h1 := ResultIdentity(base)
	h2 := ResultIdentity(base)
	if h1 == "" || h1 == base.ID || !strings.HasPrefix(h1, "c:") {
		t.Fatalf("legacy identity should be a content hash, got %q", h1)
	}
	if h1 != h2 {
		t.Fatal("the same bytes must hash to the same identity")
	}

	// Every field is part of the identity.
	changes := []Result{
		func() Result { r := base; r.Target = "b"; return r }(),
		func() Result { r := base; r.Host = "b.example"; return r }(),
		func() Result { r := base; r.Kind = KindHTTPS; return r }(),
		func() Result { r := base; r.At = base.At.Add(1); return r }(),
		func() Result { r := base; r.Status = StatusFailed; return r }(),
		func() Result { r := base; r.LatencyMS = 13; return r }(),
		func() Result { r := base; r.Detail = "x"; return r }(),
		func() Result { r := base; r.Error = "x"; return r }(),
	}
	for i, c := range changes {
		if ResultIdentity(c) == h1 {
			t.Fatalf("change %d did not alter the identity", i)
		}
	}

	// A result carrying its own ID is identified by it, whatever its
	// contents: the agent assigned the identity, hz does not second-guess it.
	withID := base
	withID.ID = "agent-minted"
	if got := ResultIdentity(withID); got != "agent-minted" {
		t.Fatalf("explicit ID should win, got %q", got)
	}
}

// New fields are additive: an old agent's JSON without them must decode, and
// steady-state encoding must not emit empty optional envelopes.
func TestPushWireBackwardCompatibility(t *testing.T) {
	var req PushRequest
	if err := json.Unmarshal([]byte(`{"vantage":"v","results":[]}`), &req); err != nil {
		t.Fatalf("an old-agent request must decode: %v", err)
	}
	if req.Spool != nil {
		t.Fatal("an absent spool block must stay nil")
	}
	b, err := json.Marshal(PushRequest{Vantage: "v", Results: nil})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "spool") || strings.Contains(string(b), "ack") {
		t.Fatalf("steady-state request gained empty optional fields: %s", b)
	}

	var resp PushResponse
	if err := json.Unmarshal([]byte(`{"accepted":3}`), &resp); err != nil {
		t.Fatalf("an old-hz response must decode: %v", err)
	}
	if resp.Accepted != 3 || resp.AckIDs != nil {
		t.Fatalf("legacy response decoded wrong: %+v", resp)
	}
}

func TestProbeTCPSucceedsAgainstALiveListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	got := probeTCP(context.Background(), Target{Name: "local", Host: "127.0.0.1", Port: port})
	if got.Status != StatusOK {
		t.Fatalf("expected ok against a live listener, got %+v", got)
	}
	if got.Kind != KindTCP {
		t.Fatalf("kind %q, expected %q", got.Kind, KindTCP)
	}
}

func TestProbeTCPFailsOnAClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close() // nothing is listening there now

	got := probeTCP(context.Background(), Target{Name: "dead", Host: "127.0.0.1", Port: addr.Port})
	if got.Status != StatusFailed {
		t.Fatalf("expected failure against a closed port, got %+v", got)
	}
	if got.Error == "" {
		t.Fatal("a failed probe must carry the reason")
	}
}

// An untrusted certificate is a failure, not a warning: from outside, a
// browser would refuse the connection outright.
func TestProbeHTTPSRejectsAnUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	got := probeHTTPS(context.Background(), Target{Name: "self-signed", Host: host, Port: port}, 0)
	if got.Status != StatusFailed {
		t.Fatalf("expected an untrusted certificate to fail, got %+v", got)
	}
}

func TestDNSExpectationClassification(t *testing.T) {
	cases := []struct {
		name   string
		expect []string
		got    []string
		want   string
	}{
		{"no expectation accepts any answer", nil, []string{"9.9.9.9"}, StatusOK},
		{"exact match", []string{"1.2.3.4"}, []string{"1.2.3.4"}, StatusOK},
		{"extra answers are fine", []string{"1.2.3.4"}, []string{"1.2.3.4", "5.6.7.8"}, StatusOK},
		{"partial match warns", []string{"1.2.3.4", "5.6.7.8"}, []string{"1.2.3.4"}, StatusWarning},
		{"pointing elsewhere fails", []string{"1.2.3.4"}, []string{"9.9.9.9"}, StatusFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _ := dnsVerdict(Target{ExpectIPs: tc.expect}, tc.got)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
