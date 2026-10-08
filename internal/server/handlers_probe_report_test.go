package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iodesystems/homelab-horizon/internal/apitypes"
	"github.com/iodesystems/homelab-horizon/internal/config"
	"github.com/iodesystems/homelab-horizon/internal/monitor"
	"github.com/iodesystems/homelab-horizon/internal/probe"
)

func pushCfg() *config.Config {
	return &config.Config{
		KioskURL:   "https://vpn.example.com",
		SSLEnabled: true,
		PublicIP:   "203.0.113.10",
		Services: []config.Service{
			{Name: "api", Domains: []string{"api.example.invalid"}, Proxy: &config.ProxyConfig{Backend: "10.0.0.1:80"}},
		},
	}
}

// report posts one push report as an agent would.
func report(t *testing.T, s *Server, token string, req probe.PushRequest) (*httptest.ResponseRecorder, probe.PushResponse) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/probe/report", strings.NewReader(string(body)))
	r.Host = "vpn.example.com"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.setupRoutes().ServeHTTP(w, r)

	var out probe.PushResponse
	_ = json.NewDecoder(strings.NewReader(w.Body.String())).Decode(&out)
	return w, out
}

func mint(t *testing.T, s *Server) string {
	t.Helper()
	w := postRemote(t, s, s.handleAPIRemoteToken, "/api/v1/checks/remotes/token", "{}")
	var out struct{ Token string }
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Token
}

// The whole point of push: the operator pastes nothing back. An agent
// installed from a command hz issued registers itself on first contact.
func TestFirstReportRegistersTheVantage(t *testing.T) {
	s := newTestServer(t, pushCfg())
	token := mint(t, s)

	now := time.Now().UTC()
	w, resp := report(t, s, token, probe.PushRequest{
		Vantage: "GCP", Version: "v-test", TargetsVersion: "",
		Results: []probe.Result{
			{Target: "api.example.invalid", Host: "api.example.invalid", Kind: probe.KindDNS,
				At: now, Status: probe.StatusOK, LatencyMS: 14},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("report returned %d: %s", w.Code, w.Body.String())
	}
	if resp.Accepted != 1 {
		t.Fatalf("accepted %d, want 1 — the agent drops exactly what hz acknowledges", resp.Accepted)
	}

	stored := s.cfg().RemoteProbes
	if len(stored) != 1 {
		t.Fatalf("expected the vantage to be registered, got %d", len(stored))
	}
	if stored[0].Name != "GCP" || !stored[0].IsPush() || stored[0].Token != token {
		t.Fatalf("registered entry = %+v", stored[0])
	}
	// No URL, because nothing dials it.
	if stored[0].URL != "" {
		t.Fatalf("a push vantage should carry no URL, got %q", stored[0].URL)
	}

	// The result reached the check rows.
	got := s.monitor.GetStatus("ext:GCP:dns:api.example.invalid")
	if got == nil || got.Vantage != "GCP" {
		t.Fatalf("result not folded into a check row: %+v", got)
	}

	// And the agent was handed the target set, since it held none.
	if resp.Targets == nil || len(resp.Targets.Targets) != 1 {
		t.Fatalf("hz should have sent the target set on first contact: %+v", resp.Targets)
	}
}

// Steady state: the agent holds the right version, so no set crosses the wire.
func TestReportOmitsTargetsWhenTheVersionMatches(t *testing.T) {
	s := newTestServer(t, pushCfg())
	token := mint(t, s)
	_, first := report(t, s, token, probe.PushRequest{Vantage: "GCP", Version: "v"})

	_, second := report(t, s, token, probe.PushRequest{
		Vantage: "GCP", Version: "v", TargetsVersion: first.TargetsVersion,
	})
	if second.Targets != nil {
		t.Fatal("an agent holding the current version should not be resent the set")
	}
	if second.TargetsVersion != first.TargetsVersion {
		t.Fatal("the version hz wants should be stable between reports")
	}
}

func TestReportRejectsUnknownTokens(t *testing.T) {
	s := newTestServer(t, pushCfg())

	for _, tc := range []struct{ name, token string }{
		{"no token", ""},
		{"never issued", "0123456789abcdef0123456789abcdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := report(t, s, tc.token, probe.PushRequest{Vantage: "X"})
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", w.Code)
			}
		})
	}
	if len(s.cfg().RemoteProbes) != 0 {
		t.Fatal("a refused report registered a vantage anyway")
	}
}

// The token authenticates; the name is only a label. An agent must not be
// able to report as somebody else by claiming their name.
func TestReportIsIdentifiedByTokenNotName(t *testing.T) {
	s := newTestServer(t, pushCfg())
	token := mint(t, s)
	report(t, s, token, probe.PushRequest{Vantage: "GCP", Version: "v"})

	// Same token, different claimed name: still the vantage the token owns.
	// A host hz actually serves, so the row survives pruning and the test is
	// about identity rather than target membership.
	const host = "api.example.invalid"
	w, _ := report(t, s, token, probe.PushRequest{
		Vantage: "somebody-else", Version: "v",
		Results: []probe.Result{{Target: host, Host: host, Kind: probe.KindDNS,
			At: time.Now().UTC(), Status: probe.StatusOK}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("report returned %d", w.Code)
	}
	if s.monitor.GetStatus("ext:somebody-else:dns:"+host) != nil {
		t.Fatal("results were filed under the name the agent claimed rather than the token's vantage")
	}
	if s.monitor.GetStatus("ext:GCP:dns:"+host) == nil {
		t.Fatal("results were not filed under the token's vantage")
	}
}

func TestRegistrationRefusesCollidingNames(t *testing.T) {
	cfg := pushCfg()
	cfg.RemoteProbes = []config.RemoteProbe{{Name: "GCP", Mode: config.ProbeModePush, Token: "other", Enabled: true}}
	s := newTestServer(t, cfg)

	w, _ := report(t, s, mint(t, s), probe.PushRequest{Vantage: "GCP", Version: "v"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 — two agents in one set of rows would interleave", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already exists") {
		t.Fatalf("the error should say what to do: %s", w.Body.String())
	}
}

func TestRegistrationRefusesBadNames(t *testing.T) {
	for _, name := range []string{"", "   ", "has:colon", "has space"} {
		s := newTestServer(t, pushCfg())
		w, _ := report(t, s, mint(t, s), probe.PushRequest{Vantage: name, Version: "v"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("name %q returned %d, want 400", name, w.Code)
		}
	}
}

// A pull vantage must not silently accept reports: the operator configured
// hz to dial it, and quietly doing both would hide a misconfigured agent.
func TestPullVantageRefusesReports(t *testing.T) {
	cfg := pushCfg()
	cfg.RemoteProbes = []config.RemoteProbe{{
		Name: "dialled", Mode: config.ProbeModePull,
		URL: "https://198.51.100.7:8443", Token: "tok", Enabled: true,
	}}
	s := newTestServer(t, cfg)

	w, _ := report(t, s, "tok", probe.PushRequest{Vantage: "dialled", Version: "v"})
	if w.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409", w.Code)
	}
}

// Like the installer, ingest belongs on the vhost that faces outward.
func TestReportIsKioskOnly(t *testing.T) {
	s := newTestServer(t, pushCfg())
	r := httptest.NewRequest(http.MethodPost, "/api/v1/probe/report", strings.NewReader("{}"))
	r.Host = "hz.example.com"
	w := httptest.NewRecorder()
	s.setupRoutes().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("admin vhost returned %d, want 404", w.Code)
	}
}

// A push vantage gets no poll loop — hz does not dial it.
func TestPushVantageStartsNoPollLoop(t *testing.T) {
	cfg := pushCfg()
	cfg.RemoteProbes = []config.RemoteProbe{
		{Name: "pushed", Mode: config.ProbeModePush, Token: "t", Enabled: true},
		{Name: "dialled", Mode: config.ProbeModePull, URL: "http://127.0.0.1:1", Token: "t", Enabled: true, Poll: 3600},
	}
	s := newTestServer(t, cfg)
	s.monitor.ReloadRemotes(s.cfg())
	defer s.monitor.Stop()

	running := s.monitor.RunningRemotesForTest()
	if running["pushed"] {
		t.Fatal("a push vantage must not get a poll loop")
	}
	if !running["dialled"] {
		t.Fatal("a pull vantage should still get one")
	}
}

// End to end with the real agent and the real Pusher: no operator step
// between installing the agent and the vantage appearing in hz.
func TestPushEndToEndWithARealAgent(t *testing.T) {
	s := newTestServer(t, pushCfg())
	token := mint(t, s)

	// hz, served on the kiosk hostname the agent will dial.
	hz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "vpn.example.com"
		s.setupRoutes().ServeHTTP(w, r)
	}))
	defer hz.Close()

	agent := probe.NewAgent("GCP", "v-e2e", token, "")
	pusher := &probe.Pusher{URL: hz.URL, Token: token, Timeout: 5 * time.Second}

	// Seed a result so the first report carries something.
	agent.Record([]probe.Result{{
		Target: "api.example.invalid", Host: "api.example.invalid",
		Kind: probe.KindHTTPS, At: time.Now().UTC(), Status: probe.StatusOK, LatencyMS: 88,
	}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// One cycle of the real loop: report, get targets, acknowledge.
	resp, err := pusher.Report(ctx, probe.PushRequest{
		Vantage: "GCP", Version: "v-e2e", TargetsVersion: agent.Targets().Version,
		Results: func() []probe.Result { r, _ := agent.Since(time.Time{}, 0); return r }(),
	})
	if err != nil {
		t.Fatalf("the agent could not report: %v", err)
	}
	if resp.Accepted != 1 {
		t.Fatalf("accepted %d, want 1", resp.Accepted)
	}
	if resp.Targets == nil {
		t.Fatal("hz should have sent the target set to an agent holding none")
	}
	agent.SetTargets(*resp.Targets)

	// hz registered it, with no URL and no pin — nothing dials this agent.
	stored := s.cfg().RemoteProbes
	if len(stored) != 1 || !stored[0].IsPush() || stored[0].URL != "" || stored[0].PinSHA256 != "" {
		t.Fatalf("registered entry = %+v", stored)
	}

	// The result is a check row, and the agent holds hz's targets.
	if got := s.monitor.GetStatus("ext:GCP:https:api.example.invalid"); got == nil || got.Status != "ok" {
		t.Fatalf("check row = %+v", got)
	}
	if held := agent.Targets(); len(held.Targets) != 1 || held.Targets[0].Host != "api.example.invalid" {
		t.Fatalf("agent holds the wrong targets: %+v", held)
	}

	// Second report: nothing new, and the set is not resent.
	resp2, err := pusher.Report(ctx, probe.PushRequest{
		Vantage: "GCP", Version: "v-e2e", TargetsVersion: agent.Targets().Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Targets != nil {
		t.Fatal("the set was resent to an agent already holding it")
	}
}

// hz tells the agent which build it holds, so a vantage on an old binary
// says so in its own log and shows as outdated in the UI.
func TestReportCarriesTheAgentVersionHzHolds(t *testing.T) {
	s := newTestServer(t, pushCfg())
	s.version = "v9.9.9"
	token := mint(t, s)

	_, resp := report(t, s, token, probe.PushRequest{Vantage: "GCP", Version: "v1.0.0"})
	if resp.AgentVersion != "v9.9.9" {
		t.Fatalf("agent_version = %q, want hz's own build", resp.AgentVersion)
	}

	list := listRemotes(t, s)
	if len(list) != 1 {
		t.Fatalf("expected one vantage, got %d", len(list))
	}
	if !list[0].AgentOutdated {
		t.Fatal("an agent on a different build should be reported as outdated")
	}
	if list[0].ExpectedAgentVersion != "v9.9.9" {
		t.Fatalf("expectedAgentVersion = %q", list[0].ExpectedAgentVersion)
	}

	// Matching build: not outdated.
	_, _ = report(t, s, token, probe.PushRequest{Vantage: "GCP", Version: "v9.9.9"})
	if listRemotes(t, s)[0].AgentOutdated {
		t.Fatal("an agent on the same build must not be flagged")
	}
}

// The unattended updater runs long after any grant expired, so a registered
// vantage's own token has to authorise the download.
func TestVantageTokenAuthorisesTheBinaryDownload(t *testing.T) {
	cfg := pushCfg()
	cfg.RemoteProbes = []config.RemoteProbe{
		{Name: "v", Mode: config.ProbeModePush, Token: "vantage-token", Enabled: true},
	}
	s := newTestServer(t, cfg)
	mux := s.setupRoutes()

	get := func(bearer string) int {
		r := httptest.NewRequest(http.MethodGet, "/admin/hz-probe/bin/linux-amd64", nil)
		r.Host = "vpn.example.com"
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	if got := get("vantage-token"); got == http.StatusUnauthorized {
		t.Fatal("a registered vantage's token should authorise its own update")
	}
	if got := get("some-other-token"); got != http.StatusUnauthorized {
		t.Fatalf("an unknown token returned %d, want 401", got)
	}
}

// withJournalRoot gives a test server a monitor backed by a real journal
// directory, the way production wires it.
func withJournalRoot(t *testing.T, s *Server, cfg *config.Config, root string) {
	t.Helper()
	s.monitor = monitor.New(cfg, monitor.WithPushJournalRoot(root))
}

// The response names the identities hz holds, and a retried batch folds once.
func TestReportAcksByIDAndDedupesTheRetry(t *testing.T) {
	s := newTestServer(t, pushCfg())
	root := filepath.Join(t.TempDir(), "push")
	withJournalRoot(t, s, pushCfg(), root)
	token := mint(t, s)

	now := time.Now().UTC()
	batch := func() probe.PushRequest {
		return probe.PushRequest{
			Vantage: "GCP", Version: "v-test",
			Results: []probe.Result{{
				ID: "result-1", Target: "api.example.invalid", Host: "api.example.invalid",
				Kind: probe.KindDNS, At: now, Status: probe.StatusOK,
			}},
		}
	}

	w1, r1 := report(t, s, token, batch())
	if w1.Code != http.StatusOK || len(r1.AckIDs) != 1 || r1.AckIDs[0] != "result-1" || r1.Accepted != 1 {
		t.Fatalf("first report = %d %+v", w1.Code, r1)
	}
	// The answer is lost; the agent retries the same batch verbatim.
	w2, r2 := report(t, s, token, batch())
	if w2.Code != http.StatusOK {
		t.Fatalf("retry returned %d: %s", w2.Code, w2.Body.String())
	}
	if len(r2.AckIDs) != 1 || r2.AckIDs[0] != "result-1" {
		t.Fatalf("the retry must still be acknowledged by identity: %+v", r2)
	}
	if got := len(s.monitor.GetHistory("ext:GCP:dns:api.example.invalid")); got != 1 {
		t.Fatalf("a retried result must carry one history point, got %d", got)
	}
}

// A gateway that cannot persist the identities must answer non-2xx, fold
// nothing, and acknowledge nothing; recovery accepts the retry once. The
// failure is injected with the journal root occupied by a regular file, which
// blocks MkdirAll regardless of the uid the tests run as.
func TestReport503WhenJournalCannotPersist(t *testing.T) {
	s := newTestServer(t, pushCfg())
	root := filepath.Join(t.TempDir(), "push")
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	withJournalRoot(t, s, pushCfg(), root)
	token := mint(t, s)

	now := time.Now().UTC()
	batch := probe.PushRequest{
		Vantage: "GCP", Version: "v",
		Results: []probe.Result{{
			ID: "r", Target: "api.example.invalid", Host: "api.example.invalid",
			Kind: probe.KindDNS, At: now, Status: probe.StatusOK,
		}},
	}
	w, _ := report(t, s, token, batch)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("an uncommittable report must be 503, got %d: %s", w.Code, w.Body.String())
	}
	if s.monitor.GetStatus("ext:GCP:dns:api.example.invalid") != nil {
		t.Fatal("nothing must fold when the journal write fails")
	}

	// Registration happened before the commit attempt, so the same token is
	// now known: the retry needs no new grant. Recovery is the file giving way
	// to the directory it always should have been.
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	w2, _ := report(t, s, token, batch)
	if w2.Code != http.StatusOK {
		t.Fatalf("retry after recovery = %d: %s", w2.Code, w2.Body.String())
	}
	if got := len(s.monitor.GetHistory("ext:GCP:dns:api.example.invalid")); got != 1 {
		t.Fatalf("after recovery exactly one history point, got %d", got)
	}
}

// Removing a vantage removes its delivery journal; a same-named re-registration
// therefore starts a fresh identity scope.
func TestReportDeletingVantageRemovesJournal(t *testing.T) {
	s := newTestServer(t, pushCfg())
	root := filepath.Join(t.TempDir(), "push")
	withJournalRoot(t, s, pushCfg(), root)
	token := mint(t, s)

	if w, _ := report(t, s, token, probe.PushRequest{Vantage: "GCP", Version: "v"}); w.Code != http.StatusOK {
		t.Fatalf("register = %d", w.Code)
	}
	journal := filepath.Join(root, "GCP.json")
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("journal should exist after first report: %v", err)
	}

	if w := postRemote(t, s, s.handleAPIRemoteDelete, "/api/v1/checks/remotes/delete", `{"name":"GCP"}`); w.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatalf("journal should be deleted with the vantage, err=%v", err)
	}
}

// Renaming a vantage carries its journal: an in-flight result stays known
// under the new name and never folds twice.
func TestReportRenamingVantageMigratesJournal(t *testing.T) {
	s := newTestServer(t, pushCfg())
	root := filepath.Join(t.TempDir(), "push")
	withJournalRoot(t, s, pushCfg(), root)
	token := mint(t, s)

	now := time.Now().UTC()
	if w, _ := report(t, s, token, probe.PushRequest{
		Vantage: "GCP", Version: "v",
		Results: []probe.Result{{
			ID: "migrated-id", Target: "api.example.invalid", Host: "api.example.invalid",
			Kind: probe.KindDNS, At: now, Status: probe.StatusOK,
		}},
	}); w.Code != http.StatusOK {
		t.Fatalf("first report = %d", w.Code)
	}

	body := `{"name":"GCP2","oldName":"GCP","mode":"push","enabled":true,"poll":300,"probe":300}`
	if w := postRemote(t, s, s.handleAPIRemoteUpdate, "/api/v1/checks/remotes/update", body); w.Code != http.StatusOK {
		t.Fatalf("rename = %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "GCP.json")); !os.IsNotExist(err) {
		t.Fatal("old journal should be gone after rename")
	}
	if _, err := os.Stat(filepath.Join(root, "GCP2.json")); err != nil {
		t.Fatalf("journal should migrate to the new name: %v", err)
	}

	// Same token, now reporting under the new name; token defines identity.
	if w, r := report(t, s, token, probe.PushRequest{
		Vantage: "GCP2", Version: "v",
		Results: []probe.Result{{
			ID: "migrated-id", Target: "api.example.invalid", Host: "api.example.invalid",
			Kind: probe.KindDNS, At: now, Status: probe.StatusOK,
		}},
	}); w.Code != http.StatusOK || len(r.AckIDs) != 1 || r.AckIDs[0] != "migrated-id" {
		t.Fatalf("migrated result should be recognised as held: %d %+v", w.Code, r)
	}
}

// Backlog signals from the agent reach the vantage API for the UI.
func TestReportSpoolStatsSurfaceInAPI(t *testing.T) {
	s := newTestServer(t, pushCfg())
	withJournalRoot(t, s, pushCfg(), filepath.Join(t.TempDir(), "push"))
	token := mint(t, s)
	oldest := time.Now().UTC().Add(-2 * time.Hour)

	w, _ := report(t, s, token, probe.PushRequest{
		Vantage: "GCP", Version: "v",
		Spool: &probe.SpoolStats{
			Pending: 9, Cap: 5000, DroppedTotal: 4, OldestAt: &oldest,
			State: probe.SpoolStateDegraded,
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("report = %d", w.Code)
	}
	list := listRemotes(t, s)
	var got apitypes.RemoteProbeResp
	for _, p := range list {
		if p.Name == "GCP" {
			got = p
		}
	}
	if got.SpoolPending != 9 || got.SpoolCap != 5000 || got.SpoolDropped != 4 ||
		got.SpoolState != "degraded" || got.SpoolOldestAt == nil {
		t.Fatalf("spool signals missing from API: %+v", got)
	}
}

// TestPushCommitLoopSurvivesLostResponseAgentAndGatewayRestart drives the
// real agent PushLoop over a durable spool against the real hz handler, and
// breaks the connection at exactly the point "hz folded the results but the
// answer never reached the agent" — the failure the commit loop exists for.
func TestPushCommitLoopSurvivesLostResponseAgentAndGatewayRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "push")
	// Each gateway process gets its own Server; the edge in front switches
	// between them through an atomic pointer — the test must not swap a live
	// Server's monitor field under its HTTP goroutines.
	newGateway := func(cfg *config.Config) *Server {
		s := newTestServer(t, cfg)
		s.monitor = monitor.New(cfg, monitor.WithPushJournalRoot(root))
		return s
	}
	s := newGateway(pushCfg())
	token := mint(t, s)
	var gw atomic.Pointer[Server]
	gw.Store(s)

	const dnsRow = "ext:GCP:dns:api.example.invalid"
	const httpsRow = "ext:GCP:https:api.example.invalid"

	// killOne makes the very next report run hz to completion — committing
	// identities and folding results — and then vanish without delivering
	// the answer: exactly "hz received it, the response was lost".
	var killOne atomic.Bool
	var postsSeen atomic.Int64
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "vpn.example.com"
		current := gw.Load()
		if r.URL.Path == "/api/v1/probe/report" {
			postsSeen.Add(1)
			if killOne.Swap(false) {
				// Let hz finish fully, buffering what would have been its
				// answer...
				rec := httptest.NewRecorder()
				current.setupRoutes().ServeHTTP(rec, r)
				if rec.Code != http.StatusOK {
					t.Errorf("killed report should have committed, got %d: %s", rec.Code, rec.Body.String())
				}
				// ...then close the client's connection without sending it.
				hj, ok := w.(http.Hijacker)
				if !ok {
					t.Error("response writer is not a hijacker")
					return
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close()
				return
			}
		}
		current.setupRoutes().ServeHTTP(w, r)
	}))
	defer edge.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	base := time.Now().UTC().Truncate(time.Second)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	startLoop := func(a *probe.Agent, interval time.Duration) (context.CancelFunc, *probe.Pusher) {
		ctx, cancel := context.WithCancel(context.Background())
		p := &probe.Pusher{URL: edge.URL, Token: token, Timeout: 2 * time.Second}
		go a.PushLoop(ctx, p, interval)
		return cancel, p
	}

	// -- Agent A: first report registers it and installs the target set. A
	// long interval makes the window between a killed post and its retry wide
	// enough to stop the loop deterministically.
	a := probe.NewAgent("GCP", "v1", token, statePath)
	a.EnablePushSpool()
	cancelA, _ := startLoop(a, 500*time.Millisecond)
	waitFor("targets to arrive", func() bool { return len(a.Targets().Targets) > 0 })

	// -- Scenario 1: response lost. hz folds once; the retry must fold nothing.
	killOne.Store(true)
	a.Record([]probe.Result{
		{ID: "r1", Target: "api.example.invalid", Host: "api.example.invalid", Kind: probe.KindDNS, At: base, Status: probe.StatusFailed, Error: "x"},
		{ID: "r2", Target: "api.example.invalid", Host: "api.example.invalid", Kind: probe.KindHTTPS, At: base.Add(time.Second), Status: probe.StatusOK},
		{ID: "r3", Target: "api.example.invalid", Host: "api.example.invalid", Kind: probe.KindDNS, At: base.Add(2 * time.Second), Status: probe.StatusWarning},
	})
	a.SignalProbedForTest()
	seenAfterKill := postsSeen.Load()
	waitFor("the killed report to reach hz", func() bool { return postsSeen.Load() > seenAfterKill })
	waitFor("the retried batch to drain", func() bool { return a.SpoolStats().Pending == 0 })

	if h := s.monitor.GetHistory(dnsRow); len(h) != 2 {
		t.Fatalf("dns history = %d points, want 2 (lost response must not duplicate)", len(h))
	} else if !h[0].Timestamp.Equal(base) || !h[1].Timestamp.Equal(base.Add(2*time.Second)) {
		t.Fatalf("dns history reordered: %s then %s", h[0].Timestamp, h[1].Timestamp)
	}
	if h := s.monitor.GetHistory(httpsRow); len(h) != 1 {
		t.Fatalf("https history = %d points, want 1", len(h))
	}

	// -- Scenario 2: agent restart with a result never acknowledged.
	// The killed report reaches hz (r4 folds), then the loop is stopped
	// before its retry: the process dies mid-flight, exactly the case in the
	// bug report.
	beforeR4 := postsSeen.Load()
	killOne.Store(true)
	a.Record([]probe.Result{{
		ID: "r4", Target: "api.example.invalid", Host: "api.example.invalid",
		Kind: probe.KindHTTPS, At: base.Add(3 * time.Second), Status: probe.StatusFailed, Error: "500",
	}})
	a.SignalProbedForTest()
	waitFor("r4's killed report to reach hz", func() bool { return postsSeen.Load() > beforeR4 })
	cancelA()
	if a.SpoolStats().Pending != 1 {
		t.Fatalf("agent A should still hold the unacknowledged r4, pending=%d", a.SpoolStats().Pending)
	}

	// A new process on the same state file resumes at the uncommitted record.
	b := probe.NewAgent("GCP", "v1", token, statePath)
	b.EnablePushSpool()
	if st := b.SpoolStats(); st.Pending != 1 {
		t.Fatalf("restarted agent recovered %d pending results, want 1", st.Pending)
	}
	if len(b.Targets().Targets) != 1 {
		t.Fatal("restarted agent lost its target set")
	}
	cancelB, _ := startLoop(b, 30*time.Millisecond)
	waitFor("r4 to drain after the agent restart", func() bool { return b.SpoolStats().Pending == 0 })
	if h := s.monitor.GetHistory(httpsRow); len(h) != 2 {
		t.Fatalf("https history = %d points, want 2 (r4 folds exactly once after restart)", len(h))
	}

	// -- Scenario 3: hz restarts (same journal dir) mid-retry.
	// r6 is folded by the old gateway on a killed connection, then a new
	// gateway process answers the retry: it must remember r6 and skip it.
	m1seen := postsSeen.Load()
	killOne.Store(true)
	b.Record([]probe.Result{{
		ID: "r6", Target: "api.example.invalid", Host: "api.example.invalid",
		Kind: probe.KindDNS, At: base.Add(4 * time.Second), Status: probe.StatusOK,
	}})
	b.SignalProbedForTest()
	waitFor("r6's killed report to reach the old hz", func() bool { return postsSeen.Load() > m1seen })

	// A new gateway process: fresh in-memory state, same durable journal.
	s2 := newGateway(s.cfg())
	gw.Store(s2)
	waitFor("r6 to be acked by the restarted hz", func() bool { return b.SpoolStats().Pending == 0 })
	if h := s2.monitor.GetHistory(dnsRow); len(h) != 0 {
		t.Fatalf("restarted hz must not re-fold r6, got %d points", len(h))
	}

	// A genuinely new result after the restart folds normally.
	b.Record([]probe.Result{{
		ID: "r7", Target: "api.example.invalid", Host: "api.example.invalid",
		Kind: probe.KindDNS, At: base.Add(5 * time.Second), Status: probe.StatusOK,
	}})
	b.SignalProbedForTest()
	waitFor("r7 to fold on the restarted hz", func() bool {
		h := s2.monitor.GetHistory(dnsRow)
		return len(h) == 1 && b.SpoolStats().Pending == 0
	})
	if h := s2.monitor.GetHistory(dnsRow); len(h) != 1 || !h[0].Timestamp.Equal(base.Add(5*time.Second)) {
		t.Fatalf("post-restart new result wrong: %+v", h)
	}

	cancelB()

	// Nothing left on the agent's disk; spool and targets share that file.
	restarted := probe.NewAgent("GCP", "v1", token, statePath)
	restarted.EnablePushSpool()
	if restarted.SpoolStats().Pending != 0 {
		t.Fatalf("drained backlog must be empty on disk, got %d", restarted.SpoolStats().Pending)
	}
}
