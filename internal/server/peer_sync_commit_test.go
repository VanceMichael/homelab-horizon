package server

// Commit-point interleaving tests for the non-primary pull flow: local state
// changing during the fetch, stale remote revisions, role/topology changes,
// save/recovery failures and recovery replay on a 304 round.
//
// The races are orchestrated DETERMINISTICALLY by making the primary's
// /api/peer/config handler perform the local mutation (or gate the response)
// at the exact point in the standby's HTTP round-trip.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iodesystems/homelab-horizon/internal/apitypes"
	"github.com/iodesystems/homelab-horizon/internal/config"
	"github.com/iodesystems/homelab-horizon/internal/haproxy"
	"github.com/iodesystems/homelab-horizon/internal/wireguard"
)

func mustEncodeConfig(t *testing.T, c *config.Config) []byte {
	t.Helper()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fleetServers bundles one or more in-process primary HTTP servers.
type fleetServers struct {
	mu sync.Mutex // serializes handler orchestration
}

// servePrimary wires ping (live from s) and a counting config handler on mux.
func servePrimary(t *testing.T, s *Server, mux *http.ServeMux, configH http.HandlerFunc) {
	t.Helper()
	mux.HandleFunc("/api/peer/ping", s.handlePeerPing)
	mux.HandleFunc("/api/peer/config", configH)
}

func httpURL(ts *httptest.Server) string {
	_, port := netSplit(ts.URL)
	return "127.0.0.1:" + port
}

func netSplit(u string) (host, port string) {
	strip := u[len("http://"):]
	for i := len(strip) - 1; i >= 0; i-- {
		if strip[i] == ':' {
			return strip[:i], strip[i+1:]
		}
	}
	return strip, ""
}

func standbyCfg(primaryAddr string) *config.Config {
	return &config.Config{
		PeerID:        "site-b",
		ConfigPrimary: false,
		Peers:         []config.Peer{{ID: "site-a", WGAddr: primaryAddr, Primary: true}},
		Services:      []config.Service{{Name: "stale"}},
		VPNRange:      "10.100.0.0/24",
	}
}

func primaryCfg(services ...string) *config.Config {
	svcs := make([]config.Service, 0, len(services))
	for _, n := range services {
		svcs = append(svcs, config.Service{Name: n})
	}
	return &config.Config{
		PeerID:        "site-a",
		ConfigPrimary: true,
		Services:      svcs,
		VPNRange:      "10.100.0.0/24",
	}
}

// flushAndServe writes the primary's live config body and flushes it, so the
// standby has the bytes while the handler is still in flight.
func flushAndServe(w http.ResponseWriter, s *Server) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	body, _ := json.MarshalIndent(s.cfg(), "", "  ")
	_, _ = w.Write(body)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// TestPullMergesLocalOnlyChangesDuringFetch is AC-1: public-IP refresh, drift
// block confirmation and a vantage edit that land WHILE the primary's body is
// in flight must survive the commit.
func TestPullMergesLocalOnlyChangesDuringFetch(t *testing.T) {
	var fs fleetServers
	primary := newTestServer(t, primaryCfg("grafana"))
	standby := newTestServer(t, standbyCfg("__ADDR__"))

	// Primary's config handler mutates the STANDBY's local-only state while
	// the standby is waiting on the body — the exact race window.
	primaryMux := http.NewServeMux()
	servePrimary(t, primary, primaryMux, func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		if err := standby.updateConfig(func(c *config.Config) {
			c.PublicIP = "203.0.113.77"
			c.PublicIPLastChecked = 1700000777
			c.DNSDriftBlocked = true
			c.DNSDriftDetail = &config.DNSDriftInfo{
				Zone: "example.com", Name: "fleet", Type: "A",
				Live:       []string{"203.0.113.77"},
				Reason:     config.DNSConflictOutOfBand,
				DetectedAt: 1700000777,
			}
			c.RemoteProbes = []config.RemoteProbe{{
				Name: "in-flight-vantage", Mode: "push", Token: "secret-token", Enabled: true,
			}}
		}); err != nil {
			t.Errorf("standby local mutation during fetch failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		flushAndServe(w, primary)
	})
	ts := httptest.NewServer(primaryMux)
	defer ts.Close()

	// Repoint the standby at the real address after it is known.
	if err := standby.updateConfig(func(c *config.Config) {
		c.Peers[0].WGAddr = httpURL(ts)
	}); err != nil {
		t.Fatal(err)
	}

	standby.pullConfigOnce()

	got := standby.cfg()
	snap := standby.peerSyncSnapshot()
	if snap.State != pullStateSynced {
		t.Fatalf("state=%s detail=%s, want synced", snap.State, snap.LastError)
	}

	// Shared fields came from the primary.
	if len(got.Services) != 1 || got.Services[0].Name != "grafana" {
		t.Errorf("shared services not converged: %+v", got.Services)
	}

	// Local-only fields are the LATEST local values, not pull-start ones.
	if got.PublicIP != "203.0.113.77" || got.PublicIPLastChecked != 1700000777 {
		t.Errorf("public IP cache regressed by pull: ip=%q checked=%d", got.PublicIP, got.PublicIPLastChecked)
	}
	if !got.DNSDriftBlocked || got.DNSDriftDetail == nil || got.DNSDriftDetail.Name != "fleet" {
		t.Errorf("DNS drift block lost during pull: blocked=%v detail=%+v", got.DNSDriftBlocked, got.DNSDriftDetail)
	}
	if len(got.RemoteProbes) != 1 || got.RemoteProbes[0].Name != "in-flight-vantage" || got.RemoteProbes[0].Token != "secret-token" {
		t.Errorf("remote probe edit lost during pull: %+v", got.RemoteProbes)
	}

	// Disk reproduces memory.
	onDisk, err := config.Load(standby.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk.PublicIP != "203.0.113.77" || !onDisk.DNSDriftBlocked {
		t.Errorf("disk diverged from memory: ip=%q blocked=%v", onDisk.PublicIP, onDisk.DNSDriftBlocked)
	}
	if len(onDisk.RemoteProbes) != 1 || onDisk.RemoteProbes[0].Token != "secret-token" {
		t.Errorf("disk lost the in-flight vantage: %+v", onDisk.RemoteProbes)
	}
}

// TestPullStaleRemoteRevisionRetried is AC-2: R1 body in hand, primary has
// already moved to R2 at the commit ping → discard R1, re-fetch, converge R2.
func TestPullStaleRemoteRevisionRetried(t *testing.T) {
	var orchestration sync.Mutex
	primary := newTestServer(t, primaryCfg("rev1-service"))

	var (
		gateReleased atomic.Bool
		releaseGate  = make(chan struct{})
		bodySent     = make(chan struct{})
		fullGets     atomic.Int32
		notModGets   atomic.Int32
	)

	mux := http.NewServeMux()
	// Ping gate: the preflight ping fires before any body was sent and
	// proceeds immediately; the commit-time revalidation ping must wait until
	// the test has moved the primary to R2 — explicit, so the test does not
	// rely on HTTP chunked-framing timing for its determinism.
	mux.HandleFunc("/api/peer/ping", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-bodySent:
			<-releaseGate
		default:
		}
		primary.handlePeerPing(w, r)
	})
	mux.HandleFunc("/api/peer/config", func(w http.ResponseWriter, r *http.Request) {
		orchestration.Lock()
		defer orchestration.Unlock()
		w.Header().Set("ETag", `"`+sharedConfigDigest(primary.cfg())+`"`)
		if r.Header.Get("If-None-Match") == `"`+sharedConfigDigest(primary.cfg())+`"` {
			notModGets.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fullGets.Add(1)
		// First GET: hand out the R1 bytes, then hold the handler open until
		// the test has moved the primary to R2; the revalidation ping is
		// gated separately on the same release.
		first := !gateReleased.Load()
		flushAndServe(w, primary)
		if !first {
			return
		}
		close(bodySent)
		<-releaseGate
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	standby := newTestServer(t, standbyCfg(httpURL(ts)))

	// Run the pull in a goroutine so this test can move the primary mid-flight.
	done := make(chan struct{})
	go func() {
		standby.pullConfigOnce()
		close(done)
	}()

	select {
	case <-bodySent:
	case <-time.After(5 * time.Second):
		t.Fatal("standby never received the R1 body")
	}

	// Primary commits R2 while the standby holds R1 and is about to
	// revalidate.
	r2 := primaryCfg("rev2-service")
	if err := primary.updateConfig(func(c *config.Config) {
		c.Services = r2.Services
	}); err != nil {
		t.Fatal(err)
	}
	gateReleased.Store(true)
	close(releaseGate)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("pull round did not finish")
	}

	got := standby.cfg()
	if len(got.Services) != 1 || got.Services[0].Name != "rev2-service" {
		t.Fatalf("standby converged to the stale revision: %+v", got.Services)
	}
	snap := standby.peerSyncSnapshot()
	if snap.State != pullStateSynced {
		t.Errorf("final state=%s detail=%s", snap.State, snap.LastError)
	}
	if snap.ConflictCount < 1 {
		t.Errorf("expected at least one conflict recorded, got %d", snap.ConflictCount)
	}
	if snap.LastError != "" {
		t.Errorf("lastError must clear after the successful retry, got %q", snap.LastError)
	}
	if fullGets.Load() < 2 {
		t.Errorf("expected the R1 body to be discarded and R2 fetched (>=2 full GETs), got %d", fullGets.Load())
	}
}

// TestPullRoleChangeEndsRound is AC-3: promotion landing during the fetch
// ends the round as a conflict and never applies the body.
func TestPullRoleChangeEndsRound(t *testing.T) {
	var fs fleetServers
	primary := newTestServer(t, primaryCfg("grafana"))
	standby := newTestServer(t, standbyCfg("__ADDR__"))

	mux := http.NewServeMux()
	servePrimary(t, primary, mux, func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		// Simulate auto-promotion happening during the fetch.
		if err := standby.updateConfig(func(c *config.Config) { c.ConfigPrimary = true }); err != nil {
			t.Errorf("promote: %v", err)
		}
		flushAndServe(w, primary)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	if err := standby.updateConfig(func(c *config.Config) { c.Peers[0].WGAddr = httpURL(ts) }); err != nil {
		t.Fatal(err)
	}

	standby.pullConfigOnce()

	got := standby.cfg()
	if len(got.Services) != 1 || got.Services[0].Name != "stale" {
		t.Errorf("body applied despite role change: %+v", got.Services)
	}
	if !got.ConfigPrimary {
		t.Error("promotion did not persist")
	}
	snap := standby.peerSyncSnapshot()
	if snap.State != pullStateConflict {
		t.Errorf("state=%s want conflict", snap.State)
	}
	if snap.ConflictCount != 1 {
		t.Errorf("conflictCount=%d want 1", snap.ConflictCount)
	}
}

// TestPullTopologyChangeRetriesNewPrimary is AC-4: while fetching from A, the
// configured primary becomes B; A's body is discarded and the round
// converges from B.
func TestPullTopologyChangeRetriesNewPrimary(t *testing.T) {
	var fs sync.Mutex

	primaryA := newTestServer(t, primaryCfg("service-from-A"))
	primaryB := newTestServer(t, &config.Config{
		PeerID:        "site-a",
		ConfigPrimary: true,
		Services:      []config.Service{{Name: "service-from-B"}},
		VPNRange:      "10.100.0.0/24",
	})

	standby := newTestServer(t, standbyCfg("__ADDR_A__"))

	var tsB *httptest.Server
	muxA := http.NewServeMux()
	muxA.HandleFunc("/api/peer/ping", primaryA.handlePeerPing)
	muxA.HandleFunc("/api/peer/config", func(w http.ResponseWriter, r *http.Request) {
		fs.Lock()
		defer fs.Unlock()
		// Topology change to B while A's body is in flight.
		_ = standby.updateConfig(func(c *config.Config) {
			c.Peers[0].WGAddr = httpURL(tsB)
		})
		flushAndServe(w, primaryA)
	})
	tsA := httptest.NewServer(muxA)

	muxB := http.NewServeMux()
	servePrimary(t, primaryB, muxB, primaryB.handlePeerConfig)
	tsB = httptest.NewServer(muxB)
	defer tsA.Close()
	defer tsB.Close()

	_ = standby.updateConfig(func(c *config.Config) { c.Peers[0].WGAddr = httpURL(tsA) })
	standby.pullConfigOnce()

	got := standby.cfg()
	if len(got.Services) != 1 || got.Services[0].Name != "service-from-B" {
		t.Fatalf("expected convergence from B after topology change, got %+v", got.Services)
	}
	snap := standby.peerSyncSnapshot()
	if snap.State != pullStateSynced {
		t.Errorf("state=%s detail=%s", snap.State, snap.LastError)
	}
	if snap.ConflictCount < 1 {
		t.Error("topology switch should record a conflict")
	}
}

// TestPullSaveFailureReportedAndUnchanged is AC-5 at the pull-flow level.
func TestPullSaveFailureReportedAndUnchanged(t *testing.T) {
	primary := newTestServer(t, primaryCfg("grafana"))
	mux := http.NewServeMux()
	servePrimary(t, primary, mux, primary.handlePeerConfig)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	standby := newTestServer(t, standbyCfg(httpURL(ts)))
	blocked := filepath.Join(t.TempDir(), "config.json")
	if err := os.Mkdir(blocked, 0755); err != nil {
		t.Fatal(err)
	}
	standby.configPath = blocked
	ptrBefore := standby.cfg()

	standby.pullConfigOnce()

	if standby.cfg() != ptrBefore {
		t.Error("live config swapped despite failing save")
	}
	if got := standby.cfg().Services; len(got) != 1 || got[0].Name != "stale" {
		t.Errorf("services changed despite failing save: %+v", got)
	}
	snap := standby.peerSyncSnapshot()
	if snap.State != pullStateRecoverFailed {
		t.Errorf("state=%s detail=%s, want recover_failed", snap.State, snap.LastError)
	}
}

// TestPullRecoveryFailureReplayedOn304 is AC-6: committed-but-unrecovered
// revision is replayed on the next round even though the primary answers
// 304 — the body is never re-downloaded.
func TestPullRecoveryReplayedOn304(t *testing.T) {
	primary := newTestServer(t, primaryCfg("grafana"))

	var (
		fullBodies atomic.Int32
		notMod     atomic.Int32
		failNext   atomic.Bool
	)
	failNext.Store(true)
	postPullRecoveryHook = func(*config.Config) error {
		if failNext.Swap(false) {
			return errors.New("injected derived-state fault")
		}
		return nil
	}
	defer func() { postPullRecoveryHook = nil }()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/peer/ping", primary.handlePeerPing)
	mux.HandleFunc("/api/peer/config", func(w http.ResponseWriter, r *http.Request) {
		rev := sharedConfigDigest(primary.cfg())
		w.Header().Set("ETag", `"`+rev+`"`)
		if r.Header.Get("If-None-Match") == `"`+rev+`"` {
			notMod.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fullBodies.Add(1)
		primary.handlePeerConfig(w, r)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	standby := newTestServer(t, standbyCfg(httpURL(ts)))

	// Round 1: commit lands, recovery fails.
	standby.pullConfigOnce()
	snap1 := standby.peerSyncSnapshot()
	if snap1.State != pullStateRecoverFailed {
		t.Fatalf("round 1 state=%s detail=%s", snap1.State, snap1.LastError)
	}
	if len(standby.cfg().Services) != 1 || standby.cfg().Services[0].Name != "grafana" {
		t.Fatal("memory must hold the committed revision even when recovery failed")
	}
	onDisk, err := config.Load(standby.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk.Services) != 1 || onDisk.Services[0].Name != "grafana" {
		t.Fatal("disk must hold the committed revision even when recovery failed")
	}
	if snap1.CommittedRev == snap1.RecoveredRev {
		t.Error("committed/recovered revisions should differ while recovery is pending")
	}

	// Round 2: primary unchanged (304), recovery replays and succeeds.
	standby.pullConfigOnce()
	snap2 := standby.peerSyncSnapshot()
	if snap2.State != pullStateSynced {
		t.Fatalf("round 2 state=%s detail=%s", snap2.State, snap2.LastError)
	}
	if fullBodies.Load() != 1 {
		t.Errorf("recovery replay re-downloaded the body: full GETs=%d, want 1", fullBodies.Load())
	}
	if notMod.Load() != 1 {
		t.Errorf("expected exactly one 304 on the replay round, got %d", notMod.Load())
	}
	if snap2.CommittedRev != snap2.RecoveredRev {
		t.Error("revisions not reconciled after replay")
	}
}

// TestPullNoChangeRoundSkipsConfigFetch is AC-8: when the ping revision
// matches, the round performs NO config GET at all and does not swap or save.
func TestPullNoChangeRoundSkipsConfigFetch(t *testing.T) {
	primary := newTestServer(t, primaryCfg("grafana"))
	var configGets atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/peer/ping", primary.handlePeerPing)
	mux.HandleFunc("/api/peer/config", func(w http.ResponseWriter, r *http.Request) {
		configGets.Add(1)
		primary.handlePeerConfig(w, r)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Seed the standby already converged to the primary's shared state.
	c := *primary.cfg()
	c.PeerID = "site-b"
	c.ConfigPrimary = false
	c.Peers = []config.Peer{{ID: "site-a", WGAddr: httpURL(ts), Primary: true}}
	standby := newTestServer(t, &c)

	info, err := os.Stat(standby.configPath)
	if err != nil {
		t.Fatal(err)
	}
	ptrBefore := standby.cfg()

	standby.pullConfigOnce()

	if configGets.Load() != 0 {
		t.Errorf("unchanged round issued %d config GETs, want 0", configGets.Load())
	}
	if standby.cfg() != ptrBefore {
		t.Error("unchanged round swapped the live pointer")
	}
	info2, _ := os.Stat(standby.configPath)
	if info2.ModTime() != info.ModTime() {
		t.Error("unchanged round rewrote the config file")
	}
	snap := standby.peerSyncSnapshot()
	if snap.State != pullStateSynced || snap.LastError != "" {
		t.Errorf("state=%s err=%q", snap.State, snap.LastError)
	}
}

// TestPullFromLegacyPrimaryConverges is AC-11: a primary that predates
// shared_rev/ETag support still converges the standby through the full-body
// fallback.
func TestPullFromLegacyPrimaryConverges(t *testing.T) {
	legacyCfg := primaryCfg("legacy-svc")
	legacyBody := mustEncodeConfig(t, legacyCfg)
	mux := http.NewServeMux()
	// Old ping shape: no shared_rev.
	mux.HandleFunc("/api/peer/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"peer_id":"site-a","config_primary":true}`)
	})
	mux.HandleFunc("/api/peer/config", func(w http.ResponseWriter, r *http.Request) {
		// Ignores If-None-Match, sends no ETag.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(legacyBody)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	standby := newTestServer(t, standbyCfg(httpURL(ts)))
	standby.pullConfigOnce()

	got := standby.cfg()
	if len(got.Services) != 1 || got.Services[0].Name != "legacy-svc" {
		t.Fatalf("standby did not converge from legacy primary: %+v", got.Services)
	}
	snap := standby.peerSyncSnapshot()
	if snap.State != pullStateSynced {
		t.Errorf("state=%s detail=%s", snap.State, snap.LastError)
	}
}

// TestPeerSyncStatusAPISurfacesFourStates is AC-10 at the API boundary: the
// dashboard and HA endpoints carry the classified state on the non-primary,
// not just an error string.
func TestPeerSyncStatusAPISurfacesFourStates(t *testing.T) {
	primary := newTestServer(t, primaryCfg("grafana"))
	mux := http.NewServeMux()
	servePrimary(t, primary, mux, primary.handlePeerConfig)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	standby := newTestServer(t, standbyCfg(httpURL(ts)))
	// The dashboard handler reads live WG/HAProxy handles (nil in the
	// stripped test server); give it inert real ones backed by temp paths.
	standby.wg = wireguard.NewConfig(filepath.Join(t.TempDir(), "wg0.conf"), "wg0")
	standby.haproxy = haproxy.New(filepath.Join(t.TempDir(), "haproxy.cfg"), filepath.Join(t.TempDir(), "admin.sock"))
	adminReq := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: standby.signCookie("admin")})
		return r
	}

	// A real successful round first.
	standby.pullConfigOnce()
	if snap := standby.peerSyncSnapshot(); snap.State != pullStateSynced {
		t.Fatalf("precondition: state=%s", snap.State)
	}

	rec := httptest.NewRecorder()
	standby.handleAPIDashboard(rec, adminReq("/api/v1/dashboard"))
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status=%d body=%s", rec.Code, rec.Body.String())
	}
	var dash apitypes.DashboardResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &dash); err != nil {
		t.Fatal(err)
	}
	if dash.PeerSync == nil {
		t.Fatal("peerSync missing on non-primary dashboard")
	}
	if dash.PeerSync.State != apitypes.PullStateSynced {
		t.Errorf("dashboard state=%q want synced", dash.PeerSync.State)
	}
	if dash.PeerSync.PrimaryID != "site-a" {
		t.Errorf("primaryId=%q", dash.PeerSync.PrimaryID)
	}

	// Every classified state maps through both endpoints.
	cases := []struct {
		state pullState
		want  string
	}{
		{pullStateFetchFailed, apitypes.PullStateFetchFailed},
		{pullStateConflict, apitypes.PullStateConflict},
		{pullStateRecoverFailed, apitypes.PullStateRecoverFailed},
		{pullStateSynced, apitypes.PullStateSynced},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			standby.peerSyncStatus.mu.Lock()
			standby.peerSyncStatus.state = tc.state
			standby.peerSyncStatus.lastError = "detail-" + string(tc.state)
			standby.peerSyncStatus.mu.Unlock()

			rec := httptest.NewRecorder()
			standby.handleAPIDashboard(rec, adminReq("/api/v1/dashboard"))
			var d apitypes.DashboardResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
				t.Fatal(err)
			}
			if d.PeerSync == nil || d.PeerSync.State != tc.want {
				t.Fatalf("dashboard state=%v want %q", d.PeerSync, tc.want)
			}

			rec2 := httptest.NewRecorder()
			standby.handleAPIHAStatus(rec2, adminReq("/api/v1/ha/status"))
			if rec2.Code != http.StatusOK {
				t.Fatalf("ha status=%d", rec2.Code)
			}
			var ha apitypes.HAStatusResponse
			if err := json.Unmarshal(rec2.Body.Bytes(), &ha); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, p := range ha.Peers {
				if p.SyncState == tc.want {
					found = true
				}
			}
			if !found {
				t.Errorf("HA fleet rows did not carry syncState %q: %+v", tc.want, ha.Peers)
			}
		})
	}
}

// TestHAStatusAttachesSyncStateToSingleRow pins F3: when the fleet lists both
// this host and the primary, pull state may appear on exactly one row (self),
// never duplicated onto the primary row.
func TestHAStatusAttachesSyncStateToSingleRow(t *testing.T) {
	primary := newTestServer(t, primaryCfg("grafana"))
	mux := http.NewServeMux()
	servePrimary(t, primary, mux, primary.handlePeerConfig)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	standby := newTestServer(t, &config.Config{
		PeerID:        "site-b",
		ConfigPrimary: false,
		Peers: []config.Peer{
			{ID: "site-a", WGAddr: httpURL(ts), Primary: true},
			{ID: "site-b", WGAddr: "127.0.0.2:8080"},
		},
		VPNRange: "10.100.0.0/24",
	})
	standby.peerSyncStatus.mu.Lock()
	standby.peerSyncStatus.state = pullStateConflict
	standby.peerSyncStatus.lastError = "detail"
	standby.peerSyncStatus.mu.Unlock()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/ha/status", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: standby.signCookie("admin")})
	rec := httptest.NewRecorder()
	standby.handleAPIHAStatus(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var ha apitypes.HAStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ha); err != nil {
		t.Fatal(err)
	}
	var withState []string
	for _, p := range ha.Peers {
		if p.SyncState != "" {
			withState = append(withState, p.ID)
		}
	}
	if len(withState) != 1 || withState[0] != "site-b" {
		t.Fatalf("syncState rows=%v, want exactly [site-b]", withState)
	}
}

// TestPullLegacyPrimaryRecoveryReplayedOnSameBody is the R1 fix: against an
// older primary (no shared_rev/ETag), a commit whose recovery failed must be
// replayed on the next round even though that round gets a 200 full body
// identical to what is already committed — the no-change collapse must not
// paper over the unfinished recovery.
func TestPullLegacyPrimaryRecoveryReplayedOnSameBody(t *testing.T) {
	legacyCfg := primaryCfg("legacy-svc")
	legacyBody := mustEncodeConfig(t, legacyCfg)

	var (
		fullGets atomic.Int32
		hits     atomic.Int32
	)
	postPullRecoveryHook = func(*config.Config) error {
		if hits.Add(1) == 1 {
			return errors.New("injected derived-state fault")
		}
		return nil
	}
	defer func() { postPullRecoveryHook = nil }()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/peer/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"peer_id":"site-a","config_primary":true}`)
	})
	mux.HandleFunc("/api/peer/config", func(w http.ResponseWriter, r *http.Request) {
		fullGets.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(legacyBody)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	standby := newTestServer(t, standbyCfg(httpURL(ts)))

	// Round 1: same body committed, recovery fails.
	standby.pullConfigOnce()
	s1 := standby.peerSyncSnapshot()
	if s1.State != pullStateRecoverFailed {
		t.Fatalf("round 1 state=%s detail=%s", s1.State, s1.LastError)
	}
	if s1.CommittedRev == s1.RecoveredRev {
		t.Fatal("committed/recovered must differ after the failed recovery")
	}

	// Round 2: legacy primary serves the SAME revision as a 200. Recovery
	// must still be replayed and the round end synced.
	standby.pullConfigOnce()
	s2 := standby.peerSyncSnapshot()
	if s2.State != pullStateSynced {
		t.Fatalf("round 2 state=%s detail=%s", s2.State, s2.LastError)
	}
	if s2.CommittedRev != s2.RecoveredRev {
		t.Error("recovery was not replayed on the identical-200 round")
	}
	if fullGets.Load() != 2 {
		t.Errorf("expected two full GETs (one per round), got %d", fullGets.Load())
	}
	if hits.Load() != 2 {
		t.Errorf("recovery step ran %d times, want 2", hits.Load())
	}
}

// TestPullExhaustsConflictRetries: when the local shared base keeps moving
// during the fetch, the round discards all attempts, stays a non-primary and
// reports conflict instead of fetch failure or a false synced.
func TestPullExhaustsConflictRetries(t *testing.T) {
	primary := newTestServer(t, primaryCfg("svc1"))
	var configGets atomic.Int32
	var standby *Server

	mux := http.NewServeMux()
	mux.HandleFunc("/api/peer/ping", primary.handlePeerPing)
	mux.HandleFunc("/api/peer/config", func(w http.ResponseWriter, r *http.Request) {
		// Every fetch lands a local SHARED write (ban convergence) before
		// the body returns, so the base gate at commit always fails.
		n := configGets.Add(1)
		_ = standby.updateConfig(func(c *config.Config) {
			c.IPBans = append(c.IPBans, config.IPBan{IP: fmt.Sprintf("10.0.0.%d", n), CreatedAt: int64(n)})
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mustEncodeConfig(t, primary.cfg()))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	standby = newTestServer(t, standbyCfg(httpURL(ts)))
	keepRunning := standby.pullConfigOnce()

	snap := standby.peerSyncSnapshot()
	if snap.State != pullStateConflict {
		t.Errorf("state=%s detail=%s, want conflict", snap.State, snap.LastError)
	}
	if !keepRunning {
		t.Error("conflict exhaustion should keep the loop alive for the next tick")
	}
	if configGets.Load() != pullMaxAttempts {
		t.Errorf("config GETs=%d, want %d", configGets.Load(), pullMaxAttempts)
	}
	if snap.ConflictCount != pullMaxAttempts {
		t.Errorf("conflictCount=%d, want %d", snap.ConflictCount, pullMaxAttempts)
	}
	if got := standby.cfg().Services; len(got) != 1 || got[0].Name != "stale" {
		t.Errorf("moving-base conflict must not apply the body: %+v", got)
	}
}

// TestPullPrimaryDemotedAtRevalidation: the primary losing its primary role
// between fetch and commit is a fetch failure (split-config guard), the body
// is never applied and the conflict counter stays at zero.
func TestPullPrimaryDemotedAtRevalidation(t *testing.T) {
	primary := newTestServer(t, primaryCfg("svc1"))
	var (
		gateReleased atomic.Bool
		releaseGate  = make(chan struct{})
		bodySent     = make(chan struct{})
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/peer/ping", func(w http.ResponseWriter, r *http.Request) {
		// Re-validation pings wait until the demotion has been installed.
		select {
		case <-bodySent:
			<-releaseGate
		default:
		}
		primary.handlePeerPing(w, r)
	})
	mux.HandleFunc("/api/peer/config", func(w http.ResponseWriter, r *http.Request) {
		flushAndServe(w, primary)
		if gateReleased.Swap(true) {
			return
		}
		close(bodySent)
		<-releaseGate
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	standby := newTestServer(t, standbyCfg(httpURL(ts)))
	done := make(chan struct{})
	go func() {
		standby.pullConfigOnce()
		close(done)
	}()

	<-bodySent
	// Primary resigns its role while the standby holds the body.
	demoted := *primary.cfg()
	demoted.ConfigPrimary = false
	primary.config.Store(&demoted)
	close(releaseGate)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("pull did not finish")
	}

	snap := standby.peerSyncSnapshot()
	if snap.State != pullStateFetchFailed {
		t.Errorf("state=%s detail=%s, want fetch_failed", snap.State, snap.LastError)
	}
	if snap.ConflictCount != 0 {
		t.Errorf("split-config refusal is not a conflict: count=%d", snap.ConflictCount)
	}
	if got := standby.cfg().Services; len(got) != 1 || got[0].Name != "stale" {
		t.Errorf("demoted-primary body must not be applied: %+v", got)
	}
}
