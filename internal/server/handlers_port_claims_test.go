package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iodesystems/homelab-horizon/internal/apitypes"
	"github.com/iodesystems/homelab-horizon/internal/config"
)

// testHost is TEST-NET-1 (RFC 5737): unroutable, so the connect scan settles
// on the dial timeout with every port closed — deterministic, nothing to bind.
const testHost = "192.0.2.10"

func mintClaim(t *testing.T, s *Server, body string) apitypes.PortClaimResp {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleAPIPortClaim(w, asAdmin(s, http.MethodPost, "/api/v1/ports/claims", body))
	if w.Code != http.StatusCreated {
		t.Fatalf("mint returned %d: %s", w.Code, w.Body.String())
	}
	var out apitypes.PortClaimResp
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPortClaimMint(t *testing.T) {
	s := newTestServer(t, &config.Config{})
	c := mintClaim(t, s, `{"host":"`+testHost+`","from":20000}`)
	if c.From != 20000 || c.To != 20000 || c.Proto != "tcp" || c.Host != testHost {
		t.Fatalf("unexpected claim: %+v", c)
	}
	if !strings.HasPrefix(c.ID, "pc_") || c.Token == "" || c.ExpiresAt == 0 {
		t.Fatalf("claim credential missing: %+v", c)
	}
}

// The race this feature exists for: two mints serialize server-side and come
// back with disjoint ranges.
func TestPortClaimConcurrentMintsAreDisjoint(t *testing.T) {
	s := newTestServer(t, &config.Config{})
	a := mintClaim(t, s, `{"host":"`+testHost+`","from":20000}`)
	b := mintClaim(t, s, `{"host":"`+testHost+`","from":20000}`)
	if a.From == b.From {
		t.Fatalf("both mints returned %d", a.From)
	}
	if b.From != a.To+1 {
		t.Fatalf("second claim %d should follow first %d-%d", b.From, a.From, a.To)
	}
}

func TestPortClaimAppearsInMapWithoutToken(t *testing.T) {
	s := newTestServer(t, &config.Config{})
	c := mintClaim(t, s, `{"host":"`+testHost+`","from":20000}`)

	w := httptest.NewRecorder()
	s.handleAPIPorts(w, asAdmin(s, http.MethodGet, "/api/v1/ports", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("ports map: %d %s", w.Code, w.Body.String())
	}
	var pm apitypes.HostPortMapResponse
	if err := json.NewDecoder(w.Body).Decode(&pm); err != nil {
		t.Fatal(err)
	}
	if len(pm.Claims) != 1 || pm.Claims[0].ID != c.ID {
		t.Fatalf("claim missing from map: %+v", pm.Claims)
	}
	if pm.Claims[0].Token != "" {
		t.Fatal("claim token must never appear in the listing response")
	}
}

func TestPortClaimValidation(t *testing.T) {
	s := newTestServer(t, &config.Config{})
	cases := []struct{ name, body string }{
		{"host required", `{"from":20000}`},
		{"host must be IP", `{"host":"not-an-ip"}`},
		{"count too big", `{"host":"192.0.2.1","count":99999}`},
		{"udp unsupported", `{"host":"192.0.2.1","proto":"udp"}`},
		{"ttl too short", `{"host":"192.0.2.1","ttl_seconds":2}`},
		{"bad json", `{`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleAPIPortClaim(w, asAdmin(s, http.MethodPost, "/api/v1/ports/claims", tc.body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
			}
			if len(s.portClaims.Active()) != 0 {
				t.Fatal("failed validation must not leave a claim")
			}
		})
	}

	// Auth and method guards.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/ports/claims", strings.NewReader(`{"host":"192.0.2.1"}`))
	s.handleAPIPortClaim(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated mint: want 401, got %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleAPIPortClaim(w, asAdmin(s, http.MethodGet, "/api/v1/ports/claims", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET mint: want 405, got %d", w.Code)
	}
}

func TestPortClaimRelease(t *testing.T) {
	s := newTestServer(t, &config.Config{})
	c := mintClaim(t, s, `{"host":"`+testHost+`","from":20000}`)

	releaseBody := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleAPIPortClaimRelease(w, asAdmin(s, http.MethodPost, "/api/v1/ports/claims/release", body))
		return w
	}

	w := releaseBody(`{"id":"` + c.ID + `","token":"wrong"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong token: want 403, got %d", w.Code)
	}
	if len(s.portClaims.Active()) != 1 {
		t.Fatal("wrong-token release must retain the claim")
	}

	w = releaseBody(`{"id":"` + c.ID + `","token":"` + c.Token + `"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("release: %d %s", w.Code, w.Body.String())
	}
	var out apitypes.PortClaimReleaseResponse
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil || !out.OK || !out.Released {
		t.Fatalf("release response: %+v err body=%s", out, w.Body.String())
	}

	// Idempotent: the same call again reports the claim already gone.
	w = releaseBody(`{"id":"` + c.ID + `","token":"` + c.Token + `"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("second release: %d %s", w.Code, w.Body.String())
	}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil || out.Released {
		t.Fatalf("idempotent release response: %+v", out)
	}
}

// Saving a config that formally adopts the leased range completes the
// takeover — the ghost claim is reaped in the same updateConfig call.
func TestPortClaimReapedWhenConfigAdoptsRange(t *testing.T) {
	s := newTestServer(t, &config.Config{})
	c := mintClaim(t, s, `{"host":"`+testHost+`","from":20000}`)

	if err := s.updateConfig(func(cfg *config.Config) {
		cfg.Services = append(cfg.Services, config.Service{
			Name:  "new-thing",
			Proxy: &config.ProxyConfig{Backend: testHost + ":20000"},
		})
	}); err != nil {
		t.Fatalf("updateConfig: %v", err)
	}
	if len(s.portClaims.Active()) != 0 {
		t.Fatalf("adopted claim %s survived the config save", c.ID)
	}
}

func TestPortClaimRoutesWiredThroughMux(t *testing.T) {
	s := newTestServer(t, &config.Config{})
	h := s.setupRoutes()

	// A malformed-but-routed POST proves the claim endpoint is served by the
	// real mux (an old server answers 404 here, which is the signal the CLI
	// refuses to fall back past).
	w := httptest.NewRecorder()
	h.ServeHTTP(w, asAdmin(s, http.MethodPost, "/api/v1/ports/claims", "{"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("routed mint: want 400, got %d: %s", w.Code, w.Body.String())
	}

	// The release route is its own path, not swallowed by the collection.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, asAdmin(s, http.MethodPost, "/api/v1/ports/claims/release", "{}"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("routed release: want 400, got %d: %s", w.Code, w.Body.String())
	}

	// Unrelated unknown paths still 404 exactly the way a pre-claims server
	// would for the whole endpoint.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, asAdmin(s, http.MethodPost, "/api/v1/does-not-exist", "{}"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown route: want 404, got %d", w.Code)
	}
}

func TestFormalOccupiedPortsSemantics(t *testing.T) {
	cfg := &config.Config{
		LocalInterface: "10.0.0.1",
		Services: []config.Service{
			{
				Name:  "web",
				Proxy: &config.ProxyConfig{Backend: "10.0.0.9:8080"},
				Forwards: []config.Forward{
					{Proto: "udp", Port: 4433, Backend: "10.0.0.9:4433"},
				},
			},
		},
	}

	tcp := formalOccupiedPorts(cfg, "10.0.0.9", "tcp")
	if !tcp[8080] {
		t.Error("tcp backend reservation missing")
	}
	if !tcp[4433] {
		t.Error("a forward must block tcp allocation too")
	}
	udp := formalOccupiedPorts(cfg, "10.0.0.9", "udp")
	if !udp[4433] {
		t.Error("forward reservation missing for udp")
	}
	if udp[8080] {
		t.Error("a plain tcp backend must not block udp allocation")
	}
}
