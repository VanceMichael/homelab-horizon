package server

// Phase 1 of multi-instance HA — see plan/plan.md.
//
// /api/peer/* endpoints are reachable only over the WireGuard site-to-site
// tunnel (the auth boundary between fleet members). They are unauthenticated
// from the application's perspective: WG itself gates them.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/iodesystems/homelab-horizon/internal/config"
	"github.com/iodesystems/homelab-horizon/internal/iptables"
)

// PeerPingResponse is returned by GET /api/peer/ping.
// IPTables summary is included so the HA Fleet tab can flag peers whose
// local iptables have drift or unknown rules without requiring a second
// round-trip. Computed fresh on each call — iptables-save is cheap enough
// that caching isn't worth the staleness risk.
type PeerPingResponse struct {
	PeerID          string            `json:"peer_id"`
	ConfigPrimary   bool              `json:"config_primary"`
	SharedRev       string            `json:"shared_rev,omitempty"`
	IPTablesSummary *iptables.Summary `json:"iptables_summary,omitempty"`
}

// handlePeerPing returns this instance's identity. Cheap, used for liveness
// at decision time (cert ownership, config sync) instead of a heartbeat.
// SharedRev lets a pulling peer decide whether a config fetch is needed
// (preflight) and re-validate, at the commit point, that the fetched body is
// still the primary's current shared revision.
func (s *Server) handlePeerPing(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg()
	resp := PeerPingResponse{
		PeerID:        cfg.PeerID,
		ConfigPrimary: cfg.ConfigPrimary,
		SharedRev:     sharedConfigDigest(cfg),
	}
	// Best-effort iptables classification — failures here don't fail the
	// ping (we still need to report peer identity for cert ownership etc.)
	if live, expected, stale, blessed, _, err := s.buildClassifierInputs(); err == nil {
		summary := iptables.SummarizeClassified(iptables.Classify(live, expected, stale, blessed))
		resp.IPTablesSummary = &summary
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handlePeerConfig returns the full config JSON. Only the config primary
// serves a meaningful response; non-primaries can serve too (it's read-only)
// but pulls should target the primary.
//
// Conditional transport: every response carries ETag: "<shared-rev>", the
// content digest of the fleet-shared fields. If-None-Match with that digest
// yields 304 and no body, so unchanged pull rounds cost no parse/save work.
// A pulling peer that does not send the header (older build) gets the full
// 200 exactly as before — mixed-version fleets keep converging.
func (s *Server) handlePeerConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg()
	rev := sharedConfigDigest(cfg)
	etag := `"` + rev + `"`
	w.Header().Set("ETag", etag)

	if match := strings.TrimSpace(r.Header.Get("If-None-Match")); match != "" && (match == etag || match == rev) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// PeerCertResponse is returned by GET /api/peer/cert/<domain>.
type PeerCertResponse struct {
	Domain string `json:"domain"`
	Cert   string `json:"cert"` // fullchain.pem contents
	Key    string `json:"key"`  // privkey.pem contents
}

// handlePeerCert returns the certificate + private key for a domain so
// non-owner peers can pull certs they don't renew themselves. The domain
// is extracted from the URL path suffix after "/api/peer/cert/".
//
// Restricted to configured peers via peerOnlyMiddleware (item 2).
func (s *Server) handlePeerCert(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/api/peer/cert/")
	if domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}

	cfg := s.cfg()
	// Strip wildcard prefix for the filesystem path (certs stored under
	// the base domain, e.g. /etc/letsencrypt/live/example.com/).
	baseDomain := strings.TrimPrefix(domain, "*.")
	certDir := filepath.Join(cfg.SSLCertDir, "live", baseDomain)

	certData, err := os.ReadFile(filepath.Join(certDir, "fullchain.pem"))
	if err != nil {
		http.Error(w, "cert not found", http.StatusNotFound)
		return
	}
	keyData, err := os.ReadFile(filepath.Join(certDir, "privkey.pem"))
	if err != nil {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(PeerCertResponse{
		Domain: domain,
		Cert:   string(certData),
		Key:    string(keyData),
	})
}

// PeerStateResponse is returned by GET /api/peer/state.
type PeerStateResponse struct {
	Bans []config.IPBan `json:"bans"`
}

// handlePeerState returns runtime state for LWW sync. Currently just bans.
func (s *Server) handlePeerState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(PeerStateResponse{
		Bans: s.cfg().IPBans,
	})
}

// peerOnlyMiddleware allows only requests from configured peer addresses.
// When the fleet has configured peers, only those specific wg_addr hosts
// are allowed — not the entire VPN CIDR. This is critical for Phase 2
// endpoints like /api/peer/cert/:domain that expose private key material.
//
// Falls back to VPN CIDR check when no peers are configured (standalone
// mode or primary with no peers listed) so the endpoint still works in
// development/testing.
func (s *Server) peerOnlyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !s.isAllowedPeer(host) {
			http.Error(w, "peer api: not a configured peer", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// isAllowedPeer reports whether ip is a configured fleet peer. When
// peers are configured, only their wg_addr hosts (stripped of port) are
// accepted. When no peers are configured, falls back to VPN CIDR.
func (s *Server) isAllowedPeer(ip string) bool {
	peers := s.cfg().Peers
	if len(peers) == 0 {
		return s.isInVPNRange(ip)
	}
	for _, p := range peers {
		peerHost := p.WGAddr
		if h, _, err := net.SplitHostPort(peerHost); err == nil {
			peerHost = h
		}
		if peerHost == ip {
			return true
		}
	}
	return false
}

// nonPrimaryGuardMiddleware returns 403 with the primary peer ID when this
// instance is non-primary and the request is a config-mutating call.
//
// Default policy is "block on non-primary" for any non-GET request. Routes
// that should be allowed (per-instance runtime ops, peer-to-peer plumbing,
// auth) opt out by being registered via handlePeerInstance /
// handlePeerInstanceSubtree, which records them in s.peerInstancePaths /
// s.peerInstancePrefixes. There is no separate exempt list to maintain.
func (s *Server) nonPrimaryGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Primary always serves.
		if s.cfg().ConfigPrimary || s.cfg().PeerID == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Read-only methods always pass through.
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		if s.isPeerInstanceRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		primaryID := ""
		if p := s.cfg().PrimaryPeer(); p != nil {
			primaryID = p.ID
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":      "this instance is read-only — edit on the config primary",
			"primary_id": primaryID,
		})
	})
}

// handlePeerInstance registers an exact-path route as a per-instance op
// (per-instance runtime, not a shared-config mutation). The path is
// recorded in s.peerInstancePaths so nonPrimaryGuardMiddleware will let
// non-GET requests through on a non-primary instance.
//
// Use this for any route that must keep working on the read-only spare:
// auth, peer-to-peer plumbing, subsystem reloads, sync triggers, etc.
// Default for routes registered via plain mux.HandleFunc is "blocked on
// non-primary".
func (s *Server) handlePeerInstance(mux *http.ServeMux, path string, h http.HandlerFunc) {
	if s.peerInstancePaths == nil {
		s.peerInstancePaths = make(map[string]bool)
	}
	s.peerInstancePaths[path] = true
	mux.HandleFunc(path, h)
}

// handlePeerInstanceSubtree is the subtree-pattern variant of
// handlePeerInstance. Use it when the underlying mux registration is a
// trailing-slash subtree (e.g. "/api/deploy/") so every path under the
// prefix is exempt from the non-primary guard.
func (s *Server) handlePeerInstanceSubtree(mux *http.ServeMux, prefix string, h http.HandlerFunc) {
	s.peerInstancePrefixes = append(s.peerInstancePrefixes, prefix)
	mux.HandleFunc(prefix, h)
}

// isPeerInstanceRoute reports whether the given URL path was registered as
// a per-instance route via handlePeerInstance or handlePeerInstanceSubtree.
func (s *Server) isPeerInstanceRoute(path string) bool {
	if s.peerInstancePaths[path] {
		return true
	}
	for _, prefix := range s.peerInstancePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// syncWGPeersToConfig snapshots the current WG config file peer list into
// cfg.WGPeers so it gets persisted to config.json and replicated to
// non-primary instances. Call this after every WG mutation (add/edit/delete/
// re-key) before config.Save.
// syncWGPeersToConfig snapshots the current WG config file peer list into
// the given config (or s.cfg() if nil). Call this before updateConfig/Save
// so WGPeers reflects the latest WG file state. Mutates cfg in place.
func (s *Server) snapshotWGPeers() []config.WGPeer {
	peers := s.wg.GetPeers()
	wgPeers := make([]config.WGPeer, len(peers))
	for i, p := range peers {
		wgPeers[i] = config.WGPeer{
			Name:       p.Name,
			PublicKey:  p.PublicKey,
			AllowedIPs: p.AllowedIPs,
		}
	}
	return wgPeers
}

// applyWGPeersFromConfig applies the WGPeers list from config to the local
// WG config file. Called when a pulled config has a different peer set.
//
// The diff is idempotent: every failing peer op is collected (not fatal) and
// the function still walks the whole desired set, so a retry after a partial
// failure converges instead of wedging on the first error. The joined error
// is what lets the pull loop report a half-applied WG state as a recovery
// failure rather than as success.
func (s *Server) applyWGPeersFromConfig(cfg *config.Config) error {
	if s.wg == nil {
		return nil
	}

	current := s.wg.GetPeers()
	currentByKey := make(map[string]struct{}, len(current))
	for _, p := range current {
		currentByKey[p.PublicKey] = struct{}{}
	}

	desiredByKey := make(map[string]config.WGPeer, len(cfg.WGPeers))
	for _, p := range cfg.WGPeers {
		desiredByKey[p.PublicKey] = p
	}

	var errs []error
	changed := false

	// Remove peers not in desired set.
	for _, p := range current {
		if _, ok := desiredByKey[p.PublicKey]; !ok {
			slog.Info("peer-sync: removing WG peer", "name", p.Name, "pubkey_prefix", safeKeyPrefix(p.PublicKey))
			if err := s.wg.RemovePeer(p.PublicKey); err != nil {
				slog.Error("peer-sync: remove WG peer failed", "name", p.Name, "err", err)
				errs = append(errs, fmt.Errorf("remove %s: %w", p.Name, err))
			}
			changed = true
		}
	}

	// Add or update peers.
	for _, desired := range cfg.WGPeers {
		if _, exists := currentByKey[desired.PublicKey]; !exists {
			slog.Info("peer-sync: adding WG peer", "name", desired.Name, "pubkey_prefix", safeKeyPrefix(desired.PublicKey))
			if err := s.wg.AddPeer(desired.Name, desired.PublicKey, desired.AllowedIPs); err != nil {
				slog.Error("peer-sync: add WG peer failed", "name", desired.Name, "err", err)
				errs = append(errs, fmt.Errorf("add %s: %w", desired.Name, err))
			}
			changed = true
		} else {
			// Check if name or AllowedIPs changed.
			for _, cur := range current {
				if cur.PublicKey == desired.PublicKey {
					if cur.Name != desired.Name || cur.AllowedIPs != desired.AllowedIPs {
						slog.Info("peer-sync: updating WG peer", "name", desired.Name)
						if err := s.wg.UpdatePeer(desired.PublicKey, desired.Name, desired.AllowedIPs); err != nil {
							slog.Error("peer-sync: update WG peer failed", "name", desired.Name, "err", err)
							errs = append(errs, fmt.Errorf("update %s: %w", desired.Name, err))
						}
						changed = true
					}
					break
				}
			}
		}
	}

	if changed {
		if err := s.wg.Reload(); err != nil {
			slog.Error("peer-sync: WG reload after peer sync failed", "err", err)
			errs = append(errs, fmt.Errorf("wg reload: %w", err))
		}
		s.rebuildWGChains()
	}
	return errors.Join(errs...)
}

// safeKeyPrefix returns the first 8 chars of a public key for logs, or a
// placeholder when the key is unexpectedly short.
func safeKeyPrefix(k string) string {
	if len(k) < 8 {
		return "?"
	}
	return k[:8]
}

// postPullRecoveryHook, when non-nil, runs as an additional step at the end
// of recoverDerivedState. Test-only seam for the recovery-failure/replay
// paths; always nil in production.
var postPullRecoveryHook func(cfg *config.Config) error

// recoverDerivedState re-derives every subsystem that follows the config,
// after the config has been durably committed. It must be idempotent and
// safe to RE-RUN (the pull loop replays it on later rounds when a previous
// recovery failed), and narrow: local checks converge via RefreshChecks
// (inside syncServices) and outside-in vantages via ReloadRemotes, which
// restarts only the probes that actually changed — never the blunt
// monitor.Reload that stops every check and wipes all history.
func (s *Server) recoverDerivedState(old, newCfg *config.Config) error {
	var errs []error

	if err := s.syncServices(); err != nil {
		errs = append(errs, err)
	}

	if err := s.applyWGPeersFromConfig(newCfg); err != nil {
		errs = append(errs, err)
	}

	// Vantages are local-only state carried through the merge unchanged, so
	// unchanged probes keep their loops; only add/remove/changed ones touch
	// the scheduler.
	if s.monitor != nil {
		s.monitor.ReloadRemotes(newCfg)
	}

	if old != nil && (old.ListenAddr != newCfg.ListenAddr ||
		old.WGInterface != newCfg.WGInterface ||
		old.WGConfigPath != newCfg.WGConfigPath) {
		slog.Warn("peer-sync: low-level config changed (listen/wg) — restart required to take effect")
	}

	if postPullRecoveryHook != nil {
		if err := postPullRecoveryHook(newCfg); err != nil {
			errs = append(errs, err)
		}
	}

	// A pulled peer config is, by definition, the synced state for this
	// instance — track it so a non-primary never shows phantom pending
	// changes, even when a derived step still needs a later replay.
	s.markSynced()

	return errors.Join(errs...)
}


