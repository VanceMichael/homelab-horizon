package server

// Phase 1 of multi-instance HA — see plan/plan.md.
//
// Non-primary instances pull config from the primary every 30s, hash-compare,
// and replace + reload on change. Pull-based: primaries never push.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iodesystems/homelab-horizon/internal/config"
)

const (
	peerSyncInterval = 30 * time.Second
	banSyncInterval  = 30 * time.Second
)

// startPeerSync starts the config pull loop on non-primary instances.
// No-op when this instance is the primary or no fleet is configured.
func (s *Server) startPeerSync() {
	if err := s.cfg().ValidateFleet(); err != nil {
		slog.Warn("peer-sync: fleet config invalid, running standalone", "err", err)
		return
	}
	if s.cfg().PeerID == "" {
		return // single-instance mode
	}
	if s.cfg().ConfigPrimary {
		slog.Info("peer-sync: this instance is the config primary", "peer_id", s.cfg().PeerID)
		return
	}
	primary := s.cfg().PrimaryPeer()
	if primary == nil {
		s.autoPromote()
		return
	}
	slog.Info("peer-sync: starting pull loop",
		"self", s.cfg().PeerID, "primary", primary.ID, "primary_addr", primary.WGAddr, "interval", peerSyncInterval)

	go func() {
		// First attempt soon after startup so warm spares converge fast.
		time.Sleep(2 * time.Second)
		if !s.pullConfigOnce() {
			slog.Info("peer-sync: pull loop ended after role change", "peer_id", s.cfg().PeerID)
			return
		}

		ticker := time.NewTicker(peerSyncInterval)
		defer ticker.Stop()
		for range ticker.C {
			if !s.pullConfigOnce() {
				slog.Info("peer-sync: pull loop ended after role change", "peer_id", s.cfg().PeerID)
				return
			}
		}
	}()
}

// autoPromote promotes this non-primary instance to primary by setting
// ConfigPrimary=true and persisting the change. Called when the peer list
// contains no entry marked primary — the operator's act of removing the
// primary peer is the explicit signal that promotion is intended.
func (s *Server) autoPromote() {
	slog.Info("peer-sync: no primary peer configured, auto-promoting to primary", "peer_id", s.cfg().PeerID)
	if err := s.updateConfig(func(cfg *config.Config) {
		cfg.ConfigPrimary = true
	}); err != nil {
		slog.Error("peer-sync: auto-promote save failed", "err", err)
	}
}

// pullMaxAttempts bounds the in-round conflict retries: each attempt re-pings
// and re-fetches from the current state, so a world that keeps moving simply
// leaves the rest to the next 30s tick instead of busy-looping.
const pullMaxAttempts = 3

// pullConfigOnce runs one pull round against the config primary. The round is
// serialized (pullMu) and decided at a single commit point:
//
//	ping (identity/role/revision)
//	  → conditional config fetch (304 = nothing new)
//	    → revalidation ping (the body must STILL be the primary's revision)
//	      → commitPulledConfig (role/topology/base gates; merge LATEST local
//	        state; atomic save; swap)
//	        → recoverDerivedState (idempotent; replayable on later rounds)
//
// Any gate failure discards the fetched body and retries from a fresh
// snapshot; a role change ends the loop (returns false). Fetch/parse/
// split-guard failures are fetch_failed; discarded bodies are conflict;
// save/recovery failures are recover_failed. Nothing is reported as synced
// unless the config is on disk and derived state has converged.
func (s *Server) pullConfigOnce() (keepRunning bool) {
	s.pullMu.Lock()
	defer s.pullMu.Unlock()

	var (
		state   = pullStateSynced
		detail  string
		applied bool
	)
	defer func() {
		s.recordPullAttempt(state, applied, detail)
	}()

	// fetchFailed / recoverFailed keep the loop alive for the next tick;
	// roleEnded stops it.
	fetchFailed := func(format string, a ...any) bool {
		state = pullStateFetchFailed
		detail = fmt.Sprintf(format, a...)
		slog.Warn("peer-sync: pull failed", "err", detail)
		return true
	}
	recoverFailed := func(format string, a ...any) bool {
		state = pullStateRecoverFailed
		detail = fmt.Sprintf(format, a...)
		slog.Error("peer-sync: recovery failure", "err", detail)
		return true
	}
	roleEnded := func(d string) bool {
		state = pullStateConflict
		detail = d
		return false
	}

	for attempt := 0; attempt < pullMaxAttempts; attempt++ {
		cfg := s.cfg()

		// Role already changed since the last tick: the loop's job is over.
		// A quiet stop, not a discarded pull — no conflict counted.
		if cfg.PeerID == "" || cfg.ConfigPrimary {
			return roleEnded("this instance is no longer a non-primary; pull loop stopped")
		}
		primary := cfg.PrimaryPeer()
		if primary == nil {
			// Operator removed the primary mid-run — the existing signal
			// for promotion; the promotion ends the loop.
			s.autoPromote()
			s.peerSyncStatus.noteConflict()
			return roleEnded("no primary peer configured; promoted this instance to primary")
		}

		s.peerSyncStatus.ensureInit(sharedConfigDigest(cfg))
		base := pullAttemptBase{
			peerID:      cfg.PeerID,
			primaryID:   primary.ID,
			primaryAddr: primary.WGAddr,
			baseRev:     sharedConfigDigest(cfg),
		}
		needRecoveryReplay := s.peerSyncStatus.recoveryPending()

		// finishWithoutNewBody is the single exit for "the primary has no
		// new shared content" — whether learned from the ping revision, a
		// 304, or a 200 body that collapses to current state (a legacy
		// primary without ETag support). A pending derived recovery is
		// replayed here regardless of how "no new content" was discovered,
		// so a 200-collapse can never paper over an unfinished recovery.
		finishWithoutNewBody := func() bool {
			if !needRecoveryReplay {
				state = pullStateSynced
				return true
			}
			cur := s.cfg()
			committed := s.peerSyncStatus.committedRevision()
			if err := s.recoverDerivedState(cur, cur); err != nil {
				return recoverFailed("recovery replay (rev %s): %v", revPrefix(committed), err)
			}
			s.peerSyncStatus.setRecovered(committed)
			state = pullStateSynced
			slog.Info("peer-sync: derived recovery replayed", "rev", revPrefix(committed))
			return true
		}

		// 1. Cheap preflight ping: identity + role + current revision.
		pingURL := buildPeerURL(primary.WGAddr, "/api/peer/ping")
		ping, err := fetchPeerPing(pingURL)
		if err != nil {
			return fetchFailed("ping %s: %v", pingURL, err)
		}
		if ping.PeerID != primary.ID {
			return fetchFailed("split-config guard: %s reports peer_id=%q, expected %q", pingURL, ping.PeerID, primary.ID)
		}
		if !ping.ConfigPrimary {
			return fetchFailed("split-config guard: %s no longer claims to be primary", primary.ID)
		}

		upToDate := ping.SharedRev != "" && ping.SharedRev == base.baseRev

		var remoteCfg *config.Config
		remoteRev := ping.SharedRev

		// 2. Fetch — skipped entirely when the revision matches and no
		//    recovery replay is pending.
		if !upToDate || needRecoveryReplay || ping.SharedRev == "" {
			cfgURL := buildPeerURL(primary.WGAddr, "/api/peer/config")
			body, etagRev, notModified, err := fetchPeerConfig(cfgURL, base.baseRev)
			if err != nil {
				return fetchFailed("fetch %s: %v", cfgURL, err)
			}
			if notModified {
				remoteRev = etagRev
				upToDate = true
			} else {
				remoteCfg, err = config.LoadFromJSON(body)
				if err != nil {
					return fetchFailed("parse remote config: %v", err)
				}
				if err := remoteCfg.ValidateFleet(); err != nil {
					return fetchFailed("remote fleet config invalid: %v", err)
				}
				if !remoteCfg.ConfigPrimary || remoteCfg.PeerID != primary.ID {
					return fetchFailed("split-config guard: remote config peer_id=%q config_primary=%v",
						remoteCfg.PeerID, remoteCfg.ConfigPrimary)
				}
				if etagRev != "" {
					remoteRev = etagRev
				} else {
					// Mixed-version primary without ETag support: derive the
					// revision from the shared portion of the body itself.
					remoteRev = sharedConfigDigest(remoteCfg)
				}
				upToDate = false
			}
		}

		// 3. No new shared revision: pure no-op, or a recovery replay.
		if upToDate {
			return finishWithoutNewBody()
		}

		// 4. Commit-time revalidation: the fetched revision must still be
		//    the primary's current one. The gates below cover everything that
		//    could move locally; this ping covers the primary side.
		ping2, err := fetchPeerPing(pingURL)
		if err != nil {
			return fetchFailed("revalidation ping: %v", err)
		}
		if ping2.PeerID != primary.ID || !ping2.ConfigPrimary {
			return fetchFailed("split-config guard: primary identity/role changed between fetch and commit")
		}

		// 5. The decidable commit point.
		merged, prev, changed, err := s.commitPulledConfig(remoteCfg, remoteRev, base, ping2.SharedRev)
		if err != nil {
			switch {
			case errors.Is(err, errPullNoPrimary):
				s.autoPromote()
				s.peerSyncStatus.noteConflict()
				return roleEnded("primary peer removed during pull; promoted this instance")
			case errors.Is(err, errPullRoleChanged):
				// Promoted (or defleet-ed) while the body was in flight.
				s.peerSyncStatus.noteConflict()
				return roleEnded(err.Error())
			case isPullConflict(err):
				// Topology/base/primary revision moved: discard the body and
				// retry the round from a fresh snapshot.
				s.peerSyncStatus.noteConflict()
				detail = err.Error()
				slog.Warn("peer-sync: stale pull discarded, retrying",
					"attempt", attempt+1, "err", err)
				continue
			default:
				// Durable save failed: live state is untouched.
				return recoverFailed("%v", err)
			}
		}
		if !changed {
			// The fetched body collapses to current live state (e.g. a
			// legacy primary re-served the same revision as 200). Nothing
			// was swapped or applied, so the apply timestamp must not move;
			// but if a previous commit's recovery is still pending, replay
			// it here instead of declaring the round synced on nothing.
			if !needRecoveryReplay {
				s.peerSyncStatus.markInSync(remoteRev)
			}
			return finishWithoutNewBody()
		}

		// 6. Durable commit landed. Recover derived subsystems OUTSIDE the
		//    config lock. Disk already equals memory here, so a failure is
		//    reproducible after restart and gets replayed on a later round.
		s.peerSyncStatus.setCommitted(remoteRev, time.Now())
		if err := s.recoverDerivedState(prev, merged); err != nil {
			return recoverFailed("committed rev %s on disk but recovery failed: %v", revPrefix(remoteRev), err)
		}
		s.peerSyncStatus.setRecovered(remoteRev)
		applied = true
		state = pullStateSynced
		slog.Info("peer-sync: applied new config", "primary", primary.ID, "rev", revPrefix(remoteRev))
		return true
	}

	// Attempts exhausted on repeated conflicts — next interval tries again.
	state = pullStateConflict
	if detail == "" {
		detail = "pull kept conflicting with concurrent changes; will retry next interval"
	}
	slog.Warn("peer-sync: giving up this round after retries", "attempts", pullMaxAttempts, "last", detail)
	return true
}

// revPrefix shortens a digest for log lines.
func revPrefix(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

// recordPullAttempt is the deferred bookkeeping for one pullConfigOnce round.
func (s *Server) recordPullAttempt(state pullState, applied bool, detail string) {
	now := time.Now()
	s.peerSyncStatus.mu.Lock()
	defer s.peerSyncStatus.mu.Unlock()
	s.peerSyncStatus.pullCount++
	s.peerSyncStatus.lastPullAt = now
	s.peerSyncStatus.state = state
	switch state {
	case pullStateSynced:
		s.peerSyncStatus.lastSuccessAt = now
		s.peerSyncStatus.lastError = ""
		if applied {
			s.peerSyncStatus.lastApplyAt = now
		}
	case pullStateConflict:
		// Conflicts are counted at the moment a body is discarded
		// (noteConflict), since rounds can end synced after retrying.
		s.peerSyncStatus.lastError = detail
	default: // fetch_failed, recover_failed
		s.peerSyncStatus.lastError = detail
	}
}

// PeerSyncStatusSnapshot returns a copy of the current peer-sync status for
// dashboard rendering. Returns the zero value when no fleet is configured.
type PeerSyncStatusSnapshot struct {
	PullCount      int
	LastPullAt     time.Time
	LastSuccessAt  time.Time
	LastApplyAt    time.Time
	LastError      string
	State          pullState
	CommittedRev   string
	RecoveredRev   string
	ConflictCount  int
	LastConflictAt time.Time
}

func (s *Server) peerSyncSnapshot() PeerSyncStatusSnapshot {
	s.peerSyncStatus.mu.RLock()
	defer s.peerSyncStatus.mu.RUnlock()
	return PeerSyncStatusSnapshot{
		PullCount:      s.peerSyncStatus.pullCount,
		LastPullAt:     s.peerSyncStatus.lastPullAt,
		LastSuccessAt:  s.peerSyncStatus.lastSuccessAt,
		LastApplyAt:    s.peerSyncStatus.lastApplyAt,
		LastError:      s.peerSyncStatus.lastError,
		State:          s.peerSyncStatus.state,
		CommittedRev:   s.peerSyncStatus.committedRev,
		RecoveredRev:   s.peerSyncStatus.recoveredRev,
		ConflictCount:  s.peerSyncStatus.conflictCount,
		LastConflictAt: s.peerSyncStatus.lastConflictAt,
	}
}

// localOnlyConfigKeys is the SINGLE authoritative list of top-level config
// JSON keys that belong to the local instance and are never replicated from
// the config primary. It drives both the shared-state digest
// (sharedConfigDigest) and, via mergeRemoteIntoLocal below, the field-by-field
// pin when a pulled config lands. A new per-instance field MUST be added here
// AND pinned in mergeRemoteIntoLocal — TestLocalOnlyKeysArePinned enforces
// that the two cannot drift apart.
//
// Per-instance fields (NOT replicated):
//   - peer_id, config_primary, peers (fleet identity/topology — locally pinned)
//   - listen_addr, wg_interface, wg_config_path, server_endpoint,
//     server_public_key, local_interface (host-specific plumbing)
//   - admin_token (host-local secret)
//   - public_ip / public_ip_override / public_ip_last_checked
//     (each peer manages its own A record / public IP detection)
//   - last_local_iface / last_lan_cidr (host's own default route memory)
//   - blessed_iptables_rules (per-host adjacency)
//   - remote_probes (per-host outside-in vantages and their tokens)
//   - last_published_records / dns_drift_blocked / dns_drift_detail
//     (each peer publishes its own records and tracks its own drift)
var localOnlyConfigKeys = map[string]struct{}{
	"peer_id":                {},
	"config_primary":         {},
	"peers":                  {},
	"listen_addr":            {},
	"wg_interface":           {},
	"wg_config_path":         {},
	"server_endpoint":        {},
	"server_public_key":      {},
	"local_interface":        {},
	"admin_token":            {},
	"public_ip":              {},
	"public_ip_override":     {},
	"public_ip_last_checked": {},
	"last_local_iface":       {},
	"last_lan_cidr":          {},
	"blessed_iptables_rules": {},
	"remote_probes":          {},
	"last_published_records": {},
	"dns_drift_blocked":      {},
	"dns_drift_detail":       {},
}

// sharedConfigDigest returns a content-addressed revision of the fleet-shared
// portion of a config: a canonical JSON serialization (map keys sorted by
// encoding/json) with every local-only top-level key removed, hashed with
// SHA-256. Two peers with the same shared state compute the same digest
// regardless of their per-instance fields, and any shared edit changes it.
//
// The digest is what the primary serves as shared_rev/ETag and what a
// non-primary compares against to decide whether a pull has anything to
// commit — no version-counter field needs to live in the config.
func sharedConfigDigest(cfg *config.Config) string {
	b, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	m := make(map[string]json.RawMessage)
	if err := json.Unmarshal(b, &m); err != nil {
		return ""
	}
	for k := range localOnlyConfigKeys {
		delete(m, k)
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return hashOf(canonical)
}

// mergeRemoteIntoLocal returns a new config containing remote's shared
// state (services, zones, certs settings, etc.) overlaid with local-only
// per-instance fields preserved from the local config.
//
// The pins below MUST cover every key in localOnlyConfigKeys — enforced by
// TestLocalOnlyKeysArePinned.
func mergeRemoteIntoLocal(remote, local *config.Config) *config.Config {
	out := *remote // shallow copy of remote (shared state)

	// Pin local-only fields back.
	out.PeerID = local.PeerID
	out.ConfigPrimary = local.ConfigPrimary
	out.Peers = local.Peers

	out.ListenAddr = local.ListenAddr
	out.WGInterface = local.WGInterface
	out.WGConfigPath = local.WGConfigPath
	out.ServerEndpoint = local.ServerEndpoint
	out.ServerPublicKey = local.ServerPublicKey

	out.PublicIP = local.PublicIP
	out.PublicIPOverride = local.PublicIPOverride
	out.PublicIPLastChecked = local.PublicIPLastChecked
	out.LocalInterface = local.LocalInterface
	out.AdminToken = local.AdminToken

	// Host-local iface/CIDR memory — each peer has its own default route,
	// so the primary's values don't apply here.
	out.LastLocalIface = local.LastLocalIface
	out.LastLanCIDR = local.LastLanCIDR

	// Blessed iptables rules are local-only — the primary's bless list
	// doesn't apply to this host's adjacent tooling.
	out.BlessedIPTablesRules = local.BlessedIPTablesRules

	// Remote probes are local-only. Each peer polls its own vantage points,
	// and the entry carries that agent's token — a credential this peer was
	// given, not one to hand out across the fleet.
	out.RemoteProbes = local.RemoteProbes

	// DNS publish memory + drift block are local-only: each peer publishes its
	// own records and detects drift against its own baseline, so the primary's
	// snapshot/block must not be inherited (would falsely block or mislead).
	out.LastPublishedRecords = local.LastPublishedRecords
	out.DNSDriftBlocked = local.DNSDriftBlocked
	out.DNSDriftDetail = local.DNSDriftDetail

	// IPBans: take the LWW-merged result from the remote config.
	// The ban sync loop on each peer independently merges bans from all
	// peers, so the primary's ban list is the authoritative merged set.

	return &out
}

// pullAttemptBase captures the local state a pull attempt started from. The
// commit point compares the live state against it to decide whether the
// fetched body is still committable.
type pullAttemptBase struct {
	peerID      string // this instance's peer id when the attempt started
	primaryID   string // configured primary's peer id
	primaryAddr string // configured primary's wg_addr
	baseRev     string // shared revision of the local config at attempt start
}

// Sentinels classify why a fetched body was rejected at the commit point.
// They are conflicts ("the world moved while we were fetching; discard and
// retry/end"), not fetch errors — the body itself was fine.
var (
	// errPullRoleChanged: this instance was promoted (or left the fleet)
	// during the pull. The fetched body is never applied.
	errPullRoleChanged = errors.New("local role changed during pull: this instance is no longer a non-primary")
	// errPullNoPrimary: the primary peer entry was removed during the pull.
	// Caller runs the usual auto-promote and ends the round.
	errPullNoPrimary = errors.New("no primary peer configured at commit time")
	// errPullTopologyMoved: the configured primary (id or address) differs
	// from the one the body was fetched from. Retry against the new target.
	errPullTopologyMoved = errors.New("primary target changed during pull")
	// errPullBaseMoved: local shared state changed during the fetch (e.g.
	// ban LWW convergence). Retry so the merge starts from the new base.
	errPullBaseMoved = errors.New("local shared state changed during pull")
	// errPullRemoteMoved: the primary's revalidation ping reports a newer
	// revision than the fetched body. Discard and re-fetch.
	errPullRemoteMoved = errors.New("primary moved to a new revision during pull")
)

// isPullConflict reports whether err is one of the commit-gate sentinels.
func isPullConflict(err error) bool {
	return errors.Is(err, errPullRoleChanged) ||
		errors.Is(err, errPullNoPrimary) ||
		errors.Is(err, errPullTopologyMoved) ||
		errors.Is(err, errPullBaseMoved) ||
		errors.Is(err, errPullRemoteMoved)
}

// commitPulledConfig is the decidable commit point of a non-primary pull.
//
// It performs NO network I/O: the caller passes the fetched remote config,
// its revision, the attempt's starting snapshot, and the revision observed by
// the commit-time revalidation ping. Under configMu it then:
//  1. verifies role, topology and the local shared base have not moved, and
//     that the primary still serves the fetched revision;
//  2. merges the remote shared state with the LATEST local-only state (the
//     live config read INSIDE the lock — never the pull-start snapshot);
//  3. persists atomically and only then swaps the live pointer.
//
// Returns the resulting config and whether it changed. Any returned conflict
// sentinel means nothing was written or swapped; a save error likewise leaves
// live state on the previous version. Derived-subsystem recovery is the
// caller's job and runs OUTSIDE the lock.
func (s *Server) commitPulledConfig(remoteCfg *config.Config, remoteRev string, base pullAttemptBase, revalidatedRev string) (merged, prev *config.Config, changed bool, err error) {
	s.configMu.Lock()
	defer s.configMu.Unlock()

	cur := s.cfg()

	// Gate 1: role. Promoted, or no longer in the fleet: the pull ends.
	if cur.PeerID == "" || cur.ConfigPrimary || cur.PeerID != base.peerID {
		return nil, nil, false, errPullRoleChanged
	}

	// Gate 2: topology — the body must come from the primary configured NOW.
	p := cur.PrimaryPeer()
	if p == nil {
		return nil, nil, false, errPullNoPrimary
	}
	if p.ID != base.primaryID || p.WGAddr != base.primaryAddr {
		return nil, nil, false, errPullTopologyMoved
	}

	// Gate 3: local shared base — a ban-LWW merge or another committed pull
	// landing during the fetch changes what the merge must start from.
	if rev := sharedConfigDigest(cur); rev != base.baseRev {
		return nil, nil, false, errPullBaseMoved
	}

	// Gate 4: the fetched revision must still be current on the primary.
	// Empty revisions on either side mean a mixed-version peer without
	// digest support — fall back to the body-level guards the caller ran.
	if remoteRev != "" && revalidatedRev != "" && remoteRev != revalidatedRev {
		return nil, nil, false, errPullRemoteMoved
	}

	// Merge against the live config read under the lock, so local-only
	// updates that landed during the fetch are folded in rather than
	// overwritten by the pull-start snapshot.
	merged = mergeRemoteIntoLocal(remoteCfg, cur)
	// Runtime-only state that never serializes from the primary: the live
	// admin token (migrated out of the config file) and the --listen
	// process override.
	merged.AdminToken = cur.AdminToken
	merged.SetListenOverride(cur.ListenOverride())

	mergedBytes, _ := json.Marshal(merged)
	curBytes, _ := json.Marshal(cur)
	if hashOf(mergedBytes) == hashOf(curBytes) {
		return cur, cur, false, nil // shared content identical — nothing to commit
	}

	if err := config.Save(s.configPath, merged); err != nil {
		return nil, cur, false, fmt.Errorf("save pulled config: %w", err)
	}
	s.config.Store(merged)
	return merged, cur, true, nil
}

// buildPeerURL builds an http URL from a peer's wg_addr (host or host:port).
// If no port is specified, assumes :8080 (the default ListenAddr).
func buildPeerURL(wgAddr, path string) string {
	addr := wgAddr
	if !strings.Contains(addr, ":") {
		addr += ":8080"
	}
	return "http://" + addr + path
}

// alivePeers pings every configured peer in parallel and returns the IDs of
// those that responded with a valid ping (including self). The result is
// deterministically sorted by ID so all peers in the fleet compute the same
// order for ownership decisions.
func (s *Server) alivePeers() []string {
	cfg := s.cfg()
	if cfg.PeerID == "" {
		return nil
	}

	// Self is always alive.
	alive := []string{cfg.PeerID}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range cfg.Peers {
		wg.Add(1)
		go func(peer config.Peer) {
			defer wg.Done()
			url := buildPeerURL(peer.WGAddr, "/api/peer/ping")
			resp, err := fetchPeerPing(url)
			if err != nil {
				slog.Debug("peer-liveness: unreachable", "peer", peer.ID, "url", url, "err", err)
				return
			}
			if resp.PeerID != peer.ID {
				slog.Warn("peer-liveness: peer_id mismatch, skipping", "peer", peer.ID, "got", resp.PeerID)
				return
			}
			mu.Lock()
			alive = append(alive, peer.ID)
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	sort.Strings(alive)
	return alive
}

// startBanSync starts a 30s ticker that pulls bans from every peer and
// merges them LWW per IP. Runs on ALL fleet members (primary and non-primary)
// so bans propagate bidirectionally regardless of where they originate.
// No-op in single-instance mode.
func (s *Server) startBanSync() {
	cfg := s.cfg()
	if cfg.PeerID == "" || len(cfg.Peers) == 0 {
		return
	}
	slog.Info("ban-sync: starting LWW sync", "interval", banSyncInterval, "peers", len(cfg.Peers))

	go func() {
		time.Sleep(5 * time.Second) // let other subsystems start first
		s.banSyncOnce()

		ticker := time.NewTicker(banSyncInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.banSyncOnce()
		}
	}()
}

// banSyncOnce fetches bans from every peer and merges them with the local
// ban list using last-write-wins per IP (by CreatedAt timestamp).
func (s *Server) banSyncOnce() {
	cfg := s.cfg()
	var allRemoteBans []config.IPBan

	for _, p := range cfg.Peers {
		url := buildPeerURL(p.WGAddr, "/api/peer/state")
		body, err := fetchPeerBody(url)
		if err != nil {
			// Peer down — skip silently (liveness is checked elsewhere).
			continue
		}
		var resp PeerStateResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			slog.Warn("ban-sync: decode error", "peer", p.ID, "err", err)
			continue
		}
		allRemoteBans = append(allRemoteBans, resp.Bans...)
	}

	if len(allRemoteBans) == 0 {
		return
	}

	merged := mergeBansLWW(cfg.IPBans, allRemoteBans)
	if len(merged) == len(cfg.IPBans) {
		// Quick check: if counts match, compare more carefully.
		same := true
		localByIP := make(map[string]int64, len(cfg.IPBans))
		for _, b := range cfg.IPBans {
			localByIP[b.IP] = b.CreatedAt
		}
		for _, b := range merged {
			if localByIP[b.IP] != b.CreatedAt {
				same = false
				break
			}
		}
		if same {
			return
		}
	}

	if err := s.updateConfig(func(c *config.Config) {
		c.IPBans = merged
	}); err != nil {
		slog.Warn("ban-sync: updateConfig", "err", err)
	}
	s.reapplyBans()
	slog.Info("ban-sync: merged bans", "total", len(merged))
}

// mergeBansLWW merges two ban lists using last-write-wins per IP.
// For each IP, the ban with the highest CreatedAt wins.
func mergeBansLWW(local, remote []config.IPBan) []config.IPBan {
	byIP := make(map[string]config.IPBan)
	for _, b := range local {
		if existing, ok := byIP[b.IP]; !ok || b.CreatedAt > existing.CreatedAt {
			byIP[b.IP] = b
		}
	}
	for _, b := range remote {
		if existing, ok := byIP[b.IP]; !ok || b.CreatedAt > existing.CreatedAt {
			byIP[b.IP] = b
		}
	}
	result := make([]config.IPBan, 0, len(byIP))
	for _, b := range byIP {
		result = append(result, b)
	}
	return result
}

// certOwner deterministically assigns a domain to one of the alive peers.
// The assignment is stable across all peers in the fleet as long as they
// agree on the alive set (same sorted IDs) — which they will when network
// partitions aren't in play.
//
// Hash: FNV-1a 64-bit — fast, well-distributed, stdlib, deterministic.
func certOwner(domain string, alivePeers []string) string {
	if len(alivePeers) == 0 {
		return ""
	}
	h := fnv.New64a()
	h.Write([]byte(domain))
	return alivePeers[h.Sum64()%uint64(len(alivePeers))]
}

// pullCertFromPeer fetches the cert+key for a domain from the owner peer
// and writes them to disk in the standard LE layout so HAProxy packaging
// and local LE status checks work normally. Also packages for HAProxy.
func (s *Server) pullCertFromPeer(domain, ownerID string, cfg *config.Config) error {
	// Find the owner's WGAddr.
	var wgAddr string
	for _, p := range cfg.Peers {
		if p.ID == ownerID {
			wgAddr = p.WGAddr
			break
		}
	}
	if wgAddr == "" {
		return fmt.Errorf("peer %q not found in config", ownerID)
	}

	url := buildPeerURL(wgAddr, "/api/peer/cert/"+domain)
	body, err := fetchPeerBody(url)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}

	var resp PeerCertResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if resp.Cert == "" || resp.Key == "" {
		return fmt.Errorf("empty cert or key in response")
	}

	// Write to the standard LE cert dir layout.
	baseDomain := strings.TrimPrefix(domain, "*.")
	certDir := fmt.Sprintf("%s/live/%s", cfg.SSLCertDir, baseDomain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(certDir+"/fullchain.pem", []byte(resp.Cert), 0600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(certDir+"/privkey.pem", []byte(resp.Key), 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	// Package for HAProxy so the pulled cert is immediately usable.
	if cfg.SSLHAProxyCertDir != "" {
		if err := os.MkdirAll(cfg.SSLHAProxyCertDir, 0700); err != nil {
			return fmt.Errorf("mkdir haproxy: %w", err)
		}
		combined := resp.Cert + resp.Key
		outPath := fmt.Sprintf("%s/%s.pem", cfg.SSLHAProxyCertDir, baseDomain)
		if err := os.WriteFile(outPath, []byte(combined), 0600); err != nil {
			return fmt.Errorf("write haproxy cert: %w", err)
		}
	}

	slog.Info("cert-renewal: pulled cert from peer", "domain", domain, "owner", ownerID)
	return nil
}

var peerHTTPClient = &http.Client{Timeout: 5 * time.Second}

func fetchPeerPing(url string) (*PeerPingResponse, error) {
	resp, err := peerHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var p PeerPingResponse
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func fetchPeerBody(url string) ([]byte, error) {
	resp, err := peerHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// fetchPeerConfig performs a conditional GET of the primary's config.
// ifNoneMatch is the caller's current shared revision; when the primary still
// serves that revision it responds 304 (notModified=true, empty body) and the
// pull becomes a no-op. rev is the primary's current revision taken from the
// ETag — empty when talking to an older primary that does not send one, in
// which case the caller computes the digest from the body instead.
func fetchPeerConfig(url, ifNoneMatch string) (body []byte, rev string, notModified bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, err
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", `"`+ifNoneMatch+`"`)
	}
	resp, err := peerHTTPClient.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	rev = strings.Trim(strings.TrimSpace(resp.Header.Get("ETag")), `"`)
	if resp.StatusCode == http.StatusNotModified {
		return nil, rev, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, rev, false, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err = io.ReadAll(resp.Body)
	return body, rev, false, err
}

func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
