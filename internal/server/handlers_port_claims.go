package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/iodesystems/homelab-horizon/internal/apitypes"
	"github.com/iodesystems/homelab-horizon/internal/config"
	"github.com/iodesystems/homelab-horizon/internal/portclaims"
	"github.com/iodesystems/homelab-horizon/internal/portscan"
)

// claimScanTimeout bounds the connect scan a mint performs while somebody
// waits on the CLI. Same budget the read-only observed endpoint uses.
const claimScanTimeout = 25 * time.Second

// claimMaxCount caps one contiguous lease. A 256-port ask is a subnet-sized
// mistake; bigger asks belong in the custom exclusion list or a config edit.
const claimMaxCount = 256

// POST /api/v1/ports/claims — atomically mint a short-lived port claim.
//
// This is the endpoint that turns `hz ports next` from read-scan-print
// (which hands the same answer to two concurrent callers) into a lease: the
// candidate is chosen and persisted under the claim store's lock, avoiding
// config-derived occupancy, built-in and custom exclusions, what is actually
// listening, and every other unexpired claim on the same host/proto.
//
// Scope is the hz INSTANCE, like install grants and vantage registrations:
// the lease file sits beside the config, not in it, so it is not
// peer-synced or captured by backups. The formal occupancy it defers to is
// shared fleet config; only two CLI callers minting against different HA
// peers inside one TTL window could overlap.
//
// Any failure — validation, scan failure, client disconnect, save failure —
// answers with an error and mints nothing. The client is built to treat the
// absence of a claim response as "print no port".
func (s *Server) handleAPIPortClaim(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if s.portClaims == nil {
		// Fail closed: a server whose claim store never opened must not let
		// the CLI mistake an unchecked suggestion for an exclusive one.
		writeJSONError(w, http.StatusServiceUnavailable, "port claim store unavailable")
		return
	}

	var req apitypes.PortClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}
	if net.ParseIP(req.Host) == nil {
		writeJSONError(w, http.StatusBadRequest, "host must be an IP address")
		return
	}
	proto := req.Proto
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" {
		// The only observation hz can do from another box is a TCP connect.
		// A UDP claim would be an unverifiable promise, which is exactly
		// what this endpoint exists not to make.
		writeJSONError(w, http.StatusBadRequest, "only proto=tcp claims are supported")
		return
	}
	count := req.Count
	if count == 0 {
		count = 1
	}
	if count < 1 || count > claimMaxCount {
		writeJSONError(w, http.StatusBadRequest, "count must be between 1 and "+strconv.Itoa(claimMaxCount))
		return
	}
	from := req.From
	if from == 0 {
		from = 20000
	}
	if from < 1 || from > 65535 {
		writeJSONError(w, http.StatusBadRequest, "from must be between 1 and 65535")
		return
	}
	ttl := portclaims.DefaultTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl < portclaims.MinTTL || ttl > portclaims.MaxTTL {
		writeJSONError(w, http.StatusBadRequest,
			"ttl_seconds must be between "+strconv.Itoa(int(portclaims.MinTTL.Seconds()))+
				" and "+strconv.Itoa(int(portclaims.MaxTTL.Seconds())))
		return
	}
	if len(req.Note) > 200 {
		writeJSONError(w, http.StatusBadRequest, "note must be at most 200 characters")
		return
	}

	cfg := s.cfg()
	allocReq := portclaims.AllocRequest{
		Host:     req.Host,
		Proto:    proto,
		From:     from,
		Count:    count,
		TTL:      ttl,
		Note:     req.Note,
		Formal:   formalOccupiedPorts(cfg, req.Host, proto),
		Excluded: cfg.PortExcluded,
		Observe: func(ctx context.Context, base, to int) ([]int, error) {
			// Re-derived per candidate so a retry never exceeds MaxPorts;
			// the ranges here are at most claimMaxCount wide.
			open := portscan.Observe(ctx, req.Host, portscan.Range(base, to))
			return portscan.Sorted(open), nil
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), claimScanTimeout)
	defer cancel()

	claim, err := s.portClaims.Allocate(ctx, allocReq)
	if err != nil {
		switch {
		case errors.Is(err, portclaims.ErrNoFreeRange):
			writeJSONError(w, http.StatusConflict,
				"no free "+strconv.Itoa(count)+"-port range >= "+strconv.Itoa(from)+
					" below 65536 on "+req.Host+" (formal occupancy, exclusions, claims and listeners all checked)")
		case errors.Is(err, portclaims.ErrScanFailed):
			writeJSONError(w, http.StatusBadGateway,
				"could not verify the candidate against "+req.Host+": "+err.Error()+
					"; no claim was made and no port should be treated as exclusive")
		case errors.Is(err, portclaims.ErrCapacity):
			writeJSONError(w, http.StatusTooManyRequests, err.Error()+"; retry after claims expire or are released")
		default:
			writeJSONError(w, http.StatusInternalServerError,
				"failed to persist port claim; no claim was made: "+err.Error())
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(claimToAPI(*claim, true))
}

// POST /api/v1/ports/claims/release — return a leased range before expiry.
// Idempotent: an id that has already expired/been reaped reports released
// false; a wrong credential is 403 so a caller that lost its token is told
// to wait for expiry instead of hammering guesses.
func (s *Server) handleAPIPortClaimRelease(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if s.portClaims == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "port claim store unavailable")
		return
	}
	var req apitypes.PortClaimReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}
	if req.ID == "" || req.Token == "" {
		writeJSONError(w, http.StatusBadRequest, "id and token are required")
		return
	}
	released, err := s.portClaims.Release(req.ID, req.Token)
	if err != nil {
		if errors.Is(err, portclaims.ErrWrongToken) {
			writeJSONError(w, http.StatusForbidden, "token does not match claim "+req.ID)
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "release not persisted; claim retained: "+err.Error())
		return
	}
	writeJSON(w, apitypes.PortClaimReleaseResponse{OK: true, Released: released})
}

// formalOccupiedPorts is the config-derived set allocation must skip on host
// for proto. It mirrors the semantics the CLI's usedPorts always had:
//
//   - tcp allocation skips tcp/empty-proto reservations AND every layer-4
//     forward, whatever that forward's protocol is (QUIC-style services pair
//     a UDP and TCP listener on one number);
//   - udp allocation skips udp reservations and the same forwards.
func formalOccupiedPorts(cfg *config.Config, host, proto string) map[int]bool {
	used := map[int]bool{}
	for _, e := range cfg.DeriveHostPortMap().Hosts[host] {
		if e.Forward {
			// forwards block allocation for every protocol
		} else if e.Proto != proto {
			continue
		}
		if p, err := strconv.Atoi(e.Port); err == nil {
			used[p] = true
		}
	}
	return used
}

// claimToAPI maps a stored claim to the wire shape. includeToken must be true
// only for the single mint response.
func claimToAPI(c portclaims.Claim, includeToken bool) apitypes.PortClaimResp {
	resp := apitypes.PortClaimResp{
		ID:        c.ID,
		Host:      c.Host,
		Proto:     c.Proto,
		From:      c.From,
		To:        c.To,
		Note:      c.Note,
		CreatedAt: c.CreatedAt.Unix(),
		ExpiresAt: c.ExpiresAt.Unix(),
	}
	if includeToken {
		resp.Token = c.Token
	}
	return resp
}

// activeClaimAPIs returns the wire form of every live claim, token-free.
func (s *Server) activeClaimAPIs() []apitypes.PortClaimResp {
	if s.portClaims == nil {
		return nil
	}
	active := s.portClaims.Active()
	out := make([]apitypes.PortClaimResp, 0, len(active))
	for _, c := range active {
		out = append(out, claimToAPI(c, false))
	}
	return out
}

// reapPortClaims removes claims shadowed by formal config occupancy
// (takeover) along with expired ones, persisting the result. Called on
// startup and after every config swap so an adopted range never leaves a
// ghost lease behind. A save failure is logged: the next reap retries, and
// reads filter expired claims regardless.
func (s *Server) reapPortClaims() {
	if s.portClaims == nil {
		return
	}
	n, err := s.portClaims.Reap(func(host, proto string) map[int]bool {
		return formalOccupiedPorts(s.cfg(), host, proto)
	})
	if err != nil {
		slog.Error("port claims: takeover reap failed", "err", err)
		return
	}
	if n > 0 {
		slog.Info("port claims: reaped adopted/expired claims", "count", n)
	}
}

// startPortClaimJanitor periodically sweeps expired claims to disk. Largely
// cosmetic — every read filters expiry — but it keeps the persisted file
// bounded across a long-running process that never mints again.
func (s *Server) startPortClaimJanitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if s.portClaims == nil {
			return
		}
		if n, err := s.portClaims.Sweep(); err != nil {
			slog.Error("port claims: expiry sweep failed", "err", err)
		} else if n > 0 {
			slog.Info("port claims: expired claims swept", "count", n)
		}
	}
}
