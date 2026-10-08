// Package portclaims holds the server-side, short-lived port claims minted by
// `hz ports next`.
//
// Before claims existed, "find a free port" was read-config, scan-host,
// print. Two callers running that sequence concurrently both got the same
// answer, and nothing marked the port as taken if neither caller used the
// advice. A claim turns one successful suggestion into an ATOMIC, durable
// lease: under the store's lock the caller's candidate is checked against
// every other source of occupancy (that check lives in the server handler)
// and is persisted before it is ever returned, so concurrent callers are
// handed disjoint ranges and a process restart keeps the leases that have
// not expired.
//
// Durability contract, deliberately small:
//
//   - A claim is written to disk (temp file + rename) BEFORE it enters the
//     live map and BEFORE the HTTP response is sent. A failed save therefore
//     leaves no claim behind and the client prints nothing.
//   - Release and reaping write the new state first; on save failure nothing
//     is mutated, so retrying is always safe.
//   - If the client is gone by the time the response would leave hz, the
//     claim is already on disk but nobody holds its token — expiry is the
//     recovery path, which is why TTLs are short.
//   - On load, an unparseable file is quarantined (never silently merged)
//     and the store starts empty; an empty answer is the failure mode that
//     cannot hand out a port twice.
//
// The store knows nothing about config derivation or connect scans. The
// server builds those occupancy sets and asks the store the questions.
package portclaims

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/iodesystems/homelab-horizon/internal/system"
)

const (
	// DefaultTTL is what a plain `hz ports next` gets. Long enough to paste
	// the result into a service definition and deploy it; the adopted range
	// is reaped on the config save, so a normal flow never runs the clock
	// out. Short enough that a client which died holding the answer frees
	// the ports quickly.
	DefaultTTL = 10 * time.Minute
	// MinTTL bounds how fast a caller can churn; MaxTTL bounds how long a
	// range can be hidden from every other allocator.
	MinTTL = 30 * time.Second
	MaxTTL = time.Hour

	// MaxActiveClaims is a backstop against a stuck script, not attacker
	// rationing: minting is admin-only.
	MaxActiveClaims = 256

	idPrefix    = "pc_"
	idBytes     = 8
	tokenBytes  = 16
	fileVersion = 1
)

// ErrNotFound is a release for an id that is not live (already expired,
// released, or adopted). Release treats it as an idempotent success.
var ErrNotFound = errors.New("port claim not found")

// ErrWrongToken means the id was right but the credential was not. It is a
// distinct failure from ErrNotFound so a caller that lost its token is told
// to wait for expiry instead of being fed a misleading 404.
var ErrWrongToken = errors.New("port claim token does not match")

// ErrCapacity means the live-claim backstop was reached. Nothing was
// persisted and the caller should retry after claims expire or are released.
var ErrCapacity = errors.New("too many active port claims")

// ErrNoFreeRange means no candidate below 65535 survived the configured
// occupancy, exclusions, sibling claims and live scans within the attempt
// budget.
var ErrNoFreeRange = errors.New("no free port range")

// ErrScanFailed means the listening check did not settle — typically the
// request deadline or a disconnected client. No claim is minted: a failed
// observation must never be presented as an exclusive answer.
var ErrScanFailed = errors.New("listening check failed")

// maxScanAttempts bounds how many rejected candidates one mint walks past.
// Mirrors the CLI's old twenty-candidate budget.
const maxScanAttempts = 20

// AllocRequest are the mint parameters plus the host-knowledge the store
// itself does not have. All callbacks run while the store lock is held, so
// they must not call back into the store.
type AllocRequest struct {
	Host  string
	Proto string
	// From is the lowest port to consider; Count the contiguous span size.
	From  int
	Count int
	TTL   time.Duration
	Note  string

	// Formal is the config-derived occupancy on Host for Proto (TCP
	// reservations plus every forward; the server builds it exactly the way
	// the CLI's usedPorts did). Not mutated.
	Formal map[int]bool
	// Excluded is the built-in + custom denylist predicate.
	Excluded func(p int) bool
	// Observe reports which ports in [from,to] are actually listening. A
	// non-nil error aborts the mint without a claim — including ctx
	// cancellation, which is how a client hanging up before the answer is a
	// failure rather than a silent claim.
	Observe func(ctx context.Context, from, to int) (open []int, err error)
}

// Allocation is a minted claim.
type Allocation = Claim

// Claim is one leased port span on one host for one protocol. Token is the
// secret credential returned exactly once, in the create response; listings
// never include it.
type Claim struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Host      string    `json:"host"`
	Proto     string    `json:"proto"`
	From      int       `json:"from"`
	To        int       `json:"to"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Live reports whether the claim is unexpired at now.
func (c *Claim) Live(now time.Time) bool {
	return now.Before(c.ExpiresAt)
}

// shape is the on-disk format. Versioned so a future change can refuse an
// older binary rather than silently dropping fields it does not know.
type shape struct {
	Version int     `json:"version"`
	Claims  []Claim `json:"claims"`
}

// Store is the durable set of claims. Its single mutex serializes every
// mutation, including the host scans the server performs while minting:
// that is what makes two concurrent `ports next` calls disjoint rather than
// merely racy.
type Store struct {
	fs   system.FileSystem
	path string

	mu   sync.Mutex
	live map[string]*Claim
	now  func() time.Time
}

// Open loads the store from path, creating an empty one when the file does
// not exist. A corrupt or wrong-version file is moved aside (never merged)
// and the store starts empty — losing advisory leases is safe, inventing
// them is not.
func Open(fs system.FileSystem, path string) (*Store, error) {
	s := &Store{
		fs:   fs,
		path: path,
		live: map[string]*Claim{},
		now:  time.Now,
	}

	data, err := fs.ReadFile(path)
	switch {
	case err == nil:
		var sh shape
		if jerr := json.Unmarshal(data, &sh); jerr != nil || sh.Version != fileVersion {
			quarantine := fmt.Sprintf("%s.corrupt-%d", path, s.now().UnixNano())
			if rerr := fs.Rename(path, quarantine); rerr != nil {
				if jerr != nil {
					return nil, fmt.Errorf("loading port claims (unreadable file and quarantine failed): %w", jerr)
				}
				return nil, fmt.Errorf("loading port claims: unsupported file version and quarantine failed: %w", rerr)
			}
			return s, nil
		}
		now := s.now()
		for i := range sh.Claims {
			c := sh.Claims[i]
			if !c.Live(now) {
				continue
			}
			s.live[c.ID] = &c
		}
	case errors.Is(err, os.ErrNotExist):
		// empty store, first run
	default:
		return nil, fmt.Errorf("loading port claims: %w", err)
	}
	return s, nil
}

// SetNow overrides the clock. Tests only.
func (s *Store) SetNow(fn func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = fn
}

// Allocate runs the whole mint under one lock acquisition: derive the
// blocked set (formal occupancy + exclusions + sibling claims), propose the
// lowest contiguous range, have it checked against what is actually
// listening, retry past conflicts, then persist the claim BEFORE it is
// returned. Two concurrent Allocate calls therefore serialize here and can
// never be handed the same range.
//
// The scan runs while the lock is held on purpose: releasing it "to be
// polite" would reopen the exact race the claim exists to close. Mints are
// admin-driven and take seconds at most.
//
// Failure modes never mint: ErrNoFreeRange, ErrScanFailed, ErrCapacity and
// any persistence error.
func (s *Store) Allocate(ctx context.Context, req AllocRequest) (*Claim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)

	if len(s.live) >= MaxActiveClaims {
		return nil, ErrCapacity
	}

	// Local copy: listener conflicts accumulate into it across attempts and
	// must not mutate the caller's formal set.
	blocked := make(map[int]bool, len(req.Formal)+16)
	for p := range req.Formal {
		blocked[p] = true
	}
	for _, c := range s.live {
		if !c.Live(now) || c.Host != req.Host || c.Proto != req.Proto {
			continue
		}
		for p := c.From; p <= c.To; p++ {
			blocked[p] = true
		}
	}

	from := req.From
	if from < 1 {
		from = 1
	}
	for attempt := 0; attempt < maxScanAttempts; attempt++ {
		base := findFreeRange(blocked, from, req.Count, req.Excluded)
		if base == 0 {
			return nil, ErrNoFreeRange
		}
		to := base + req.Count - 1

		open, err := req.Observe(ctx, base, to)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrScanFailed, err)
		}
		if ctx.Err() != nil {
			// The client (or the 25s budget) went away mid-scan. A partial
			// answer about what is listening cannot be trusted, so this must
			// not become a claim.
			return nil, fmt.Errorf("%w: %v", ErrScanFailed, ctx.Err())
		}
		if len(open) > 0 {
			sort.Ints(open)
			for _, p := range open {
				blocked[p] = true
			}
			from = open[0] + 1 // resume past the first conflict
			continue
		}

		id, err := randomID()
		if err != nil {
			return nil, err
		}
		token, err := randomToken()
		if err != nil {
			return nil, err
		}
		c := &Claim{
			ID:        id,
			Token:     token,
			Host:      req.Host,
			Proto:     req.Proto,
			From:      base,
			To:        to,
			Note:      req.Note,
			CreatedAt: now,
			ExpiresAt: now.Add(req.TTL),
		}
		// Persist BEFORE the claim becomes visible. If this fails there is
		// no in-memory ghost and no response claiming exclusivity.
		if err := s.appendPersistLocked(c); err != nil {
			return nil, err
		}
		s.live[c.ID] = c
		cp := *c
		return &cp, nil
	}
	return nil, fmt.Errorf("%w: gave up after %d candidates", ErrNoFreeRange, maxScanAttempts)
}

// findFreeRange returns the lowest base >= from where [base, base+count) is
// outside both the blocked set and the excluded predicate. 0 means nothing
// fit below 65535.
func findFreeRange(blocked map[int]bool, from, count int, excluded func(int) bool) int {
	for base := from; base+count-1 <= 65535; base++ {
		free := true
		for p := base; p < base+count; p++ {
			if blocked[p] || excluded(p) {
				free = false
				base = p // hop past the conflict
				break
			}
		}
		if free {
			return base
		}
	}
	return 0
}

// Release deletes a claim given its credential. Idempotent: an unknown id
// (already expired, released, or adopted by config) reports (false, nil). A
// wrong token for a live id is ErrWrongToken. On save failure the claim is
// retained and the error is returned, so the caller may retry.
func (s *Store) Release(id, token string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.live[id]
	if !ok || !c.Live(s.now()) {
		return false, nil
	}
	if subtle.ConstantTimeCompare([]byte(c.Token), []byte(token)) != 1 {
		return false, ErrWrongToken
	}
	if err := s.withoutPersistLocked(id); err != nil {
		return false, err
	}
	delete(s.live, id)
	return true, nil
}

// ClaimedPorts returns every port currently leased on host for proto.
//
// A forward reservation blocks allocation regardless of protocol, and the
// caller models that by also asking for the other proto. Claims do not have
// a "both protocols" kind today, so callers that need forward semantics pass
// each proto in turn; proto=="" means "claims of every protocol" for that
// purpose.
func (s *Store) ClaimedPorts(host, proto string) map[int]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := map[int]bool{}
	for _, c := range s.live {
		if !c.Live(now) || c.Host != host {
			continue
		}
		if proto != "" && c.Proto != proto {
			continue
		}
		for p := c.From; p <= c.To; p++ {
			out[p] = true
		}
	}
	return out
}

// Active returns a sorted snapshot of live claims (expired entries are
// filtered without rewriting the file — a GET must not cause writes). The
// Token field is blanked: listings land in terminals, logs and screenshots.
func (s *Store) Active() []Claim {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]Claim, 0, len(s.live))
	for _, c := range s.live {
		if !c.Live(now) {
			continue
		}
		cp := *c
		cp.Token = ""
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].From < out[j].From
	})
	return out
}

// Sweep removes expired claims and persists when anything changed. Used by
// the background janitor and at startup; failure leaves the live set intact
// (the claims are filtered everywhere on read anyway) and is returned so the
// ticker can log and try again.
func (s *Store) Sweep() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(s.now())
}

// Reap removes claims that shadow real, configured occupancy — the takeover
// path: once the adopted range exists in config the lease has served its
// purpose and must not linger as a ghost listing. Any overlap reaps the
// whole claim: a lease that intersects formal usage can no longer promise
// the contiguous span it granted.
//
// occupied builds the formally-reserved port set for a host/proto (the
// server derives it from config). It is evaluated lazily, once per distinct
// (host,proto) pair present in claims.
func (s *Store) Reap(occupied func(host, proto string) map[int]bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	sets := map[string]map[int]bool{}
	occ := func(host, proto string) map[int]bool {
		key := host + "/" + proto
		if set, ok := sets[key]; ok {
			return set
		}
		set := occupied(host, proto)
		sets[key] = set
		return set
	}

	var doomed []string
	for _, c := range s.live {
		if !c.Live(now) {
			doomed = append(doomed, c.ID)
			continue
		}
		for p := c.From; p <= c.To; p++ {
			if occ(c.Host, c.Proto)[p] {
				doomed = append(doomed, c.ID)
				break
			}
		}
	}
	if len(doomed) == 0 {
		return 0, nil
	}
	if err := s.withoutPersistLocked(doomed...); err != nil {
		return 0, err
	}
	for _, id := range doomed {
		delete(s.live, id)
	}
	return len(doomed), nil
}

// expireLocked drops expired entries in memory without persisting. Cheap and
// write-free, so read paths and Create can call it.
func (s *Store) expireLocked(now time.Time) {
	for id, c := range s.live {
		if !c.Live(now) {
			delete(s.live, id)
		}
	}
}

func (s *Store) sweepLocked(now time.Time) (int, error) {
	var stale []string
	for id, c := range s.live {
		if !c.Live(now) {
			stale = append(stale, id)
		}
	}
	if len(stale) == 0 {
		return 0, nil
	}
	if err := s.withoutPersistLocked(stale...); err != nil {
		return 0, err
	}
	for _, id := range stale {
		delete(s.live, id)
	}
	return len(stale), nil
}

// appendPersistLocked writes a file that additionally contains c. Used by
// Create so the new claim is durable before it is visible.
func (s *Store) appendPersistLocked(c *Claim) error {
	claims := make([]Claim, 0, len(s.live)+1)
	for _, ex := range s.live {
		claims = append(claims, *ex)
	}
	claims = append(claims, *c)
	return s.writeLocked(claims)
}

// withoutPersistLocked writes a file that omits the given ids. The live map
// is mutated by the caller only after this succeeds.
func (s *Store) withoutPersistLocked(ids ...string) error {
	drop := make(map[string]bool, len(ids))
	for _, id := range ids {
		drop[id] = true
	}
	claims := make([]Claim, 0, len(s.live))
	for id, c := range s.live {
		if !drop[id] {
			claims = append(claims, *c)
		}
	}
	return s.writeLocked(claims)
}

// writeLocked is the only writer. Temp file + rename gives crash atomicity:
// a crash lands on either the old file or the new one, never a torn merge.
func (s *Store) writeLocked(claims []Claim) error {
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].Host != claims[j].Host {
			return claims[i].Host < claims[j].Host
		}
		if claims[i].Proto != claims[j].Proto {
			return claims[i].Proto < claims[j].Proto
		}
		return claims[i].From < claims[j].From
	})
	data, err := json.MarshalIndent(shape{Version: fileVersion, Claims: claims}, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.path); dir != "." && dir != "" {
		if err := s.fs.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := s.fs.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return s.fs.Rename(tmp, s.path)
}

func randomID() (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return idPrefix + hex.EncodeToString(b), nil
}

func randomToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
