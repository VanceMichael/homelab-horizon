package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iodesystems/homelab-horizon/internal/apitypes"
)

func sleep1s() { time.Sleep(time.Second) }

const (
	// safeBandLow is the default lowest port allocation considers — well above
	// the crowded 0–9999 range where databases and dev tools cluster.
	safeBandLow = 20000
	// safeBandHigh is the top of the preferred band, kept below the typical
	// Linux ephemeral range (32768+) so fixed backends don't collide with
	// outbound connections' source ports.
	safeBandHigh = 32767
)

// commonPorts are well-known service/dev ports allocation always skips — even
// if --from drops into their range — so a horizon backend never lands on a port
// a database or dev tool expects to own.
var commonPorts = map[int]bool{
	// classic / system
	21: true, 22: true, 23: true, 25: true, 53: true, 80: true, 110: true,
	123: true, 143: true, 161: true, 389: true, 443: true, 465: true,
	587: true, 636: true, 993: true, 995: true, 3389: true, 5900: true,
	// databases
	1433: true, 1521: true, 3306: true, 5432: true, 5433: true, 6379: true,
	6380: true, 8086: true, 9042: true, 11211: true, 5984: true,
	27017: true, 27018: true, 27019: true,
	// search / analytics
	9200: true, 9300: true, 7700: true, 5601: true,
	// messaging / streaming
	1883: true, 2181: true, 4222: true, 6222: true, 8222: true, 5672: true,
	15672: true, 9092: true, 61616: true,
	// web / app dev servers
	3000: true, 3001: true, 4200: true, 5000: true, 5173: true, 8000: true,
	8008: true, 8080: true, 8081: true, 8443: true, 8888: true, 4040: true,
	// infra / orchestration / observability
	2375: true, 2376: true, 2379: true, 2380: true, 3100: true, 6443: true,
	8200: true, 8300: true, 8301: true, 8500: true, 8600: true, 9000: true,
	9090: true, 9091: true, 9093: true, 10250: true,
}

// commonRanges are contiguous bands dev tooling likes to spin things up in;
// allocation skips them entirely.
var commonRanges = [][2]int{
	{3000, 3010},
	{4000, 4010},
	{5000, 5010},
	{8000, 8099},
	{9000, 9099},
}

func isCommonPort(p int) bool {
	if commonPorts[p] {
		return true
	}
	for _, rg := range commonRanges {
		if p >= rg[0] && p <= rg[1] {
			return true
		}
	}
	return false
}

// runPorts reports port allocation on a host using the server's authoritative
// port map (service backends, blue-green deploy next-backends, HAProxy,
// WireGuard, dnsmasq, admin server) plus its short-lived claim store.
//
// `ports next` mints an atomic, durable server-side claim: two concurrent
// callers get disjoint ranges and the lease survives a server restart until
// it expires, is released, or is reaped once config adopts the range.
func runPorts(c *client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hz ports <next|list|release> --host IP [--count N] [--from PORT]")
	}
	switch args[0] {
	case "next":
		return runPortsNext(c, args[1:])
	case "list":
		return runPortsList(c, args[1:])
	case "release":
		return runPortsRelease(c, args[1:])
	default:
		return fmt.Errorf("usage: hz ports <next|list|release> --host IP [--count N] [--from PORT]")
	}
}

func runPortsNext(c *client, args []string) error {
	fs := flag.NewFlagSet("ports next", flag.ContinueOnError)
	host := fs.String("host", "", "host IP to allocate on (required)")
	count := fs.Int("count", 1, "size of the contiguous range")
	from := fs.Int("from", safeBandLow, "lowest port to consider")
	ttl := fs.Duration("ttl", 10*time.Minute, "how long the claim holds (30s..1h); adopted ranges are reaped on config save")
	note := fs.String("note", "", "optional label recorded with the claim")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return fmt.Errorf("--host is required")
	}
	if *count < 1 {
		return fmt.Errorf("--count must be >= 1")
	}

	// The server does the whole read-scan-claim transaction atomically and
	// returns the lease credential. There is deliberately no local fallback:
	// printing a locally-guessed port against a server that cannot claim it
	// would hand two callers the same "exclusive" answer.
	var claim apitypes.PortClaimResp
	req := apitypes.PortClaimRequest{
		Host:       *host,
		Proto:      "tcp",
		Count:      *count,
		From:       *from,
		TTLSeconds: int(ttl.Seconds()),
		Note:       *note,
	}
	err := c.do("POST", "/api/v1/ports/claims", req, &claim)
	if err != nil {
		if se, ok := err.(*apiStatusError); ok && (se.Code == 404 || se.Code == 405) {
			return fmt.Errorf("this hz server does not support atomic port claims (no /api/v1/ports/claims); " +
				"upgrade the server — refusing to print an unchecked port that would look exclusive")
		}
		return err
	}
	if claim.ID == "" || claim.ExpiresAt == 0 {
		return fmt.Errorf("server returned no claim; not printing a port")
	}

	// Stdout stays machine-readable exactly as before — the bare port, or
	// the bare range. Everything a human wants goes to stderr so existing
	// scripts (`PORT=$(hz ports next --host …)`) keep working.
	if claim.From == claim.To {
		fmt.Println(claim.From)
	} else {
		fmt.Printf("%d-%d\n", claim.From, claim.To)
	}
	exp := time.Unix(claim.ExpiresAt, 0).Format("15:04:05")
	fmt.Fprintf(os.Stderr, "hz: CLAIMED %d-%d/%s on %s until %s (id %s)\n",
		claim.From, claim.To, claim.Proto, claim.Host, exp, claim.ID)
	fmt.Fprintf(os.Stderr, "hz: release early with: hz ports release --id %s --token %s\n",
		claim.ID, claim.Token)
	return nil
}

// runPortsRelease returns a leased range before its TTL. Idempotent: an
// already-gone claim reports so and exits zero. The credential is what a
// caller received on stderr from `ports next`; an operator who lost it waits
// for expiry (at most an hour).
func runPortsRelease(c *client, args []string) error {
	fs := flag.NewFlagSet("ports release", flag.ContinueOnError)
	id := fs.String("id", "", "claim id returned by 'ports next' (required)")
	token := fs.String("token", "", "claim token returned by 'ports next' (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *token == "" {
		return fmt.Errorf("--id and --token are required")
	}
	var out apitypes.PortClaimReleaseResponse
	if err := c.do("POST", "/api/v1/ports/claims/release",
		apitypes.PortClaimReleaseRequest{ID: *id, Token: *token}, &out); err != nil {
		return err
	}
	if out.Released {
		fmt.Printf("released claim %s\n", *id)
	} else {
		fmt.Printf("claim %s already gone (expired, released, or adopted into config)\n", *id)
	}
	return nil
}

func runPortsList(c *client, args []string) error {
	fs := flag.NewFlagSet("ports list", flag.ContinueOnError)
	host := fs.String("host", "", "host IP to list ports for (required)")
	count := fs.Int("count", 5, "how many suggested free ports to show")
	from := fs.Int("from", safeBandLow, "lowest port to suggest from")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return fmt.Errorf("--host is required")
	}

	pm, err := fetchPortMap(c)
	if err != nil {
		return err
	}

	entries := append([]apitypes.HostPortEntry(nil), pm.Hosts[*host]...)
	sort.Slice(entries, func(i, j int) bool {
		return portNum(entries[i].Port) < portNum(entries[j].Port)
	})

	fmt.Printf("FORMAL RESERVATIONS on %s (%d)\n", *host, len(entries))
	if len(entries) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, e := range entries {
			label := e.Service
			if e.Domain != "" {
				label += "  " + e.Domain
			}
			fmt.Printf("  %-6s %-4s %s\n", e.Port, e.Proto, label)
		}
	}

	// Temporary claims: leases minted by `ports next`, distinct from formal
	// reservations. They expire on their own clock, can be released with
	// their credential, and disappear once config adopts the range.
	var hostClaims []apitypes.PortClaimResp
	for _, cl := range pm.Claims {
		if cl.Host != *host {
			continue
		}
		hostClaims = append(hostClaims, cl)
	}
	sort.Slice(hostClaims, func(i, j int) bool { return hostClaims[i].From < hostClaims[j].From })
	fmt.Printf("\nTEMPORARY CLAIMS on %s (%d) — short-lived leases from 'hz ports next'\n", *host, len(hostClaims))
	if len(hostClaims) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, cl := range hostClaims {
			span := strconv.Itoa(cl.From)
			if cl.To > cl.From {
				span = fmt.Sprintf("%d-%d", cl.From, cl.To)
			}
			note := ""
			if cl.Note != "" {
				note = "  " + cl.Note
			}
			fmt.Printf("  %-10s %-4s until %s  %s%s\n",
				span, cl.Proto, time.Unix(cl.ExpiresAt, 0).Format("15:04:05"), cl.ID, note)
		}
	}

	if len(pm.Exclusions.Custom) > 0 {
		fmt.Printf("\nCUSTOM EXCLUSIONS (%d) — edit in the Ports UI\n", len(pm.Exclusions.Custom))
		for _, r := range pm.Exclusions.Custom {
			span := strconv.Itoa(r.From)
			if r.To > r.From {
				span = fmt.Sprintf("%d-%d", r.From, r.To)
			}
			note := ""
			if r.Note != "" {
				note = "  " + r.Note
			}
			fmt.Printf("  %s%s\n", span, note)
		}
	}

	// What the host is running that hz has no record of. This is the gap that
	// made the allocator wrong: hz knew 14 ports on this host and the host was
	// listening on more, so "free" meant "free as far as hz knows".
	if obs, err := observedUnreserved(c, *host, *from, *from+255); err != nil {
		fmt.Printf("\nLISTENING BUT UNREGISTERED: could not check (%v)\n", err)
	} else if len(obs) > 0 {
		fmt.Printf("\nLISTENING BUT UNREGISTERED in %d–%d (%d)\n", *from, *from+255, len(obs))
		for _, p := range obs {
			fmt.Printf("  %-6d tcp  (something is on this port; hz has no record of it)\n", p)
		}
		fmt.Println("  These are skipped when suggesting/minting ports, but hz cannot say what they are.")
	}

	// Suggestions remain a pure, read-only view — they create no claim. They
	// do skip live claims, so an advisory glance never points at a range
	// another caller is currently holding.
	free := suggestFree(blockedPorts(pm, *host), *from, *count, excludedFunc(pm))
	fmt.Printf("\nSUGGESTED FREE (safe band %d–%d, reservations + claims + common/excluded ports skipped; no claim created)\n",
		safeBandLow, safeBandHigh)
	if len(free) == 0 {
		fmt.Println("  (none available)")
		return nil
	}
	strs := make([]string, len(free))
	for i, p := range free {
		strs[i] = strconv.Itoa(p)
	}
	fmt.Printf("  %s\n", strings.Join(strs, "  "))
	return nil
}

func fetchPortMap(c *client) (apitypes.HostPortMapResponse, error) {
	var pm apitypes.HostPortMapResponse
	err := c.do("GET", "/api/v1/ports", nil, &pm)
	return pm, err
}

// observedUnreserved is what is listening that hz has no record of — the
// read-only probe backing the 'ports list' section. It mints nothing.
func observedUnreserved(c *client, host string, from, to int) ([]int, error) {
	var out apitypes.ObservedPortsResp
	path := fmt.Sprintf("/api/v1/ports/observed?host=%s&from=%d&to=%d", url.QueryEscape(host), from, to)
	if err := c.do("GET", path, nil, &out); err != nil {
		return nil, err
	}
	return out.Unreserved, nil
}

func portNum(s string) int {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 1 << 30 // sort unparseable ports last
	}
	return p
}

// usedPorts is the set of ports allocation must skip on the host: every TCP
// reservation, plus every port-forward reservation whatever its protocol.
//
// Other UDP reservations (WireGuard, dnsmasq) don't block a TCP backend. A
// forward's port does: allocation does not know which protocol the new service
// will speak, and the services forwards exist for (QUIC, WebTransport) commonly
// pair a UDP and a TCP listener on one number.
func usedPorts(pm apitypes.HostPortMapResponse, host string) map[int]bool {
	used := map[int]bool{}
	for _, e := range pm.Hosts[host] {
		if e.Proto != "" && e.Proto != "tcp" && !e.Forward {
			continue
		}
		if p, err := strconv.Atoi(e.Port); err == nil {
			used[p] = true
		}
	}
	return used
}

// blockedPorts is what the read-only 'list' suggestions must skip on a host:
// formal reservations (usedPorts) plus every unexpired claim on that host.
// Claims on OTHER hosts are ignored.
func blockedPorts(pm apitypes.HostPortMapResponse, host string) map[int]bool {
	blocked := usedPorts(pm, host)
	for _, cl := range pm.Claims {
		if cl.Host != host {
			continue
		}
		if cl.Proto != "" && cl.Proto != "tcp" {
			continue
		}
		for p := cl.From; p <= cl.To; p++ {
			blocked[p] = true
		}
	}
	return blocked
}

// excludedFunc builds the port-denylist predicate from the server-provided
// exclusions (builtin + custom). Falls back to the CLI's hardcoded common-port
// list only when an older server returns no exclusions.
func excludedFunc(pm apitypes.HostPortMapResponse) func(int) bool {
	ranges := append(append([]apitypes.PortRange{}, pm.Exclusions.Builtin...), pm.Exclusions.Custom...)
	if len(ranges) == 0 {
		return isCommonPort
	}
	return func(p int) bool {
		for _, r := range ranges {
			hi := r.To
			if hi < r.From {
				hi = r.From
			}
			if p >= r.From && p <= hi {
				return true
			}
		}
		return false
	}
}

// suggestFree returns up to count free ports at or above from (never below the
// safe band), skipping used and excluded ports.
func suggestFree(used map[int]bool, from, count int, excluded func(int) bool) []int {
	if from < safeBandLow {
		from = safeBandLow
	}
	var out []int
	for p := from; p <= 65535 && len(out) < count; p++ {
		if used[p] || excluded(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}
