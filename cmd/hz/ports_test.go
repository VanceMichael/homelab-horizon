package main

import (
	"reflect"
	"testing"

	"github.com/iodesystems/homelab-horizon/internal/apitypes"
)

func TestIsCommonPort(t *testing.T) {
	common := []int{80, 443, 22, 3306, 5432, 6379, 4222, 27017, 9200, 5672,
		8080, 8000, 8443, 9090, 8500, 3000, 5000, // explicit
		8050, 8099, 3005, 5010, 9042, 9099} // range members / db
	for _, p := range common {
		if !isCommonPort(p) {
			t.Errorf("isCommonPort(%d) = false, want true", p)
		}
	}
	safe := []int{20000, 20001, 21000, 25000, 30000, 32767, 19999, 11000}
	for _, p := range safe {
		if isCommonPort(p) {
			t.Errorf("isCommonPort(%d) = true, want false", p)
		}
	}
}

func TestSuggestFree(t *testing.T) {
	used := map[int]bool{20000: true, 20001: true}
	got := suggestFree(used, 20000, 3, isCommonPort)
	want := []int{20002, 20003, 20004}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("suggestFree = %v, want %v", got, want)
	}
	// from below the safe band is clamped up to safeBandLow.
	if got := suggestFree(map[int]bool{}, 500, 1, isCommonPort); len(got) != 1 || got[0] != safeBandLow {
		t.Errorf("suggestFree(from=500) = %v, want [%d]", got, safeBandLow)
	}
}

func TestUsedTCPExcludesUDP(t *testing.T) {
	pm := apitypes.HostPortMapResponse{Hosts: map[string][]apitypes.HostPortEntry{
		"h": {
			{Port: "8080", Proto: "tcp", Service: "a"},
			{Port: "53", Proto: "udp", Service: "dnsmasq"},
			{Port: "51820", Proto: "udp", Service: "wireguard"},
			{Port: "9000", Proto: "", Service: "legacy-empty-proto"}, // treated as tcp
		},
	}}
	used := usedPorts(pm, "h")
	if !used[8080] || !used[9000] {
		t.Errorf("expected tcp/empty-proto ports marked used: %v", used)
	}
	if used[53] || used[51820] {
		t.Errorf("udp ports must not block tcp allocation: %v", used)
	}
}

func TestBlockedPortsIncludesClaimsOnSameHostOnly(t *testing.T) {
	pm := apitypes.HostPortMapResponse{
		Hosts: map[string][]apitypes.HostPortEntry{
			"h": {{Port: "21000", Proto: "tcp", Service: "svc"}},
		},
		Claims: []apitypes.PortClaimResp{
			{ID: "pc_a", Host: "h", Proto: "tcp", From: 22000, To: 22002},
			{ID: "pc_b", Host: "other", Proto: "tcp", From: 23000, To: 23000},
		},
	}
	blocked := blockedPorts(pm, "h")
	if !blocked[21000] {
		t.Error("formal reservation missing from blocked set")
	}
	for _, p := range []int{22000, 22001, 22002} {
		if !blocked[p] {
			t.Errorf("claimed port %d must block suggestions", p)
		}
	}
	if blocked[23000] {
		t.Error("a claim on another host must not block this host's suggestions")
	}
}
