package engine

import (
	"net/netip"
	"testing"

	"github.com/yulcaribe/vpnengine/internal/core"
)

func TestHostSubnetConflicts(t *testing.T) {
	s := Defaults(core.WireGuard)
	s.IPv6 = true
	for _, tc := range []struct {
		name, device, prefix string
		conflict             bool
	}{
		{"docker supernet", "docker0", "10.0.0.0/8", true},
		{"LAN subnet", "eth1", "10.66.66.128/25", true},
		{"own tunnel", "vpnwg0", "10.66.66.0/24", false},
		{"default route", "eth0", "0.0.0.0/0", false},
		{"unrelated network", "eth1", "192.168.0.0/24", false},
		{"IPv6 overlap", "eth1", "fd66:66::/48", true},
		{"IPv6 default", "eth0", "::/0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkHostPrefixes(s, []hostPrefix{{tc.device, netip.MustParsePrefix(tc.prefix)}})
			if (err != nil) != tc.conflict {
				t.Fatalf("conflict=%v, error=%v", tc.conflict, err)
			}
		})
	}
	s.IPv6 = false
	if err := checkHostPrefixes(s, []hostPrefix{{"eth0", netip.MustParsePrefix("fd66:66::/64")}}); err != nil {
		t.Fatal("disabled IPv6 must not reject unrelated host IPv6 settings:", err)
	}
}
