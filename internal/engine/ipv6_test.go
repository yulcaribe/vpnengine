package engine

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yulcaribe/vpnengine/internal/core"
)

func TestIPv6AddressAndValidation(t *testing.T) {
	for _, tt := range []struct {
		offset uint64
		want   string
	}{{1, "fd66:66::1"}, {255, "fd66:66::ff"}, {math.MaxUint64, "fd66:66::ffff:ffff:ffff:ffff"}} {
		got, err := IPv6Address("fd66:66::/64", tt.offset)
		if err != nil || got != tt.want {
			t.Fatalf("offset %d: got %q, %v; want %q", tt.offset, got, err, tt.want)
		}
	}
	for _, cidr := range []string{"fd66:66::1/64", "fd66:66::/48", "2001:db8::/64", "::/64", "10.66.66.0/24", "::ffff:10.66.66.0/120"} {
		if _, err := IPv6Address(cidr, 2); err == nil {
			t.Fatalf("accepted invalid IPv6 pool %q", cidr)
		}
	}
	legacy := core.Service{ID: core.WireGuard}
	if err := ValidateIPv6(legacy, nil); err != nil {
		t.Fatalf("legacy IPv4 configuration rejected: %v", err)
	}
	s := core.Service{ID: core.WireGuard, IPv6: true, IPv6CIDR: "fd66:66::/64", IPv6Interface: "eth0"}
	if err := ValidateIPv6(s, nil); err != nil {
		t.Fatal(err)
	}
	other := core.Service{ID: core.OpenVPN, Installed: true, IPv6: true, IPv6CIDR: s.IPv6CIDR}
	if err := ValidateIPv6(s, map[string]core.Service{other.ID: other}); err == nil {
		t.Fatal("accepted overlapping active IPv6 pools")
	}
	other.IPv6 = false
	if err := ValidateIPv6(s, map[string]core.Service{other.ID: other}); err != nil {
		t.Fatalf("disabled IPv6 pool should not collide: %v", err)
	}
	s.IPv6Interface = "eth0;false"
	if err := ValidateIPv6(s, nil); err == nil {
		t.Fatal("accepted invalid IPv6 interface")
	}
}

func TestWireGuardIPv6ProfilesPreserveKeysAndAddresses(t *testing.T) {
	s := core.Service{ID: core.WireGuard, Port: 123, CIDR: "10.66.66.0/24", IPv6: true, IPv6CIDR: "fd66:66::/64", DNS: "1.1.1.1", Endpoint: "vpn.example.com"}
	u := core.User{Name: "alice", Service: core.WireGuard, Enabled: true, Address: "10.66.66.42", PrivateKey: "existing-private-key", PublicKey: "existing-public-key"}
	conf, err := wgConfigWithKey(s, []core.User{u}, "existing-server-private-key")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Address = 10.66.66.1/24, fd66:66::1/64", "ListenPort = 123", "PrivateKey = existing-server-private-key", "PublicKey = existing-public-key", "AllowedIPs = 10.66.66.42/32, fd66:66::2a/128"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("server config missing %q: %s", want, conf)
		}
	}
	profile, err := wgProfileWithKey(s, u, "existing-server-public-key")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PrivateKey = existing-private-key", "Address = 10.66.66.42/32, fd66:66::2a/128", "Endpoint = vpn.example.com:123", "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25"} {
		if !strings.Contains(profile, want) {
			t.Fatalf("profile missing %q: %s", want, profile)
		}
	}
	// Older databases contain neither the toggle nor the IPv6 prefix. New
	// profiles still capture IPv6; the server does not permit these packets.
	s.IPv6, s.IPv6CIDR = false, ""
	conf, err = wgConfigWithKey(s, []core.User{u}, "existing-server-private-key")
	if err != nil || strings.Contains(conf, "fd66") || !strings.Contains(conf, "AllowedIPs = 10.66.66.42/32\n") {
		t.Fatalf("IPv4-only server config changed: %s, %v", conf, err)
	}
	profile, err = wgProfileWithKey(s, u, "existing-server-public-key")
	if err != nil || !strings.Contains(profile, "::/0") || !strings.Contains(profile, "IPv6 internet is disabled") {
		t.Fatalf("missing IPv6 sink route or explanation: %s, %v", profile, err)
	}
	if u.IPv6Address != "" || u.Address != "10.66.66.42" || u.PrivateKey != "existing-private-key" {
		t.Fatal("profile export mutated a legacy user's credentials")
	}
}

func TestWireGuardIPv6RejectsReservedAndDuplicateAddresses(t *testing.T) {
	s := core.Service{ID: core.WireGuard, CIDR: "10.66.66.0/24", IPv6: true, IPv6CIDR: "fd66:66::/64"}
	u := core.User{Name: "alice", Service: core.WireGuard, Enabled: true, Address: "10.66.66.2", PublicKey: "public-key"}
	for _, address := range []string{"fd66:66::", "fd66:66::1", "fd67:67::2", "10.66.66.2"} {
		u.IPv6Address = address
		if _, err := wireGuardUserIPv6(s, u); err == nil {
			t.Fatalf("accepted invalid client address %q", address)
		}
	}
	u.IPv6Address = "fd66:66::2"
	other := u
	other.Name, other.Address = "bob", "10.66.66.3"
	if _, err := wgConfigWithKey(s, []core.User{u, other}, "server-key"); err == nil {
		t.Fatal("accepted duplicate IPv6 peer addresses")
	}
	other.Enabled = false
	if _, err := wgConfigWithKey(s, []core.User{u, other}, "server-key"); err != nil {
		t.Fatalf("disabled peer interfered with enabled peer: %v", err)
	}
}

func TestNewWireGuardUserKeepsIPv4Allocation(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in\ngenkey) printf '%s\\n' 'test-private-key';;\npubkey) cat >/dev/null; printf '%s\\n' 'test-public-key';;\n*) exit 1;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "wg"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := core.Service{ID: core.WireGuard, CIDR: "10.66.66.0/24", IPv6CIDR: "fd66:66::/64"}
	users := []core.User{{Service: core.WireGuard, Address: "10.66.66.2"}, {Service: core.WireGuard, Address: "10.66.66.3", Enabled: false}}
	u, err := NewWireGuardUser("alice", users, s)
	if err != nil || u.Address != "10.66.66.4" || u.IPv6Address != "fd66:66::4" || u.PrivateKey != "test-private-key" {
		t.Fatalf("got %#v, %v", u, err)
	}
}

func TestWireGuardSyncFailureKeepsRevocation(t *testing.T) {
	for _, tt := range []struct {
		name, want string
		rollback   bool
		running    bool
		calls      int
	}{
		{"revocation remains saved", "revoked config", false, true, 1},
		{"ordinary update rolls back", "old config", true, true, 2},
		{"stopped service updates safely", "revoked config", false, false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vpnwg0.conf")
			if err := os.WriteFile(path, []byte("old config"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			sync := func() error {
				calls++
				if calls == 1 {
					return errors.New("live update failed")
				}
				return nil
			}
			err := applyWireGuardConfig(path, []byte("revoked config"), tt.running, tt.rollback, sync)
			if (err != nil) != tt.running {
				t.Fatalf("unexpected sync result: %v", err)
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil || string(data) != tt.want || calls != tt.calls {
				t.Fatalf("saved config %q, sync calls %d, error %v", data, calls, readErr)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("WireGuard keys were not saved with private permissions")
			}
		})
	}
}

func TestIPv6AvailabilityRequiresAddressRouteAndVerifiedProbe(t *testing.T) {
	for _, tt := range []struct {
		name, route, address, response string
		probeErr                       bool
		want                           bool
	}{
		{name: "usable", route: "default via fe80::1 dev ens3 proto ra", address: "2: ens3 inet6 2001:db8::2/64 scope global dynamic", response: "2001:db8::2\n", want: true},
		{name: "no route", address: "2: ens3 inet6 2001:db8::2/64 scope global", response: "2001:db8::2"},
		{name: "ULA only", route: "default dev ens3", address: "2: ens3 inet6 fd66:66::2/64 scope global", response: "2001:db8::2"},
		{name: "tentative", route: "default dev ens3", address: "2: ens3 inet6 2001:db8::2/64 scope global tentative", response: "2001:db8::2"},
		{name: "probe failed", route: "default dev ens3", address: "2: ens3 inet6 2001:db8::2/64 scope global", probeErr: true},
		{name: "proxy IPv4", route: "default dev ens3", address: "2: ens3 inet6 2001:db8::2/64 scope global", response: "198.51.100.2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			d := ipv6Detector{run: func(ctx context.Context, command string, args ...string) ([]byte, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 6*time.Second {
					t.Fatal("unbounded IPv6 probe")
				}
				if command == "curl" {
					want := []string{"-6", "--noproxy", "*", "-fsS", "--max-time", "4", "https://api64.ipify.org"}
					if !reflect.DeepEqual(args, want) {
						t.Fatalf("unexpected HTTPS probe arguments: %v", args)
					}
					if tt.probeErr {
						return nil, errors.New("TLS or connection failure")
					}
					return []byte(tt.response), nil
				}
				if reflect.DeepEqual(args, []string{"-6", "route", "show", "default"}) {
					return []byte(tt.route), nil
				}
				return []byte(tt.address), nil
			}}
			now := time.Now()
			if got := d.availableAt(context.Background(), now); got != tt.want {
				t.Fatalf("IPv6Available = %v, want %v", got, tt.want)
			}
			before := calls
			d.availableAt(context.Background(), now.Add(30*time.Second))
			if calls != before {
				t.Fatal("IPv6 availability was not cached")
			}
			d.availableAt(context.Background(), now.Add(61*time.Second))
			if calls == before {
				t.Fatal("stale IPv6 availability was not rechecked")
			}
		})
	}
}

func TestIPv6RulesRestrictForwardingAndUseIPv6Egress(t *testing.T) {
	for _, id := range []string{core.WireGuard, core.OpenVPN, core.IKEv2} {
		s := core.Service{ID: id, IPv6: true, IPv6CIDR: "fd66:66::/64", Interface: "ipv4-out", IPv6Interface: "ipv6-out"}
		rules := ipv6Rules(s)
		if len(rules) != 3 || rules[2].table != "nat" {
			t.Fatalf("missing NAT66 rules for %s", id)
		}
		outbound, inbound, nat := strings.Join(rules[0].args, " "), strings.Join(rules[1].args, " "), strings.Join(rules[2].args, " ")
		if !strings.Contains(outbound, "-s fd66:66::/64") || !strings.Contains(outbound, "-o ipv6-out") || !strings.Contains(outbound, "NEW,ESTABLISHED,RELATED") {
			t.Fatalf("unsafe outbound rule: %s", outbound)
		}
		if !strings.Contains(inbound, "-d fd66:66::/64") || !strings.Contains(inbound, "--ctstate ESTABLISHED,RELATED") || strings.Contains(inbound, "NEW,") {
			t.Fatalf("unsafe inbound rule: %s", inbound)
		}
		if !strings.Contains(nat, "-s fd66:66::/64 -o ipv6-out") || !strings.HasSuffix(nat, "-j MASQUERADE") || strings.Contains(nat, "ipv4-out") {
			t.Fatalf("incorrect NAT66 rule: %s", nat)
		}
		if id == core.IKEv2 && (!strings.Contains(outbound, "--dir in --pol ipsec") || !strings.Contains(inbound, "--dir out --pol ipsec")) {
			t.Fatal("IPsec forwarding accepted pool addresses without a policy")
		}
	}
}

func TestFirewallRulesAreIdempotentAndRemovable(t *testing.T) {
	for _, tt := range []struct {
		name       string
		present    bool
		add        bool
		wantChange string
	}{{"add absent", false, true, "-A"}, {"add present", true, true, ""}, {"delete present", true, false, "-D"}, {"delete absent", false, false, ""}} {
		t.Run(tt.name, func(t *testing.T) {
			var calls [][]string
			run := func(_ context.Context, binary string, args ...string) error {
				if binary != ip6tablesBinary {
					t.Fatalf("unexpected firewall binary: %s", binary)
				}
				calls = append(calls, append([]string(nil), args...))
				if len(calls) == 1 && !tt.present {
					return firewallExitError(1)
				}
				return nil
			}
			args := []string{"POSTROUTING", "-s", "fd66:66::/64", "-j", "MASQUERADE"}
			if err := firewallRule(context.Background(), run, ip6tablesBinary, "nat", tt.add, args); err != nil {
				t.Fatal(err)
			}
			want := [][]string{append([]string{"-w", "-t", "nat", "-C"}, args...)}
			if tt.wantChange != "" {
				want = append(want, append([]string{"-w", "-t", "nat", tt.wantChange}, args...))
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("got firewall calls %v; want %v", calls, want)
			}
		})
	}
}

type firewallExitError int

func (e firewallExitError) Error() string { return "firewall command failed" }
func (e firewallExitError) ExitCode() int { return int(e) }

func TestFirewallInspectionFailureIsNotReportedAsCleanup(t *testing.T) {
	for _, inspectionErr := range []error{firewallExitError(2), errors.New("binary not found")} {
		calls := 0
		run := func(context.Context, string, ...string) error {
			calls++
			return inspectionErr
		}
		if err := firewallRule(context.Background(), run, ip6tablesBinary, "nat", false, []string{"POSTROUTING"}); err == nil || calls != 1 {
			t.Fatalf("failed inspection was accepted as successful cleanup: error %v, calls %d", err, calls)
		}
	}
}

func TestIPv4FirewallInspectionErrorsRemainErrors(t *testing.T) {
	for _, add := range []bool{true, false} {
		calls := 0
		run := func(_ context.Context, binary string, _ ...string) error {
			calls++
			if binary != iptablesBinary {
				t.Fatalf("unexpected binary %s", binary)
			}
			return firewallExitError(4)
		}
		if err := firewallRule(context.Background(), run, iptablesBinary, "", add, []string{"FORWARD"}); err == nil || calls != 1 {
			t.Fatalf("inspection failure reported success: %v, calls %d", err, calls)
		}
	}
}

func TestNetworkCleanupAttemptsBothFamiliesAfterIndividualFailure(t *testing.T) {
	s := Defaults(core.WireGuard)
	s.Interface, s.Endpoint, s.IPv6Interface, s.IPv6 = "eth0", "vpn.example.com", "eth1", true
	var commands []string
	run := func(_ context.Context, binary string, args ...string) error {
		line := binary + " " + strings.Join(args, " ")
		commands = append(commands, line)
		if len(commands) == 1 {
			return firewallExitError(4)
		}
		return nil
	}
	if err := applyNetService(context.Background(), s, false, run); err == nil {
		t.Fatal("network cleanup failure was hidden")
	}
	for _, want := range []string{iptablesBinary + " -w -t nat -D POSTROUTING", ip6tablesBinary + " -w -D FORWARD", ip6tablesBinary + " -w -t nat -D POSTROUTING"} {
		found := false
		for _, command := range commands {
			if strings.HasPrefix(command, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("cleanup skipped %q after an earlier failure: %v", want, commands)
		}
	}
}

func TestPendingNetworkCleanupKeepsIPv6EgressAndOldRuleVariants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard.cleanup.json")
	s := Defaults(core.WireGuard)
	s.Interface, s.Endpoint, s.IPv6, s.IPv6Interface = "eth0", "vpn.example.com", true, "eth1"
	old := s
	old.IPv6, old.IPv6Interface = false, ""
	if err := saveNetCleanups(path, []core.Service{s, old, s}); err != nil {
		t.Fatal(err)
	}
	saved, err := readNetCleanups(path, core.WireGuard)
	if err != nil || len(saved) != 2 || saved[0].IPv6Interface != "eth1" || saved[1].IPv6 {
		t.Fatalf("cleanup metadata lost: %#v, %v", saved, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("cleanup metadata is not private")
	}
	if _, err := readNetCleanups(path, core.OpenVPN); err == nil {
		t.Fatal("accepted cleanup metadata for a different service")
	}
	if err := saveNetCleanups(path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("completed cleanup marker was not removed")
	}
}

func TestIPv6RuntimeRollbackPreservesHostForwardingAndOverrides(t *testing.T) {
	root := t.TempDir()
	original := map[string]string{}
	for _, fixture := range []struct{ device, forwarding, ra string }{{"all", "1", "0"}, {"default", "0", "1"}, {"eth0", "0", "2"}, {"eth1", "1", "0"}} {
		if err := os.Mkdir(filepath.Join(root, fixture.device), 0700); err != nil {
			t.Fatal(err)
		}
		for setting, value := range map[string]string{"forwarding": fixture.forwarding, "accept_ra": fixture.ra} {
			if err := os.WriteFile(filepath.Join(root, fixture.device, setting), []byte(value+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			original["net/ipv6/conf/"+fixture.device+"/"+setting] = value
		}
	}
	values, err := snapshotIPv6Runtime(root)
	if err != nil {
		t.Fatal(err)
	}
	// Model the side effect of enabling all.forwarding: every interface flag
	// changes even if it previously had its own override.
	live := map[string]string{}
	for key := range original {
		live[key] = "1"
	}
	run := func(_ context.Context, command string, args ...string) error {
		if command != "sysctl" || len(args) < 3 || args[0] != "-w" || args[1] != "net/ipv6/conf/all/forwarding=1" || args[2] != "net/ipv6/conf/default/forwarding=0" {
			t.Fatalf("runtime restore lost prior host forwarding or global-first order: %v", args)
		}
		for _, arg := range args[1:] {
			key, value, found := strings.Cut(arg, "=")
			if !found {
				t.Fatalf("invalid restore argument: %s", arg)
			}
			if key == "net/ipv6/conf/all/forwarding" {
				for existing := range live {
					if strings.HasSuffix(existing, "/forwarding") {
						live[existing] = value
					}
				}
			}
			live[key] = value
		}
		return nil
	}
	if err := restoreIPv6Runtime(context.Background(), values, run); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(live, original) {
		t.Fatalf("runtime rollback failed to restore per-interface settings: got %v, want %v", live, original)
	}
	if err := restoreIPv6Runtime(context.Background(), values, func(context.Context, string, ...string) error { return errors.New("sysctl failed") }); err == nil {
		t.Fatal("runtime rollback failure was hidden")
	}
	if err := os.WriteFile(filepath.Join(root, "eth0", "forwarding"), []byte("9\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotIPv6Runtime(root); err == nil {
		t.Fatal("accepted an invalid runtime snapshot")
	}
}
