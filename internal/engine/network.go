package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/yulcaribe/vpnengine/internal/core"
)

func saveNetService(s core.Service) error {
	if s.IPv6 {
		s.IPv6Interface = IPv6DefaultInterface(context.Background())
		if s.IPv6Interface == "" {
			return fmt.Errorf("no IPv6 default route is available")
		}
	}
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return write0600(filepath.Join(DataDir, "services", s.ID+".json"), b)
}
func netService(id string) (core.Service, error) {
	var s core.Service
	if !core.IsService(id) {
		return s, fmt.Errorf("invalid service")
	}
	b, e := os.ReadFile(filepath.Join(DataDir, "services", id+".json"))
	if e != nil {
		return s, e
	}
	e = json.Unmarshal(b, &s)
	return s, e
}
func enableForward(ctx context.Context) error {
	if err := write0600("/etc/sysctl.d/99-vpn-engine.conf", []byte("net.ipv4.ip_forward=1\n")); err != nil {
		return err
	}
	return quiet(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1")
}

func enableIPv6Forward(ctx context.Context, s core.Service) error {
	if !s.IPv6 {
		return nil
	}
	if err := ValidateIPv6(s, nil); err != nil {
		return err
	}
	iface := IPv6DefaultInterface(ctx)
	if iface == "" {
		return fmt.Errorf("no IPv6 default route is available")
	}
	// Forwarding normally stops Linux from accepting router advertisements.
	// Keep them on the public interface so hosts using SLAAC retain their route.
	settings := []string{"net/ipv6/conf/" + iface + "/accept_ra=2", "net.ipv6.conf.all.forwarding=1", "net.ipv6.conf.default.forwarding=1"}
	data := "# Managed by VPN Engine; preserve the host's IPv6 router advertisements.\n"
	for _, setting := range settings {
		data += setting + "\n"
	}
	if err := write0600(filepath.Join("/etc/sysctl.d", "99-vpn-engine-ipv6-"+s.ID+".conf"), []byte(data)); err != nil {
		return err
	}
	return quiet(ctx, "sysctl", append([]string{"-w"}, settings...)...)
}

const iptablesBinary = "/usr/sbin/iptables"
const ip6tablesBinary = "/usr/sbin/ip6tables"

type firewallCommand func(context.Context, string, ...string) error

func firewallRule(ctx context.Context, run firewallCommand, binary, table string, add bool, args []string) error {
	prefix := []string{"-w"}
	if table != "" {
		prefix = append(prefix, "-t", table)
	}
	check := append(append([]string(nil), prefix...), "-C")
	checkErr := run(ctx, binary, append(check, args...)...)
	present := checkErr == nil
	if checkErr != nil {
		var exitErr interface{ ExitCode() int }
		if !errors.As(checkErr, &exitErr) || exitErr.ExitCode() != 1 {
			return fmt.Errorf("%s rule inspection failed: %w", binary, checkErr)
		}
	}
	if add && present || !add && !present {
		return nil
	}
	mode := "-A"
	if !add {
		mode = "-D"
	}
	cmd := append(append(append([]string(nil), prefix...), mode), args...)
	if err := run(ctx, binary, cmd...); err != nil {
		return fmt.Errorf("%s rule update: %w", binary, err)
	}
	return nil
}

type ipv6Rule struct {
	table string
	args  []string
}

func ipv6Rules(s core.Service) []ipv6Rule {
	comment := []string{"-m", "comment", "--comment", "VPN-ENGINE-" + s.ID, "-j", "ACCEPT"}
	var outbound, inbound []string
	if s.ID == core.IKEv2 {
		// Require an actual IPsec policy; matching a spoofed pool address alone
		// must not grant access to forwarding rules.
		outbound = []string{"FORWARD", "-s", s.IPv6CIDR, "-o", s.IPv6Interface, "-m", "policy", "--dir", "in", "--pol", "ipsec"}
		inbound = []string{"FORWARD", "-d", s.IPv6CIDR, "-i", s.IPv6Interface, "-m", "policy", "--dir", "out", "--pol", "ipsec"}
	} else {
		iface := InterfaceFor(s.ID)
		outbound = []string{"FORWARD", "-i", iface, "-s", s.IPv6CIDR, "-o", s.IPv6Interface}
		inbound = []string{"FORWARD", "-o", iface, "-d", s.IPv6CIDR, "-i", s.IPv6Interface}
	}
	outbound = append(outbound, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED")
	inbound = append(inbound, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED")
	return []ipv6Rule{
		{args: append(outbound, comment...)},
		{args: append(inbound, comment...)},
		{table: "nat", args: []string{"POSTROUTING", "-s", s.IPv6CIDR, "-o", s.IPv6Interface, "-m", "comment", "--comment", "VPN-ENGINE-" + s.ID, "-j", "MASQUERADE"}},
	}
}

func netIPv6(ctx context.Context, s core.Service, up bool) error {
	return applyIPv6Rules(ctx, s, up, quiet)
}

func applyIPv6Rules(ctx context.Context, s core.Service, up bool, run firewallCommand) error {
	if !s.IPv6 {
		return nil
	}
	if s.IPv6Interface == "" {
		s.IPv6Interface = IPv6DefaultInterface(ctx)
	}
	if s.IPv6Interface == "" {
		return fmt.Errorf("no saved IPv6 outgoing interface is available")
	}
	if err := ValidateIPv6(s, nil); err != nil {
		return err
	}
	var failures []error
	for _, rule := range ipv6Rules(s) {
		if err := firewallRule(ctx, run, ip6tablesBinary, rule.table, up, rule.args); err != nil {
			if up {
				return err
			}
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func iptables(ctx context.Context, add bool, args []string) error {
	return firewallRule(ctx, quiet, iptablesBinary, "", add, args)
}
func iptablesNAT(ctx context.Context, add bool, args []string) error {
	return firewallRule(ctx, quiet, iptablesBinary, "nat", add, args)
}
func (Manager) Net(ctx context.Context, id string, up bool) error {
	if !core.IsService(id) {
		return fmt.Errorf("invalid service")
	}
	cleanupPath := filepath.Join(DataDir, "services", id+".cleanup.json")
	pending, err := readNetCleanups(cleanupPath, id)
	if err != nil {
		return err
	}
	var pendingFailures []error
	var remaining []core.Service
	for _, s := range pending {
		if err := applyNetService(ctx, s, false, quiet); err != nil {
			pendingFailures = append(pendingFailures, err)
			remaining = append(remaining, s)
		}
	}
	var currentErr error
	s, err := netService(id)
	if err != nil {
		if up || !os.IsNotExist(err) {
			currentErr = err
		}
	} else if s.ID != id {
		currentErr = fmt.Errorf("bad saved service")
	} else if err := applyNetService(ctx, s, up, quiet); err != nil {
		currentErr = err
		remaining = append(remaining, s)
	}
	// Keep a small root-private copy of any rules that could not be removed.
	// This survives restoring the old service JSON and is retried by net hooks.
	var metadataErr error
	if err := saveNetCleanups(cleanupPath, remaining); err != nil {
		metadataErr = fmt.Errorf("save pending network cleanup: %w", err)
	}
	if up && currentErr == nil {
		// A wg-quick PostUp failure deletes the interface. A stale cleanup
		// warning must not prevent restoring the working IPv4 configuration.
		for _, err := range pendingFailures {
			log.Printf("VPN Engine: pending network cleanup for %s remains: %v", id, err)
		}
		return metadataErr
	}
	return errors.Join(currentErr, errors.Join(pendingFailures...), metadataErr)
}

func applyNetService(ctx context.Context, s core.Service, up bool, run firewallCommand) error {
	if err := Validate(s, nil); err != nil {
		return err
	}
	var rules [][]string
	comment := []string{"-m", "comment", "--comment", "VPN-ENGINE-" + s.ID, "-j", "ACCEPT"}
	if s.ID == core.IKEv2 {
		rules = [][]string{append([]string{"FORWARD", "-s", s.CIDR}, comment...), append([]string{"FORWARD", "-d", s.CIDR}, comment...)}
	} else {
		iface := InterfaceFor(s.ID)
		rules = [][]string{append([]string{"FORWARD", "-i", iface}, comment...), append([]string{"FORWARD", "-o", iface}, comment...)}
	}
	var failures []error
	for _, r := range rules {
		if err := firewallRule(ctx, run, iptablesBinary, "", up, r); err != nil {
			if up {
				return err
			}
			failures = append(failures, err)
		}
	}
	if err := firewallRule(ctx, run, iptablesBinary, "nat", up, []string{"POSTROUTING", "-s", s.CIDR, "-o", s.Interface, "-m", "comment", "--comment", "VPN-ENGINE-" + s.ID, "-j", "MASQUERADE"}); err != nil {
		if up {
			return err
		}
		failures = append(failures, err)
	}
	failures = append(failures, applyIPv6Rules(ctx, s, up, run))
	return errors.Join(failures...)
}

func readNetCleanups(path, id string) ([]core.Service, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var services []core.Service
	if err := json.Unmarshal(data, &services); err != nil {
		return nil, fmt.Errorf("invalid pending network cleanup: %w", err)
	}
	for _, s := range services {
		if s.ID != id {
			return nil, fmt.Errorf("bad saved network cleanup service")
		}
		if err := Validate(s, nil); err != nil {
			return nil, err
		}
	}
	return services, nil
}

func saveNetCleanups(path string, services []core.Service) error {
	var unique []core.Service
	for _, s := range services {
		found := false
		for _, previous := range unique {
			if s.ID == previous.ID && s.CIDR == previous.CIDR && s.Interface == previous.Interface && s.IPv6 == previous.IPv6 && s.IPv6CIDR == previous.IPv6CIDR && s.IPv6Interface == previous.IPv6Interface {
				found = true
				break
			}
		}
		if !found {
			unique = append(unique, s)
		}
	}
	if len(unique) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(unique)
	if err != nil {
		return err
	}
	return write0600(path, data)
}
