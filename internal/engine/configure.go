package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/yulcaribe/vpnengine/internal/core"
)

type hostPrefix struct {
	device string
	prefix netip.Prefix
}

func checkHostPrefixes(s core.Service, prefixes []hostPrefix) error {
	for _, configured := range []string{s.CIDR, s.IPv6CIDR} {
		p, err := netip.ParsePrefix(configured)
		if err != nil || (p.Addr().Is6() && !s.IPv6) {
			continue
		}
		for _, existing := range prefixes {
			if existing.device == InterfaceFor(s.ID) || existing.prefix.Bits() == 0 {
				continue
			}
			if p.Overlaps(existing.prefix) {
				return fmt.Errorf("VPN subnet %s overlaps %s on %s; choose a different subnet", p, existing.prefix, existing.device)
			}
		}
	}
	return nil
}

func checkHostNetwork(s core.Service) error {
	if _, err := net.InterfaceByName(s.Interface); err != nil {
		return fmt.Errorf("outgoing interface %q was not found; check the interface name", s.Interface)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("check network interfaces: %w", err)
	}
	var prefixes []hostPrefix
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("check addresses on %s: %w", iface.Name, err)
		}
		for _, addr := range addresses {
			if p, err := netip.ParsePrefix(addr.String()); err == nil {
				prefixes = append(prefixes, hostPrefix{iface.Name, p.Masked()})
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, family := range []string{"-4", "-6"} {
		if family == "-6" && !s.IPv6 {
			continue
		}
		data, err := exec.CommandContext(ctx, "ip", "-j", family, "route", "show", "table", "all").Output()
		if err != nil {
			return fmt.Errorf("check %s routes: %w", family, err)
		}
		var routes []struct {
			Destination string `json:"dst"`
			Device      string `json:"dev"`
		}
		if err := json.Unmarshal(data, &routes); err != nil {
			return fmt.Errorf("read %s routes: %w", family, err)
		}
		for _, route := range routes {
			if p, err := netip.ParsePrefix(route.Destination); err == nil {
				prefixes = append(prefixes, hostPrefix{route.Device, p.Masked()})
			}
		}
	}
	return checkHostPrefixes(s, prefixes)
}

func serviceConfig(s core.Service, users []core.User) ([]byte, error) {
	switch s.ID {
	case core.WireGuard:
		conf, err := wgConfig(s, users)
		return []byte(conf), err
	case core.OpenVPN:
		return []byte(ovpnConfig(s, PKIPaths(s.ID))), nil
	case core.IKEv2:
		return []byte(swanctlConfig(s, users)), nil
	default:
		return nil, errors.New("unsupported VPN service")
	}
}

// ConfigureIPv6 changes only the managed protocol. Keys, accounts and its IPv4
// subnet are retained; existing IPv4 installations stay unchanged until selected.
func (m Manager) ConfigureIPv6(ctx context.Context, previous core.Service, enabled bool, users []core.User, log Log, save func(core.Service) error) (updated core.Service, err error) {
	updated = previous
	if previous.IPv6 == enabled {
		return updated, nil
	}
	updated.IPv6 = enabled
	if updated.IPv6CIDR == "" {
		updated.IPv6CIDR = Defaults(updated.ID).IPv6CIDR
	}
	if !enabled {
		updated.IPv6Interface = ""
	}
	if err = Validate(updated, nil); err != nil {
		return previous, err
	}
	if updated.ID == core.OpenVPN && !enabled {
		if err = CheckOpenVPNIPv6Sink(ctx); err != nil {
			return previous, err
		}
	}
	if enabled && !IPv6Available(ctx) {
		return previous, errors.New("IPv6 Internet access is unavailable on this server")
	}
	if enabled {
		check := updated
		check.CIDR = "" // Its already-installed IPv4 subnet must remain unchanged.
		if err = checkHostNetwork(check); err != nil {
			return previous, err
		}
	}
	if !ServiceInstalled(updated.ID) {
		return previous, errors.New("service is not installed")
	}
	oldConfig, err := os.ReadFile(configPath(updated.ID))
	if err != nil {
		return previous, err
	}
	netPath := filepath.Join(DataDir, "services", updated.ID+".json")
	oldNet, err := os.ReadFile(netPath)
	if err != nil {
		return previous, err
	}
	newConfig, err := serviceConfig(updated, users)
	if err != nil {
		return previous, err
	}
	running := Status(updated.ID) == "running"
	sysctlPath := filepath.Join("/etc/sysctl.d", "99-vpn-engine-ipv6-"+updated.ID+".conf")
	oldSysctl, sysctlErr := os.ReadFile(sysctlPath)
	if sysctlErr != nil && !os.IsNotExist(sysctlErr) {
		return previous, sysctlErr
	}
	var liveSysctls []ipv6RuntimeValue
	if enabled {
		liveSysctls, err = snapshotIPv6Runtime("/proc/sys/net/ipv6/conf")
		if err != nil {
			return previous, err
		}
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		recovery, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		restoreErr := errors.Join(m.Net(recovery, updated.ID, false), write0600(configPath(updated.ID), oldConfig), write0600(netPath, oldNet))
		if sysctlErr == nil {
			restoreErr = errors.Join(restoreErr, write0600(sysctlPath, oldSysctl))
		} else if removeErr := os.Remove(sysctlPath); removeErr != nil && !os.IsNotExist(removeErr) {
			restoreErr = errors.Join(restoreErr, removeErr)
		}
		if running {
			if previous.ID == core.IKEv2 {
				restoreErr = errors.Join(restoreErr, m.SyncIKEv2(recovery, previous, users))
			} else {
				restoreErr = errors.Join(restoreErr, quiet(recovery, "systemctl", "restart", SystemdUnit(previous.ID)))
			}
			restoreErr = errors.Join(restoreErr, m.Net(recovery, previous.ID, true))
		}
		// Firewall/service recovery can exhaust its timeout. Still make a
		// bounded independent attempt to restore the host's live sysctls.
		runtimeRecovery, cancelRuntime := context.WithTimeout(context.Background(), 5*time.Second)
		restoreErr = errors.Join(restoreErr, restoreIPv6Runtime(runtimeRecovery, liveSysctls, quiet))
		cancelRuntime()
		if restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore previous IPv6 settings: %w", restoreErr))
		}
		updated = previous
	}()
	if running {
		if err = m.Net(ctx, updated.ID, false); err != nil {
			return previous, err
		}
	}
	if err = enableIPv6Forward(ctx, updated); err != nil {
		return previous, err
	}
	if err = saveNetService(updated); err != nil {
		return previous, err
	}
	if err = write0600(configPath(updated.ID), newConfig); err != nil {
		return previous, err
	}
	if !enabled {
		if removeErr := os.Remove(sysctlPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return previous, removeErr
		}
	}
	if running {
		if updated.ID == core.IKEv2 {
			err = m.SyncIKEv2(ctx, updated, users)
		} else {
			err = quiet(ctx, "systemctl", "restart", SystemdUnit(updated.ID))
		}
		if err == nil {
			err = m.Net(ctx, updated.ID, true)
		}
		if err != nil {
			return previous, fmt.Errorf("apply IPv6 settings: %w", err)
		}
		if Status(updated.ID) != "running" {
			return previous, errors.New("VPN service did not stay active after changing IPv6 settings")
		}
	}
	if save != nil {
		if err = save(updated); err != nil {
			return previous, fmt.Errorf("save IPv6 settings: %w", err)
		}
	}
	committed = true
	if log != nil {
		log("IPv6 settings saved. Reconnect clients and download updated profiles where applicable.")
	}
	return updated, nil
}

type ipv6RuntimeValue struct {
	key   string
	value string
}

// all.forwarding also changes each interface's forwarding flag. Capturing
// individual flags retains host-specific overrides when an update fails.
func snapshotIPv6Runtime(root string) ([]ipv6RuntimeValue, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read current IPv6 forwarding settings: %w", err)
	}
	var values []ipv6RuntimeValue
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, setting := range []string{"forwarding", "accept_ra"} {
			data, err := os.ReadFile(filepath.Join(root, entry.Name(), setting))
			if err != nil {
				return nil, fmt.Errorf("read IPv6 %s/%s: %w", entry.Name(), setting, err)
			}
			value := strings.TrimSpace(string(data))
			if value != "0" && value != "1" && (setting != "accept_ra" || value != "2") {
				return nil, fmt.Errorf("unexpected IPv6 %s/%s setting", entry.Name(), setting)
			}
			values = append(values, ipv6RuntimeValue{"net/ipv6/conf/" + entry.Name() + "/" + setting, value})
		}
	}
	return values, nil
}

func restoreIPv6Runtime(ctx context.Context, values []ipv6RuntimeValue, run firewallCommand) error {
	if len(values) == 0 {
		return nil
	}
	// Restore global/default flags first; restore individual overrides after
	// all.forwarding has propagated its value to the existing interfaces.
	args := []string{"-w"}
	for _, key := range []string{"net/ipv6/conf/all/forwarding", "net/ipv6/conf/default/forwarding"} {
		for _, v := range values {
			if v.key == key {
				args = append(args, v.key+"="+v.value)
			}
		}
	}
	for _, v := range values {
		if v.key != "net/ipv6/conf/all/forwarding" && v.key != "net/ipv6/conf/default/forwarding" {
			args = append(args, v.key+"="+v.value)
		}
	}
	if err := run(ctx, "sysctl", args...); err != nil {
		return fmt.Errorf("restore live IPv6 forwarding settings: %w", err)
	}
	return nil
}
