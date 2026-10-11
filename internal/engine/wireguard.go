package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/yulcaribe/vpnengine/internal/core"
)

func wgKeypair() (string, string, error) {
	priv, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", err
	}
	p := strings.TrimSpace(string(priv))
	c := exec.Command("wg", "pubkey")
	c.Stdin = strings.NewReader(p + "\n")
	pub, err := c.Output()
	if err != nil {
		return "", "", err
	}
	return p, strings.TrimSpace(string(pub)), nil
}
func serverPrivate() string {
	b, _ := os.ReadFile(filepath.Join(DataDir, "wireguard", "server.key"))
	return strings.TrimSpace(string(b))
}
func serverPublic() string {
	b, _ := os.ReadFile(filepath.Join(DataDir, "wireguard", "server.pub"))
	return strings.TrimSpace(string(b))
}
func WGAddress(cidr string, offset uint8) (string, error) {
	p, e := netip.ParsePrefix(cidr)
	if e != nil || p.Bits() != 24 || !p.Addr().Is4() {
		return "", fmt.Errorf("invalid /24 subnet")
	}
	raw := p.Addr().As4()
	raw[3] = offset
	return netip.AddrFrom4(raw).String(), nil
}
func wgConfig(s core.Service, users []core.User) (string, error) {
	return wgConfigWithKey(s, users, serverPrivate())
}
func wgConfigWithKey(s core.Service, users []core.User, key string) (string, error) {
	addr, e := WGAddress(s.CIDR, 1)
	if e != nil {
		return "", e
	}
	if key == "" {
		return "", fmt.Errorf("WireGuard server key missing")
	}
	var b strings.Builder
	addresses := addr + "/24"
	if s.IPv6 {
		v6, err := IPv6Address(s.IPv6CIDR, 1)
		if err != nil {
			return "", err
		}
		addresses += ", " + v6 + "/64"
	}
	fmt.Fprintf(&b, "# Managed by VPN Engine\n[Interface]\nAddress = %s\nListenPort = %d\nPrivateKey = %s\nPostUp = /usr/local/bin/vpn-engine net up wireguard\nPostDown = /usr/local/bin/vpn-engine net down wireguard\n", addresses, s.Port, key)
	usedIPv6 := map[string]bool{}
	for _, u := range users {
		if u.Service != core.WireGuard || !u.Enabled {
			continue
		}
		if u.PublicKey == "" || u.Address == "" {
			return "", fmt.Errorf("client has incomplete keys")
		}
		allowed := u.Address + "/32"
		if s.IPv6 {
			v6, err := wireGuardUserIPv6(s, u)
			if err != nil {
				return "", err
			}
			if usedIPv6[v6] {
				return "", fmt.Errorf("duplicate WireGuard IPv6 address")
			}
			usedIPv6[v6] = true
			allowed += ", " + v6 + "/128"
		}
		fmt.Fprintf(&b, "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s\n", u.Name, u.PublicKey, allowed)
	}
	return b.String(), nil
}
func installWireGuard(ctx context.Context, s core.Service, log Log) error {
	if err := mkdir700(filepath.Join(DataDir, "wireguard")); err != nil {
		return err
	}
	priv, pub, err := wgKeypair()
	if err != nil {
		return err
	}
	if err = write0600(filepath.Join(DataDir, "wireguard", "server.key"), []byte(priv+"\n")); err != nil {
		return err
	}
	if err = write0600(filepath.Join(DataDir, "wireguard", "server.pub"), []byte(pub+"\n")); err != nil {
		return err
	}
	conf, err := wgConfig(s, nil)
	if err != nil {
		return err
	}
	if err = write0600(WGConf, []byte(conf)); err != nil {
		return err
	}
	log("WireGuard configuration written (vpnwg0)")
	return nil
}
func (Manager) SyncWireGuard(ctx context.Context, s core.Service, users []core.User) error {
	return syncWireGuard(ctx, s, users, true)
}

// SyncWireGuardRevoked keeps removed peers out of the saved configuration even
// when the live update fails; restarting must not restore revoked access.
func (Manager) SyncWireGuardRevoked(ctx context.Context, s core.Service, users []core.User) error {
	return syncWireGuard(ctx, s, users, false)
}

func syncWireGuard(ctx context.Context, s core.Service, users []core.User, rollback bool) error {
	if !ServiceInstalled(core.WireGuard) {
		return fmt.Errorf("WireGuard is not installed")
	}
	newConfig, e := wgConfig(s, users)
	if e != nil {
		return e
	}
	return applyWireGuardConfig(WGConf, []byte(newConfig), Status(core.WireGuard) == "running", rollback, func() error { return syncWG(ctx) })
}

func applyWireGuardConfig(path string, newConfig []byte, running, rollback bool, sync func() error) error {
	old, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if e = write0600(path, newConfig); e != nil {
		return e
	}
	if !running {
		return nil
	}
	if e = sync(); e != nil {
		if rollback {
			if restoreErr := write0600(path, old); restoreErr != nil {
				return fmt.Errorf("WireGuard live update failed (%v); saved configuration could not be restored: %w", e, restoreErr)
			}
			if restoreErr := sync(); restoreErr != nil {
				return fmt.Errorf("WireGuard live update failed (%v); active configuration could not be restored: %w", e, restoreErr)
			}
		} else {
			return fmt.Errorf("access is revoked in the saved configuration, but active peer removal could not be verified: %w", e)
		}
		return e
	}
	return nil
}
func syncWG(ctx context.Context) error {
	stripped, e := exec.CommandContext(ctx, "wg-quick", "strip", "vpnwg0").Output()
	if e != nil {
		return fmt.Errorf("wg-quick strip: %w", e)
	}
	// Ubuntu's enforced wg AppArmor profile permits WireGuard-owned files under
	// /etc/wireguard but may reject arbitrary temporary files under /tmp.
	f, e := os.CreateTemp(filepath.Dir(WGConf), ".vpn-engine-sync-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(stripped); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	output, e := exec.CommandContext(ctx, "wg", "syncconf", "vpnwg0", f.Name()).CombinedOutput()
	if e != nil {
		return fmt.Errorf("wg syncconf: %s: %w", bytes.TrimSpace(output), e)
	}
	return nil
}
func WGProfile(s core.Service, u core.User) (string, error) {
	return wgProfileWithKey(s, u, serverPublic())
}

func wireGuardUserIPv6(s core.Service, u core.User) (string, error) {
	cidr := s.IPv6CIDR
	if cidr == "" && !s.IPv6 {
		cidr = "fd66:66::/64"
	}
	p, err := ipv6Prefix(cidr)
	if err != nil {
		return "", err
	}
	if u.IPv6Address != "" {
		a, err := netip.ParseAddr(u.IPv6Address)
		server, _ := IPv6Address(cidr, 1)
		if err != nil || !a.Is6() || a.Is4In6() || !p.Contains(a) || a == p.Addr() || a.String() == server {
			return "", fmt.Errorf("invalid WireGuard client IPv6 address")
		}
		return a.String(), nil
	}
	a, err := netip.ParseAddr(u.Address)
	v4, prefixErr := netip.ParsePrefix(s.CIDR)
	if err != nil || !a.Is4() || prefixErr != nil || !v4.Contains(a) {
		return "", fmt.Errorf("invalid WireGuard client IPv4 address")
	}
	raw := a.As4()
	if raw[3] < 2 || raw[3] == 255 {
		return "", fmt.Errorf("reserved WireGuard client address")
	}
	return IPv6Address(cidr, uint64(raw[3]))
}

func wgProfileWithKey(s core.Service, u core.User, pub string) (string, error) {
	if pub == "" || u.PrivateKey == "" || u.Address == "" {
		return "", fmt.Errorf("keys missing")
	}
	v6, err := wireGuardUserIPv6(s, u)
	if err != nil {
		return "", err
	}
	comment := "# Reimport this profile after changing IPv6 Support. Verify IPv6 routing on your device.\n"
	if !s.IPv6 {
		comment += "# IPv6 internet is disabled. Supported WireGuard clients route IPv6 into this tunnel to prevent bypass.\n"
	}
	return fmt.Sprintf("%s[Interface]\nPrivateKey = %s\nAddress = %s/32, %s/128\nDNS = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n", comment, u.PrivateKey, u.Address, v6, s.DNS, pub, s.Endpoint, s.Port), nil
}
func NewWireGuardUser(name string, users []core.User, s core.Service) (core.User, error) {
	used := map[string]bool{}
	for _, u := range users {
		if u.Service == core.WireGuard {
			used[u.Address] = true
		}
	}
	for n := uint8(2); n < 255; n++ {
		addr, e := WGAddress(s.CIDR, n)
		if e != nil {
			return core.User{}, e
		}
		if used[addr] {
			continue
		}
		priv, pub, e := wgKeypair()
		if e != nil {
			return core.User{}, e
		}
		u := core.User{Name: name, Service: core.WireGuard, Address: addr, PrivateKey: priv, PublicKey: pub, Enabled: true}
		u.IPv6Address, e = wireGuardUserIPv6(s, u)
		if e != nil {
			return core.User{}, e
		}
		return u, nil
	}
	return core.User{}, fmt.Errorf("WireGuard subnet is full")
}
