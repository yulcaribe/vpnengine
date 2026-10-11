package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/yulcaribe/vpnengine/internal/core"
)

const OpenVPNIPv6Sink = "fd67:67:ffff::/64"

// OpenVPNIPv6HostEnabled checks whether Linux can address a newly created tun
// interface. It never enables host IPv6 or changes administrator settings.
func OpenVPNIPv6HostEnabled() bool {
	for _, name := range []string{"all", "default"} {
		value, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6")
		if err != nil || strings.TrimSpace(string(value)) != "0" {
			return false
		}
	}
	return true
}

func openVPNIPv6OffConfig(hostEnabled bool) string {
	addressing := "server-ipv6 " + OpenVPNIPv6Sink + "\n"
	if !hostEnabled {
		// Blocking happens inside the compatible client before packets reach
		// this IPv4-only server; no IPv6 host address or host route is created.
		addressing = "# Host IPv6 is disabled: client-only blocking requires a compatible client.\n" +
			"push \"ifconfig-ipv6 fd67:67:ffff::2/64 fd67:67:ffff::1\"\n"
	}
	return addressing + "push \"redirect-gateway ipv6\"\npush \"block-ipv6\"\n"
}

func openVPNHasClientIPv6Blocking(conf string) bool {
	return strings.Contains(conf, "push \"ifconfig-ipv6 fd67:67:ffff::2/64 fd67:67:ffff::1\"") &&
		strings.Contains(conf, "push \"redirect-gateway ipv6\"") && strings.Contains(conf, "push \"block-ipv6\"")
}

// CheckOpenVPNIPv6Sink refuses to install the IPv6-off route over a network
// already used by the host. The existing managed tunnel's own route is allowed.
func CheckOpenVPNIPv6Sink(ctx context.Context) error {
	if !OpenVPNIPv6HostEnabled() {
		return nil // Client-only blocking creates no host IPv6 sink route.
	}
	routes, err := managementCommandOutput(ctx, "ip", "-6", "route", "show", "table", "all")
	if err != nil {
		return fmt.Errorf("cannot check OpenVPN IPv6 blocking network: %w", err)
	}
	return checkOpenVPNIPv6SinkRoutes(routes, ServiceInstalled(core.OpenVPN))
}

func checkOpenVPNIPv6SinkRoutes(routes string, allowManagedInterface bool) error {
	sink := netip.MustParsePrefix(OpenVPNIPv6Sink)
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		position := 0
		switch fields[0] {
		case "local", "unreachable", "blackhole", "prohibit", "throw", "multicast", "broadcast", "unicast", "anycast", "nat":
			position = 1
		}
		if len(fields) <= position {
			return errors.New("cannot safely parse the host IPv6 routing table")
		}
		destination := fields[position]
		if destination == "default" {
			continue
		}
		prefix, err := netip.ParsePrefix(destination)
		if err != nil {
			address, parseErr := netip.ParseAddr(destination)
			if parseErr != nil || !address.Is6() {
				return errors.New("cannot safely parse the host IPv6 routing table")
			}
			prefix = netip.PrefixFrom(address, 128)
		}
		if !prefix.Addr().Is6() || prefix.Bits() == 0 || !prefix.Overlaps(sink) {
			continue
		}
		iface := ""
		for i, field := range fields {
			if field == "dev" && i+1 < len(fields) {
				iface = fields[i+1]
			}
		}
		if allowManagedInterface && iface == InterfaceFor(core.OpenVPN) {
			continue
		}
		return fmt.Errorf("OpenVPN IPv6 blocking network %s conflicts with host route %s on %s; existing routes were preserved", OpenVPNIPv6Sink, destination, iface)
	}
	return nil
}

func openVPNHasIPv6Server(conf string) bool {
	for _, line := range strings.Split(conf, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "server-ipv6" {
			return true
		}
	}
	return false
}

func ovpnConfig(s core.Service, p CertPaths) string {
	return ovpnConfigForHost(s, p, OpenVPNIPv6HostEnabled())
}

func ovpnConfigForHost(s core.Service, p CertPaths, hostIPv6 bool) string {
	conf := fmt.Sprintf(`# Managed by VPN Engine
port %d
proto udp
dev tun-vpneng
topology subnet
server %s 255.255.255.0
ca %s
cert %s
key %s
dh none
tls-server
tls-version-min 1.2
tls-crypt %s
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM
verify-client-cert none
username-as-common-name
auth-user-pass-verify "/usr/local/bin/vpn-engine auth openvpn" via-file
script-security 2
up "/usr/local/bin/vpn-engine net up openvpn"
down "/usr/local/bin/vpn-engine net down openvpn"
keepalive 10 120
persist-key
persist-tun
explicit-exit-notify 1
push "redirect-gateway def1"
push "dhcp-option DNS %s"
verb 3
`, s.Port, strings.Split(s.CIDR, "/")[0], p.CA, p.Server, p.Key, filepath.Join(DataDir, "pki", "openvpn", "tls-crypt.key"), s.DNS)
	conf += openVPNManagementConfig
	if s.IPv6 {
		conf += fmt.Sprintf("server-ipv6 %s\npush \"redirect-gateway ipv6\"\n", s.IPv6CIDR)
	} else {
		// The client routes IPv6 into the tunnel and drops it there instead of
		// continuing to use its ordinary IPv6 internet connection.
		conf += openVPNIPv6OffConfig(hostIPv6)
	}
	return conf
}
func installOpenVPN(ctx context.Context, s core.Service, log Log) error {
	if !s.IPv6 {
		if err := CheckOpenVPNIPv6Sink(ctx); err != nil {
			return err
		}
	}
	if err := ensureOpenVPNRuntime(ctx); err != nil {
		return err
	}
	log("Generating OpenVPN CA and server certificate")
	p, e := makePKI(core.OpenVPN, s.Endpoint)
	if e != nil {
		return e
	}
	tlsKey := filepath.Join(DataDir, "pki", "openvpn", "tls-crypt.key")
	if _, e = os.Stat(tlsKey); os.IsNotExist(e) {
		if e = LogCmd(ctx, log, "openvpn", "--genkey", "secret", tlsKey); e != nil {
			return e
		}
		_ = os.Chmod(tlsKey, 0600)
	}
	if e = write0600(OVPNConf, []byte(ovpnConfig(s, p))); e != nil {
		return e
	}
	log("OpenVPN username/password authentication enabled")
	return nil
}
func OpenVPNProfile(s core.Service) (string, error) {
	p := PKIPaths(core.OpenVPN)
	ca, e := os.ReadFile(p.CA)
	if e != nil {
		return "", e
	}
	tls, e := os.ReadFile(filepath.Join(DataDir, "pki", "openvpn", "tls-crypt.key"))
	if e != nil {
		return "", e
	}
	protection := ""
	if !s.IPv6 {
		protection = "# IPv6 is blocked by compatible OpenVPN clients while connected.\nblock-ipv6\n"
	}
	return fmt.Sprintf(`client
dev tun
proto udp
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
auth-nocache
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
%s
verb 3
<ca>
%s</ca>
<tls-crypt>
%s</tls-crypt>
`, s.Endpoint, s.Port, protection, string(ca), string(tls)), nil
}
