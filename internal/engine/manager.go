package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yulcaribe/vpnengine/internal/core"
)

const (
	DataDir      = "/etc/vpn-engine"
	WGConf       = "/etc/wireguard/vpnwg0.conf"
	OVPNConf     = "/etc/openvpn/server/vpnengine.conf"
	IPsecConf    = "/etc/swanctl/conf.d/vpn-engine.conf"
	IPsecInclude = "include conf.d/*.conf"
)

type Log func(string)
type Progress func(int, string)
type Manager struct{}

func reportProgress(progress Progress, percent int, stage string) {
	if progress != nil {
		progress(percent, stage)
	}
}

type commandLogWriter struct {
	mu  sync.Mutex
	log Log
	buf string
}

func (w *commandLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf += strings.ReplaceAll(string(p), "\r", "\n")
	for {
		i := strings.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(w.buf[:i])
		w.buf = w.buf[i+1:]
		if line != "" {
			w.log(line)
		}
	}
	return len(p), nil
}
func (w *commandLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if line := strings.TrimSpace(w.buf); line != "" {
		w.log(line)
	}
	w.buf = ""
}

func Defaults(id string) core.Service {
	switch id {
	case core.WireGuard:
		return core.Service{ID: id, Port: 123, CIDR: "10.66.66.0/24", DNS: "1.1.1.1", IPv6CIDR: "fd66:66::/64"}
	case core.OpenVPN:
		return core.Service{ID: id, Port: 1194, CIDR: "10.67.67.0/24", DNS: "1.1.1.1", IPv6CIDR: "fd67:67::/64"}
	case core.IKEv2:
		return core.Service{ID: id, Port: 500, CIDR: "10.68.68.0/24", DNS: "1.1.1.1", IPv6CIDR: "fd68:68::/64"}
	default:
		return core.Service{}
	}
}
func InterfaceFor(id string) string {
	switch id {
	case core.WireGuard:
		return "vpnwg0"
	case core.OpenVPN:
		return "tun-vpneng"
	default:
		return ""
	}
}
func SystemdUnit(id string) string {
	switch id {
	case core.WireGuard:
		return "wg-quick@vpnwg0.service"
	case core.OpenVPN:
		return "openvpn-server@vpnengine.service"
	case core.IKEv2:
		return "strongswan.service"
	}
	return ""
}
func configPath(id string) string {
	switch id {
	case core.WireGuard:
		return WGConf
	case core.OpenVPN:
		return OVPNConf
	case core.IKEv2:
		return IPsecConf
	}
	return ""
}

var labelPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,31}$`)
var ifacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
var domainPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

func ValidUsername(s string) bool { return labelPattern.MatchString(s) }
func Validate(s core.Service, others map[string]core.Service) error {
	if !core.IsService(s.ID) {
		return errors.New("unsupported VPN service")
	}
	if s.ID == core.IKEv2 && s.Port != 500 {
		return errors.New("IKEv2 uses UDP 500 and 4500")
	}
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("invalid UDP port")
	}
	if s.Interface == "" || !ifacePattern.MatchString(s.Interface) {
		return errors.New("invalid outgoing interface")
	}
	if s.Endpoint == "" || len(s.Endpoint) > 253 {
		return errors.New("invalid public address")
	}
	if a, e := netip.ParseAddr(s.Endpoint); e != nil || !a.Is4() {
		if !domainPattern.MatchString(s.Endpoint) {
			return errors.New("endpoint must be IPv4 address or DNS hostname")
		}
	}
	netw, e := netip.ParsePrefix(s.CIDR)
	if e != nil || !netw.Addr().Is4() || netw.Bits() != 24 || netw.Masked() != netw || !netw.Addr().IsPrivate() {
		return errors.New("VPN network must be a private IPv4 /24 subnet")
	}
	a, e := netip.ParseAddr(s.DNS)
	if e != nil || !a.Is4() {
		return errors.New("DNS must be a valid IPv4 address")
	}
	for id, other := range others {
		if id == s.ID || !other.Installed {
			continue
		}
		p, e := netip.ParsePrefix(other.CIDR)
		if e == nil && (netw.Contains(p.Addr()) || p.Contains(netw.Addr())) {
			return fmt.Errorf("subnet conflicts with %s", id)
		}
		if s.ID == core.IKEv2 {
			if other.Port == 500 || other.Port == 4500 {
				return fmt.Errorf("IKEv2 UDP port conflicts with %s", id)
			}
		}
		if id == core.IKEv2 {
			if s.Port == 500 || s.Port == 4500 {
				return errors.New("port is reserved by IKEv2")
			}
		}
		if s.Port == other.Port {
			return fmt.Errorf("UDP port already used by %s", id)
		}
	}
	return ValidateIPv6(s, others)
}
func DetectInterface() string {
	b, e := exec.Command("ip", "-4", "route", "show", "default").Output()
	if e != nil {
		return ""
	}
	parts := strings.Fields(string(b))
	for i, p := range parts {
		if p == "dev" && i+1 < len(parts) && ifacePattern.MatchString(parts[i+1]) {
			return parts[i+1]
		}
	}
	return ""
}
func DetectPublicIPv4(ctx context.Context) string {
	c, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	b, e := exec.CommandContext(c, "curl", "-4", "-fsS", "--max-time", "3", "https://api.ipify.org").Output()
	if e != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if a, e := netip.ParseAddr(s); e == nil && a.Is4() {
		return s
	}
	return ""
}
func checkUDP(port int) error {
	l, e := net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", port))
	if e != nil {
		return fmt.Errorf("UDP %d is already occupied: %w", port, e)
	}
	return l.Close()
}
func Preflight(s core.Service, others map[string]core.Service) error {
	if err := Validate(s, others); err != nil {
		return err
	}
	if err := checkHostNetwork(s); err != nil {
		return err
	}
	if s.IPv6 {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		if !IPv6Available(ctx) {
			return errors.New("IPv6 Internet access is unavailable on this server; turn IPv6 off to continue")
		}
	}
	if _, e := os.Stat(configPath(s.ID)); e == nil {
		return errors.New("VPN configuration already exists; refusing to overwrite it")
	}
	if s.ID == core.IKEv2 {
		if _, e := os.Stat("/etc/ipsec.conf"); e == nil {
			b, _ := os.ReadFile("/etc/ipsec.conf")
			if strings.Contains(string(b), "conn ") {
				return errors.New("existing legacy IPsec configuration detected; refusing to replace it")
			}
		}
	}
	if s.ID == core.IKEv2 {
		if err := checkUDP(500); err != nil {
			return err
		}
		return checkUDP(4500)
	}
	return checkUDP(s.Port)
}
func wireGuardAppArmorCompatNeeded() bool {
	if _, err := os.Stat("/etc/apparmor.d/wg-quick"); err != nil {
		return false
	}
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	id, version := "", ""
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "\"")
		switch key {
		case "ID":
			id = value
		case "VERSION_ID":
			version = value
		}
	}
	return id == "ubuntu" && strings.HasPrefix(version, "26.")
}
func wgQuickProfileAlreadyComplain() bool {
	b, err := os.ReadFile("/etc/apparmor.d/wg-quick")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "profile wg-quick") && strings.Contains(line, "complain") {
			return true
		}
	}
	return false
}
func prepareWireGuardAppArmor(ctx context.Context, log Log) error {
	if !wireGuardAppArmorCompatNeeded() {
		return nil
	}
	if wgQuickProfileAlreadyComplain() {
		log("Ubuntu 26 wg-quick AppArmor profile is already in compatibility mode")
		return nil
	}
	log("Applying Ubuntu 26 wg-quick AppArmor compatibility mode")
	if err := LogCmd(ctx, log, "aa-complain", "/etc/apparmor.d/wg-quick"); err != nil {
		return fmt.Errorf("configure wg-quick AppArmor compatibility: %w", err)
	}
	marker := filepath.Join(DataDir, "wg-quick-apparmor-compat")
	if err := write0600(marker, []byte("managed by VPN Engine\n")); err != nil {
		_ = quiet(ctx, "aa-enforce", "/etc/apparmor.d/wg-quick")
		return err
	}
	return nil
}
func restoreWireGuardAppArmor(ctx context.Context, log Log) {
	marker := filepath.Join(DataDir, "wg-quick-apparmor-compat")
	if _, err := os.Stat(marker); err != nil {
		return
	}
	log("Restoring wg-quick AppArmor enforcement")
	if err := LogCmd(ctx, log, "aa-enforce", "/etc/apparmor.d/wg-quick"); err != nil {
		log("Warning: could not restore wg-quick AppArmor enforcement: " + err.Error())
		return
	}
	_ = os.Remove(marker)
}

func LogCmd(ctx context.Context, log Log, command string, args ...string) error {
	log("Running: " + command + " " + strings.Join(args, " "))
	c := exec.CommandContext(ctx, command, args...)
	if command == "apt-get" {
		c.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a")
	}
	w := &commandLogWriter{log: log}
	c.Stdout = w
	c.Stderr = w
	err := c.Run()
	w.Flush()
	if err != nil {
		return fmt.Errorf("%s: %w", command, err)
	}
	return nil
}
func quiet(ctx context.Context, command string, args ...string) error {
	return exec.CommandContext(ctx, command, args...).Run()
}
func write0600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".vpn-engine-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func mkdir700(path string) error { return os.MkdirAll(path, 0700) }
func safeFile(path string) bool {
	b, e := os.ReadFile(path)
	return e == nil && strings.Contains(string(b), "Managed by VPN Engine")
}
func ServiceInstalled(id string) bool { return safeFile(configPath(id)) }
func Status(id string) string {
	if !core.IsService(id) {
		return "unknown"
	}
	if !ServiceInstalled(id) {
		return "not installed"
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", SystemdUnit(id)).Run(); err == nil {
		return "running"
	}
	return "stopped"
}
func (Manager) Install(ctx context.Context, s core.Service, others map[string]core.Service, log Log, progress Progress) error {
	reportProgress(progress, 5, "Preparing installation")
	if err := Preflight(s, others); err != nil {
		return err
	}

	reportProgress(progress, 15, "Installing required packages")
	log("Checking required packages for " + s.ID)
	packages := map[string][]string{
		core.WireGuard: {"wireguard-tools", "iptables", "qrencode", "iproute2"},
		core.OpenVPN:   {"openvpn", "iptables", "openssl", "iproute2"},
		core.IKEv2:     {"charon-systemd", "strongswan-swanctl", "libcharon-extauth-plugins", "libcharon-extra-plugins", "iptables", "openssl", "iproute2"},
	}
	selected := append([]string(nil), packages[s.ID]...)
	if s.ID == core.WireGuard && wireGuardAppArmorCompatNeeded() {
		selected = append(selected, "apparmor-utils")
	}
	opts := []string{"-o", "DPkg::Lock::Timeout=180", "install", "-y"}
	if err := LogCmd(ctx, log, "apt-get", append(opts, selected...)...); err != nil {
		return err
	}
	success, prepared := false, false
	defer func() {
		if success {
			return
		}
		bg, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if prepared {
			_ = quiet(bg, "systemctl", "stop", SystemdUnit(s.ID))
			_ = (Manager{}).Net(bg, s.ID, false)
			cleanupServiceFiles(s.ID)
		}
		_ = os.Remove(filepath.Join("/etc/sysctl.d", "99-vpn-engine-ipv6-"+s.ID+".conf"))
		if s.ID == core.OpenVPN {
			_ = quiet(bg, "systemctl", "daemon-reload")
		}
		if s.ID == core.WireGuard {
			restoreWireGuardAppArmor(bg, log)
		}
	}()

	reportProgress(progress, 38, "Preparing system compatibility")
	if s.ID == core.WireGuard {
		if err := prepareWireGuardAppArmor(ctx, log); err != nil {
			return err
		}
	}

	reportProgress(progress, 48, "Configuring network")
	log("Enabling IPv4 forwarding")
	if err := enableForward(ctx); err != nil {
		return err
	}
	if err := enableIPv6Forward(ctx, s); err != nil {
		return err
	}
	if err := mkdir700(filepath.Join(DataDir, "services")); err != nil {
		return err
	}
	// The net hooks read this file even before the database transaction commits.
	if err := saveNetService(s); err != nil {
		return err
	}
	prepared = true

	reportProgress(progress, 60, "Creating VPN configuration")
	var err error
	switch s.ID {
	case core.WireGuard:
		err = installWireGuard(ctx, s, log)
	case core.OpenVPN:
		err = installOpenVPN(ctx, s, log)
	case core.IKEv2:
		err = installIKEv2(ctx, s, log)
	}
	if err != nil {
		return err
	}

	reportProgress(progress, 78, "Starting VPN service")
	log("Starting " + SystemdUnit(s.ID))
	if err = LogCmd(ctx, log, "systemctl", "enable", "--now", SystemdUnit(s.ID)); err != nil {
		return err
	}
	if s.ID == core.IKEv2 {
		reportProgress(progress, 86, "Applying network rules")
		if err = (Manager{}).SyncIKEv2(ctx, s, nil); err != nil {
			return err
		}
		if err = (Manager{}).Net(ctx, s.ID, true); err != nil {
			return err
		}
	}

	reportProgress(progress, 94, "Verifying VPN service")
	log("Verifying " + SystemdUnit(s.ID))
	if err = quiet(ctx, "systemctl", "is-active", "--quiet", SystemdUnit(s.ID)); err != nil {
		return fmt.Errorf("%s did not stay active", SystemdUnit(s.ID))
	}

	success = true
	reportProgress(progress, 97, "Finalizing installation")
	log("Service installed and started")
	return nil
}
func (Manager) Control(ctx context.Context, id, action string, log Log) error {
	if !core.IsService(id) || !ServiceInstalled(id) {
		return errors.New("service not installed")
	}
	switch action {
	case "start":
		if err := LogCmd(ctx, log, "systemctl", "start", SystemdUnit(id)); err != nil {
			return err
		}
		if id == core.IKEv2 {
			return (Manager{}).Net(ctx, id, true)
		}
	case "stop":
		if err := LogCmd(ctx, log, "systemctl", "stop", SystemdUnit(id)); err != nil {
			return err
		}
		if id == core.IKEv2 {
			return (Manager{}).Net(ctx, id, false)
		}
	case "restart":
		if err := LogCmd(ctx, log, "systemctl", "restart", SystemdUnit(id)); err != nil {
			return err
		}
		if id == core.IKEv2 {
			return (Manager{}).Net(ctx, id, true)
		}
	default:
		return errors.New("unsupported action")
	}
	return nil
}
func (Manager) Remove(ctx context.Context, id string, log Log) error {
	if !core.IsService(id) || !ServiceInstalled(id) {
		return errors.New("service not installed")
	}
	if err := LogCmd(ctx, log, "systemctl", "disable", "--now", SystemdUnit(id)); err != nil {
		return err
	}
	if err := (Manager{}).Net(ctx, id, false); err != nil {
		log("Warning: cleanup of forwarding rules: " + err.Error())
	}
	cleanupServiceFiles(id)
	if id == core.WireGuard {
		restoreWireGuardAppArmor(ctx, log)
	}
	if id == core.IKEv2 || id == core.OpenVPN {
		_ = quiet(ctx, "systemctl", "daemon-reload")
	}
	log("Service configuration removed. System packages remain installed.")
	return nil
}
func cleanupServiceFiles(id string) {
	if !core.IsService(id) {
		return
	}
	_ = os.Remove(configPath(id))
	_ = os.Remove(filepath.Join(DataDir, "services", id+".json"))
	_ = os.RemoveAll(filepath.Join(DataDir, "pki", id))
	_ = os.Remove(filepath.Join("/etc/sysctl.d", "99-vpn-engine-ipv6-"+id+".conf"))
	if id == core.OpenVPN {
		_ = os.Remove(OpenVPNManagementUnit)
		_ = os.Remove(filepath.Dir(OpenVPNManagementUnit)) // Only removes an empty directory.
	}
	if id == core.WireGuard {
		_ = os.RemoveAll(filepath.Join(DataDir, "wireguard"))
	}
	if id == core.IKEv2 {
		for _, f := range []string{"/etc/swanctl/x509/vpn-engine-server.crt", "/etc/swanctl/x509ca/vpn-engine-ca.crt", "/etc/swanctl/private/vpn-engine-server.key", "/etc/systemd/system/strongswan.service.d/vpn-engine.conf"} {
			_ = os.Remove(f)
		}
	}
}
func Logs(id string) string {
	if !core.IsService(id) {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "journalctl", "--no-pager", "-n", "40", "-u", SystemdUnit(id)).CombinedOutput()
	if e != nil {
		return e.Error()
	}
	if len(b) > 12000 {
		b = b[len(b)-12000:]
	}
	return string(b)
}
