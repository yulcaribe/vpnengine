package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/yulcaribe/vpnengine/internal/core"
)

// IPv6Address keeps the network portion of a private /64 and sets its host ID.
func IPv6Address(cidr string, offset uint64) (string, error) {
	p, err := ipv6Prefix(cidr)
	if err != nil {
		return "", err
	}
	raw := p.Addr().As16()
	binary.BigEndian.PutUint64(raw[8:], offset)
	return netip.AddrFrom16(raw).String(), nil
}

func ipv6Prefix(cidr string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != 64 || p.Masked() != p || !p.Addr().IsPrivate() {
		return netip.Prefix{}, fmt.Errorf("VPN IPv6 network must be a private IPv6 /64 subnet")
	}
	return p, nil
}

func ValidateIPv6(s core.Service, others map[string]core.Service) error {
	if !s.IPv6 && s.IPv6CIDR == "" {
		return nil // Existing IPv4-only databases remain valid.
	}
	p, err := ipv6Prefix(s.IPv6CIDR)
	if err != nil {
		return err
	}
	if s.IPv6Interface != "" && !ifacePattern.MatchString(s.IPv6Interface) {
		return fmt.Errorf("invalid IPv6 outgoing interface")
	}
	if !s.IPv6 {
		return nil
	}
	for id, other := range others {
		if id == s.ID || !other.Installed || !other.IPv6 {
			continue
		}
		op, err := netip.ParsePrefix(other.IPv6CIDR)
		if err == nil && (p.Contains(op.Addr()) || op.Contains(p.Addr())) {
			return fmt.Errorf("IPv6 subnet conflicts with %s", id)
		}
	}
	return nil
}

type commandOutput func(context.Context, string, ...string) ([]byte, error)

func output(ctx context.Context, command string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, command, args...).Output()
}

func ipv6DefaultInterface(ctx context.Context, run commandOutput) string {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b, err := run(c, "ip", "-6", "route", "show", "default")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		for i, field := range fields {
			if field == "dev" && i+1 < len(fields) && ifacePattern.MatchString(fields[i+1]) {
				return fields[i+1]
			}
		}
	}
	return ""
}

// IPv6DefaultInterface can differ from the IPv4 outgoing interface.
func IPv6DefaultInterface(ctx context.Context) string {
	return ipv6DefaultInterface(ctx, output)
}

type ipv6Detector struct {
	mu        sync.Mutex
	run       commandOutput
	checkedAt time.Time
	available bool
}

var hostIPv6 = ipv6Detector{run: output}

// IPv6Available requires an address, a route, and a successful direct HTTPS
// request over IPv6. Cached checks avoid repeatedly delaying panel requests.
func IPv6Available(ctx context.Context) bool { return hostIPv6.availableAt(ctx, time.Now()) }

func (d *ipv6Detector) availableAt(ctx context.Context, now time.Time) bool {
	if ctx.Err() != nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.checkedAt.IsZero() && now.Sub(d.checkedAt) < time.Minute {
		return d.available
	}
	c, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	d.available = d.probe(c)
	if ctx.Err() == nil {
		d.checkedAt = now
	}
	return d.available
}

func publicIPv6(a netip.Addr) bool {
	return a.Is6() && !a.Is4In6() && a.IsGlobalUnicast() && !a.IsPrivate()
}

func (d *ipv6Detector) probe(ctx context.Context) bool {
	iface := ipv6DefaultInterface(ctx, d.run)
	if iface == "" {
		return false
	}
	b, err := d.run(ctx, "ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "global")
	if err != nil {
		return false
	}
	hasAddress := false
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		unusable := false
		for _, field := range fields {
			if field == "tentative" || field == "dadfailed" {
				unusable = true
			}
		}
		if unusable {
			continue
		}
		for i, field := range fields {
			if field == "inet6" && i+1 < len(fields) {
				p, err := netip.ParsePrefix(fields[i+1])
				if err == nil && publicIPv6(p.Addr()) {
					hasAddress = true
				}
			}
		}
	}
	if !hasAddress {
		return false
	}
	// Do not use environment proxies: their IPv6 connectivity says nothing
	// about the host's ability to forward VPN clients' IPv6 traffic.
	b, err = d.run(ctx, "curl", "-6", "--noproxy", "*", "-fsS", "--max-time", "4", "https://api64.ipify.org")
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(string(b)))
	return err == nil && publicIPv6(a)
}
