package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yulcaribe/vpnengine/internal/core"
)

var ikePasswordPattern = regexp.MustCompile(`^[A-Za-z0-9@._!+\-=#%]{8,72}$`)

func ValidIKEPassword(p string) bool { return ikePasswordPattern.MatchString(p) }
func swanctlConfig(s core.Service, users []core.User) string {
	var b strings.Builder
	pools, selectors, ipv6Pool := "vpn-engine-pool", "0.0.0.0/0", ""
	if s.IPv6 {
		pools += ", vpn-engine-ipv6"
		selectors += ", ::/0"
		ipv6Pool = fmt.Sprintf("  vpn-engine-ipv6 {\n    addrs = %s\n  }\n", s.IPv6CIDR)
	}
	fmt.Fprintf(&b, `# Managed by VPN Engine
connections {
  vpn-engine {
    version = 2
    local_addrs = %%any
    pools = %s
    fragmentation = yes
    send_cert = always
    mobike = yes
    local {
      auth = pubkey
      certs = vpn-engine-server.crt
      id = %s
    }
    remote {
      auth = eap-mschapv2
      eap_id = %%any
    }
    children {
      tunnel {
        local_ts = %s
        rekey_time = 0s
      }
    }
  }
}
pools {
  vpn-engine-pool {
    addrs = %s
    dns = %s
  }
%s
}
secrets {
`, pools, s.Endpoint, selectors, s.CIDR, s.DNS, ipv6Pool)
	for _, u := range users {
		if u.Service != core.IKEv2 || !u.Enabled {
			continue
		}
		// Only restricted usernames and passwords can be interpolated here.
		fmt.Fprintf(&b, "  eap-vpn-engine-%s {\n    id = %s\n    secret = \"%s\"\n  }\n", u.Name, u.Name, u.IKESecret)
	}
	b.WriteString("}\n")
	return b.String()
}
func writeSwanctlInclude() error {
	path := "/etc/swanctl/swanctl.conf"
	b, e := os.ReadFile(path)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if strings.Contains(string(b), IPsecInclude) {
		return nil
	}
	if strings.Contains(string(b), "include conf.d/") {
		return fmt.Errorf("swanctl.conf uses a custom include; please inspect manually")
	}
	appended := append(append([]byte(nil), b...), []byte("\n# VPN Engine: include managed protocol configuration\n"+IPsecInclude+"\n")...)
	return write0600(path, appended)
}
func installIKEv2(ctx context.Context, s core.Service, log Log) error {
	log("Creating IKEv2 certificate authority and server certificate")
	p, e := makePKI(core.IKEv2, s.Endpoint)
	if e != nil {
		return e
	}
	if e = CopyPrivate(p.CA, "/etc/swanctl/x509ca/vpn-engine-ca.crt"); e != nil {
		return e
	}
	if e = CopyPrivate(p.Server, "/etc/swanctl/x509/vpn-engine-server.crt"); e != nil {
		return e
	}
	if e = CopyPrivate(p.Key, "/etc/swanctl/private/vpn-engine-server.key"); e != nil {
		return e
	}
	if e = writeSwanctlInclude(); e != nil {
		return e
	}
	if e = write0600(IPsecConf, []byte(swanctlConfig(s, nil))); e != nil {
		return e
	}
	if e = mkdir700(filepath.Join("/etc/systemd/system", "strongswan.service.d")); e != nil {
		return e
	}
	// This hook restores NAT rules across reboots when strongSwan starts.
	unit := `[Service]
ExecStartPost=/usr/local/bin/vpn-engine net up ikev2
ExecStopPost=/usr/local/bin/vpn-engine net down ikev2
`
	if e = write0600("/etc/systemd/system/strongswan.service.d/vpn-engine.conf", []byte(unit)); e != nil {
		return e
	}
	if e = LogCmd(ctx, log, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	log("IKEv2 EAP-MSCHAPv2 configured on UDP 500 and 4500")
	return nil
}
func (Manager) SyncIKEv2(ctx context.Context, s core.Service, users []core.User) error {
	if !ServiceInstalled(core.IKEv2) {
		return fmt.Errorf("IKEv2 not installed")
	}
	for _, u := range users {
		if u.Service == core.IKEv2 && (!ValidUsername(u.Name) || !ValidIKEPassword(u.IKESecret)) {
			return fmt.Errorf("invalid IKEv2 credentials")
		}
	}
	old, e := os.ReadFile(IPsecConf)
	if e != nil {
		return e
	}
	known, e := rememberIKESecretOwnership(old, users)
	if e != nil {
		return e
	}
	if e = write0600(IPsecConf, []byte(swanctlConfig(s, users))); e != nil {
		return e
	}
	running, e := managementServiceRunning(ctx, core.IKEv2)
	if e != nil {
		return e
	}
	if !running {
		return nil
	}
	// VICI can replace/remove only our shared credentials. load-creds --clear
	// (or load-creds with a partial file) would affect unrelated host secrets.
	if e = refreshIKECredentials(ctx, known, users); e != nil {
		return fmt.Errorf("IKEv2 configuration saved, credential refresh failed: %w", e)
	}
	if e = (Manager{}).RefreshIKEv2(ctx, s); e != nil {
		return fmt.Errorf("IKEv2 configuration saved, runtime configuration refresh failed: %w", e)
	}
	return nil
}
