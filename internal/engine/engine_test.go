package engine

import (
	"strings"
	"testing"

	"github.com/yulcaribe/vpnengine/internal/core"
)

func TestValidationAndCollisions(t *testing.T) {
	wg := Defaults(core.WireGuard)
	wg.Interface = "ens160"
	wg.Endpoint = "89.252.177.70"
	if err := Validate(wg, nil); err != nil {
		t.Fatal(err)
	}
	if err := Validate(core.Service{ID: core.WireGuard, Port: 123, Interface: "ens160;rm -rf /", Endpoint: "89.252.177.70", CIDR: "10.66.66.0/24", DNS: "1.1.1.1"}, nil); err == nil {
		t.Fatal("accepted command injection")
	}
	if err := Validate(core.Service{ID: core.WireGuard, Port: 123, Interface: "ens160", Endpoint: "89.252.177.70", CIDR: "10.66.66.1/24", DNS: "1.1.1.1"}, nil); err == nil {
		t.Fatal("accepted unmasked subnet")
	}
	if err := Validate(core.Service{ID: core.WireGuard, Port: 123, Interface: "ens160", Endpoint: "89.252.177.70", CIDR: "8.8.8.0/24", DNS: "1.1.1.1"}, nil); err == nil {
		t.Fatal("accepted public subnet")
	}
	ov := Defaults(core.OpenVPN)
	ov.Interface = "ens160"
	ov.Endpoint = "vpn.example.com"
	ov.Installed = true
	wg.Port = 1194
	if err := Validate(wg, map[string]core.Service{core.OpenVPN: ov}); err == nil {
		t.Fatal("accepted port collision")
	}
	wg.Port = 123
	wg.CIDR = ov.CIDR
	if err := Validate(wg, map[string]core.Service{core.OpenVPN: ov}); err == nil {
		t.Fatal("accepted network collision")
	}
}
func TestProfilesAndIKE(t *testing.T) {
	a, e := WGAddress("10.66.66.0/24", 2)
	if e != nil || a != "10.66.66.2" {
		t.Fatalf("got %s %v", a, e)
	}
	if _, e = WGAddress("10.66.66.0/16", 2); e == nil {
		t.Fatal("accepted /16")
	}
	s := Defaults(core.IKEv2)
	s.Endpoint = "vpn.example.com"
	users := []core.User{{Name: "alice", Service: core.IKEv2, Enabled: true, IKESecret: "secret_pass#123"}, {Name: "bob", Service: core.IKEv2, Enabled: false, IKESecret: "disabled"}}
	conf := swanctlConfig(s, users)
	for _, v := range []string{"auth = eap-mschapv2", "pools = vpn-engine-pool", "fragmentation = yes", "secret = \"secret_pass#123\"", "local_ts = 0.0.0.0/0"} {
		if !strings.Contains(conf, v) {
			t.Fatalf("missing %s", v)
		}
	}
	if strings.Contains(conf, "bob") {
		t.Fatal("disabled user leaked into secrets")
	}
	if ValidIKEPassword("hello\"; exploit") || !ValidIKEPassword("Secret1234!") {
		t.Fatal("invalid password validation")
	}
	ovpn := ovpnConfig(Defaults(core.OpenVPN), PKIPaths(core.OpenVPN))
	if !strings.Contains(ovpn, "verify-client-cert none") || !strings.Contains(ovpn, "auth-user-pass-verify") || !strings.Contains(ovpn, "tun-vpneng") {
		t.Fatal("broken OpenVPN config")
	}
}
