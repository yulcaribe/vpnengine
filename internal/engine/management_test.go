package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yulcaribe/vpnengine/internal/core"
)

func localManagementPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("unix", t.TempDir()+"/control.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	t.Cleanup(func() { client.Close(); server.Close() })
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	return client, server
}

func TestOpenVPNDisconnectAllSessionsAndConfirm(t *testing.T) {
	client, server := localManagementPair(t)
	commands := make(chan []string, 1)
	go func() {
		reader := bufio.NewReader(server)
		var seen []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				commands <- seen
				return
			}
			line = strings.TrimSpace(line)
			seen = append(seen, line)
			switch line {
			case "status 3":
				fmt.Fprintln(server, ">INFO:local management")
				fmt.Fprintln(server, "HEADER\tCLIENT_LIST\tUsername\tCommon Name\tClient ID")
				if len(seen) == 1 {
					fmt.Fprintln(server, "CLIENT_LIST\talice\tUNDEF\t7")
					fmt.Fprintln(server, "CLIENT_LIST\talice\talice\t12")
					fmt.Fprintln(server, "CLIENT_LIST\tUNDEF\tUNDEF\t13")
				}
				fmt.Fprintln(server, "CLIENT_LIST\tbob\tbob\t9")
				fmt.Fprintln(server, "END")
				if len(seen) > 1 {
					commands <- seen
					return
				}
			case "client-kill 7", "client-kill 12", "client-kill 13":
				fmt.Fprintln(server, "SUCCESS: client scheduled for disconnect")
			default:
				fmt.Fprintln(server, "ERROR: unexpected command")
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := revokeOpenVPN(ctx, client, "alice"); err != nil {
		t.Fatal(err)
	}
	want := []string{"status 3", "client-kill 7", "client-kill 12", "client-kill 13", "status 3"}
	if got := <-commands; !reflect.DeepEqual(got, want) {
		t.Fatalf("commands %v, want %v", got, want)
	}
}

func TestWireGuardRevokeRemovesOnlyTargetAndVerifiesAbsence(t *testing.T) {
	target := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	var commands [][]string
	run := func(ctx context.Context, command string, args ...string) (string, error) {
		commands = append(commands, append([]string{command}, args...))
		if args[0] == "show" {
			return other + "\n", nil
		}
		return "", nil
	}
	if err := revokeWireGuard(context.Background(), target, run); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"wg", "set", "vpnwg0", "peer", target, "remove"}, {"wg", "show", "vpnwg0", "peers"}}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands %v", commands)
	}
}

func TestWireGuardRevokeFailuresCannotReportSuccess(t *testing.T) {
	target := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for _, kind := range []string{"remove", "verify", "still present", "malformed listing", "invalid key"} {
		t.Run(kind, func(t *testing.T) {
			key := target
			if kind == "invalid key" {
				key = target + "; rm -rf /"
			}
			run := func(ctx context.Context, command string, args ...string) (string, error) {
				if kind == "remove" && args[0] == "set" || kind == "verify" && args[0] == "show" {
					return "", errors.New("command failed")
				}
				if args[0] == "show" && kind == "still present" {
					return target, nil
				}
				if args[0] == "show" && kind == "malformed listing" {
					return "not-a-public-key", nil
				}
				return "", nil
			}
			if err := revokeWireGuard(context.Background(), key, run); err == nil {
				t.Fatal("failed WireGuard revocation reported as successful")
			}
		})
	}
}

func TestOpenVPNDoesNotReportFailedDisconnectAsSuccess(t *testing.T) {
	client, server := localManagementPair(t)
	go func() {
		reader := bufio.NewReader(server)
		reader.ReadString('\n')
		fmt.Fprint(server, "HEADER\tCLIENT_LIST\tUsername\tClient ID\nCLIENT_LIST\talice\t7\nEND\n")
		reader.ReadString('\n')
		fmt.Fprintln(server, "ERROR: disconnect failed")
	}()
	if err := revokeOpenVPN(context.Background(), client, "alice"); err == nil {
		t.Fatal("failed disconnect reported as successful")
	}
}

func TestOpenVPNManagementMigrationPreservesConfiguration(t *testing.T) {
	old := "# Managed by VPN Engine\nport 1194\ncustom-directive value\n"
	updated, changed, err := withOpenVPNManagement(old)
	if err != nil || !changed || !strings.HasPrefix(updated, old) || !strings.Contains(updated, openVPNManagementConfig) {
		t.Fatalf("migration %q, changed %v, error %v", updated, changed, err)
	}
	if !strings.Contains(updated, "server-ipv6 fd67:67:ffff::/64") || !strings.Contains(updated, "push \"redirect-gateway ipv6\"") || !strings.Contains(updated, "push \"block-ipv6\"") {
		t.Fatal("legacy IPv4 configuration did not receive a virtual IPv6 route and sink")
	}
	if again, changed, err := withOpenVPNManagement(updated); err != nil || changed || again != updated {
		t.Fatal("migration is not idempotent")
	}
	if _, _, err := withOpenVPNManagement(old + "management 0.0.0.0 7505\n"); err == nil {
		t.Fatal("custom endpoint was overwritten")
	}
	if _, _, err := withOpenVPNManagement("port 1194\n"); err == nil {
		t.Fatal("unmanaged config was changed")
	}
}

func TestVICICodecRejectsMalformedFrames(t *testing.T) {
	known, err := encodeVICI(viciMessage{"success": "yes"})
	if err != nil || !reflect.DeepEqual(known, []byte{3, 7, 's', 'u', 'c', 'c', 'e', 's', 's', 0, 3, 'y', 'e', 's'}) {
		t.Fatalf("VICI wire encoding differs from protocol: %v: %v", known, err)
	}
	want := viciMessage{"key": "value", "owners": []string{"alice", "bob"}, "child": viciMessage{"raw": []byte{0, 1, 255}}}
	encoded, err := encodeVICI(want)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeVICI(encoded)
	if err != nil || viciValue(decoded, "key") != "value" || !reflect.DeepEqual(decoded["owners"], []string{"alice", "bob"}) {
		t.Fatalf("decoded %v: %v", decoded, err)
	}
	for _, malformed := range [][]byte{{2}, {1, 1, 'a'}, {3, 1, 'a', 0, 5, 'x'}, {5, 0, 1, 'a'}, {6}} {
		if _, err := decodeVICI(malformed); err == nil {
			t.Fatalf("accepted malformed message %v", malformed)
		}
	}
}

func TestVICIParsesOfficialCommandResponseFrame(t *testing.T) {
	client, server := localManagementPair(t)
	go func() {
		// uint32 frame length, CMD_RESPONSE, KEY_VALUE, key length and bytes,
		// uint16 value length, value bytes. No command-name field in a reply.
		server.Write([]byte{0, 0, 0, 15, 1, 3, 7, 's', 'u', 'c', 'c', 'e', 's', 's', 0, 3, 'y', 'e', 's'})
	}()
	kind, _, reply, err := (&viciClient{conn: client}).read()
	if err != nil || kind != 1 || viciValue(reply, "success") != "yes" {
		t.Fatalf("could not parse official response frame: %v, %v, %v", kind, reply, err)
	}
}

func sendVICIReply(conn net.Conn, kind byte, event string, msg viciMessage) {
	encoded, _ := encodeVICI(msg)
	body := []byte{kind}
	if kind == 7 {
		body = append(body, byte(len(event)))
		body = append(body, event...)
	}
	body = append(body, encoded...)
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	conn.Write(append(frame, body...))
}

func TestIKECredentialsRemoveOnlyOwnedSecrets(t *testing.T) {
	client, server := localManagementPair(t)
	commands := make(chan []string, 1)
	go func() {
		peer := &viciClient{conn: server}
		var seen []string
		for i := 0; i < 3; i++ {
			_, command, msg, err := peer.read()
			if err != nil {
				break
			}
			seen = append(seen, command+":"+viciValue(msg, "id"))
			sendVICIReply(server, 1, "", viciMessage{"success": "yes"})
		}
		commands <- seen
	}()
	users := []core.User{{Name: "alice", Service: core.IKEv2, Enabled: true, IKESecret: "NewPassword123!"}}
	known := []string{"eap-alice", "eap-vpn-engine-bob", "eap-vpn-engine-alice"}
	if err := syncIKEShared(&viciClient{conn: client}, known, users); err != nil {
		t.Fatal(err)
	}
	want := []string{"unload-shared:eap-alice", "unload-shared:eap-vpn-engine-bob", "load-shared:eap-vpn-engine-alice"}
	if got := <-commands; !reflect.DeepEqual(got, want) {
		t.Fatalf("commands %v, want %v", got, want)
	}
}

func TestIKEFailedRemovalOwnershipSurvivesDesiredConfigRewrite(t *testing.T) {
	path := t.TempDir() + "/owned.json"
	old := []byte("# Managed by VPN Engine\nsecrets {\n  eap-alice {\n    id = alice\n    secret = \"OldPassword123!\"\n  }\n}\n")
	known, err := rememberIKESecretOwnershipAt(path, old, nil)
	if err != nil || !reflect.DeepEqual(known, []string{"eap-alice"}) {
		t.Fatalf("initial ownership %v: %v", known, err)
	}
	// Desired disk configuration removes Alice, but a failed VICI call may leave
	// the old daemon secret loaded. Its ID must survive to be retried.
	known, err = rememberIKESecretOwnershipAt(path, []byte("# Managed by VPN Engine\nsecrets {}\n"), nil)
	if err != nil || !reflect.DeepEqual(known, []string{"eap-alice"}) {
		t.Fatalf("retry lost revoked credential %v: %v", known, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("ownership ledger is not private")
	}
	if _, err := rememberIKESecretOwnershipAt(path, []byte("# Managed by VPN Engine\n  eap-alice {\n unexpected config\n}\n"), nil); err == nil {
		t.Fatal("unrecognized credentials silently skipped")
	}
}

func TestIKEFailedTerminationIsNotReportedAsSuccess(t *testing.T) {
	client, server := localManagementPair(t)
	go func() {
		peer := &viciClient{conn: server}
		peer.read()
		sendVICIReply(server, 5, "", nil)
		peer.read()
		sendVICIReply(server, 7, "list-sa", viciMessage{"vpn-engine": viciMessage{"uniqueid": "1", "state": "ESTABLISHED", "remote-id": "alice"}})
		sendVICIReply(server, 1, "", nil)
		peer.read()
		sendVICIReply(server, 5, "", nil)
		peer.read()
		sendVICIReply(server, 1, "", viciMessage{"success": "no", "matches": "1", "terminated": "0"})
	}()
	if err := revokeIKE(context.Background(), &viciClient{conn: client}, "alice"); err == nil {
		t.Fatal("failed IKE disconnect reported as successful")
	}
}

func TestIKERuntimeRefreshDoesNotSweepOtherConnections(t *testing.T) {
	client, server := localManagementPair(t)
	requests := make(chan []string, 1)
	go func() {
		peer := &viciClient{conn: server}
		var names []string
		for i := 0; i < 2; i++ {
			_, name, msg, err := peer.read()
			if err != nil {
				break
			}
			names = append(names, name)
			if name == "load-conn" {
				connection, ok := msg["vpn-engine"].(viciMessage)
				if !ok || len(msg) != 1 {
					names = append(names, "unexpected connection scope")
				} else {
					local, _ := connection["local"].(viciMessage)
					children, _ := connection["children"].(viciMessage)
					tunnel, _ := children["tunnel"].(viciMessage)
					if viciValue(connection, "version") != "2" || viciValue(local, "id") != "vpn.example" || !reflect.DeepEqual(local["certs"], []string{"test certificate"}) || !reflect.DeepEqual(tunnel["local_ts"], []string{"0.0.0.0/0", "::/0"}) {
						names = append(names, "invalid connection schema")
					}
				}
			} else if name == "load-pool" {
				pool, _ := msg["vpn-engine-pool"].(viciMessage)
				ipv6, _ := msg["vpn-engine-ipv6"].(viciMessage)
				if len(msg) != 2 || viciValue(pool, "addrs") != "10.68.68.0/24" || !reflect.DeepEqual(pool["dns"], []string{"1.1.1.1"}) || viciValue(ipv6, "addrs") != "fd68:68::/64" {
					names = append(names, "invalid pool scope/schema")
				}
			}
			sendVICIReply(server, 1, "", viciMessage{"success": "yes"})
		}
		requests <- names
	}()
	s := core.Service{ID: core.IKEv2, CIDR: "10.68.68.0/24", DNS: "1.1.1.1", Endpoint: "vpn.example", IPv6: true, IPv6CIDR: "fd68:68::/64"}
	if err := loadIKEConfiguration(&viciClient{conn: client}, s, []byte("test certificate")); err != nil {
		t.Fatal(err)
	}
	if got := <-requests; !reflect.DeepEqual(got, []string{"load-pool", "load-conn"}) {
		t.Fatalf("runtime refresh changed unrelated entries: %v", got)
	}
}

func TestIKERevokeTargetsAllUserSAsAndPendingHandshakes(t *testing.T) {
	client, server := localManagementPair(t)
	terminated := make(chan []string, 1)
	go func() {
		peer := &viciClient{conn: server}
		var ids []string
		snapshots := 0
		for {
			kind, command, msg, err := peer.read()
			if err != nil {
				terminated <- ids
				return
			}
			if kind == 3 || kind == 4 {
				sendVICIReply(server, 5, "", nil)
				if kind == 4 && snapshots > 1 {
					terminated <- ids
					return
				}
				continue
			}
			switch command {
			case "list-sas":
				snapshots++
				if snapshots == 1 {
					for _, sa := range []viciMessage{
						{"uniqueid": "1", "state": "ESTABLISHED", "remote-id": "outer", "remote-eap-id": "alice"},
						{"uniqueid": "2", "state": "ESTABLISHED", "remote-id": "alice"},
						{"uniqueid": "3", "state": "ESTABLISHED", "remote-id": "bob"},
						{"uniqueid": "4", "state": "CONNECTING", "remote-id": "unknown"},
					} {
						sendVICIReply(server, 7, "list-sa", viciMessage{"vpn-engine": sa})
					}
					// Even an incorrectly filtered daemon event cannot kill another connection.
					sendVICIReply(server, 7, "list-sa", viciMessage{"external-vpn": viciMessage{"uniqueid": "5", "state": "CONNECTING"}})
				}
				sendVICIReply(server, 1, "", nil)
			case "terminate":
				ids = append(ids, viciValue(msg, "ike-id"))
				sendVICIReply(server, 1, "", viciMessage{"success": "yes", "matches": "1", "terminated": "1"})
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := revokeIKE(ctx, &viciClient{conn: client}, "alice"); err != nil {
		t.Fatal(err)
	}
	if got := <-terminated; !reflect.DeepEqual(got, []string{"1", "2", "4"}) {
		t.Fatalf("terminated %v", got)
	}
}

func TestProtocolIPv6Configurations(t *testing.T) {
	s := core.Service{ID: core.OpenVPN, Port: 1194, CIDR: "10.67.67.0/24", DNS: "1.1.1.1", IPv6: true, IPv6CIDR: "fd67:67::/64"}
	on := ovpnConfig(s, CertPaths{})
	if !strings.Contains(on, "server-ipv6 fd67:67::/64") || strings.Contains(on, "block-ipv6") || !strings.Contains(on, openVPNManagementConfig) {
		t.Fatal("OpenVPN dual-stack configuration missing or incorrectly blocked")
	}
	s.IPv6 = false
	if off := ovpnConfig(s, CertPaths{}); !strings.Contains(off, "block-ipv6") || !strings.Contains(off, "redirect-gateway ipv6") {
		t.Fatal("IPv6-off OpenVPN does not request route-and-block protection")
	}
	s.ID, s.IPv6, s.IPv6CIDR = core.IKEv2, true, "fd68:68::/64"
	if ike := swanctlConfig(s, nil); !strings.Contains(ike, "local_ts = 0.0.0.0/0, ::/0") || !strings.Contains(ike, "addrs = fd68:68::/64") {
		t.Fatal("IKEv2 dual-stack selectors/pool missing")
	}
}

func TestOpenVPNIPv6SinkRoutePreflightPreservesHostNetworks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		routes  string
		managed bool
		wantErr bool
	}{
		{"IPv4-only host", "", false, false},
		{"ordinary IPv6 routes", "default via fe80::1 dev eth0\n2001:db8:1::/64 dev eth0\nlocal ::1 dev lo\nanycast fe80:: dev eth0\n", false, false},
		{"same host subnet", "fd67:67:ffff::/64 dev eth0\n", false, true},
		{"host address only", "local fd67:67:ffff::123 dev eth0 table local\n", false, true},
		{"aggregate blackhole", "blackhole fd67:67::/32\n", false, true},
		{"managed sink already installed", "fd67:67:ffff::/64 dev tun-vpneng\nlocal fd67:67:ffff::1 dev tun-vpneng table local\n", true, false},
		{"unmanaged interface with same name", "fd67:67:ffff::/64 dev tun-vpneng\n", false, true},
		{"malformed route output", "invalid-routing-output\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOpenVPNIPv6SinkRoutes(tc.routes, tc.managed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("preflight error %v, expected error %v", err, tc.wantErr)
			}
		})
	}
}

func TestOpenVPNIPv6DisabledHostKeepsIPv4ServerWorking(t *testing.T) {
	s := core.Service{ID: core.OpenVPN, Port: 1194, CIDR: "10.67.67.0/24", DNS: "1.1.1.1"}
	conf := ovpnConfigForHost(s, CertPaths{}, false)
	if strings.Contains(conf, "server-ipv6") || !strings.Contains(conf, "server 10.67.67.0 255.255.255.0") || !openVPNHasClientIPv6Blocking(conf) || !strings.Contains(conf, "requires a compatible client") {
		t.Fatal("disabled-host configuration either configures host IPv6 or omits client protection/limitation")
	}
	old := "# Managed by VPN Engine\nport 1194\nserver 10.67.67.0 255.255.255.0\n"
	updated, changed, err := withOpenVPNManagementForHost(old, false)
	if err != nil || !changed || strings.Contains(updated, "server-ipv6") || !strings.HasPrefix(updated, old) || !openVPNHasClientIPv6Blocking(updated) {
		t.Fatalf("disabled-host migration failed: changed %v, error %v", changed, err)
	}
	if again, changed, err := withOpenVPNManagementForHost(updated, false); err != nil || changed || again != updated {
		t.Fatal("disabled-host migration is not idempotent")
	}
	existingSink := old + openVPNIPv6OffConfig(true) + openVPNManagementConfig
	updated, changed, err = withOpenVPNManagementForHost(existingSink, false)
	if err != nil || !changed || strings.Contains(updated, "server-ipv6") || !openVPNHasClientIPv6Blocking(updated) {
		t.Fatal("previous managed sink was not safely converted to client-only blocking")
	}
}
