package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yulcaribe/vpnengine/internal/core"
)

const openVPNManagementSocket = "/run/vpn-engine/openvpn.sock"
const openVPNManagementConfig = "management " + openVPNManagementSocket + " unix\nmanagement-client-user root\nmanagement-client-group root\n"
const OpenVPNManagementUnit = "/etc/systemd/system/openvpn-server@vpnengine.service.d/vpn-engine-management.conf"
const viciSocket = "/var/run/charon.vici"

func ensureOpenVPNManagementDir() error {
	if err := os.MkdirAll(filepath.Dir(openVPNManagementSocket), 0700); err != nil {
		return err
	}
	info, err := os.Lstat(filepath.Dir(openVPNManagementSocket))
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || stat.Uid != 0 {
		return errors.New("OpenVPN management directory must be owned by root")
	}
	return os.Chmod(filepath.Dir(openVPNManagementSocket), 0700)
}

func ensureOpenVPNRuntime(ctx context.Context) error {
	if err := ensureOpenVPNManagementDir(); err != nil {
		return err
	}
	// /run is cleared on reboot. The existing OpenVPN unit creates its own
	// protected control directory before it tries to bind the Unix socket.
	want := []byte("[Service]\nRuntimeDirectory=vpn-engine\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=restart\n")
	existing, err := os.ReadFile(OpenVPNManagementUnit)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && string(existing) != string(want) {
		return errors.New("refusing to replace a custom OpenVPN management unit override")
	}
	if os.IsNotExist(err) {
		if err = write0600(OpenVPNManagementUnit, want); err != nil {
			return err
		}
	}
	return quiet(ctx, "systemctl", "daemon-reload")
}

// EnsureOpenVPNManagement migrates only the managed configuration. A one-time
// restart is necessary to create the socket; profiles and key material stay intact.
func (Manager) EnsureOpenVPNManagement(ctx context.Context) error {
	if !ServiceInstalled(core.OpenVPN) {
		return nil
	}
	old, err := os.ReadFile(OVPNConf)
	if err != nil {
		return err
	}
	hostIPv6 := OpenVPNIPv6HostEnabled()
	updated, changed, err := withOpenVPNManagementForHost(string(old), hostIPv6)
	if err != nil {
		return err
	}
	if hostIPv6 && !openVPNHasIPv6Server(string(old)) && !openVPNHasClientIPv6Blocking(string(old)) {
		if err = CheckOpenVPNIPv6Sink(ctx); err != nil {
			return err
		}
	}
	if err = ensureOpenVPNRuntime(ctx); err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if err = write0600(OVPNConf, []byte(updated)); err != nil {
		return err
	}
	if Status(core.OpenVPN) != "running" {
		return nil
	}
	if err = quiet(ctx, "systemctl", "restart", SystemdUnit(core.OpenVPN)); err == nil {
		err = quiet(ctx, "systemctl", "is-active", "--quiet", SystemdUnit(core.OpenVPN))
	}
	if err != nil {
		recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		writeErr := write0600(OVPNConf, old)
		restartErr := quiet(recovery, "systemctl", "restart", SystemdUnit(core.OpenVPN))
		return fmt.Errorf("OpenVPN management migration failed: %w; restore configuration: %v; restore service: %v", err, writeErr, restartErr)
	}
	return nil
}

func withOpenVPNManagement(conf string) (string, bool, error) {
	return withOpenVPNManagementForHost(conf, true)
}

func withOpenVPNManagementForHost(conf string, hostIPv6 bool) (string, bool, error) {
	if !strings.Contains(conf, "Managed by VPN Engine") {
		return "", false, errors.New("refusing to modify unmanaged OpenVPN configuration")
	}
	original := conf
	if !hostIPv6 && strings.Contains(conf, "push \"block-ipv6\"") {
		// A previously installed IPv6-off sink must not prevent an IPv4 service
		// restart after an administrator disables IPv6 on the host.
		var kept []string
		for _, line := range strings.Split(conf, "\n") {
			if strings.TrimSpace(line) != "server-ipv6 "+OpenVPNIPv6Sink {
				kept = append(kept, line)
			}
		}
		conf = strings.Join(kept, "\n")
	}
	seen := map[string]bool{}
	hasIPv6 := false
	for _, line := range strings.Split(conf, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], ";") {
			continue
		}
		switch fields[0] {
		case "server-ipv6":
			hasIPv6 = true
		case "management":
			if len(fields) != 3 || fields[1] != openVPNManagementSocket || fields[2] != "unix" {
				return "", false, errors.New("managed OpenVPN has a custom management endpoint; refusing to replace it")
			}
			seen[fields[0]] = true
		case "management-client-user", "management-client-group":
			if len(fields) != 2 || fields[1] != "root" {
				return "", false, errors.New("OpenVPN management must accept root only")
			}
			seen[fields[0]] = true
		}
	}
	addition := ""
	for _, line := range strings.Split(strings.TrimSpace(openVPNManagementConfig), "\n") {
		if !seen[strings.Fields(line)[0]] {
			addition += line + "\n"
		}
	}
	// Legacy IPv4 profiles already pull server options, so a one-time migration
	// can provide a virtual IPv6 route and sink without replacing their keys.
	if !hasIPv6 && !openVPNHasClientIPv6Blocking(conf) {
		addition += openVPNIPv6OffConfig(hostIPv6)
	}
	if addition == "" {
		return conf, conf != original, nil
	}
	return strings.TrimRight(conf, "\n") + "\n" + addition, true, nil
}

// RevokeUser is called after the desired account state and credentials have been
// persisted. Failure must not cause callers to re-enable revoked credentials.
func (Manager) RevokeUser(ctx context.Context, s core.Service, u core.User) error {
	if !core.IsService(s.ID) || !ValidUsername(u.Name) || s.ID != u.Service {
		return errors.New("invalid user revocation")
	}
	running, err := managementServiceRunning(ctx, s.ID)
	if err != nil {
		return err
	}
	if !running {
		return nil
	}
	switch s.ID {
	case core.WireGuard:
		return revokeWireGuard(ctx, u.PublicKey, managementCommandOutput)
	case core.OpenVPN:
		conn, err := rootSocket(ctx, openVPNManagementSocket, true)
		if err != nil {
			return fmt.Errorf("OpenVPN local session control unavailable: %w", err)
		}
		defer conn.Close()
		stop := cancelSocket(ctx, conn)
		defer stop()
		return revokeOpenVPN(ctx, conn, u.Name)
	case core.IKEv2:
		client, err := dialVICI(ctx)
		if err != nil {
			return err
		}
		defer client.conn.Close()
		stop := cancelSocket(ctx, client.conn)
		defer stop()
		return revokeIKE(ctx, client, u.Name)
	default:
		return errors.New("unsupported service")
	}
}

type managementOutput struct{ bytes.Buffer }

func (out *managementOutput) Write(p []byte) (int, error) {
	if out.Len()+len(p) > 512*1024 {
		return 0, errors.New("management command output too large")
	}
	return out.Buffer.Write(p)
}

func managementCommandOutput(ctx context.Context, command string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	out := &managementOutput{}
	cmd.Stdout = out
	err := cmd.Run()
	return out.String(), err
}

func validWGPublicKey(key string) bool {
	raw, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == key
}

func revokeWireGuard(ctx context.Context, publicKey string, run func(context.Context, string, ...string) (string, error)) error {
	if !validWGPublicKey(publicKey) {
		return errors.New("cannot revoke WireGuard peer: invalid public key")
	}
	if _, err := run(ctx, "wg", "set", InterfaceFor(core.WireGuard), "peer", publicKey, "remove"); err != nil {
		return fmt.Errorf("WireGuard targeted peer removal failed: %w", err)
	}
	peers, err := run(ctx, "wg", "show", InterfaceFor(core.WireGuard), "peers")
	if err != nil {
		return fmt.Errorf("cannot verify WireGuard peer removal: %w", err)
	}
	for _, peer := range strings.Fields(peers) {
		if !validWGPublicKey(peer) {
			return errors.New("cannot verify WireGuard peer removal: invalid peer listing")
		}
		if peer == publicKey {
			return errors.New("WireGuard peer remains active; credentials remain revoked")
		}
	}
	return nil
}

func managementServiceRunning(ctx context.Context, id string) (bool, error) {
	output, err := exec.CommandContext(ctx, "systemctl", "is-active", SystemdUnit(id)).Output()
	state := strings.TrimSpace(string(output))
	if err == nil && state == "active" {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 3 {
		switch state {
		case "inactive", "failed":
			return false, nil
		case "activating", "reloading", "deactivating":
			return true, nil // Connections may still exist during a transition.
		}
	}
	if err == nil {
		err = errors.New("unexpected service state")
	}
	return false, fmt.Errorf("cannot confirm %s service state: %s: %w", id, state, err)
}

func rootSocket(ctx context.Context, path string, protectedDirectory bool) (net.Conn, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSocket == 0 || !ok || stat.Uid != 0 {
		return nil, errors.New("management endpoint must be a root-owned Unix socket")
	}
	if protectedDirectory {
		dir, e := os.Lstat(filepath.Dir(path))
		if e != nil {
			return nil, e
		}
		owner, ok := dir.Sys().(*syscall.Stat_t)
		if !dir.IsDir() || !ok || owner.Uid != 0 || dir.Mode().Perm()&0077 != 0 {
			return nil, errors.New("management directory must be accessible only to root")
		}
	} else if info.Mode().Perm()&0007 != 0 || stat.Gid != 0 && info.Mode().Perm()&0070 != 0 {
		return nil, errors.New("VICI socket must be accessible only to root")
	}
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

func cancelSocket(ctx context.Context, conn net.Conn) func() {
	deadline := time.Now().Add(30 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	return func() { stop() }
}

func waitManagement(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func revokeOpenVPN(ctx context.Context, conn net.Conn, name string) error {
	reader := bufio.NewReaderSize(conn, 4096)
	for tries := 0; tries < 50; tries++ {
		if _, err := io.WriteString(conn, "status 3\n"); err != nil {
			return err
		}
		var lines []string
		for count := 0; ; count++ {
			if count > 10000 {
				return errors.New("OpenVPN management response too large")
			}
			line, err := managementLine(reader)
			if err != nil {
				return err
			}
			if line == "END" {
				break
			}
			if strings.HasPrefix(line, "ERROR:") {
				return errors.New("OpenVPN status query failed")
			}
			lines = append(lines, line)
		}
		ids, err := openVPNSessions(lines, name)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		for _, id := range ids {
			if _, err = io.WriteString(conn, "client-kill "+id+"\n"); err != nil {
				return err
			}
			line, e := managementLine(reader)
			if e != nil {
				return e
			}
			if !strings.HasPrefix(line, "SUCCESS:") {
				return errors.New("OpenVPN could not terminate the selected client; credentials remain revoked")
			}
		}
		if err := waitManagement(ctx); err != nil {
			return err
		}
	}
	return errors.New("OpenVPN client disconnect was not confirmed; credentials remain revoked")
}

func managementLine(reader *bufio.Reader) (string, error) {
	for count := 0; count < 1000; count++ {
		var raw []byte
		for {
			part, err := reader.ReadSlice('\n')
			if len(raw)+len(part) > 16384 {
				return "", errors.New("OpenVPN management line too long")
			}
			raw = append(raw, part...)
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				return "", err
			}
			break
		}
		line := strings.TrimSpace(string(raw))
		if line != "" && !strings.HasPrefix(line, ">") {
			return line, nil
		}
	}
	return "", errors.New("OpenVPN management response did not finish")
}

func openVPNSessions(lines []string, name string) ([]string, error) {
	var columns []string
	var ids []string
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) > 2 && fields[0] == "HEADER" && fields[1] == "CLIENT_LIST" {
			columns = fields[2:]
			continue
		}
		if len(fields) == 0 || fields[0] != "CLIENT_LIST" {
			continue
		}
		if len(columns) == 0 || len(fields) != len(columns)+1 {
			return nil, errors.New("unsupported OpenVPN client status format")
		}
		values := map[string]string{}
		for i, column := range columns {
			values[column] = fields[i+1]
		}
		identity := values["Username"]
		if identity == "" || identity == "UNDEF" {
			identity = values["Common Name"]
		}
		// An unidentified handshake can already hold authentication state. As
		// with IKEv2, it may retry; identified unrelated users are preserved.
		if identity != name && identity != "" && identity != "UNDEF" {
			continue
		}
		id := values["Client ID"]
		if _, err := strconv.ParseUint(id, 10, 64); err != nil {
			return nil, errors.New("OpenVPN did not supply a valid client ID")
		}
		ids = append(ids, id)
	}
	if columns == nil {
		return nil, errors.New("OpenVPN did not supply a client status header")
	}
	return ids, nil
}

type viciMessage map[string]any
type viciClient struct{ conn net.Conn }

func dialVICI(ctx context.Context) (*viciClient, error) {
	conn, err := rootSocket(ctx, viciSocket, false)
	if err != nil {
		return nil, fmt.Errorf("strongSwan local VICI control unavailable: %w", err)
	}
	return &viciClient{conn: conn}, nil
}

func (c *viciClient) packet(kind byte, name string, msg viciMessage) error {
	if len(name) > 255 {
		return errors.New("VICI command name too long")
	}
	body := []byte{kind, byte(len(name))}
	body = append(body, name...)
	encoded, err := encodeVICI(msg)
	if err != nil {
		return err
	}
	body = append(body, encoded...)
	if len(body) > 512*1024 {
		return errors.New("VICI message too large")
	}
	frame := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	frame = append(frame, body...)
	_, err = c.conn.Write(frame)
	return err
}

func (c *viciClient) read() (byte, string, viciMessage, error) {
	var header [4]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return 0, "", nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size < 1 || size > 512*1024 {
		return 0, "", nil, errors.New("invalid VICI frame size")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return 0, "", nil, err
	}
	kind, offset, name := body[0], 1, ""
	if kind == 0 || kind == 3 || kind == 4 || kind == 7 {
		if len(body) < 2 || int(body[1])+2 > len(body) {
			return 0, "", nil, errors.New("invalid VICI packet name")
		}
		offset = int(body[1]) + 2
		name = string(body[2:offset])
	}
	msg, err := decodeVICI(body[offset:])
	return kind, name, msg, err
}

func (c *viciClient) command(name string, msg viciMessage) (viciMessage, error) {
	if err := c.packet(0, name, msg); err != nil {
		return nil, err
	}
	kind, _, reply, err := c.read()
	if err != nil {
		return nil, err
	}
	if kind != 1 {
		return nil, fmt.Errorf("strongSwan does not support VICI command %s", name)
	}
	return reply, nil
}

func viciValue(msg viciMessage, key string) string {
	switch value := msg[key].(type) {
	case []byte:
		return string(value)
	case string:
		return value
	default:
		return ""
	}
}

func viciSucceeded(reply viciMessage, operation string) error {
	if viciValue(reply, "success") != "yes" {
		return fmt.Errorf("strongSwan %s failed: %s", operation, viciValue(reply, "errmsg"))
	}
	return nil
}

func encodeVICI(msg viciMessage) ([]byte, error) {
	var out []byte
	keys := make([]string, 0, len(msg))
	for key := range msg {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(key) > 255 {
			return nil, errors.New("VICI element name too long")
		}
		value := msg[key]
		switch value := value.(type) {
		case viciMessage:
			out = append(out, 1, byte(len(key)))
			out = append(out, key...)
			child, err := encodeVICI(value)
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
			out = append(out, 2)
		case []string:
			out = append(out, 4, byte(len(key)))
			out = append(out, key...)
			for _, entry := range value {
				if len(entry) > 65535 {
					return nil, errors.New("VICI value too long")
				}
				out = append(out, 5, byte(len(entry)>>8), byte(len(entry)))
				out = append(out, entry...)
			}
			out = append(out, 6)
		case string, []byte:
			var raw []byte
			if text, ok := value.(string); ok {
				raw = []byte(text)
			} else {
				raw = value.([]byte)
			}
			if len(raw) > 65535 {
				return nil, errors.New("VICI value too long")
			}
			out = append(out, 3, byte(len(key)))
			out = append(out, key...)
			out = append(out, byte(len(raw)>>8), byte(len(raw)))
			out = append(out, raw...)
		default:
			return nil, errors.New("unsupported VICI value")
		}
	}
	return out, nil
}

func decodeVICI(body []byte) (viciMessage, error) {
	root := viciMessage{}
	stack := []viciMessage{root}
	listName := ""
	var list []string
	name := func() (string, error) {
		if len(body) < 1 || int(body[0])+1 > len(body) {
			return "", io.ErrUnexpectedEOF
		}
		n := int(body[0])
		value := string(body[1 : n+1])
		body = body[n+1:]
		return value, nil
	}
	value := func() ([]byte, error) {
		if len(body) < 2 {
			return nil, io.ErrUnexpectedEOF
		}
		n := int(binary.BigEndian.Uint16(body[:2]))
		if n+2 > len(body) {
			return nil, io.ErrUnexpectedEOF
		}
		result := body[2 : n+2]
		body = body[n+2:]
		return result, nil
	}
	for len(body) > 0 {
		kind := body[0]
		body = body[1:]
		current := stack[len(stack)-1]
		if listName != "" && kind != 5 && kind != 6 {
			return nil, errors.New("invalid VICI list")
		}
		switch kind {
		case 1, 3, 4:
			key, err := name()
			if err != nil || key == "" {
				return nil, errors.New("invalid VICI element name")
			}
			switch kind {
			case 1:
				if len(stack) >= 64 {
					return nil, errors.New("VICI nesting too deep")
				}
				child := viciMessage{}
				current[key] = child
				stack = append(stack, child)
			case 3:
				raw, err := value()
				if err != nil {
					return nil, err
				}
				current[key] = raw
			case 4:
				listName, list = key, nil
			}
		case 2:
			if len(stack) <= 1 {
				return nil, errors.New("unbalanced VICI section")
			}
			stack = stack[:len(stack)-1]
		case 5:
			if listName == "" {
				return nil, errors.New("VICI list item outside list")
			}
			raw, err := value()
			if err != nil {
				return nil, err
			}
			list = append(list, string(raw))
		case 6:
			if listName == "" {
				return nil, errors.New("VICI list end outside list")
			}
			current[listName] = list
			listName, list = "", nil
		default:
			return nil, errors.New("unknown VICI element")
		}
	}
	if len(stack) != 1 || listName != "" {
		return nil, errors.New("incomplete VICI message")
	}
	return root, nil
}

var managedIKESecret = regexp.MustCompile(`(?m)^[ \t]*(eap-[A-Za-z][A-Za-z0-9_.-]*)[ \t]*\{[ \t]*\r?\n[ \t]*id[ \t]*=[ \t]*([A-Za-z][A-Za-z0-9_.-]{0,31})[ \t]*\r?\n[ \t]*secret[ \t]*=[ \t]*"([^"\r\n]*)"[ \t]*\r?\n[ \t]*\}`)
var managedIKESecretHeader = regexp.MustCompile(`(?m)^[ \t]*eap-[A-Za-z][A-Za-z0-9_.-]*[ \t]*\{`)

func ikeSecretIDs(users []core.User) []string {
	var ids []string
	for _, user := range users {
		if user.Service == core.IKEv2 && user.Enabled {
			ids = append(ids, "eap-vpn-engine-"+user.Name)
		}
	}
	sort.Strings(ids)
	return ids
}

func rememberIKESecretOwnership(old []byte, users []core.User) ([]string, error) {
	return rememberIKESecretOwnershipAt(filepath.Join(DataDir, "pki", core.IKEv2, "shared-secret-ids.json"), old, users)
}

func rememberIKESecretOwnershipAt(path string, old []byte, users []core.User) ([]string, error) {
	if !strings.Contains(string(old), "Managed by VPN Engine") {
		return nil, errors.New("refusing to unload credentials from unmanaged IKEv2 configuration")
	}
	known := ikeSecretIDs(users)
	previous, err := os.ReadFile(path)
	if err == nil {
		var ids []string
		if err = json.Unmarshal(previous, &ids); err != nil {
			return nil, errors.New("invalid IKEv2 credential ownership record")
		}
		known = append(known, ids...)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	matches := managedIKESecret.FindAllSubmatch(old, -1)
	if len(matches) != len(managedIKESecretHeader.FindAll(old, -1)) {
		return nil, errors.New("cannot safely identify managed IKEv2 secrets")
	}
	for _, match := range matches {
		id, name := string(match[1]), string(match[2])
		if id != "eap-"+name && id != "eap-vpn-engine-"+name {
			return nil, errors.New("unknown managed IKEv2 secret label")
		}
		known = append(known, id)
	}
	unique := map[string]bool{}
	for _, id := range known {
		name := strings.TrimPrefix(id, "eap-")
		if strings.HasPrefix(id, "eap-vpn-engine-") {
			name = strings.TrimPrefix(id, "eap-vpn-engine-")
		}
		if !strings.HasPrefix(id, "eap-") || !ValidUsername(name) {
			return nil, errors.New("invalid IKEv2 credential ownership record")
		}
		unique[id] = true
	}
	known = known[:0]
	for id := range unique {
		known = append(known, id)
	}
	sort.Strings(known)
	data, _ := json.Marshal(known)
	// Retain old IDs until refresh succeeds, so a failed removal remains retryable
	// even though the desired config no longer contains the revoked account.
	if err = write0600(path, data); err != nil {
		return nil, err
	}
	return known, nil
}

func refreshIKECredentials(ctx context.Context, known []string, users []core.User) error {
	client, err := dialVICI(ctx)
	if err != nil {
		return err
	}
	defer client.conn.Close()
	stop := cancelSocket(ctx, client.conn)
	defer stop()
	if err = syncIKEShared(client, known, users); err != nil {
		return err
	}
	data, _ := json.Marshal(ikeSecretIDs(users))
	return write0600(filepath.Join(DataDir, "pki", core.IKEv2, "shared-secret-ids.json"), data)
}

// RefreshIKEv2 changes only VPN Engine's named connection and pools. The swanctl
// bulk loaders remove other daemon entries missing from a partial config file.
func (Manager) RefreshIKEv2(ctx context.Context, s core.Service) error {
	if s.ID != core.IKEv2 {
		return errors.New("invalid IKEv2 service")
	}
	client, err := dialVICI(ctx)
	if err != nil {
		return err
	}
	defer client.conn.Close()
	stop := cancelSocket(ctx, client.conn)
	defer stop()
	paths := PKIPaths(core.IKEv2)
	for _, item := range []struct{ path, command, kind, flag string }{
		{paths.CA, "load-cert", "X509", "CA"},
		{paths.Server, "load-cert", "X509", "NONE"},
		{paths.Key, "load-key", "any", ""},
	} {
		raw, err := os.ReadFile(item.path)
		if err != nil {
			return err
		}
		request := viciMessage{"type": item.kind, "data": raw}
		if item.flag != "" {
			request["flag"] = item.flag
		}
		reply, err := client.command(item.command, request)
		if err != nil {
			return err
		}
		if err = viciSucceeded(reply, item.command); err != nil {
			return err
		}
	}
	server, err := os.ReadFile(paths.Server)
	if err != nil {
		return err
	}
	return loadIKEConfiguration(client, s, server)
}

func loadIKEConfiguration(client *viciClient, s core.Service, server []byte) error {
	pools := []string{"vpn-engine-pool"}
	selectors := []string{"0.0.0.0/0"}
	request := viciMessage{"vpn-engine-pool": viciMessage{"addrs": s.CIDR, "dns": []string{s.DNS}}}
	if s.IPv6 {
		request["vpn-engine-ipv6"] = viciMessage{"addrs": s.IPv6CIDR}
		pools = append(pools, "vpn-engine-ipv6")
		selectors = append(selectors, "::/0")
	}
	reply, err := client.command("load-pool", request)
	if err != nil {
		return err
	}
	if err = viciSucceeded(reply, "managed pool update"); err != nil {
		return err
	}
	request = viciMessage{"vpn-engine": viciMessage{
		"version": "2", "local_addrs": []string{"%any"}, "pools": pools,
		"fragmentation": "yes", "send_cert": "always", "mobike": "yes",
		"local":    viciMessage{"auth": "pubkey", "id": s.Endpoint, "certs": []string{string(server)}},
		"remote":   viciMessage{"auth": "eap-mschapv2", "eap_id": "%any"},
		"children": viciMessage{"tunnel": viciMessage{"local_ts": selectors, "rekey_time": "0s"}},
	}}
	reply, err = client.command("load-conn", request)
	if err != nil {
		return err
	}
	return viciSucceeded(reply, "managed connection update")
}

func syncIKEShared(client *viciClient, known []string, users []core.User) error {
	desired := map[string]core.User{}
	for _, user := range users {
		if user.Service == core.IKEv2 && user.Enabled {
			if !ValidUsername(user.Name) || !ValidIKEPassword(user.IKESecret) {
				return errors.New("invalid IKEv2 credentials")
			}
			desired["eap-vpn-engine-"+user.Name] = user
		}
	}
	for _, id := range known {
		if _, exists := desired[id]; exists {
			continue // load-shared replaces this secret atomically.
		}
		reply, err := client.command("unload-shared", viciMessage{"id": id})
		if err != nil {
			return err
		}
		if err = viciSucceeded(reply, "credential removal"); err != nil {
			return err
		}
	}
	ids := make([]string, 0, len(desired))
	for id := range desired {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		user := desired[id]
		reply, err := client.command("load-shared", viciMessage{"id": id, "type": "EAP", "data": []byte(user.IKESecret), "owners": []string{user.Name}})
		if err != nil {
			return err
		}
		if err = viciSucceeded(reply, "credential update"); err != nil {
			return err
		}
	}
	return nil
}

func (c *viciClient) sas() ([]viciMessage, error) {
	if err := c.packet(3, "list-sa", nil); err != nil {
		return nil, err
	}
	kind, _, _, err := c.read()
	if err != nil || kind != 5 {
		return nil, errors.New("strongSwan does not support session enumeration")
	}
	if err := c.packet(0, "list-sas", viciMessage{"ike": "vpn-engine"}); err != nil {
		return nil, err
	}
	var sessions []viciMessage
	for count := 0; count < 10000; count++ {
		kind, event, msg, err := c.read()
		if err != nil {
			return nil, err
		}
		if kind == 1 {
			if err = c.packet(4, "list-sa", nil); err != nil {
				return nil, err
			}
			kind, _, _, err = c.read()
			if err != nil || kind != 5 {
				return nil, errors.New("strongSwan session enumeration did not finish")
			}
			return sessions, nil
		}
		if kind != 7 || event != "list-sa" {
			return nil, errors.New("unexpected strongSwan session response")
		}
		if session, ok := msg["vpn-engine"].(viciMessage); ok {
			sessions = append(sessions, session)
		}
	}
	return nil, errors.New("strongSwan session response too large")
}

func revokeIKE(ctx context.Context, client *viciClient, name string) error {
	for tries := 0; tries < 50; tries++ {
		sessions, err := client.sas()
		if err != nil {
			return err
		}
		var targets []string
		for _, session := range sessions {
			identity := viciValue(session, "remote-eap-id")
			if identity == "" {
				identity = viciValue(session, "remote-id")
			}
			// An already authenticated but incomplete EAP exchange may hold its
			// old MSK without exposing the username. Established other users stay.
			if identity != name && viciValue(session, "state") != "CONNECTING" {
				continue
			}
			id := viciValue(session, "uniqueid")
			if _, err := strconv.ParseUint(id, 10, 64); err != nil {
				return errors.New("strongSwan did not supply a valid session ID")
			}
			targets = append(targets, id)
		}
		if len(targets) == 0 {
			return nil
		}
		for _, id := range targets {
			reply, err := client.command("terminate", viciMessage{"ike-id": id, "force": "yes", "timeout": "5000"})
			if err != nil {
				return err
			}
			// A session may disappear between enumeration and termination.
			if viciValue(reply, "success") != "yes" && viciValue(reply, "matches") != "0" {
				return errors.New("strongSwan could not terminate the selected session; credentials remain revoked")
			}
		}
		if err := waitManagement(ctx); err != nil {
			return err
		}
	}
	return errors.New("IKEv2 session disconnect was not confirmed; credentials remain revoked")
}
