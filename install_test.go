package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Installer tests source its functions and substitute package, service and network
// commands. Every file operation stays under t.TempDir; no host setup is performed.
func runInstallerShell(t *testing.T, dir, body string) (string, error) {
	t.Helper()
	installer, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", "source \"$1\"\ntest_root=\"$2\"\n"+body, "installer-test", installer, dir)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestInstallerHelpHasNoHTTPFlag(t *testing.T) {
	output, err := runInstallerShell(t, t.TempDir(), `main --help`)
	if err != nil || strings.Contains(output, "--allow-http") || !strings.Contains(output, "Usage: bash install.sh") {
		t.Fatalf("installer help still requires HTTP flag: %v\n%s", err, output)
	}
}

func TestInstallerMissingUnitsAreNotReportedAsErrors(t *testing.T) {
	dir := t.TempDir()
	output, err := runInstallerShell(t, dir, `
ENGINE="$test_root/engine"
SERVICE="$test_root/service"
NGINX_SITE="$test_root/nginx-site"
NGINX_ENABLED="$test_root/nginx-enabled"
HTTPS_IP_FILE="$test_root/https-ip"
ALLOW_HTTP_FILE="$test_root/allow-http"
RENEW_SCRIPT="$test_root/renew-script"
RENEW_SERVICE="$test_root/renew-service"
RENEW_TIMER="$test_root/renew-timer"
WORK_DIR="$test_root/work"
mkdir -p "$WORK_DIR"
systemctl() {
  if [[ "$1" = is-enabled ]]; then
    printf 'Failed to get unit file state for %s: No such file or directory\n' "${@: -1}" >&2
  fi
  return 1
}
backup_installation
[[ "$OLD_PANEL_ACTIVE:$OLD_PANEL_ENABLED:$OLD_NGINX_ACTIVE:$OLD_NGINX_ENABLED:$OLD_TIMER_ACTIVE:$OLD_TIMER_ENABLED" = "no:no:no:no:no:no" ]]
`)
	if err != nil || strings.Contains(output, "Failed to get unit file state") {
		t.Fatalf("missing units should not print diagnostics: %v\n%s", err, output)
	}
}

func TestInstallerPortWithoutControllingTerminal(t *testing.T) {
	for _, openTTY := range []string{"open_tty() { return 1; }", "open_tty() { exec {TTY_FD}< /dev/null; }"} {
		output, err := runInstallerShell(t, t.TempDir(), openTTY+"\nPANEL_PORT=51821\nchoose_port\n[ \"$PANEL_PORT\" = 51821 ]")
		if err != nil {
			t.Fatalf("noninteractive port selection: %v\n%s", err, output)
		}
	}
}

func TestInstallerChallengeSiteDoesNotExposePanel(t *testing.T) {
	dir := t.TempDir()
	output, err := runInstallerShell(t, dir, `
NGINX_SITE="$test_root/nginx"
PUBLIC_IP=203.0.113.10
ACME_WEBROOT="$test_root/acme"
PANEL_PORT=51821
write_http_nginx
`)
	if err != nil {
		t.Fatalf("challenge site: %v\n%s", err, output)
	}
	config, err := os.ReadFile(filepath.Join(dir, "nginx"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "proxy_pass") || !strings.Contains(string(config), "return 503;") || !strings.Contains(string(config), "/.well-known/acme-challenge/") {
		t.Fatalf("the certificate challenge site exposes the panel: %s", config)
	}
}

func TestInstallerGoVersionValidation(t *testing.T) {
	output, err := runInstallerShell(t, t.TempDir(), `
version_at_least 1.22.2 1.22
! version_at_least 1.21.9 1.22
version_at_least 1.27 1.22
! version_at_least invalid 1.22
`)
	if err != nil {
		t.Fatalf("Go version validation: %v\n%s", err, output)
	}
}

func TestInstallerReusesSystemGo(t *testing.T) {
	output, err := runInstallerShell(t, t.TempDir(), `
REQUIRED_GO=1.22
go() {
  if [ "$1" = version ]; then echo "go version go1.23.2 linux/amd64"; else return 1; fi
}
curl() { echo UNEXPECTED_DOWNLOAD; return 1; }
prepare_go
[ "$GO_BIN" = "$(command -v go)" ]
`)
	if err != nil || strings.Contains(output, "UNEXPECTED_DOWNLOAD") {
		t.Fatalf("installed Go must be reused without download: %v\n%s", err, output)
	}
}

func TestInstallerCompilesAndValidatesCandidate(t *testing.T) {
	output, err := runInstallerShell(t, t.TempDir(), `
WORK_DIR="$test_root/work"
mkdir -p "$WORK_DIR/source"
ARCH=amd64
download_source() { RELEASE_TAG=1.2.3+0123456789ab; }
prepare_go() {
  GO_BIN="$test_root/fake-go"
  cat > "$GO_BIN" <<'FAKE'
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then shift; output="$1"; break; fi
  shift
done
cat > "$output" <<'CANDIDATE'
#!/usr/bin/env bash
printf 'VPN Engine 1.2.3+0123456789ab\n'
CANDIDATE
chmod +x "$output"
FAKE
  chmod +x "$GO_BIN"
}
build_from_source
[ -x "$CANDIDATE" ]
[ "$RELEASE_TAG" = 1.2.3+0123456789ab ]
`)
	if err != nil {
		t.Fatalf("source compilation and version check: %v\n%s", err, output)
	}
}

func TestInstallerCleansBuildFilesEvenOnRollbackFailure(t *testing.T) {
	for _, badRollback := range []bool{false, true} {
		dir := t.TempDir()
		prefix := "WORK_DIR=\"$test_root/work\"\n" +
			"mkdir -p \"$WORK_DIR/backup\" \"$WORK_DIR/source\" \"$WORK_DIR/go-runtime\" \"$WORK_DIR/go-cache\" \"$WORK_DIR/go-path\" \"$WORK_DIR/go-tmp\"\n" +
			"printf 'source' > \"$WORK_DIR/source.tar.gz\"\n" +
			"printf 'go' > \"$WORK_DIR/go-toolchain.tar.gz\"\n"
		if badRollback {
			prefix += "TRANSACTION_STARTED=yes\nCOMMITTED=no\nrollback_installation() { return 1; }\n"
		} else {
			prefix += "TRANSACTION_STARTED=no\nCOMMITTED=yes\n"
		}
		_, _ = runInstallerShell(t, dir, prefix+"finish_installation\n")
		work := filepath.Join(dir, "work")
		for _, name := range []string{"source", "go-runtime", "go-cache", "go-path", "go-tmp", "source.tar.gz", "go-toolchain.tar.gz"} {
			if _, err := os.Stat(filepath.Join(work, name)); !os.IsNotExist(err) {
				t.Errorf("rollbackFailure=%v: leftover temporary item %s", badRollback, name)
			}
		}
		if badRollback {
			if _, err := os.Stat(filepath.Join(work, "backup")); err != nil {
				t.Errorf("original backup was removed after failed rollback: %v", err)
			}
		} else if _, err := os.Stat(work); !os.IsNotExist(err) {
			t.Errorf("installer work directory still exists: %v", err)
		}
	}
}

func TestInstallerDeploymentAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name, mode                       string
		legacy, existingHTTPS, beforeBad bool
		afterBad, badCandidate, wantFail bool
		wantPublicHTTP                   bool
	}{
		{"fresh HTTPS", "https", false, false, false, false, false, false, false},
		{"fresh automatic HTTP fallback", "local", false, false, false, false, false, false, true},
		{"fresh HTTPS rejection HTTP fallback", "http", false, false, false, false, false, false, true},
		{"legacy HTTP preserved", "local", true, false, false, false, false, false, true},
		{"working HTTPS preserved", "local", false, true, false, false, false, false, false},
		{"preexisting HTTPS failure stays private", "local", false, true, true, true, false, false, false},
		{"new HTTPS regression rolls back", "local", false, true, false, true, false, true, false},
		{"bad update rolls back", "local", true, false, false, false, true, true, true},
		{"failed first install preserves data", "local", false, false, false, false, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			boolString := func(v bool) string {
				if v {
					return "yes"
				}
				return "no"
			}
			prefix := fmt.Sprintf("MODE=%s\nLEGACY=%s\nEXISTING=%s\nBEFORE_BAD=%s\nAFTER_BAD=%s\nBAD_CANDIDATE=%s\n", tc.mode, boolString(tc.legacy), boolString(tc.existingHTTPS), boolString(tc.beforeBad), boolString(tc.afterBad), boolString(tc.badCandidate))
			output, err := runInstallerShell(t, dir, prefix+installerDeploymentMocks)
			if (err != nil) != tc.wantFail {
				t.Fatalf("deployment failure=%v, expected %v\n%s", err, tc.wantFail, output)
			}
			unit, unitErr := os.ReadFile(filepath.Join(dir, "service"))
			binary, binaryErr := os.ReadFile(filepath.Join(dir, "engine"))
			if tc.wantFail && !tc.legacy && !tc.existingHTTPS {
				if !os.IsNotExist(unitErr) || !os.IsNotExist(binaryErr) {
					t.Fatalf("failed first installation left an active unit or binary\n%s", output)
				}
			} else {
				if unitErr != nil || binaryErr != nil {
					t.Fatalf("missing installation: unit=%v binary=%v\n%s", unitErr, binaryErr, output)
				}
				isPublic := !strings.Contains(string(unit), "VPN_ENGINE_PROXY_MODE=1")
				if isPublic != tc.wantPublicHTTP {
					t.Fatalf("public HTTP=%v, expected %v\n%s\n%s", isPublic, tc.wantPublicHTTP, unit, output)
				}
				version := "v1.2.3"
				if tc.wantFail {
					version = "v0.9.0"
				}
				if !strings.Contains(string(binary), "VPN Engine "+version) {
					t.Fatalf("incorrect deployed version, expected %s: %s", version, binary)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "allow-http")); !os.IsNotExist(err) {
				t.Fatalf("obsolete HTTP approval marker should be removed: %v", err)
			}
			if tc.wantFail && !strings.Contains(output, "preserved") {
				t.Fatalf("rollback status not reported\n%s", output)
			}
			state, stateErr := os.ReadFile(filepath.Join(dir, "state.json"))
			if stateErr != nil || !strings.Contains(string(state), "keep-existing-keys") {
				t.Fatalf("user state was not preserved: %v %s", stateErr, state)
			}
		})
	}
}

func TestInstallerUnfinishedLegacyRollbackStaysPrivate(t *testing.T) {
	for _, existing := range []string{"no", "yes"} {
		t.Run("HTTPS="+existing, func(t *testing.T) {
			dir := t.TempDir()
			output, err := runInstallerShell(t, dir, "MODE=local\nLEGACY=yes\nEXISTING="+existing+"\nBEFORE_BAD=no\nAFTER_BAD=no\nBAD_CANDIDATE=yes\nUNFINISHED=yes\n"+installerDeploymentMocks)
			if err == nil {
				t.Fatalf("expected the candidate health check to fail\n%s", output)
			}
			unit, err := os.ReadFile(filepath.Join(dir, "service"))
			if err != nil || !strings.Contains(string(unit), "ExecStart=/usr/bin/env VPN_ENGINE_PROXY_MODE=1") {
				t.Fatalf("unfinished older panel was not restricted to loopback: %v\n%s\n%s", err, unit, output)
			}
			if !strings.Contains(output, "older binary does not enforce setup codes") {
				t.Fatalf("older bootstrap limitation was not reported\n%s", output)
			}
			if existing == "yes" {
				config, err := os.ReadFile(filepath.Join(dir, "nginx-site"))
				if err != nil || strings.Contains(string(config), "proxy_pass") || !strings.Contains(string(config), "return 503;") || !strings.Contains(string(config), "ssl_certificate old-certificate") {
					t.Fatalf("older HTTPS setup was exposed or certificates were lost: %v\n%s", err, config)
				}
			}
		})
	}
}

func TestInstallerLegacyHTTPProxyKeepsRollbackPrivate(t *testing.T) {
	for _, tc := range []struct {
		name, unfinished, bad string
		wantFail, wantProxy   bool
	}{
		{"unfinished automatic HTTP fallback", "yes", "no", false, true},
		{"unfinished rollback", "yes", "yes", true, false},
		{"configured legacy HTTP fallback", "no", "no", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			prefix := "MODE=local\nLEGACY=yes\nEXISTING=no\nBEFORE_BAD=no\nAFTER_BAD=no\nBAD_CANDIDATE=" + tc.bad + "\nHTTP_PROXY=yes\nUNFINISHED=" + tc.unfinished + "\n"
			output, err := runInstallerShell(t, dir, prefix+installerDeploymentMocks)
			if (err != nil) != tc.wantFail {
				t.Fatalf("legacy HTTP proxy failure=%v expected=%v\n%s", err, tc.wantFail, output)
			}
			config, err := os.ReadFile(filepath.Join(dir, "nginx-site"))
			if err != nil || strings.Contains(string(config), "proxy_pass") != tc.wantProxy {
				t.Fatalf("legacy nginx route mismatch: %v\n%s\n%s", err, config, output)
			}
			if !tc.wantProxy && (!strings.Contains(string(config), "return 503;") || !strings.Contains(string(config), "location ^~ /.well-known/acme-challenge/")) {
				t.Fatalf("application route was not blocked while retaining ACME\n%s", config)
			}
		})
	}
}

func TestInstallerDoesNotStartBehindUnrestrictedRunningProxy(t *testing.T) {
	for _, failure := range []string{"validation", "reload"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			prefix := "MODE=local\nLEGACY=yes\nEXISTING=no\nBEFORE_BAD=no\nAFTER_BAD=no\nBAD_CANDIDATE=no\nHTTP_PROXY=yes\nUNFINISHED=yes\nNGINX_FAILURE=" + failure + "\n"
			output, err := runInstallerShell(t, dir, prefix+installerDeploymentMocks)
			if err == nil || !strings.Contains(output, "The new panel was not started") {
				t.Fatalf("unrestricted running nginx was allowed to forward to the candidate: %v\n%s", err, output)
			}
			binary, err := os.ReadFile(filepath.Join(dir, "engine"))
			if err == nil && strings.Contains(string(binary), "VPN Engine v1.2.3") {
				t.Fatal("candidate activated despite unsafe nginx frontend")
			}
		})
	}
}

func TestInstallerRecoveredHTTPSRouteReopensAfterSecureUpdate(t *testing.T) {
	dir := t.TempDir()
	output, err := runInstallerShell(t, dir, "MODE=local\nLEGACY=no\nEXISTING=yes\nBEFORE_BAD=yes\nAFTER_BAD=no\nBAD_CANDIDATE=no\nRECOVERY=yes\n"+installerDeploymentMocks)
	if err != nil {
		t.Fatalf("secure recovery update: %v\n%s", err, output)
	}
	config, err := os.ReadFile(filepath.Join(dir, "nginx-site"))
	if err != nil || strings.Contains(string(config), "insecure legacy recovery") || !strings.Contains(string(config), "proxy_pass http://127.0.0.1:51821") {
		t.Fatalf("secure update did not reopen the recovered HTTPS route: %v\n%s", err, config)
	}
	unit, err := os.ReadFile(filepath.Join(dir, "service"))
	if err != nil || !strings.Contains(string(unit), "VPN_ENGINE_PROXY_MODE=1") {
		t.Fatalf("secure recovered backend was not restricted to loopback: %v\n%s", err, unit)
	}
}

const installerDeploymentMocks = `
ENGINE="$test_root/engine"
SERVICE="$test_root/service"
STATE="$test_root/state.json"
ALLOW_HTTP_FILE="$test_root/allow-http"
HTTPS_IP_FILE="$test_root/https-ip"
NGINX_SITE="$test_root/nginx-site"
NGINX_ENABLED="$test_root/nginx-enabled"
RENEW_SCRIPT="$test_root/renew-script"
RENEW_SERVICE="$test_root/renew-service"
RENEW_TIMER="$test_root/renew-timer"
ACME_WEBROOT="$test_root/acme"
CERTBOT_DIR="$test_root/certbot"
printf '{"config":{"setupComplete":false},"private":"keep-existing-keys"}\n' > "$STATE"
make_binary() {
  printf '#!/usr/bin/env bash\ncase "$1" in --version) echo "VPN Engine %s";; bootstrap) echo "obsolete bootstrap invocation" >&2; exit 42;; esac\n' "$2" > "$1"
  chmod 0700 "$1"
}
make_binary "$test_root/candidate" v1.2.3
if [[ "$LEGACY" = yes || "$EXISTING" = yes ]]; then
  make_binary "$ENGINE" v0.9.0
  PANEL_PORT=51821
  if [[ "$EXISTING" = yes ]]; then
    write_service yes
    printf '203.0.113.10\n' > "$HTTPS_IP_FILE"
    printf '# Managed by VPN Engine\nssl_certificate old-certificate;\nlocation / {\nproxy_pass http://127.0.0.1:51821;\n}\n' > "$NGINX_SITE"
    if [[ "${RECOVERY:-no}" = yes ]]; then
      printf '# Managed by VPN Engine\n# VPN Engine: insecure legacy recovery\nssl_certificate old-certificate;\nlocation / {\nreturn 503;\n}\n' > "$NGINX_SITE"
    fi
    ln -s "$NGINX_SITE" "$NGINX_ENABLED"
    printf 'existing renewal settings\n' > "$RENEW_SCRIPT"
  else
    write_service no
  fi
  printf '{"config":{"setupComplete":true,"panelPort":51821},"private":"keep-existing-keys"}\n' > "$STATE"
  if [[ "${UNFINISHED:-no}" = yes ]]; then
    printf '{"config":{"setupComplete":false,"panelPort":51821},"private":"keep-existing-keys"}\n' > "$STATE"
  fi
fi
if [[ "${HTTP_PROXY:-no}" = yes ]]; then
  printf '# Managed by VPN Engine\nlisten 80;\nlocation ^~ /.well-known/acme-challenge/ {\ntry_files $uri =404;\n}\nlocation / {\nproxy_pass http://127.0.0.1:51821;\n}\n' > "$NGINX_SITE"
  ln -s "$NGINX_SITE" "$NGINX_ENABLED"
fi
id() { printf '0\n'; }
uname() { printf 'x86_64\n'; }
function [() {
  if [[ "$1" = -d && "$2" = /run/systemd/system ]]; then return 0; fi
  builtin [ "$@"
}
apt-get() { :; }
open_tty() { return 1; }
sleep() { :; }
timeout() { shift; "$@"; }
journalctl() { :; }
nginx() { [[ "${NGINX_FAILURE:-no}" != validation ]]; }
install() {
  local args=()
  while [[ "$#" -gt 0 ]]; do
    case "$1" in -o|-g) shift 2;; *) args+=("$1"); shift;; esac
  done
  command install "${args[@]}"
}
build_from_source() { RELEASE_TAG=v1.2.3; CANDIDATE="$test_root/candidate"; }
systemctl() {
  local unit="${@: -1}"
  if [[ "$1" = is-active || "$1" = is-enabled ]]; then
    case "$unit" in
      vpn-engine) [[ -f "$SERVICE" && -f "$ENGINE" ]];;
      nginx) [[ "$EXISTING" = yes || "${HTTP_PROXY:-no}" = yes ]];;
      vpn-engine-cert-renew.timer) [[ "$EXISTING" = yes ]];;
      *) return 1;;
    esac
  elif [[ "$1" = restart && "$unit" = vpn-engine && -f "$ENGINE" ]]; then
    if [[ "${HTTP_PROXY:-no}" = yes && "$("$ENGINE" --version)" = 'VPN Engine v1.2.3' ]] && grep -q 'VPN_ENGINE_PROXY_MODE=1' "$SERVICE"; then
      ! grep -q 'proxy_pass' "$NGINX_SITE" || return 43
    fi
  elif [[ "$1" = reload && "$unit" = nginx ]]; then
    [[ "${NGINX_FAILURE:-no}" != reload ]]
  fi
}
curl() {
  local version
  case "$*" in
    *api.ipify.org*) printf '203.0.113.10';;
    *api/state*)
      version="$("$ENGINE" --version)"; version="${version#VPN Engine }"
      if [[ "$*" = *https://* ]]; then
        if [[ "$version" = v0.9.0 && "$BEFORE_BAD" = yes || "$version" = v1.2.3 && "$AFTER_BAD" = yes ]]; then return 1; fi
      elif [[ "$version" = v1.2.3 && "$BAD_CANDIDATE" = yes ]]; then
        version=wrong-server
      fi
      printf '{"version":"%s"}\n' "$version";;
    *) return 1;;
  esac
}
setup_https() {
  grep -q 'VPN_ENGINE_PROXY_MODE=1' "$SERVICE" || return 50
  if [[ "${HTTP_PROXY:-no}" = yes ]]; then ! grep -q 'proxy_pass' "$NGINX_SITE" || return 52; fi
  [[ "$MODE" = https ]]
}
main
`

// Regression: curl ... | bash streams the installer through stdin, where
// BASH_SOURCE[0] is unset under set -u. --help exits before touching the host.
func TestInstallerEntrypointViaStdin(t *testing.T) {
	f, err := os.Open("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command("bash", "-s", "--", "--help")
	cmd.Stdin = f
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Usage: bash install.sh") {
		t.Fatalf("installer stdin entrypoint: %v\n%s", err, out)
	}
}

func TestUninstallerCertificateIPIsSafe(t *testing.T) {
	script, err := filepath.Abs("uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"
is_ipv4 203.0.113.10
! is_ipv4 203.0.113.999
! is_ipv4 '../another-certificate'
`, "uninstaller-test", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("uninstaller address validation: %v\n%s", err, output)
	}
}

func TestUninstallerOnlyRemovesVPNEngineFirewallRules(t *testing.T) {
	script, err := filepath.Abs("uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmd := exec.Command("bash", "-c", `source "$1"
test_root="$2"
iptables() {
  if [ "$1" = '-t' ] && [ "$3" = '-S' ]; then
    if [ ! -f "$test_root/removed" ]; then
      echo '-A FORWARD -i vpnwg0 -m comment --comment VPN-ENGINE-wireguard -j ACCEPT'
    fi
    echo '-A FORWARD -i other0 -m comment --comment KEEP-ME -j ACCEPT'
  elif [ "$1" = '-w' ] && [ "$4" = '-D' ]; then
    printf '%s\n' "$*" >> "$test_root/deletions"
    touch "$test_root/removed"
  fi
}
remove_tagged_rules iptables filter FORWARD
test -f "$test_root/removed"
grep -q VPN-ENGINE-wireguard "$test_root/deletions"
! grep -q KEEP-ME "$test_root/deletions"
`, "uninstaller-test", script, dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("uninstaller firewall isolation: %v\n%s", err, output)
	}
}

func TestUninstallerEntrypointViaStdin(t *testing.T) {
	f, err := os.Open("uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command("bash", "-s", "--", "--help")
	cmd.Stdin = f
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Usage: bash uninstall.sh") {
		t.Fatalf("uninstaller stdin execution: %v\n%s", err, out)
	}
}

func TestUninstallerDirectHelpDoesNotRequireRoot(t *testing.T) {
	out, err := exec.Command("bash", "uninstall.sh", "--help").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Usage: bash uninstall.sh") {
		t.Fatalf("uninstaller direct execution: %v\n%s", err, out)
	}
}
