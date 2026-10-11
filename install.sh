#!/usr/bin/env bash
set -Eeuo pipefail

REPO="yulcaribe/vpnengine"
DEFAULT_PORT=51821
STATE=/etc/vpn-engine/state.json
ENGINE=/usr/local/bin/vpn-engine
ALLOW_HTTP_FILE=/etc/vpn-engine/allow-http
SERVICE=/etc/systemd/system/vpn-engine.service
HTTPS_IP_FILE=/etc/vpn-engine/https-ip
NGINX_SITE=/etc/nginx/sites-available/vpn-engine
NGINX_ENABLED=/etc/nginx/sites-enabled/vpn-engine
ACME_WEBROOT=/var/lib/vpn-engine/acme
CERTBOT_DIR=/opt/vpn-engine-certbot
RENEW_SCRIPT=/usr/local/sbin/vpn-engine-renew-cert
RENEW_SERVICE=/etc/systemd/system/vpn-engine-cert-renew.service
RENEW_TIMER=/etc/systemd/system/vpn-engine-cert-renew.timer

say(){ printf '%s\n' "$*"; }
fail(){ say "ERROR: $*" >&2; exit 1; }

open_tty() { { exec {TTY_FD}<>/dev/tty; } 2>/dev/null; }
close_tty() { exec {TTY_FD}>&-; }

valid_ipv4() {
  local ip="$1" a="" b="" c="" d="" x
  IFS=. read -r a b c d <<<"$ip"
  for x in "$a" "$b" "$c" "$d"; do
    [[ "$x" =~ ^[0-9]+$ ]] || return 1
    [ "$x" -ge 0 ] && [ "$x" -le 255 ] || return 1
  done
  [ -n "$d" ]
}

port_listening() {
  ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E ":$1$" >/dev/null
}

write_service() {
  local proxy="${1:-no}" proxy_line=""
  [ "$proxy" = yes ] && proxy_line="Environment=VPN_ENGINE_PROXY_MODE=1"
  cat > "$SERVICE" <<UNIT
[Unit]
Description=VPN Engine admin panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$ENGINE
Environment=VPN_ENGINE_PORT=$PANEL_PORT
$proxy_line
Restart=always
RestartSec=3
WorkingDirectory=/etc/vpn-engine
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
}

choose_port() {
  local TTY_FD input=""
  if ! open_tty; then
    say "No interactive terminal found. Using internal TCP port $PANEL_PORT."
    return 0
  fi
  while true; do
    printf 'Internal admin backend TCP port [%s]: ' "$PANEL_PORT"
    if ! IFS= read -r -u "$TTY_FD" input; then
      close_tty
      say "No terminal input. Using internal TCP port $PANEL_PORT."
      return 0
    fi
    input="${input:-$PANEL_PORT}"
    if ! [[ "$input" =~ ^[0-9]+$ ]] || [ "$input" -lt 1 ] || [ "$input" -gt 65535 ]; then
      say "Enter a port from 1 to 65535."
      continue
    fi
    if command -v ss >/dev/null 2>&1 && port_listening "$input"; then
      say "Port $input is already in use. Choose another."
      continue
    fi
    PANEL_PORT="$input"
    close_tty
    return 0
  done
}

version_at_least() {
  local actual="$1" required="$2" a_major a_minor r_major r_minor
  [[ "$actual" =~ ^([0-9]+)\.([0-9]+) ]] || return 1
  a_major="${BASH_REMATCH[1]}"; a_minor="${BASH_REMATCH[2]}"
  [[ "$required" =~ ^([0-9]+)\.([0-9]+) ]] || return 1
  r_major="${BASH_REMATCH[1]}"; r_minor="${BASH_REMATCH[2]}"
  (( 10#$a_major > 10#$r_major || (10#$a_major == 10#$r_major && 10#$a_minor >= 10#$r_minor) ))
}

download_source() {
  local archive="$WORK_DIR/source.tar.gz"
  say "Resolving the current GitHub main commit..."
  curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 15 --max-time 60 \
    "https://api.github.com/repos/$REPO/commits/main" -o "$WORK_DIR/source-commit.json" || return 1
  SOURCE_COMMIT="$(python3 - "$WORK_DIR/source-commit.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    print(json.load(f)["sha"])
PY
)" || return 1
  [[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { say "Invalid GitHub source commit."; return 1; }
  say "Downloading source commit ${SOURCE_COMMIT:0:12}..."
  curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 15 --max-time 180 \
    "https://codeload.github.com/$REPO/tar.gz/$SOURCE_COMMIT" -o "$archive" || return 1
  mkdir -p "$WORK_DIR/source" || return 1
  tar -xzf "$archive" -C "$WORK_DIR/source" --strip-components=1 --no-same-owner || return 1
  grep -qx 'module github.com/yulcaribe/vpnengine' "$WORK_DIR/source/go.mod" || { say "The source module is not VPN Engine."; return 1; }
  SOURCE_VERSION="$(sed -n 's/^var version = "\([0-9][0-9.]*\)"$/\1/p' "$WORK_DIR/source/main.go")"
  [[ "$SOURCE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { say "Invalid VPN Engine source version."; return 1; }
  REQUIRED_GO="$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' "$WORK_DIR/source/go.mod")"
  [[ "$REQUIRED_GO" =~ ^[0-9]+\.[0-9]+$ ]] || { say "Invalid Go version in go.mod."; return 1; }
  RELEASE_TAG="$SOURCE_VERSION+${SOURCE_COMMIT:0:12}"
}

prepare_go() {
  local installed_version="" selected=""
  GO_BIN=""
  if command -v go >/dev/null 2>&1; then
    selected="$(go version 2>/dev/null || true)"
    if [[ "$selected" =~ go([0-9]+\.[0-9]+\.[0-9]+) ]] || [[ "$selected" =~ go([0-9]+\.[0-9]+) ]]; then
      installed_version="${BASH_REMATCH[1]}"
      if version_at_least "$installed_version" "$REQUIRED_GO"; then
        GO_BIN="$(command -v go)"
        say "Using existing Go $installed_version (will not remove it)."
        return 0
      fi
    fi
  fi
  say "Downloading a temporary verified Go toolchain (existing Go is untouched)..."
  curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 15 --max-time 60 \
    'https://go.dev/dl/?mode=json' -o "$WORK_DIR/go-versions.json" || return 1
  python3 - "$WORK_DIR/go-versions.json" "$ARCH" > "$WORK_DIR/go-selected.txt" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    versions = json.load(f)
for release in versions:
    if not release.get("stable"):
        continue
    for item in release.get("files", []):
        if item.get("os") == "linux" and item.get("arch") == sys.argv[2] and item.get("kind") == "archive":
            filename, checksum = item["filename"], item["sha256"]
            if filename.startswith("go") and filename.endswith(".tar.gz") and len(checksum) == 64:
                print(release["version"], filename, checksum)
                sys.exit(0)
sys.exit("No stable Linux Go toolchain found for this CPU architecture")
PY
  read -r GO_VERSION GO_FILENAME GO_CHECKSUM < "$WORK_DIR/go-selected.txt" || return 1
  [[ "$GO_VERSION" =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  [[ "$GO_FILENAME" == "$GO_VERSION.linux-$ARCH.tar.gz" ]] || return 1
  [[ "$GO_CHECKSUM" =~ ^[a-fA-F0-9]{64}$ ]] || return 1
  version_at_least "${GO_VERSION#go}" "$REQUIRED_GO" || return 1
  curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 15 --max-time 300 \
    "https://go.dev/dl/$GO_FILENAME" -o "$WORK_DIR/go-toolchain.tar.gz" || return 1
  (cd "$WORK_DIR" && printf '%s  %s\n' "$GO_CHECKSUM" go-toolchain.tar.gz | sha256sum -c -) || return 1
  mkdir -p "$WORK_DIR/go-runtime" || return 1
  tar -xzf "$WORK_DIR/go-toolchain.tar.gz" -C "$WORK_DIR/go-runtime" --no-same-owner || return 1
  GO_BIN="$WORK_DIR/go-runtime/go/bin/go"
  [ -x "$GO_BIN" ] || return 1
  say "Temporary Go $GO_VERSION is ready."
}

build_from_source() {
  download_source || return 1
  prepare_go || return 1
  mkdir -p "$WORK_DIR/go-cache" "$WORK_DIR/go-path" "$WORK_DIR/go-tmp" || return 1
  CANDIDATE="$WORK_DIR/candidate"
  say "Compiling VPN Engine $RELEASE_TAG on this server..."
  (
    cd "$WORK_DIR/source" || exit 1
    GOCACHE="$WORK_DIR/go-cache" \
      GOPATH="$WORK_DIR/go-path" \
      GOTMPDIR="$WORK_DIR/go-tmp" \
      GOENV=off GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
      CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
      "$GO_BIN" build -p 2 -trimpath -ldflags="-s -w -X main.version=$RELEASE_TAG" -o "$CANDIDATE" .
  ) || return 1
  chmod 0700 "$CANDIDATE" || return 1
  local candidate_version
  candidate_version="$(timeout 10s "$CANDIDATE" --version)" || return 1
  [ "$candidate_version" = "VPN Engine $RELEASE_TAG" ] || { say "Compiled program version mismatch."; return 1; }
}

health_check() {
  local port="$1" expected="${2:-}" body observed attempt
  # Existing protocol configuration migrations can delay the first listener by 75s.
  for attempt in {1..100}; do
    if systemctl is-active --quiet vpn-engine && \
       body="$(curl --noproxy '*' -fsS --connect-timeout 2 --max-time 3 "http://127.0.0.1:$port/api/state")"; then
      observed="$(sed -n 's/.*"version":[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$body")"
      if [ -n "$observed" ] && { [ -z "$expected" ] || [ "$observed" = "$expected" ]; }; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

https_health_check() {
  local ip="$1" expected="${2:-}" body observed
  valid_ipv4 "$ip" || return 1
  body="$(curl --noproxy '*' --proto '=https' --connect-to "$ip:443:127.0.0.1:443" \
    -fsS --connect-timeout 3 --max-time 10 "https://$ip/api/state")" || return 1
  observed="$(sed -n 's/.*"version":[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$body")"
  [ -n "$observed" ] && { [ -z "$expected" ] || [ "$observed" = "$expected" ]; }
}

backup_installation() {
  local index path
  BACKUP_PATHS=("$ENGINE" "$SERVICE" "$NGINX_SITE" "$NGINX_ENABLED" "$HTTPS_IP_FILE" "$ALLOW_HTTP_FILE" "$RENEW_SCRIPT" "$RENEW_SERVICE" "$RENEW_TIMER")
  mkdir -m 0700 "$WORK_DIR/backup" || return 1
  for index in "${!BACKUP_PATHS[@]}"; do
    path="${BACKUP_PATHS[$index]}"
    if [ -e "$path" ] || [ -L "$path" ]; then cp -a -- "$path" "$WORK_DIR/backup/$index" || return 1; fi
  done
  OLD_PANEL_ACTIVE=no; OLD_PANEL_ENABLED=no; OLD_NGINX_ACTIVE=no; OLD_NGINX_ENABLED=no
  OLD_TIMER_ACTIVE=no; OLD_TIMER_ENABLED=no
  # A missing unit is expected on a fresh install; systemctl may report
  # "Failed to get unit file state" even with --quiet. Suppress only probes.
  if systemctl is-active --quiet vpn-engine 2>/dev/null; then OLD_PANEL_ACTIVE=yes; fi
  if systemctl is-enabled --quiet vpn-engine 2>/dev/null; then OLD_PANEL_ENABLED=yes; fi
  if systemctl is-active --quiet nginx 2>/dev/null; then OLD_NGINX_ACTIVE=yes; fi
  if systemctl is-enabled --quiet nginx 2>/dev/null; then OLD_NGINX_ENABLED=yes; fi
  if systemctl is-active --quiet vpn-engine-cert-renew.timer 2>/dev/null; then OLD_TIMER_ACTIVE=yes; fi
  if systemctl is-enabled --quiet vpn-engine-cert-renew.timer 2>/dev/null; then OLD_TIMER_ENABLED=yes; fi
}

restore_file() {
  local index="$1" path="${BACKUP_PATHS[$1]}" backup="$WORK_DIR/backup/$1"
  if [ -e "$backup" ] || [ -L "$backup" ]; then
    rm -f -- "$path" || return 1
    cp -a -- "$backup" "$path" || return 1
  else
    rm -f -- "$path" || return 1
  fi
}

restore_unit_state() {
  local unit="$1" enabled="$2" active="$3" result=0
  if [ "$enabled" = yes ]; then systemctl enable "$unit" >/dev/null || result=1; fi
  if [ "$active" = yes ]; then
    systemctl restart "$unit" || result=1
  elif systemctl is-active --quiet "$unit"; then
    systemctl stop "$unit" || result=1
  fi
  return "$result"
}

block_panel_proxy() {
  local marker="$1"
  BLOCKED_PROXY=no
  if [ -f "$NGINX_SITE" ] && grep -qF "Managed by VPN Engine" "$NGINX_SITE"; then
    awk -v marker="$marker" '
      BEGIN {print marker}
      /^[[:space:]]*proxy_pass[[:space:]]/ {$0 = "        return 503;"}
      {print}
    ' "$NGINX_SITE" > "$WORK_DIR/blocked-nginx" || return 1
    install -o root -g root -m 0644 "$WORK_DIR/blocked-nginx" "$NGINX_SITE" || return 1
    BLOCKED_PROXY=yes
  fi
}

restore_https_configuration() {
  local block="${1:-no}" index result=0
  if [ "$OLD_TIMER_ENABLED" = no ]; then systemctl disable vpn-engine-cert-renew.timer >/dev/null 2>&1 || true; fi
  if [ "$OLD_NGINX_ENABLED" = no ]; then systemctl disable nginx >/dev/null 2>&1 || true; fi
  for index in 2 3 4 6 7 8; do restore_file "$index" || result=1; done
  # Restrict restored proxy routes before a running nginx can reload them.
  if [ "$block" != no ]; then block_panel_proxy "$block" || return 1; fi
  systemctl daemon-reload || result=1
  restore_unit_state vpn-engine-cert-renew.timer "$OLD_TIMER_ENABLED" "$OLD_TIMER_ACTIVE" || result=1
  if [ "$OLD_NGINX_ACTIVE" = yes ]; then
    nginx -t && systemctl reload nginx || result=1
  elif systemctl is-active --quiet nginx; then
    systemctl stop nginx || result=1
  fi
  if [ "$OLD_NGINX_ENABLED" = yes ]; then systemctl enable nginx >/dev/null || result=1; fi
  return "$result"
}

rollback_installation() {
  local index result=0
  systemctl stop vpn-engine >/dev/null 2>&1 || true
  if [ "$OLD_PANEL_ENABLED" = no ]; then systemctl disable vpn-engine >/dev/null 2>&1 || true; fi
  for index in 0 1 5; do restore_file "$index" || result=1; done
  if [ "$OLD_SETUP_COMPLETE" = no ] && [ -f "$WORK_DIR/backup/0" ] && [ -f "$SERVICE" ]; then
    # Older binaries do not enforce setup codes. Never reopen their unfinished setup.
    awk -v engine="$ENGINE" '
      /^\[Service\]$/ {print; print "Environment=VPN_ENGINE_PROXY_MODE=1"; next}
      /^Environment=VPN_ENGINE_PROXY_MODE=/ {next}
      $0 == "ExecStart=" engine {$0 = "ExecStart=/usr/bin/env VPN_ENGINE_PROXY_MODE=1 " engine}
      {print}
    ' "$SERVICE" > "$WORK_DIR/recovered-service" && \
      install -o root -g root -m 0644 "$WORK_DIR/recovered-service" "$SERVICE" || return 1
    say "The unfinished legacy setup was restricted to loopback. Recover it over SSH; the older binary does not enforce setup codes."
  fi
  if [ "$OLD_SETUP_COMPLETE" = no ]; then
    restore_https_configuration '# VPN Engine: insecure legacy recovery' || return 1
    say "Any recovered nginx application proxy was blocked until a secure update is installed; certificates and ACME renewal were retained."
  else
    restore_https_configuration || result=1
  fi
  systemctl daemon-reload || result=1
  restore_unit_state vpn-engine "$OLD_PANEL_ENABLED" "$OLD_PANEL_ACTIVE" || result=1
  if [ "$OLD_PANEL_ACTIVE" = yes ]; then health_check "$OLD_PANEL_PORT" "$OLD_VERSION" || result=1; fi
  if [ "$OLD_HTTPS_HEALTHY" = yes ] && [ "$OLD_SETUP_COMPLETE" = yes ]; then https_health_check "$OLD_HTTPS_IP" "$OLD_VERSION" || result=1; fi
  return "$result"
}

finish_installation() {
  local status=$? rollback_failed=no
  trap - EXIT INT TERM
  if [ "$TRANSACTION_STARTED" = yes ] && [ "$COMMITTED" = no ]; then
    [ "$status" -ne 0 ] || status=1
    say "ERROR: Installation or update failed. Restoring the previous panel installation."
    if rollback_installation; then
      if [ -f "$WORK_DIR/backup/0" ]; then
        say "The previous binary and configuration were restored. Existing VPN data was preserved."
      else
        say "The incomplete first installation was removed. Any bootstrap state and VPN data were preserved."
      fi
    else
      rollback_failed=yes
      say "ERROR: Automatic rollback was incomplete. Check systemctl status vpn-engine and journalctl -u vpn-engine."
      say "The original installation backup was retained in $WORK_DIR/backup."
    fi
  fi
  # Remove temporary Go binaries, source, downloaded archives, and caches
  # even when a rollback error forces preservation of the old binary backup.
  if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
    rm -rf -- "$WORK_DIR/source" "$WORK_DIR/go-runtime" "$WORK_DIR/go-cache" "$WORK_DIR/go-path" "$WORK_DIR/go-tmp"
    rm -f -- "$WORK_DIR/source.tar.gz" "$WORK_DIR/source-commit.json" "$WORK_DIR/go-versions.json" "$WORK_DIR/go-selected.txt" "$WORK_DIR/go-toolchain.tar.gz" "$WORK_DIR/candidate"
  fi
  if [ "$rollback_failed" = no ]; then rm -rf -- "$WORK_DIR"; fi
  exit "$status"
}

write_http_nginx() {
  cat > "$NGINX_SITE" <<NGINX
# Managed by VPN Engine
server {
    listen 80;
    listen [::]:80;
    server_name $PUBLIC_IP;

    location ^~ /.well-known/acme-challenge/ {
        root $ACME_WEBROOT;
        default_type text/plain;
        try_files \$uri =404;
    }

    location / {
        return 503;
    }
}
NGINX
}

write_https_nginx() {
  cat > "$NGINX_SITE" <<NGINX
# Managed by VPN Engine
server {
    listen 80;
    listen [::]:80;
    server_name $PUBLIC_IP;

    location ^~ /.well-known/acme-challenge/ {
        root $ACME_WEBROOT;
        default_type text/plain;
        try_files \$uri =404;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $PUBLIC_IP;

    ssl_certificate /etc/letsencrypt/live/$PUBLIC_IP/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$PUBLIC_IP/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:VPNEngineTLS:10m;
    ssl_session_timeout 10m;

    client_max_body_size 64k;

    location / {
        proxy_pass http://127.0.0.1:$PANEL_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 90s;
    }
}
NGINX
}

install_renewal() {
  cat > "$RENEW_SCRIPT" <<SCRIPT || return 1
#!/usr/bin/env bash
set -Eeuo pipefail
"$CERTBOT_DIR/bin/certbot" renew --quiet --deploy-hook "/usr/bin/systemctl reload nginx"
SCRIPT
  chmod 0755 "$RENEW_SCRIPT" || return 1

  cat > "$RENEW_SERVICE" <<UNIT || return 1
[Unit]
Description=Renew VPN Engine HTTPS certificate
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$RENEW_SCRIPT
UNIT

  cat > "$RENEW_TIMER" <<UNIT || return 1
[Unit]
Description=Check VPN Engine HTTPS certificate renewal

[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=30m
Persistent=true
Unit=vpn-engine-cert-renew.service

[Install]
WantedBy=timers.target
UNIT

  systemctl daemon-reload || return 1
  systemctl enable --now vpn-engine-cert-renew.timer >/dev/null || return 1
}

setup_https() {
  valid_ipv4 "$PUBLIC_IP" || { say "HTTPS: public IPv4 could not be detected."; return 1; }
  [ "$PANEL_PORT" != 80 ] && [ "$PANEL_PORT" != 443 ] || { say "HTTPS: internal panel port cannot be 80 or 443."; return 1; }

  local managed_nginx=no
  [ -f "$NGINX_SITE" ] && grep -qF "Managed by VPN Engine" "$NGINX_SITE" && managed_nginx=yes

  if [ "$managed_nginx" != yes ]; then
    if port_listening 80 || port_listening 443; then
      say "HTTPS: TCP 80 or 443 is already in use by another service."
      return 1
    fi
  fi

  say "Configuring automatic HTTPS for $PUBLIC_IP..."
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=240 install -y -qq nginx python3-venv || return 1
  mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge" || return 1
  chmod 0755 /var/lib/vpn-engine "$ACME_WEBROOT" "$ACME_WEBROOT/.well-known" "$ACME_WEBROOT/.well-known/acme-challenge" || return 1

  if [ ! -x "$CERTBOT_DIR/bin/certbot" ]; then
    python3 -m venv "$CERTBOT_DIR" || return 1
  fi
  "$CERTBOT_DIR/bin/pip" install --disable-pip-version-check -q --upgrade "certbot>=5.4" || return 1
  "$CERTBOT_DIR/bin/certbot" --version || return 1

  write_http_nginx || return 1
  ln -sfn "$NGINX_SITE" "$NGINX_ENABLED" || return 1
  nginx -t >/dev/null 2>&1 || return 1
  systemctl enable --now nginx >/dev/null || return 1
  systemctl reload nginx || return 1

  if [ ! -s "/etc/letsencrypt/live/$PUBLIC_IP/privkey.pem" ] ||
     ! openssl x509 -checkend 86400 -noout -in "/etc/letsencrypt/live/$PUBLIC_IP/fullchain.pem" >/dev/null 2>&1; then
    "$CERTBOT_DIR/bin/certbot" certonly \
      --non-interactive \
      --agree-tos \
      --register-unsafely-without-email \
      --preferred-profile shortlived \
      --cert-name "$PUBLIC_IP" \
      --force-renewal \
      --webroot \
      --webroot-path "$ACME_WEBROOT" \
      --ip-address "$PUBLIC_IP" || return 1
  fi

  write_https_nginx || return 1
  nginx -t >/dev/null 2>&1 || return 1
  systemctl reload nginx || return 1
  install_renewal || return 1

  printf '%s\n' "$PUBLIC_IP" > "$WORK_DIR/https-ip" || return 1
  install -o root -g root -m 0600 "$WORK_DIR/https-ip" "$HTTPS_IP_FILE" || return 1
  https_health_check "$PUBLIC_IP" "$RELEASE_TAG" || return 1
}

main() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h) say "Usage: bash install.sh"; say "HTTPS is attempted automatically; if unavailable, HTTP opens with a warning and no approval prompt."; return 0;;
      *) fail "Unknown option: $1";;
    esac
    shift
  done
  [ "$(id -u)" = 0 ] || fail "Run as root."
  [ -d /run/systemd/system ] || fail "systemd is required."
  command -v apt-get >/dev/null 2>&1 || fail "VPN Engine requires an APT-based system."
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}:${VERSION_ID:-}" in
      ubuntu:24|ubuntu:24.*|ubuntu:26|ubuntu:26.*|debian:12|debian:12.*|debian:13|debian:13.*) ;;
      *) say "WARNING: Supported systems are Ubuntu 24.x/26.x and Debian 12/13. Detected ${PRETTY_NAME:-unknown}; continuing.";;
    esac
  fi
  case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) fail "Unsupported CPU architecture.";; esac

  PANEL_PORT="${VPN_ENGINE_PORT:-$DEFAULT_PORT}"
  FRESH=yes
  if [ -e "$STATE" ]; then
    FRESH=no
    local saved_port
    saved_port="$(sed -n 's/.*"panelPort":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$STATE")"
    if [[ "$saved_port" =~ ^[0-9]+$ ]] && [ "$saved_port" -ge 1 ] && [ "$saved_port" -le 65535 ]; then PANEL_PORT="$saved_port"; fi
  fi
  if [ -f "$SERVICE" ] && { [ "$FRESH" = yes ] || [ "${saved_port:-0}" = 0 ]; }; then
    local service_port
    service_port="$(sed -n 's/^Environment=VPN_ENGINE_PORT=\([0-9][0-9]*\)$/\1/p' "$SERVICE")"
    if [[ "$service_port" =~ ^[0-9]+$ ]] && [ "$service_port" -ge 1 ] && [ "$service_port" -le 65535 ]; then PANEL_PORT="$service_port"; fi
  fi
  [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] && [ "$PANEL_PORT" -ge 1 ] && [ "$PANEL_PORT" -le 65535 ] || fail "Invalid internal panel TCP port."
  say "VPN Engine installer / updater"
  if [ "$FRESH" = yes ] && [ ! -f "$SERVICE" ]; then
    say "This installs the management panel. VPN protocols are installed separately from the panel."
    choose_port
  else
    say "Keeping existing accounts, VPN profiles, keys, certificates and settings."
  fi

  OLD_PANEL_PORT="$PANEL_PORT"
  OLD_VERSION=""
  if [ -x "$ENGINE" ]; then OLD_VERSION="$(timeout 10s "$ENGINE" --version | sed -n 's/^VPN Engine //p')"; fi
  OLD_HTTPS_IP="$(cat "$HTTPS_IP_FILE" 2>/dev/null || true)"
  EXISTING_HTTPS=no
  if { [ -e "$NGINX_ENABLED" ] || [ -L "$NGINX_ENABLED" ]; } && [ -f "$NGINX_SITE" ] &&
     grep -qF "Managed by VPN Engine" "$NGINX_SITE" && grep -q 'ssl_certificate ' "$NGINX_SITE"; then
    EXISTING_HTTPS=yes
  fi
  OLD_HTTPS_HEALTHY=no
  if [ "$EXISTING_HTTPS" = yes ] && command -v curl >/dev/null 2>&1 && https_health_check "$OLD_HTTPS_IP" "$OLD_VERSION"; then
    OLD_HTTPS_HEALTHY=yes
  fi
  OLD_SETUP_COMPLETE=no
  if [ -f "$STATE" ] && grep -q '"setupComplete":[[:space:]]*true' "$STATE"; then OLD_SETUP_COMPLETE=yes; fi
  mkdir -p "$(dirname "$ENGINE")"
  WORK_DIR="$(mktemp -d "$(dirname "$ENGINE")/.vpn-engine-install.XXXXXX")"
  chmod 0700 "$WORK_DIR"
  TRANSACTION_STARTED=no; COMMITTED=no
  trap finish_installation EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  backup_installation || fail "Could not back up the existing panel installation."
  say "Installing minimum dependencies..."
  apt-get -o DPkg::Lock::Timeout=240 update -qq
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=240 install -y -qq ca-certificates curl openssl iproute2 python3 tar
  build_from_source || fail "Source download, Go verification or compilation failed. The current binary was not changed."

  TRANSACTION_STARTED=yes
  if systemctl is-active --quiet vpn-engine; then systemctl stop vpn-engine; fi
  if [ "$EXISTING_HTTPS" = no ]; then
    block_panel_proxy '# VPN Engine: HTTPS configuration in progress'
    if [ "$BLOCKED_PROXY" = yes ] && { [ -e "$NGINX_ENABLED" ] || [ -L "$NGINX_ENABLED" ]; } && systemctl is-active --quiet nginx; then
      nginx -t || fail "Could not validate the restricted nginx proxy. The new panel was not started."
      systemctl reload nginx || fail "Could not activate the restricted nginx proxy. The new panel was not started."
    fi
  fi
  install -d -o root -g root -m 0700 "$(dirname "$STATE")"
  install -o root -g root -m 0755 "$CANDIDATE" "$WORK_DIR/activate"
  mv -f "$WORK_DIR/activate" "$ENGINE"
  # Admin credentials are configured by the first browser visitor.
  write_service yes
  systemctl daemon-reload
  systemctl enable vpn-engine >/dev/null
  systemctl restart vpn-engine
  health_check "$PANEL_PORT" "$RELEASE_TAG" || { journalctl -u vpn-engine -n 15 --no-pager >&2 || true; fail "The new panel failed its local API health check."; }

  PUBLIC_IP="$(curl --proto '=https' -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
  if ! valid_ipv4 "$PUBLIC_IP"; then PUBLIC_IP=""; fi
  HTTPS_OK=no; HTTP_OK=no
  if [ "$EXISTING_HTTPS" = yes ]; then
    # Normal upgrades leave the working certificate, nginx site and renewal setup alone.
    HTTPS_OK=yes
    PUBLIC_IP="$OLD_HTTPS_IP"
    if ! valid_ipv4 "$PUBLIC_IP"; then PUBLIC_IP=""; fi
    if grep -qF '# VPN Engine: insecure legacy recovery' "$NGINX_SITE"; then
      valid_ipv4 "$OLD_HTTPS_IP" || fail "Repair the saved HTTPS IP before reopening the recovered frontend."
      write_https_nginx
      nginx -t
      if systemctl is-active --quiet nginx; then systemctl reload nginx; fi
      say "The recovered HTTPS application route now uses the secure panel. Existing certificates and renewal settings were retained."
    fi
    if ! https_health_check "$OLD_HTTPS_IP" "$RELEASE_TAG"; then
      if [ "$OLD_HTTPS_HEALTHY" = yes ]; then fail "The previously working HTTPS frontend failed after the update."; fi
      say "WARNING: The HTTPS frontend already failed its health check before this update. Its configuration was preserved without enabling public HTTP."
      say "Check nginx and run $RENEW_SCRIPT as root to troubleshoot certificate renewal."
    fi
  elif setup_https; then
    HTTPS_OK=yes
    rm -f "$ALLOW_HTTP_FILE"
  else
    say "WARNING: HTTPS certificate setup failed. Opening the public admin panel over unencrypted HTTP."
    restore_https_configuration || fail "Could not restore the prior HTTPS configuration after certificate setup failed."
    write_service no
    systemctl daemon-reload
    systemctl restart vpn-engine
    health_check "$PANEL_PORT" "$RELEASE_TAG" || fail "The HTTP panel failed its local API health check."
    HTTP_OK=yes
  fi
  health_check "$PANEL_PORT" "$RELEASE_TAG" || fail "The panel is not responding after configuration."
  # Remove the legacy HTTP approval marker. No terminal or browser confirmation is required.
  rm -f "$ALLOW_HTTP_FILE"
  COMMITTED=yes
  say ""
  say "VPN Engine installed / updated."
  if [ "$HTTPS_OK" = yes ]; then
    say "Admin panel: https://${PUBLIC_IP:-SERVER_IP}"
    say "The backend is restricted to loopback. HTTPS certificate renewal settings are preserved."
  elif [ "$HTTP_OK" = yes ]; then
    say "Admin panel: http://${PUBLIC_IP:-SERVER_IP}:$PANEL_PORT"
    say "WARNING: HTTP is not encrypted. Enable HTTPS before sending sensitive data over untrusted networks."
  fi
  say "Temporary sources, toolchain and build caches have been removed."
  say "For new installations, open the panel and create the admin account immediately."
  say "WARNING: Until an admin exists, anyone who can reach the panel can claim it."
  say "Existing VPN accounts, profiles, keys and certificates were preserved."
}

if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
