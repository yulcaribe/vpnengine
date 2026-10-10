#!/usr/bin/env bash
set -Eeuo pipefail

ENGINE=/usr/local/bin/vpn-engine
DATA=/etc/vpn-engine
HTTPS_IP=
say(){ printf '%s\n' "$*"; }

managed_service() {
  local id="$1" config="$2"
  [ -f "$DATA/services/$id.json" ] || { [ -f "$config" ] && grep -qF "Managed by VPN Engine" "$config"; }
}
is_ipv4() {
  local a b c d part
  [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<< "$1"
  for part in "$a" "$b" "$c" "$d"; do
    (( 10#$part <= 255 )) || return 1
  done
}
# Remove any old VPN Engine rules, including ones left by previous broken
# upgrades. Rules are selected ONLY by their exact VPN Engine comment tags.
remove_tagged_rules() {
  local binary="$1" table="$2" chain="$3" record token label found removed round i
  local -a args=()
  command -v "$binary" >/dev/null 2>&1 || return 0
  for round in {1..50}; do
    removed=no
    while IFS= read -r record; do
      [[ "$record" == "-A $chain "* ]] || continue
      read -r -a args <<< "$record"
      found=no
      for ((i=0; i < ${#args[@]}-1; i++)); do
        if [[ "${args[i]}" == --comment ]]; then
          label="${args[i+1]//\"/}"
          case "$label" in
            VPN-ENGINE-wireguard|VPN-ENGINE-openvpn|VPN-ENGINE-ikev2) found=yes;;
          esac
          break
        fi
      done
      [ "$found" = yes ] || continue
      args[0]=-D
      for ((i=1; i < ${#args[@]}; i++)); do args[i]="${args[i]//\"/}"; done
      if "$binary" -w -t "$table" "${args[@]}" >/dev/null 2>&1; then
        removed=yes
      else
        say "WARNING: Could not remove one VPN Engine $binary rule from $table/$chain."
      fi
    done < <("$binary" -t "$table" -S "$chain" 2>/dev/null || true)
    [ "$removed" = yes ] || break
  done
}
remove_temp_installers() {
  # Old interrupted installers could leave rollback backups with private keys.
  if [ -d /usr/local/bin ]; then
    find /usr/local/bin -maxdepth 1 -mindepth 1 -type d -name '.vpn-engine-install.*' -exec rm -rf -- {} +
  fi
}

main() {
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  say "Usage: bash uninstall.sh"
  say "Removes VPN Engine managed services, private data and network rules."
  return 0
fi
[ "$#" -eq 0 ] || { echo "Unknown argument: $1" >&2; return 2; }
[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
[ -d /run/systemd/system ] || { echo "systemd is required" >&2; exit 1; }
HTTPS_IP="$(cat "$DATA/https-ip" 2>/dev/null || true)"
WG=no; OVPN=no; IKE=no
if managed_service wireguard /etc/wireguard/vpnwg0.conf; then WG=yes; fi
if managed_service openvpn /etc/openvpn/server/vpnengine.conf; then OVPN=yes; fi
if managed_service ikev2 /etc/swanctl/conf.d/vpn-engine.conf; then IKE=yes; fi

say "Stopping VPN Engine and its managed VPN protocols..."
systemctl disable --now vpn-engine.service 2>/dev/null || true

# Stop each managed VPN before deleting its config and the engine's net hooks.
if [ "$WG" = yes ]; then
  systemctl disable --now wg-quick@vpnwg0.service 2>/dev/null || true
  [ -x "$ENGINE" ] && "$ENGINE" net down wireguard 2>/dev/null || true
fi
if [ "$OVPN" = yes ]; then
  systemctl disable --now openvpn-server@vpnengine.service 2>/dev/null || true
  [ -x "$ENGINE" ] && "$ENGINE" net down openvpn 2>/dev/null || true
fi
if [ "$IKE" = yes ]; then
  systemctl disable --now strongswan.service 2>/dev/null || true
  [ -x "$ENGINE" ] && "$ENGINE" net down ikev2 2>/dev/null || true
fi

# Remove orphaned rules left by older versions, even if service JSON is missing.
say "Cleaning VPN Engine forwarding and NAT rules..."
remove_tagged_rules iptables filter FORWARD
remove_tagged_rules iptables nat POSTROUTING
remove_tagged_rules ip6tables filter FORWARD
remove_tagged_rules ip6tables nat POSTROUTING

if [ -f "$DATA/wg-quick-apparmor-compat" ] &&
   command -v aa-enforce >/dev/null 2>&1 &&
   [ -f /etc/apparmor.d/wg-quick ]; then
  aa-enforce /etc/apparmor.d/wg-quick >/dev/null 2>&1 || true
fi

say "Removing VPN Engine HTTPS and certificate renewal setup..."
systemctl disable --now vpn-engine-cert-renew.timer 2>/dev/null || true
systemctl stop vpn-engine-cert-renew.service 2>/dev/null || true
rm -f /etc/systemd/system/vpn-engine-cert-renew.timer /etc/systemd/system/vpn-engine-cert-renew.service
rm -f /usr/local/sbin/vpn-engine-renew-cert

# Never overwrite or remove an nginx site that no longer belongs to VPN Engine.
if [ -f /etc/nginx/sites-available/vpn-engine ] &&
   grep -qF 'Managed by VPN Engine' /etc/nginx/sites-available/vpn-engine; then
  rm -f /etc/nginx/sites-enabled/vpn-engine /etc/nginx/sites-available/vpn-engine
  if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
    systemctl reload nginx 2>/dev/null || true
  fi
fi
if [ -n "$HTTPS_IP" ] && is_ipv4 "$HTTPS_IP"; then
  rm -f "/etc/letsencrypt/renewal/$HTTPS_IP.conf"
  rm -rf "/etc/letsencrypt/live/$HTTPS_IP" "/etc/letsencrypt/archive/$HTTPS_IP"
fi
rm -rf /opt/vpn-engine-certbot /var/lib/vpn-engine /run/vpn-engine

# Owned configurations only; avoid deleting other WireGuard/OpenVPN instances.
if [ "$WG" = yes ]; then rm -f /etc/wireguard/vpnwg0.conf; fi
if [ "$OVPN" = yes ]; then rm -f /etc/openvpn/server/vpnengine.conf; fi
if [ "$IKE" = yes ]; then rm -f /etc/swanctl/conf.d/vpn-engine.conf; fi
rm -f /etc/systemd/system/openvpn-server@vpnengine.service.d/vpn-engine-management.conf
rmdir /etc/systemd/system/openvpn-server@vpnengine.service.d 2>/dev/null || true
rm -f /etc/swanctl/x509/vpn-engine-server.crt /etc/swanctl/x509ca/vpn-engine-ca.crt
rm -f /etc/swanctl/private/vpn-engine-server.key
rm -f /etc/systemd/system/strongswan.service.d/vpn-engine.conf
rmdir /etc/systemd/system/strongswan.service.d 2>/dev/null || true

if [ -f /etc/swanctl/swanctl.conf ]; then
  sed -i '/^# VPN Engine: include managed protocol configuration$/ {N;/\ninclude conf\.d\/\*\.conf$/d;}' /etc/swanctl/swanctl.conf
fi

rm -f /etc/systemd/system/vpn-engine.service "$ENGINE"
rm -rf "$DATA"
rm -f /etc/sysctl.d/99-vpn-engine.conf
rm -f /etc/sysctl.d/99-vpn-engine-ipv6-wireguard.conf
rm -f /etc/sysctl.d/99-vpn-engine-ipv6-openvpn.conf
rm -f /etc/sysctl.d/99-vpn-engine-ipv6-ikev2.conf
remove_temp_installers
systemctl daemon-reload

# Shared system packages and system-wide forwarding state must NOT be blindly
# purged or disabled. They may be in use by other VPNs, containers or services.
# Existing Go installations are also never touched.
say "VPN Engine binaries, managed VPN configs, firewall rules, private state, certificates, runtime sockets, build leftovers and systemd units were removed."
say "Shared system packages and global forwarding settings were preserved to avoid breaking other services."

}

# BASH_SOURCE[0] is empty for `curl ... | bash` (stdin), but populated
# when this file is sourced by tests. Both direct and piped execution run main.
if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
