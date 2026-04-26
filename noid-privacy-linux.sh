#!/usr/bin/env bash
###############################################################################
#  NoID Privacy for Linux v3.4.1 — Privacy & Security Audit
#  Copyright (C) 2026 Fabio Mantegna (NexusOne23)
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#  https://noid-privacy.com/linux.html | https://github.com/NexusOne23/noid-privacy-linux
#  Fedora / RHEL / Debian / Ubuntu — Full-Spectrum Audit
#  390+ checks across 42 sections
#  Requires: root
###############################################################################
NOID_PRIVACY_VERSION="3.4.1"
set +e          # Don't exit on errors — we handle them ourselves

# Bash 4+ required for associative arrays and other features
if (( BASH_VERSINFO[0] < 4 )); then
  echo "Error: Bash 4.0+ required (found ${BASH_VERSION})" >&2; exit 1
fi

# --- Argument Parsing ---
NO_COLOR=false
AI_MODE=false
JSON_MODE=false
declare -a SKIP_SECTIONS=()
declare -a FAIL_MSGS=()
declare -a WARN_MSGS=()
declare -a JSON_FINDINGS=()
CURRENT_SECTION=""

show_help() {
  cat <<EOF
Usage: noid-privacy-linux.sh [OPTIONS]

🛡️  NoID Privacy for Linux v${NOID_PRIVACY_VERSION} — Privacy & Security Audit

Options:
  --help          Show this help message
  --no-color      Disable color output (for logs/pipes)
  --ai            Generate AI assistant prompt with findings at the end
  --json          Output results as JSON only (no normal output)
  --offline       Skip all sections that make network requests
                  (equivalent to --skip vpn --skip interfaces --skip netleaks)
  --skip SECTION  Skip a section (can be repeated)
                  Sections: kernel, selinux, firewall, nftables, vpn,
                  sysctl, services, ports, ssh, audit, users, filesystem,
                  crypto, updates, rootkit, processes, network, containers,
                  logs, performance, hardware, interfaces, certificates,
                  environment, systemd, desktop, ntp, fail2ban, logins,
                  hardening, permissions, modules, boot, integrity,
                  browser, telemetry, netprivacy, netleaks, dataprivacy,
                  session, media, btprivacy, keyring, summary

Examples:
  sudo bash noid-privacy-linux.sh
  sudo bash noid-privacy-linux.sh --no-color > report.txt
  sudo bash noid-privacy-linux.sh --skip rootkit --skip containers
  sudo bash noid-privacy-linux.sh --ai
  sudo bash noid-privacy-linux.sh --json | jq .

390+ checks. Requires root. Tested on Fedora 43, RHEL 9, Debian 12, Ubuntu 24.04.
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) show_help ;;
    --no-color) NO_COLOR=true; shift ;;
    --ai) AI_MODE=true; shift ;;
    --json) JSON_MODE=true; NO_COLOR=true; shift ;;
    --skip) [[ -z "${2:-}" ]] && { echo "Error: --skip requires a section name"; exit 1; }; SKIP_SECTIONS+=("$2"); shift 2 ;;
    --offline) SKIP_SECTIONS+=("vpn" "interfaces" "netleaks"); shift ;;
    *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
  esac
done

# --ai and --json now combine: JSON output includes ai_prompt as a field
# (eliminates the entrypoint.sh double-run problem, F-273)

should_skip() {
  local section="$1"
  for s in "${SKIP_SECTIONS[@]}"; do
    [[ "$s" == "$section" ]] && return 0
  done
  return 1
}

# --- Colors ---
if $NO_COLOR; then
  RED=''; GRN=''; YLW=''; MAG=''; CYN=''; WHT=''; RST=''; BOLD=''
else
  RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
  MAG='\033[0;35m'; CYN='\033[0;36m'; WHT='\033[1;37m'; RST='\033[0m'
  BOLD='\033[1m'
fi

PASS=0; FAIL=0; WARN=0; INFO=0
TOTAL_START=$(date +%s)
TOTAL_SECTIONS=42

# F-008: graceful SIGINT/SIGTERM handler. Long-running checks (rpm -Va,
# ausearch, find /) can take minutes; without trap, Ctrl-C kills the script
# mid-output with no summary. Print partial results and exit with standard
# 130 (SIGINT) or 143 (SIGTERM) so wrappers can distinguish from clean
# exit codes (0/1/2 from F-007 final block).
_noid_interrupted() {
  local sig="$1" rc="$2"
  echo "" >&2
  printf '\n  ⚠️  Interrupted by %s — partial results:\n' "$sig" >&2
  printf '     PASS=%s FAIL=%s WARN=%s INFO=%s (scan incomplete)\n' \
    "${PASS:-0}" "${FAIL:-0}" "${WARN:-0}" "${INFO:-0}" >&2
  exit "$rc"
}
trap '_noid_interrupted INT 130'  INT
trap '_noid_interrupted TERM 143' TERM

# Safe count: reads stdin, strips all non-digit characters, returns the number (or 0).
# Used after `wc -l | ccount` or `grep -c | ccount` to handle whitespace and empty output.
ccount() { local v; v=$(cat); v=${v//[^0-9]/}; echo "${v:-0}"; }

# --- JSON helper: escape string for JSON ---
_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\b'/\\b}"
  s="${s//$'\f'/\\f}"
  printf '%s' "$s"
}

pass() {
  ((PASS++))
  if $JSON_MODE; then
    JSON_FINDINGS+=("{\"severity\":\"PASS\",\"section\":\"$(_json_escape "$CURRENT_SECTION")\",\"message\":\"$(_json_escape "$1")\"}")
  else
    printf "  ${GRN}✅ PASS${RST}  %s\n" "$1"
  fi
}
fail() {
  ((FAIL++))
  FAIL_MSGS+=("$1")
  if $JSON_MODE; then
    JSON_FINDINGS+=("{\"severity\":\"FAIL\",\"section\":\"$(_json_escape "$CURRENT_SECTION")\",\"message\":\"$(_json_escape "$1")\"}")
  else
    printf "  ${RED}🔴 FAIL${RST}  %s\n" "$1"
  fi
}
warn() {
  ((WARN++))
  WARN_MSGS+=("$1")
  if $JSON_MODE; then
    JSON_FINDINGS+=("{\"severity\":\"WARN\",\"section\":\"$(_json_escape "$CURRENT_SECTION")\",\"message\":\"$(_json_escape "$1")\"}")
  else
    printf "  ${YLW}⚠️  WARN${RST}  %s\n" "$1"
  fi
}
info() {
  ((INFO++))
  if $JSON_MODE; then
    JSON_FINDINGS+=("{\"severity\":\"INFO\",\"section\":\"$(_json_escape "$CURRENT_SECTION")\",\"message\":\"$(_json_escape "$1")\"}")
  else
    printf "  ${CYN}ℹ️  INFO${RST}  %s\n" "$1"
  fi
}
header() {
  CURRENT_SECTION="$2"
  if ! $JSON_MODE; then
    printf "\n${BOLD}${MAG}━━━ [%s/%s] %s ━━━${RST}\n" "$1" "$TOTAL_SECTIONS" "$2"
  fi
}
sub_header() { $JSON_MODE || printf "  ${CYN}--- %s ---${RST}\n" "$1"; }
txt() { $JSON_MODE || printf "%s\n" "$1"; }

# --- Dependency Check Helper ---
require_cmd() {
  command -v "$1" &>/dev/null
}

# --- SSH config helper: read effective value from sshd_config + includes ---
sshd_cfg_val() {
  local key="$1" val=""
  # Primary: sshd's own parser (handles includes, Match, ordering correctly)
  if command -v sshd &>/dev/null; then
    val=$(sshd -T 2>/dev/null | grep -i "^${key} " | head -1 | awk '{print $2}')
  fi
  # Fallback: manual grep (includes first, then main config — first match wins)
  if [[ -z "$val" && -f /etc/ssh/sshd_config ]]; then
    val=$(grep -hiE "^\s*${key}\s+" /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
  fi
  echo "${val:-}"
}

# --- Privacy Section Helpers ---
_for_each_user() {
  local callback="$1"
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    [[ -d "$home" ]] || continue
    "$callback" "$user" "$uid" "$home"
  done < /etc/passwd
}

_ff_pref() {
  # Search prefs.js, then user.js, then system policies for a Firefox preference.
  # Returns the most specific value found (user.js > prefs.js > policy).
  local file="$1" pref="$2"
  local val="" profile_dir
  profile_dir="$(dirname "$file")"

  # 1. prefs.js (runtime state)
  if [[ -f "$file" ]]; then
    val="$(grep -oP "user_pref\\(\"${pref//./\\.}\",\\s*\\K[^)]*" "$file" 2>/dev/null | tail -1 | tr -d ' "')"
  fi
  # 2. user.js overrides prefs.js
  if [[ -f "$profile_dir/user.js" ]]; then
    local uval
    uval="$(grep -oP "user_pref\\(\"${pref//./\\.}\",\\s*\\K[^)]*" "$profile_dir/user.js" 2>/dev/null | tail -1 | tr -d ' "')"
    [[ -n "$uval" ]] && val="$uval"
  fi
  # 3. System policies (lowest priority, only if nothing found yet)
  if [[ -z "$val" ]]; then
    local pdir pol_val=""
    for pdir in /etc/firefox/policies /usr/lib64/firefox/distribution /usr/lib/firefox/distribution; do
      [[ -f "$pdir/policies.json" ]] || continue
      local pcontent
      pcontent="$(cat "$pdir/policies.json" 2>/dev/null)"
      case "$pref" in
        toolkit.telemetry.enabled)
          if echo "$pcontent" | grep -q '"DisableTelemetry".*true' 2>/dev/null; then
            pol_val="false"
          elif echo "$pcontent" | grep -q '"DisableTelemetry".*false' 2>/dev/null; then
            pol_val="true"
          fi ;;
        browser.contentblocking.category)
          # Extract only the Value within the EnableTrackingProtection block
          local _etp_block
          _etp_block="$(echo "$pcontent" | sed -n '/"EnableTrackingProtection"/,/}/p' 2>/dev/null)"
          if [[ -n "$_etp_block" ]] && echo "$_etp_block" | grep -q '"Value".*true' 2>/dev/null; then
            pol_val="strict"
          fi ;;
        network.cookie.cookieBehavior)
          pol_val="$(echo "$pcontent" | grep -oP '"Behavior"\s*:\s*\K\d+' 2>/dev/null | head -1)" ;;
      esac
      [[ -n "$pol_val" ]] && val="$pol_val" && break
    done
  fi
  [[ -n "$val" ]] && echo "$val" || return 1
}

_gsettings_user() {
  local user="$1" uid="$2" schema="$3" key="$4"
  require_cmd sudo || return 1
  local bus="unix:path=/run/user/${uid}/bus"
  [[ -S "/run/user/${uid}/bus" ]] || return 1
  sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="$bus" gsettings get "$schema" "$key" 2>/dev/null
}

_human_size() {
  # F-002: Use IEC binary prefixes (GiB/MiB/KiB) since values use 2^30/2^20/2^10
  # boundaries — labelling them GB/MB/KB (SI = 10^9/10^6/10^3) is technically
  # incorrect and confuses users comparing to drive marketing capacities.
  local bytes="${1:-0}"
  [[ "$bytes" =~ ^[0-9]+$ ]] || { echo "0B"; return; }
  if [[ "$bytes" -ge 1073741824 ]]; then
    echo "$(( bytes / 1073741824 ))GiB"
  elif [[ "$bytes" -ge 1048576 ]]; then
    echo "$(( bytes / 1048576 ))MiB"
  elif [[ "$bytes" -ge 1024 ]]; then
    echo "$(( bytes / 1024 ))KiB"
  else
    echo "${bytes}B"
  fi
}

# Read effective systemd drop-in config value (main config + drop-in dirs, last wins)
# Usage: _systemd_conf_val <unit_conf> <key>
# Example: _systemd_conf_val /etc/systemd/coredump.conf Storage
_systemd_conf_val() {
  # F-003: previously used `cut -d= -f2` which truncates values containing '='
  # (e.g. Environment=FOO=bar would lose '=bar'). Now uses sed to capture
  # everything after the first '=' and trims surrounding whitespace.
  local base_conf="$1" key="$2" val=""
  local dropin_dir="${base_conf%.conf}.conf.d"
  # Main config
  if [[ -f "$base_conf" ]]; then
    val=$(grep -i "^${key}\s*=" "$base_conf" 2>/dev/null | tail -1 | sed -E 's/^[^=]+=[[:space:]]*//' | sed -E 's/[[:space:]]+$//')
  fi
  # Drop-in overrides (alphabetical, last one wins)
  for dropin in "${dropin_dir}"/*.conf; do
    [[ -f "$dropin" ]] || continue
    local dval
    dval=$(grep -i "^${key}\s*=" "$dropin" 2>/dev/null | tail -1 | sed -E 's/^[^=]+=[[:space:]]*//' | sed -E 's/[[:space:]]+$//')
    [[ -n "$dval" ]] && val="$dval"
  done
  echo "$val"
}

_gsettings_for_users() {
  local schema="$1" key="$2" callback="$3"
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    [[ -S "/run/user/$uid/bus" ]] || continue
    local val
    val=$(sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
      gsettings get "$schema" "$key" 2>/dev/null) || continue
    $callback "$user" "$uid" "$val"
  done < /etc/passwd
}

# KDE Plasma per-user config reader.
# Tries kreadconfig6 → kreadconfig5 → direct INI parse fallback so it works
# on Plasma 5, Plasma 6, and even systems where the kreadconfig binaries
# are not installed (sandboxed/minimal). $home is required for the fallback.
_kreadconfig_for_users() {
  local file="$1" group="$2" key="$3" callback="$4"
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    [[ -S "/run/user/$uid/bus" ]] || continue
    [[ -d "$home/.config" ]] || continue
    local val=""
    if command -v kreadconfig6 &>/dev/null; then
      val=$(sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$uid" \
        kreadconfig6 --file "$file" --group "$group" --key "$key" 2>/dev/null)
    fi
    if [[ -z "$val" ]] && command -v kreadconfig5 &>/dev/null; then
      val=$(sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$uid" \
        kreadconfig5 --file "$file" --group "$group" --key "$key" 2>/dev/null)
    fi
    # Fallback: direct INI parse — works without KDE tooling installed
    if [[ -z "$val" && -f "$home/.config/$file" ]]; then
      val=$(awk -F= -v g="[$group]" -v k="$key" '
        $0==g {in_group=1; next}
        /^\[/ {in_group=0}
        in_group && $1==k {sub(/^[^=]*=/,""); print; exit}
      ' "$home/.config/$file" 2>/dev/null)
    fi
    [[ -n "$val" ]] || continue
    $callback "$user" "$uid" "$val"
  done < /etc/passwd
}

# XFCE per-user config reader using xfconf-query.
# XFCE has no INI fallback — without xfconf-query the check skips silently.
_xfconf_for_users() {
  local channel="$1" property="$2" callback="$3"
  command -v xfconf-query &>/dev/null || return 0
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    [[ -S "/run/user/$uid/bus" ]] || continue
    local val
    val=$(sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
      xfconf-query -c "$channel" -p "$property" 2>/dev/null) || continue
    [[ -n "$val" ]] && $callback "$user" "$uid" "$val"
  done < /etc/passwd
}

# DE-aware screen lock enabled check. Dispatches to GNOME/KDE/XFCE/MATE/Cinnamon.
# Returns "found" via global _DE_LOCK_FOUND for fallthrough INFO messages.
_de_check_screen_lock() {
  local cb="$1"
  _DE_LOCK_FOUND=0
  case "$_DE_FAMILY" in
    gnome)
      _gsettings_for_users "org.gnome.desktop.screensaver" "lock-enabled" "$cb"
      ;;
    kde)
      _kreadconfig_for_users "kscreenlockerrc" "Daemon" "Autolock" "$cb"
      ;;
    xfce)
      _xfconf_for_users "xfce4-screensaver" "/lock/enabled" "$cb"
      ;;
    mate)
      _gsettings_for_users "org.mate.screensaver" "lock-enabled" "$cb"
      ;;
    cinnamon)
      _gsettings_for_users "org.cinnamon.desktop.screensaver" "lock-enabled" "$cb"
      ;;
  esac
}

# DE-aware idle delay check. GNOME/MATE return seconds; KDE/XFCE return minutes
# — callbacks are responsible for normalizing units.
_de_check_idle_delay() {
  local cb="$1"
  case "$_DE_FAMILY" in
    gnome)
      _gsettings_for_users "org.gnome.desktop.session" "idle-delay" "$cb"
      ;;
    kde)
      # Plasma uses minutes via kscreenlockerrc Daemon Timeout
      _kreadconfig_for_users "kscreenlockerrc" "Daemon" "Timeout" "$cb"
      ;;
    xfce)
      # XFCE uses minutes via xfce4-screensaver /idle-activation/delay
      _xfconf_for_users "xfce4-screensaver" "/idle-activation/delay" "$cb"
      ;;
    mate)
      _gsettings_for_users "org.mate.session" "idle-delay" "$cb"
      ;;
    cinnamon)
      _gsettings_for_users "org.cinnamon.desktop.session" "idle-delay" "$cb"
      ;;
  esac
}

# DE-aware lock-on-suspend check. Boolean.
_de_check_lock_on_suspend() {
  local cb="$1"
  case "$_DE_FAMILY" in
    gnome)
      # ubuntu-lock-on-suspend (Ubuntu) → fallback lock-enabled (upstream)
      _gsettings_for_users "org.gnome.desktop.screensaver" "ubuntu-lock-on-suspend" "$cb"
      ;;
    kde)
      _kreadconfig_for_users "kscreenlockerrc" "Daemon" "LockOnResume" "$cb"
      ;;
    xfce)
      _xfconf_for_users "xfce4-screensaver" "/lock/enabled" "$cb"
      ;;
    mate)
      _gsettings_for_users "org.mate.screensaver" "lock-enabled" "$cb"
      ;;
    cinnamon)
      _gsettings_for_users "org.cinnamon.desktop.screensaver" "lock-enabled" "$cb"
      ;;
  esac
}

# DE-aware notifications-on-lockscreen check.
_de_check_notifications_on_lock() {
  local cb="$1"
  case "$_DE_FAMILY" in
    gnome)
      _gsettings_for_users "org.gnome.desktop.notifications" "show-in-lock-screen" "$cb"
      ;;
    kde)
      # Plasma 5/6: ~/.config/plasmanotifyrc [DoNotDisturb] WhenScreenLocked
      _kreadconfig_for_users "plasmanotifyrc" "DoNotDisturb" "WhenScreenLocked" "$cb"
      ;;
    cinnamon)
      _gsettings_for_users "org.cinnamon.desktop.notifications" "display-notifications-on-lock-screen" "$cb"
      ;;
  esac
}

# DE-aware user-switching lockdown check.
_de_check_user_switching() {
  local cb="$1"
  case "$_DE_FAMILY" in
    gnome)
      _gsettings_for_users "org.gnome.desktop.lockdown" "disable-user-switching" "$cb"
      ;;
    kde)
      # Plasma: ~/.config/kdeglobals [KDE Action Restrictions] action/start_new_session
      _kreadconfig_for_users "kdeglobals" "KDE Action Restrictions" "action/start_new_session" "$cb"
      ;;
    cinnamon)
      _gsettings_for_users "org.cinnamon.desktop.lockdown" "disable-user-switching" "$cb"
      ;;
  esac
}

# DE-aware file indexer detection (GNOME Tracker / KDE Baloo / Recoll / etc.).
# Returns description text via stdout, severity via exit code: 0=running,1=not.
_de_check_file_indexer() {
  case "$_DE_FAMILY" in
    gnome)
      local _u _uid _shell
      while IFS=: read -r _u _ _uid _ _ _ _shell; do
        [[ "$_uid" -ge 1000 && "$_uid" -lt 65534 ]] || continue
        [[ "$_shell" == */nologin || "$_shell" == */false ]] && continue
        if sudo -u "$_u" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${_uid}/bus" \
             systemctl --user is-active --quiet tracker-miner-fs-3.service 2>/dev/null \
           || sudo -u "$_u" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${_uid}/bus" \
             systemctl --user is-active --quiet tracker-miner-fs.service 2>/dev/null \
           || sudo -u "$_u" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${_uid}/bus" \
             systemctl --user is-active --quiet localsearch-3.service 2>/dev/null; then
          echo "GNOME Tracker"; return 0
        fi
      done < /etc/passwd
      echo "GNOME Tracker"; return 1
      ;;
    kde)
      if pgrep -x baloo_file &>/dev/null || pgrep -x baloo_file_extractor &>/dev/null; then
        echo "KDE Baloo"; return 0
      fi
      echo "KDE Baloo"; return 1
      ;;
    *)
      # Recoll/Strigi/etc — generic process check
      if pgrep -x recoll &>/dev/null || pgrep -x recollindex &>/dev/null; then
        echo "Recoll"; return 0
      fi
      echo "any"; return 1
      ;;
  esac
}

# Snapshot/backup/container-aware find for system-wide scans.
# Excludes:
# - Snapper (/.snapshots, /home/.snapshots, /var/.snapshots) — btrfs subvolumes
#   share dev-id with parent, so -xdev alone doesn't filter them
# - Timeshift (Mint default)
# - Custom btrfs snapshot conventions (.btrfs-snapshots, .snapper)
# - Container storage (Podman, Docker, LXD, systemd-nspawn) — image layers
#   contain full /usr/bin SUID trees that inflate counts massively on
#   bootc/Silverblue/OCI-image-build systems
# - OSTree object stores — content-addressed file objects carry original SUID
_safe_find_root() {
  timeout 30 find / -xdev \
    -not -path '*/.snapshots/*' \
    -not -path '*/.timeshift/*' \
    -not -path '*/timeshift-btrfs/*' \
    -not -path '*/.btrfs-snapshots/*' \
    -not -path '*/.snapper/*' \
    -not -path '/var/lib/containers/storage/*' \
    -not -path '/var/lib/docker/*' \
    -not -path '/var/lib/lxd/*' \
    -not -path '/var/lib/lxc/*' \
    -not -path '/var/lib/machines/*' \
    -not -path '*/ostree/repo/objects/*' \
    "$@" 2>/dev/null
}

# Same exclusion pattern, scoped to /home and /root for secret/key scans.
# Also excludes common dev/cache directories where false-positive .key/.env
# files live (node_modules, .git/objects, .cache, .venv).
_safe_find_home() {
  find /home /root \
    -not -path '*/.snapshots/*' \
    -not -path '*/.timeshift/*' \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/objects/*' \
    -not -path '*/.cache/*' \
    -not -path '*/.venv/*' \
    -not -path '*/__pycache__/*' \
    -not -path '*/target/*' \
    "$@" 2>/dev/null
}

# Content-based private key detection.
# Filename ".key" alone is NOT a key (uBlock Origin IDB records, test fixtures,
# API config files all use this). Magic-string check on first 64 bytes for
# OpenSSL/PEM headers, fallback to file(1) for OpenSSH custom format.
_is_real_private_key() {
  local f="$1"
  [[ -r "$f" && -s "$f" ]] || return 1
  # OpenSSL/PEM format (covers RSA, EC, DSA, encrypted keys)
  if head -c 64 "$f" 2>/dev/null | grep -qE "^-----BEGIN.*PRIVATE KEY-----"; then
    return 0
  fi
  # OpenSSH custom format (id_ed25519 etc. without PEM header)
  if command -v file &>/dev/null; then
    file "$f" 2>/dev/null | grep -qiE "openssh private key|ssh private key|pem rsa private|pem ec private" && return 0
  fi
  return 1
}

# Generalized firewall-block check: any active firewall blocking on PRIMARY_IFACE.
# Replaces nft-only has_nft_drop_on_phys for fairness on iptables/ufw systems.
has_firewall_block_on_phys() {
  has_nft_drop_on_phys && return 0
  if require_cmd iptables; then
    iptables -L -n -v 2>/dev/null | awk -v iface="$PRIMARY_IFACE" \
      '/DROP/ && $0 ~ iface {found=1} END{exit !found}' && return 0
    iptables -L INPUT -n 2>/dev/null | grep -qE "policy DROP|policy REJECT" && return 0
  fi
  if require_cmd ufw && systemctl is-active ufw &>/dev/null; then
    return 0
  fi
  return 1
}

# Cross-distro GRUB main-config path detection.
_grub_main_cfg() {
  local p
  for p in /boot/grub2/grub.cfg /boot/grub/grub.cfg \
           /boot/efi/EFI/fedora/grub.cfg /boot/efi/EFI/debian/grub.cfg \
           /boot/efi/EFI/ubuntu/grub.cfg /boot/efi/EFI/arch/grub.cfg; do
    [[ -f "$p" ]] && { echo "$p"; return; }
  done
}

# Cross-distro password-file paths for GRUB.
_grub_password_paths() {
  local paths=()
  [[ -f /boot/grub2/user.cfg ]] && paths+=(/boot/grub2/user.cfg)
  [[ -f /boot/grub/user.cfg ]] && paths+=(/boot/grub/user.cfg)
  [[ -d /etc/grub.d ]] && paths+=(/etc/grub.d)
  [[ -f /etc/default/grub ]] && paths+=(/etc/default/grub)
  printf '%s\n' "${paths[@]}"
}

# Service-name normalization across distros.
# httpd|apache2 are different distros' names for the same Apache.
# smb|smbd|nmb|nmbd vary between Fedora and Debian.
_service_active_any() {
  # Returns 0 if any of the service names is active
  local s
  for s in "$@"; do
    systemctl is-active "$s" &>/dev/null && return 0
  done
  return 1
}

_service_masked_any() {
  local s
  for s in "$@"; do
    systemctl is-masked "$s" &>/dev/null && return 0
  done
  return 1
}

_service_enabled_any() {
  local s
  for s in "$@"; do
    systemctl is-enabled "$s" &>/dev/null && return 0
  done
  return 1
}

[[ $EUID -ne 0 ]] && { echo "Requires root. Run with: sudo bash \"$0\""; exit 1; }

# --- Distro Detection ---
DISTRO="unknown"
DISTRO_FAMILY="unknown"
DISTRO_PRETTY="Unknown Linux"
if [[ -f /etc/os-release ]]; then
  # Parse os-release safely — no eval, no source, explicit key whitelist only
  while IFS='=' read -r _osr_key _osr_val; do
    _osr_val="${_osr_val%\"}"; _osr_val="${_osr_val#\"}"
    # shellcheck disable=SC2034  # VERSION_ID reserved for future per-distro version checks
    case "$_osr_key" in
      ID)          ID="$_osr_val" ;;
      NAME)        NAME="$_osr_val" ;;
      PRETTY_NAME) PRETTY_NAME="$_osr_val" ;;
      VERSION_ID)  VERSION_ID="$_osr_val" ;;
    esac
  done < <(grep -E '^(ID|NAME|PRETTY_NAME|VERSION_ID)=' /etc/os-release 2>/dev/null)
  DISTRO_PRETTY="${PRETTY_NAME:-$NAME}"
  # shellcheck disable=SC2034  # DISTRO reserved for future per-distro checks
  case "${ID,,}" in
    fedora)                                DISTRO="fedora"; DISTRO_FAMILY="rhel" ;;
    rhel|centos|rocky|alma|almalinux)      DISTRO="${ID,,}"; DISTRO_FAMILY="rhel" ;;
    ubuntu)                                DISTRO="ubuntu"; DISTRO_FAMILY="debian" ;;
    debian|linuxmint|pop)                  DISTRO="${ID,,}"; DISTRO_FAMILY="debian" ;;
    arch|manjaro|endeavouros|artix|garuda) DISTRO="${ID,,}"; DISTRO_FAMILY="arch" ;;
    opensuse*|sles|suse)                   DISTRO="${ID,,}"; DISTRO_FAMILY="suse" ;;
    *)                                     DISTRO="${ID,,}"; DISTRO_FAMILY="unknown" ;;
  esac
fi

KERNEL=$(uname -r)
HOSTNAME=$(hostname)
NOW=$(date '+%Y-%m-%d %H:%M:%S')
ARCH=$(uname -m)

# --- Detect Desktop Environment (survives sudo) ---
if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]]; then
  DESKTOP_ENV="$XDG_CURRENT_DESKTOP"
elif [[ -n "${DESKTOP_SESSION:-}" ]]; then
  DESKTOP_ENV="$DESKTOP_SESSION"
else
  # Under sudo, env vars are stripped. Read from the real user's session process.
  _detect_user="${SUDO_USER:-}"
  if [[ -n "$_detect_user" ]]; then
    # Try gnome-shell, plasmashell, xfce4-session, cinnamon-session, mate-session
    for _de_proc in gnome-shell plasmashell xfce4-session cinnamon-session mate-session sway Hyprland; do
      _de_pid=$(pgrep -u "$_detect_user" "$_de_proc" 2>/dev/null | head -1)
      if [[ -n "$_de_pid" && -r "/proc/$_de_pid/environ" ]]; then
        DESKTOP_ENV=$(tr '\0' '\n' < "/proc/$_de_pid/environ" 2>/dev/null | grep -oP '^XDG_CURRENT_DESKTOP=\K.*' | head -1)
        [[ -n "$DESKTOP_ENV" ]] && break
      fi
    done
  fi
fi
DESKTOP_ENV="${DESKTOP_ENV:-unknown}"

# Desktop detection — used by service-severity adjustments throughout.
# Considers system "desktop" if any DE detected OR a display manager is active.
_IS_DESKTOP=false
[[ "$DESKTOP_ENV" != "unknown" ]] && _IS_DESKTOP=true
if ! $_IS_DESKTOP; then
  for _dm in gdm gdm3 lightdm sddm lxdm; do
    if systemctl is-active "$_dm" &>/dev/null; then
      _IS_DESKTOP=true
      break
    fi
  done
fi

# DE-family classification for per-DE config dispatching (KDE/XFCE/etc).
# Used by screen-lock, file-indexer, clipboard, keyring checks instead of
# GNOME-only gsettings calls.
_DE_FAMILY="unknown"
case "${DESKTOP_ENV,,}" in
  *gnome*|*unity*|*budgie*|*pantheon*) _DE_FAMILY="gnome" ;;
  *kde*|*plasma*) _DE_FAMILY="kde" ;;
  *xfce*) _DE_FAMILY="xfce" ;;
  *cinnamon*) _DE_FAMILY="cinnamon" ;;
  *mate*) _DE_FAMILY="mate" ;;
  *lxqt*) _DE_FAMILY="lxqt" ;;
  *sway*|*hypr*|*wayfire*|*river*) _DE_FAMILY="wm" ;;
esac

# --- Dynamic Interface & Gateway Detection ---
PRIMARY_IFACE=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
if [[ -z "$PRIMARY_IFACE" ]] || echo "$PRIMARY_IFACE" | grep -qE "^(tun|wg|proton|pvpn)"; then
  PRIMARY_IFACE=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -vE '^(lo|tun|wg|proton|pvpn|docker|br-|veth)' | head -1)
fi
PRIMARY_IFACE="${PRIMARY_IFACE:-eth0}"

ACTUAL_GW=$(ip route show default 2>/dev/null | grep -oP 'via \K\S+' | head -1)

# VPN interfaces (dynamic)
VPN_IFACES=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(tun|wg|proton|pvpn)' | tr '\n' ' ')

# Helper: check if any nftables rule drops traffic on the physical interface
has_nft_drop_on_phys() {
  require_cmd nft || return 1
  local tables
  tables=$(nft list tables 2>/dev/null | awk '{print $2, $3}')
  while read -r family table; do
    [[ -z "$table" ]] && continue
    if nft list table "$family" "$table" 2>/dev/null | grep -qE "oifname \"$PRIMARY_IFACE\".*drop"; then
      return 0
    fi
  done <<< "$tables"
  return 1
}

get_killswitch_tables() {
  require_cmd nft || return
  while read -r _ family table; do
    [[ -z "$table" ]] && continue
    if nft list table "$family" "$table" 2>/dev/null | grep -qE "oifname \"$PRIMARY_IFACE\".*drop"; then
      echo "$family $table"
    fi
  done < <(nft list tables 2>/dev/null)
}

if ! $JSON_MODE; then
printf "${BOLD}${WHT}\n"
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  🛡️ NoID Privacy for Linux v${NOID_PRIVACY_VERSION} — Privacy & Security Audit"
echo "║  $NOW | $HOSTNAME | $KERNEL"
echo "║  Arch: $ARCH | Distro: $DISTRO_PRETTY"
echo "║  Checks: 390+ across $TOTAL_SECTIONS sections"
echo "╚══════════════════════════════════════════════════════════════════════╝"
printf "${RST}\n"
fi

if ! $JSON_MODE; then
  case "$DISTRO_FAMILY" in
    rhel|debian) ;; # Full support
    arch)    printf "  ${YLW}⚠️  Arch-based distro ($DISTRO_PRETTY) — some package checks adapted${RST}\n" ;;
    suse)    printf "  ${YLW}⚠️  SUSE-based distro ($DISTRO_PRETTY) — some package checks adapted${RST}\n" ;;
    unknown) printf "  ${YLW}⚠️  Unknown distro ($DISTRO_PRETTY) — some checks may not apply${RST}\n" ;;
  esac
fi

###############################################################################
if ! should_skip "kernel"; then
header "01" "KERNEL & BOOT INTEGRITY"
###############################################################################

info "Kernel: $KERNEL"

# Secure Boot — only relevant on UEFI systems (F-018: legacy BIOS misclassified)
if [[ ! -d /sys/firmware/efi ]]; then
  info "Secure Boot: N/A (legacy BIOS, no UEFI firmware)"
elif require_cmd mokutil; then
  if mokutil --sb-state 2>/dev/null | grep -q "enabled"; then
    pass "Secure Boot: ENABLED"
  else
    fail "Secure Boot: DISABLED"
  fi
elif [[ -d /sys/firmware/efi/efivars ]]; then
  # Fallback: read EFI variable directly when mokutil missing
  _SB_VAR=$(find /sys/firmware/efi/efivars -name "SecureBoot-*" 2>/dev/null | head -1)
  if [[ -n "$_SB_VAR" ]] && [[ "$(od -An -t u1 -N1 -j4 "$_SB_VAR" 2>/dev/null | tr -d ' ')" == "1" ]]; then
    pass "Secure Boot: ENABLED (via efivars)"
  else
    info "Secure Boot: cannot determine without mokutil"
  fi
else
  info "Secure Boot: cannot determine (mokutil missing, efivars unreadable)"
fi

# Kernel Lockdown
if [[ -f /sys/kernel/security/lockdown ]]; then
  LOCKDOWN=$(grep -oP '\[\K[^\]]+' /sys/kernel/security/lockdown 2>/dev/null)
  if [[ -z "$LOCKDOWN" ]]; then
    warn "Kernel Lockdown: could not parse status"
  elif [[ "$LOCKDOWN" == "none" ]]; then
    warn "Kernel Lockdown: none (despite Secure Boot)"
  else
    pass "Kernel Lockdown: $LOCKDOWN"
  fi
else
  warn "Kernel Lockdown: not available"
fi

# Kernel Taint
TAINT=$(< /proc/sys/kernel/tainted)
if [[ "$TAINT" -eq 0 ]]; then
  pass "Kernel Taint: 0 (clean)"
else
  if (( TAINT & 4096 )) || (( TAINT & 1 )); then
    info "Kernel Taint: $TAINT (proprietary/out-of-tree module — expected with NVIDIA)"
  else
    warn "Kernel Taint: $TAINT (unexpected taint flags)"
  fi
fi

# Insecure boot parameters check
CMDLINE=$(< /proc/cmdline)
for PARAM in "nomodeset" "noapic" "acpi=off" "selinux=0" "enforcing=0" "audit=0"; do
  if echo "$CMDLINE" | grep -qw "$PARAM"; then
    fail "Insecure boot parameter: $PARAM"
  fi
done

# Secure boot parameters
for PARAM in "init_on_alloc=1" "init_on_free=1" "slab_nomerge" "pti=on" "vsyscall=none" "debugfs=off" "page_alloc.shuffle=1" "randomize_kstack_offset=on"; do
  if echo "$CMDLINE" | grep -qw "$PARAM"; then
    pass "Boot hardening: $PARAM"
  else
    warn "Boot hardening missing: $PARAM"
  fi
done

# Grub cmdline security params (new)
PARAM="spec_store_bypass_disable=on"
if echo "$CMDLINE" | grep -qw "$PARAM"; then
  pass "Boot security param: $PARAM"
else
  warn "Boot security param missing: $PARAM"
fi
# Optional params (can break NVIDIA/hardware on desktop systems)
for PARAM in "iommu=force" "lockdown=confidentiality"; do
  if echo "$CMDLINE" | grep -qw "$PARAM"; then
    pass "Boot security param: $PARAM"
  else
    info "Boot security param not set: $PARAM (optional — may break NVIDIA/hardware)"
  fi
done

# LUKS
if lsblk -o TYPE 2>/dev/null | grep -q crypt; then
  pass "LUKS encryption active"
  LUKS_DEVS=$(lsblk -o NAME,TYPE 2>/dev/null | grep crypt | awk '{print $1}')
  info "LUKS devices: $LUKS_DEVS"
else
  fail "No LUKS encryption detected"
fi

# Boot Performance
if require_cmd systemd-analyze; then
  BOOT_TIME=$(systemd-analyze 2>/dev/null | head -1)
  info "Boot: $BOOT_TIME"

  # Top 5 slowest boot services
  sub_header "Top 5 slowest boot services"
  if ! $JSON_MODE; then
    while read -r line; do
      printf "       %s\n" "$line"
    done < <(systemd-analyze blame 2>/dev/null | head -5)
  fi
fi

# GRUB Password — F-031: cross-distro detection (Fedora/RHEL: /boot/grub2/,
# Debian/Ubuntu/Arch: /boot/grub/) plus direct grub.cfg content scan as
# authoritative fallback (catches all generation paths).
_GRUB_CFG=$(_grub_main_cfg)
if [[ -n "$_GRUB_CFG" ]]; then
  _grub_pwd_found=false
  # 1. user.cfg (Fedora's grub-setpassword convention)
  for _gucfg in /boot/grub2/user.cfg /boot/grub/user.cfg; do
    [[ -f "$_gucfg" ]] && _grub_pwd_found=true
  done
  # 2. grub.d snippets (Debian convention via 40_password.conf or similar)
  if ! $_grub_pwd_found; then
    if grep -rqE '^\s*(password_pbkdf2|password)\s+' /etc/grub.d/ 2>/dev/null; then
      _grub_pwd_found=true
    fi
  fi
  # 3. Authoritative: scan generated grub.cfg directly — works on any distro
  #    regardless of how the password was inserted (Anaconda, debconf, manual)
  if ! $_grub_pwd_found; then
    if grep -qE '^\s*(password_pbkdf2|password)\s+' "$_GRUB_CFG" 2>/dev/null; then
      _grub_pwd_found=true
    fi
  fi
  if $_grub_pwd_found; then
    pass "GRUB password set"
  else
    if lsblk -o TYPE 2>/dev/null | grep -q crypt; then
      info "GRUB no password (LUKS encryption protects)"
    else
      warn "GRUB no password (physical access = root)"
    fi
  fi
fi

# Running latest installed kernel?
LATEST_KERNEL=$(ls -v /boot/vmlinuz-* 2>/dev/null | tail -1 | sed 's|.*/vmlinuz-||')
if [[ -n "$LATEST_KERNEL" ]]; then
  if [[ "$KERNEL" == "$LATEST_KERNEL" ]]; then
    pass "Running latest installed kernel ($KERNEL)"
  else
    warn "Running kernel $KERNEL but $LATEST_KERNEL is installed — reboot recommended"
  fi
fi

fi # end kernel

###############################################################################
# Initialize MAC detection variables (used in AI output even if section is skipped)
HAS_SELINUX=false
HAS_APPARMOR=false
if require_cmd getenforce; then
  _se_mode=$(getenforce 2>/dev/null)
  [[ "$_se_mode" == "Enforcing" || "$_se_mode" == "Permissive" ]] && HAS_SELINUX=true
fi
require_cmd aa-status && HAS_APPARMOR=true

if ! should_skip "selinux"; then

if $HAS_SELINUX; then
header "02" "SELINUX & MAC"
###############################################################################

SE_STATUS=$(getenforce)
if [[ "$SE_STATUS" == "Enforcing" ]]; then
  pass "SELinux: Enforcing"
elif [[ "$SE_STATUS" == "Permissive" ]]; then
  fail "SELinux: Permissive (logging only, not blocking!)"
else
  fail "SELinux: Disabled"
fi

# SELinux Booleans (dangerous ones)
if require_cmd getsebool; then
  DANGEROUS_BOOLS="httpd_can_network_connect httpd_execmem allow_execheap allow_execmod allow_execstack"
  for BOOL in $DANGEROUS_BOOLS; do
    VAL=$(getsebool "$BOOL" 2>/dev/null | awk '{print $3}' || echo "n/a")
    if [[ "$VAL" == "on" ]]; then
      if [[ "$BOOL" == "allow_execmod" || "$BOOL" == "allow_execstack" ]] && lsmod | grep -q nvidia; then
        info "SELinux bool active: $BOOL = on (NVIDIA dependency)"
      else
        warn "SELinux bool active: $BOOL = on"
      fi
    fi
  done
fi

# SELinux Denials
# Known-benign processes that routinely generate AVC denials as part of their normal operation:
#   aide         — file integrity checks access many restricted paths
#   usbguard-daemon — USB access control interacts with udev/systemd
#   systemd-logind  — session management, normal boot-time interactions
# Only warn if AVC denials come from OTHER (unexpected) processes.
if require_cmd ausearch; then
  _SE_AVC_RAW=$(ausearch -m avc --start recent 2>/dev/null)
  SE_DENIALS=$(echo "$_SE_AVC_RAW" | grep -c "type=AVC" || true)
  SE_DENIALS=${SE_DENIALS//[^0-9]/}
  SE_DENIALS=${SE_DENIALS:-0}
  if [[ "$SE_DENIALS" -gt 0 ]]; then
    _SE_UNEXPECTED=$(echo "$_SE_AVC_RAW" \
      | grep -oP 'comm="\K[^"]+' \
      | grep -cvE "^(aide|usbguard-daemon|usbguard|systemd-logind|rpm)$" || true)
    _SE_UNEXPECTED=${_SE_UNEXPECTED//[^0-9]/}
    _SE_UNEXPECTED=${_SE_UNEXPECTED:-0}
    if [[ "$_SE_UNEXPECTED" -eq 0 ]]; then
      info "SELinux: $SE_DENIALS AVC denials (recent) — aide/usbguard/logind only (MAC working correctly)"
    else
      warn "SELinux: $SE_DENIALS AVC denials ($_SE_UNEXPECTED from unexpected processes)"
    fi
  else
    pass "SELinux: 0 AVC denials (recent)"
  fi
fi

elif $HAS_APPARMOR; then
  header "02" "APPARMOR & MAC"

  AA_ENFORCED=$(aa-status 2>/dev/null | grep -oP '^\s*\K\d+(?=\s+profiles? are in enforce mode)' || echo "0")
  AA_ENFORCED=${AA_ENFORCED:-0}
  AA_COMPLAIN=$(aa-status 2>/dev/null | grep -oP '^\s*\K\d+(?=\s+profiles? are in complain mode)' || echo "0")
  AA_COMPLAIN=${AA_COMPLAIN:-0}
  if [[ "$AA_ENFORCED" -gt 0 ]]; then
    pass "AppArmor: $AA_ENFORCED profiles enforcing, $AA_COMPLAIN complaining"
  else
    warn "AppArmor: no enforcing profiles"
  fi

else
  header "02" "MANDATORY ACCESS CONTROL"
  if require_cmd getenforce && [[ "$(getenforce 2>/dev/null)" == "Disabled" ]]; then
    fail "SELinux: Disabled (getenforce present but SELinux is off)"
  else
    warn "No MAC system (SELinux/AppArmor) detected"
  fi
fi
fi # end selinux

###############################################################################
if ! should_skip "firewall"; then
header "03" "FIREWALL"
###############################################################################

if require_cmd firewall-cmd && systemctl is-active firewalld &>/dev/null; then
  pass "firewalld: active"

  # Check zones (permanent config only — runtime overrides are not checked)
  _DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "")
  for ZONE in $(firewall-cmd --get-zones 2>/dev/null); do
    TARGET=$(firewall-cmd --zone="$ZONE" --get-target --permanent 2>/dev/null || echo "")
    [[ -z "$TARGET" ]] && continue  # zone doesn't exist
    SERVICES=$(firewall-cmd --zone="$ZONE" --list-services --permanent 2>/dev/null || echo "")
    PORTS=$(firewall-cmd --zone="$ZONE" --list-ports --permanent 2>/dev/null || echo "")
    IFACES=$(firewall-cmd --zone="$ZONE" --list-interfaces --permanent 2>/dev/null || echo "")

    # Only evaluate zones that are actively in use:
    # - Zones with interfaces explicitly assigned, OR
    # - The default zone (applies to any interface not in another zone)
    # Zones with no interfaces and not the default zone are inactive — skip them.
    _ZONE_IS_DEFAULT=false
    [[ "$ZONE" == "$_DEFAULT_ZONE" ]] && _ZONE_IS_DEFAULT=true

    if [[ -n "$IFACES" ]] || $_ZONE_IS_DEFAULT; then
      # Check if all assigned interfaces are VPN/virtual (not physical internet-facing)
      _ALL_VPN=true
      for _iface in $IFACES; do
        if ! echo "$_iface" | grep -qE "^(tun|wg|proton|pvpn|lo)"; then
          _ALL_VPN=false
          break
        fi
      done
      # VPN-only zones or empty default zones with VPN traffic are not directly internet-facing
      if [[ -z "$IFACES" ]] && $_ZONE_IS_DEFAULT; then
        # Default zone applies to all unassigned interfaces — evaluate as exposed
        if [[ "$TARGET" == "DROP" || "$TARGET" == "REJECT" || "$TARGET" == "%%REJECT%%" ]]; then
          pass "Zone $ZONE (default): target=$TARGET"
        else
          warn "Zone $ZONE (default): target=$TARGET (not DROP/REJECT — applies to unassigned interfaces)"
        fi
        if [[ -n "$SERVICES" ]]; then
          warn "Zone $ZONE (default) open services: $SERVICES"
        fi
        if [[ -n "$PORTS" ]]; then
          warn "Zone $ZONE (default) open ports: $PORTS"
        fi
      elif $_ALL_VPN && [[ -n "$IFACES" ]]; then
        info "Zone $ZONE: target=$TARGET (VPN-only interfaces: $IFACES)"
      elif [[ "$TARGET" == "DROP" || "$TARGET" == "REJECT" || "$TARGET" == "%%REJECT%%" ]]; then
        pass "Zone $ZONE: target=$TARGET"
      else
        warn "Zone $ZONE: target=$TARGET (not DROP/REJECT)"
      fi
      if [[ -n "$SERVICES" ]] && ! $_ALL_VPN && [[ -n "$IFACES" ]]; then
        warn "Zone $ZONE open services: $SERVICES"
      elif [[ -n "$SERVICES" ]] && [[ -n "$IFACES" ]]; then
        info "Zone $ZONE services: $SERVICES (VPN-only)"
      fi
      if [[ -n "$PORTS" ]] && ! $_ALL_VPN && [[ -n "$IFACES" ]]; then
        warn "Zone $ZONE open ports: $PORTS"
      fi
      if [[ -n "$IFACES" ]]; then
        info "Zone $ZONE interfaces: $IFACES"
      fi
    fi
  done

  # Default Zone
  DEF_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
  info "Default zone: $DEF_ZONE"

  # Active Zones
  ACTIVE_ZONES=$(firewall-cmd --get-active-zones 2>/dev/null)
  info "Active zones:"
  if ! $JSON_MODE; then
    while IFS= read -r zline; do
      [[ -n "$zline" ]] && printf "  %s\n" "$zline"
    done <<< "$ACTIVE_ZONES"
  fi

  # Rich Rules
  RICH_RULES=$(firewall-cmd --list-rich-rules 2>/dev/null || echo "")
  if [[ -n "$RICH_RULES" ]]; then
    RICH_COUNT=$(echo "$RICH_RULES" | wc -l)
    info "Rich rules: $RICH_COUNT"
    if ! $JSON_MODE; then
      while read -r rule; do
        printf "       %s\n" "$rule"
      done < <(echo "$RICH_RULES" | head -5)
    fi
  fi

  # Forward Ports
  FWD=$(firewall-cmd --list-forward-ports 2>/dev/null || echo "")
  if [[ -n "$FWD" ]]; then
    warn "Forward ports active: $FWD"
  fi

  # Masquerading
  if firewall-cmd --query-masquerade &>/dev/null; then
    warn "Masquerading active"
  fi

  # Firewall Policies (firewalld 0.9+: inter-zone traffic control)
  FWD_POLICIES=$(firewall-cmd --list-policies 2>/dev/null || true)
  if [[ -n "$FWD_POLICIES" ]]; then
    sub_header "Firewall Policies"
    while IFS= read -r policy; do
      [[ -z "$policy" ]] && continue
      PTARGET=$(firewall-cmd --policy="$policy" --get-target 2>/dev/null || echo "unknown")
      if [[ "$PTARGET" == "DROP" || "$PTARGET" == "REJECT" ]]; then
        pass "Policy '$policy': target=$PTARGET (blocks inter-zone traffic)"
      elif [[ "$PTARGET" == "CONTINUE" || "$PTARGET" == "ACCEPT" ]]; then
        info "Policy '$policy': target=$PTARGET"
      else
        info "Policy '$policy': target=$PTARGET"
      fi
    done <<< "$FWD_POLICIES"
  fi
elif require_cmd ufw; then
  UFW_STATUS=$(ufw status 2>/dev/null | head -1)
  if echo "$UFW_STATUS" | grep -qi "active"; then
    pass "ufw: active"
  else
    fail "ufw: inactive"
  fi
  info "Firewall: ufw (firewalld not available)"
elif require_cmd iptables; then
  # Count actual rules (not chain headers) — subtract header lines and empty lines
  IPTABLES_RULES=$(iptables -L -n 2>/dev/null | grep -cvE "^Chain |^target |^$" || true)
  IPTABLES_RULES=${IPTABLES_RULES:-0}
  if [[ "$IPTABLES_RULES" -gt 0 ]]; then
    pass "iptables: $IPTABLES_RULES rules"
  else
    warn "iptables: minimal rules"
  fi
  info "Firewall: iptables (firewalld not available)"
else
  fail "No firewall detected (firewalld/ufw/iptables)"
fi

# Firewall Logging
sub_header "Firewall Logging"
if require_cmd firewall-cmd && systemctl is-active firewalld &>/dev/null; then
  _FW_LOG_DENIED=$(firewall-cmd --get-log-denied 2>/dev/null || echo "off")
  if [[ "$_FW_LOG_DENIED" == "off" ]]; then
    warn "Firewall logging: denied packets NOT logged (firewall-cmd --get-log-denied=off)"
  else
    pass "Firewall logging: denied packets logged (mode: $_FW_LOG_DENIED)"
  fi
elif require_cmd ufw; then
  _UFW_LOG=$(ufw status verbose 2>/dev/null | grep -i "^Logging:" | awk '{print $2}')
  if [[ "${_UFW_LOG,,}" == "off" || -z "$_UFW_LOG" ]]; then
    warn "UFW logging disabled"
  else
    pass "UFW logging: $_UFW_LOG"
  fi
elif require_cmd iptables; then
  _IPT_LOG=$(iptables -L -n 2>/dev/null | grep -c "LOG" || true)
  if [[ "${_IPT_LOG:-0}" -gt 0 ]]; then
    pass "iptables: $_IPT_LOG LOG rules"
  else
    info "iptables: no LOG rules detected"
  fi
fi

fi # end firewall

###############################################################################
if ! should_skip "nftables"; then
header "04" "NFTABLES & KILL-SWITCH"
###############################################################################

if require_cmd nft; then
  # Detect if firewalld manages nftables as its backend (default on Fedora/RHEL)
  _NFTABLES_BACKEND=false
  if systemctl is-active firewalld &>/dev/null; then
    _FWD_BE=$(grep -i "^FirewallBackend" /etc/firewalld/firewalld.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
    # Default backend on modern systems (Fedora 31+, RHEL 8+) is nftables
    if [[ -z "$_FWD_BE" || "${_FWD_BE,,}" == "nftables" ]]; then
      _NFTABLES_BACKEND=true
    fi
  fi

  if systemctl is-active nftables &>/dev/null; then
    pass "nftables: active (standalone)"
  elif $_NFTABLES_BACKEND; then
    pass "nftables: active via firewalld backend"
  else
    warn "nftables: inactive"
  fi

  if systemctl is-enabled nftables &>/dev/null; then
    pass "nftables: boot-persistent (standalone)"
  elif $_NFTABLES_BACKEND; then
    pass "nftables: boot-persistent via firewalld"
  else
    warn "nftables: not boot-persistent"
  fi

  # Kill-Switch detection
  KS_TABLES=$(get_killswitch_tables)
  if [[ -n "$KS_TABLES" ]]; then
    KS_COUNT=$(echo "$KS_TABLES" | wc -l)
    pass "VPN kill-switch detected ($KS_COUNT table(s) dropping on $PRIMARY_IFACE)"

    if has_nft_drop_on_phys; then
      pass "Kill-switch: $PRIMARY_IFACE drop active"
    else
      fail "Kill-switch: $PRIMARY_IFACE drop MISSING"
    fi

    # Duplicate rule check
    ALL_RULES=""
    while read -r ks_family ks_table; do
      ALL_RULES+=$(nft list table "$ks_family" "$ks_table" 2>/dev/null | grep "oifname")
      ALL_RULES+=$'\n'
    done <<< "$KS_TABLES"
    RULE_COUNT=$(echo "$ALL_RULES" | grep -c "oifname" || true)
    RULE_COUNT=${RULE_COUNT:-0}
    UNIQUE_RULES=$(echo "$ALL_RULES" | grep "oifname" | sort -u | wc -l)
    if [[ "$RULE_COUNT" -ne "$UNIQUE_RULES" ]]; then
      info "Kill-switch: $RULE_COUNT rules ($UNIQUE_RULES unique) — duplicates from VPN management"
    else
      pass "Kill-switch: $RULE_COUNT rules (no duplicates)"
    fi
  else
    # Also check for WireGuard/ProtonVPN-style killswitch via ip routing rules
    # These use policy routing (ip rule) to suppress default routes when VPN is down
    _IP_RULE_KS=false
    if require_cmd ip; then
      # Look for fwmark-based rules that send non-VPN traffic to a blackhole table
      if ip rule show 2>/dev/null | grep -qE "not from all fwmark|from all fwmark.*blackhole|suppress_prefixlength"; then
        _IP_RULE_KS=true
      fi
      # ProtonVPN specific: rules that suppress default routes without VPN mark
      if ip rule show 2>/dev/null | grep -qE "lookup (main|default).*suppress|from all lookup.*fwmark"; then
        _IP_RULE_KS=true
      fi
    fi
    if $_IP_RULE_KS; then
      pass "VPN kill-switch detected via ip routing rules (WireGuard/policy routing)"
    else
      warn "No VPN kill-switch found (no nftables drop on $PRIMARY_IFACE, no ip rule killswitch)"
    fi
  fi
else
  info "nftables not installed — skipped"
fi

fi # end nftables

###############################################################################
if ! should_skip "vpn"; then
header "05" "VPN & NETWORK"
###############################################################################

# NOTE: This section makes network requests (ping, dig).
# Use --skip vpn to avoid network traffic from this section.

# Internet Connectivity Test — F-057: prefer ICMP-only (no HTTP tracking)
# Try ping first (no third-party logs); fall back to Cloudflare's
# generate_204 endpoint (less identifiable than detectportal.firefox.com).
if ping -c1 -W2 1.1.1.1 &>/dev/null; then
  pass "Internet connectivity: OK (ICMP)"
elif ping -c1 -W2 9.9.9.9 &>/dev/null; then
  pass "Internet connectivity: OK (ICMP fallback)"
elif curl -fsS --max-time 5 http://cp.cloudflare.com/generate_204 &>/dev/null; then
  pass "Internet connectivity: OK (HTTP)"
else
  warn "Internet connectivity: FAIL (ICMP + HTTP timeout)"
fi

# VPN Interface
VPN_UP=false
for IFACE in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(proton|tun|wg|pvpn)'); do
  STATE=$(ip link show "$IFACE" 2>/dev/null | grep -oP 'state \K\w+')
  # WireGuard/tun interfaces report UNKNOWN state — that's normal (they have no carrier detection)
  pass "VPN interface $IFACE: active${STATE:+ (state: $STATE)}"
  VPN_UP=true
done
$VPN_UP || warn "No VPN interface active"

# Default Route
DEF_ROUTE=$(ip route show default 2>/dev/null | head -1)
if echo "$DEF_ROUTE" | grep -qE "proton|tun|wg|pvpn"; then
  pass "Default route via VPN: $DEF_ROUTE"
elif $VPN_UP; then
  fail "Default route NOT via VPN: $DEF_ROUTE"
else
  info "Default route: $DEF_ROUTE (no VPN active)"
fi

# DNS
DNS_SERVERS=$(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
info "DNS servers: $DNS_SERVERS"

# DNS over VPN check
VPN_DNS=false
STUB_DNS=false
for DNS in $(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}'); do
  if [[ "$DNS" =~ ^10\. || "$DNS" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. || "$DNS" =~ ^192\.168\. || "$DNS" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]]; then
    VPN_DNS=true
  elif [[ "$DNS" == "127.0.0.53" || "$DNS" == "127.0.0.54" ]]; then
    STUB_DNS=true
  fi
done
if $VPN_DNS; then
  pass "DNS via VPN (private/CGNAT range)"
elif $STUB_DNS && $VPN_UP; then
  pass "DNS via systemd-resolved (stub resolver — VPN routes DNS)"
else
  if $VPN_UP; then
    warn "DNS servers not on VPN network (potential DNS leak)"
  else
    info "DNS not via VPN (no VPN active)"
  fi
fi

# DNSSEC validation status (systemd-resolved)
if require_cmd resolvectl; then
  _DNSSEC_STATUS=$(resolvectl status 2>/dev/null | grep -oP 'DNSSEC\s*[=:]\s*\K\S+' | head -1)
  if [[ "$_DNSSEC_STATUS" == "yes" ]]; then
    pass "DNSSEC validation: enabled"
  elif [[ -n "$_DNSSEC_STATUS" ]]; then
    info "DNSSEC validation: $_DNSSEC_STATUS"
  else
    info "DNSSEC validation: could not determine"
  fi
fi

# DNS Leak Test & External IP (makes network requests — skippable with --skip netleaks)
if ! should_skip "netleaks"; then
  if require_cmd dig; then
    RESOLVED_IP=$(dig +short +time=5 whoami.akamai.net @ns1-1.akamaitech.net 2>/dev/null || echo "timeout")
    if [[ "$RESOLVED_IP" != "timeout" && -n "$RESOLVED_IP" ]]; then
      info "DNS leak test (public IP via DNS): $RESOLVED_IP"
    fi
  fi

  if require_cmd curl; then
    EXT_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "timeout")
    if [[ "$EXT_IP" != "timeout" ]]; then
      info "Public IP (HTTP): $EXT_IP"
      if [[ "$EXT_IP" =~ ^192\.168\. ]] || [[ "$EXT_IP" =~ ^10\. ]] || [[ "$EXT_IP" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        fail "Public IP is private — VPN leak?"
      fi
    fi
  fi
fi

# IPv6 (filter link-local fe80, multicast ff, and VPN-internal addresses to avoid false positives)
if [[ -f /proc/net/if_inet6 ]]; then
  # Count global IPv6 addresses, excluding VPN tunnel interfaces (proton/pvpn/tun/wg).
  # IPv6 on VPN interfaces is internal to the tunnel and not an internet-facing leak.
  IPV6_GLOBAL=0
  while read -r _v6addr _ _ _ _ _v6iface; do
    # Skip link-local (fe80), multicast (ff), ULA (fd), loopback (::1)
    [[ "$_v6addr" =~ ^(fe80|ff|fd|0000000000000000) ]] && continue
    # Skip VPN interfaces — their IPv6 is tunnel-internal, not a leak
    echo "$_v6iface" | grep -qE "^(tun|wg|proton|pvpn)" && continue
    ((IPV6_GLOBAL++))
  done < /proc/net/if_inet6
  IPV6_TOTAL=$(wc -l < /proc/net/if_inet6)
  if [[ "$IPV6_GLOBAL" -gt 0 ]]; then
    warn "IPv6 active ($IPV6_GLOBAL global addresses on physical interfaces, $IPV6_TOTAL total) — leak risk"
  else
    # Remaining addresses may be link-local (fe80), ULA (fd), or loopback (::1)
    IPV6_ULA=$(grep -c '^fd' /proc/net/if_inet6 2>/dev/null || true)
    IPV6_ULA=${IPV6_ULA:-0}
    if [[ "$IPV6_ULA" -gt 0 ]]; then
      pass "IPv6: disabled/minimal ($IPV6_TOTAL addresses: link-local + $IPV6_ULA ULA)"
    else
      pass "IPv6: disabled/minimal ($IPV6_TOTAL link-local only)"
    fi
  fi
else
  pass "IPv6: completely disabled"
fi

# LAN Isolation
LAN_GW_LIST="192.168.1.1 192.168.0.1 10.0.0.1"
if [[ -n "$ACTUAL_GW" ]]; then
  LAN_GW_LIST="$ACTUAL_GW $LAN_GW_LIST"
fi
TESTED_GWS=""
for GW in $LAN_GW_LIST; do
  echo "$TESTED_GWS" | grep -qwF "$GW" && continue
  TESTED_GWS="$TESTED_GWS $GW"
  if ! ping -c1 -W1 "$GW" &>/dev/null; then
    pass "LAN blocked: $GW"
  else
    # Check if this gateway belongs to a VPN interface (e.g. WireGuard killswitch dummy)
    # These are intentionally reachable — they are the VPN's own internal addresses
    _GW_IS_VPN=false
    if require_cmd ip; then
      _GW_IFACE=$(ip route get "$GW" 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
      if echo "$_GW_IFACE" | grep -qE "^(tun|wg|proton|pvpn)"; then
        _GW_IS_VPN=true
      fi
      # Also check if the GW IP is assigned to a VPN interface itself
      if ip addr show 2>/dev/null | grep -qP "inet\s+${GW//./\\.}/"; then
        _VPN_IFACE_OF_IP=$(ip addr show 2>/dev/null | grep -B3 "inet ${GW//./\\.}/" | grep -oP "^\d+:\s*\K\S+" | head -1)
        echo "$_VPN_IFACE_OF_IP" | grep -qE "^(tun|wg|proton|pvpn)" && _GW_IS_VPN=true
      fi
    fi
    if $_GW_IS_VPN; then
      pass "LAN gateway $GW: VPN internal address (expected — WireGuard/killswitch interface)"
    elif [[ "$GW" == "$ACTUAL_GW" ]]; then
      warn "LAN gateway reachable: $GW (kill-switch?)"
    else
      warn "LAN reachable: $GW (kill-switch?)"
    fi
  fi
done

# Promiscuous Mode — F-072: filter known virtualization bridges/veth pairs
# (libvirt virbr*, docker docker0/br-*, lxc lxcbr*, podman cni-*) that
# legitimately enable promisc when slaves are attached.
PROMISC=$(ip -o link show | grep -i promisc | \
  grep -vE '^[0-9]+: (virbr|docker[0-9]|br-|veth|lxcbr|cni-|podman[0-9]+|tap)' || true)
if [[ -z "$PROMISC" ]]; then
  pass "No promiscuous mode (virt bridges excluded)"
else
  fail "Promiscuous mode active: $PROMISC"
fi

# ARP Table
ARP_COUNT=$(ip neigh show | wc -l)
info "ARP entries: $ARP_COUNT"

# Network Namespaces
NS_COUNT=$(ip netns list 2>/dev/null | wc -l)
if [[ "$NS_COUNT" -gt 0 ]]; then
  info "Network namespaces: $NS_COUNT"
else
  info "Network namespaces: 0"
fi

fi # end vpn

###############################################################################
if ! should_skip "sysctl"; then
header "06" "KERNEL HARDENING (sysctl)"
###############################################################################

declare -A SYSCTL_CHECKS=(
  ["kernel.randomize_va_space"]=2
  ["kernel.kptr_restrict"]=2
  ["kernel.dmesg_restrict"]=1
  ["kernel.sysrq"]=0
  ["fs.suid_dumpable"]=0
  ["fs.protected_hardlinks"]=1
  ["fs.protected_symlinks"]=1
  ["fs.protected_fifos"]=2
  ["fs.protected_regular"]=2
  ["kernel.unprivileged_bpf_disabled"]=1  # 2 is also accepted (stricter)
  ["net.core.bpf_jit_harden"]=2
  ["dev.tty.ldisc_autoload"]=0
  ["net.ipv4.conf.all.accept_redirects"]=0
  ["net.ipv4.conf.default.accept_redirects"]=0
  ["net.ipv4.conf.all.send_redirects"]=0
  ["net.ipv4.conf.default.send_redirects"]=0
  ["net.ipv4.conf.all.accept_source_route"]=0
  ["net.ipv4.conf.all.log_martians"]=1
  ["net.ipv4.conf.default.log_martians"]=1
  ["net.ipv4.conf.all.rp_filter"]=1  # 2 (loose) also accepted — needed for WireGuard/VPN
  ["net.ipv4.conf.default.rp_filter"]=1  # 2 (loose) also accepted
  ["net.ipv4.tcp_syncookies"]=1
  ["net.ipv4.icmp_echo_ignore_broadcasts"]=1
  ["net.ipv4.icmp_ignore_bogus_error_responses"]=1
  ["kernel.yama.ptrace_scope"]=2
)

declare -A SYSCTL_STRICT=(
  ["kernel.perf_event_paranoid"]=3
  ["kernel.unprivileged_userns_clone"]=0
  ["vm.unprivileged_userfaultfd"]=0
  ["vm.mmap_min_addr"]=65536
  ["kernel.kexec_load_disabled"]=1
)

# Params where any value >= expected is acceptable (more = stricter)
declare -A SYSCTL_MIN_OK=(
  ["kernel.yama.ptrace_scope"]=1
  ["kernel.unprivileged_bpf_disabled"]=1
  ["net.ipv4.conf.all.rp_filter"]=1
  ["net.ipv4.conf.default.rp_filter"]=1
)

for KEY in "${!SYSCTL_CHECKS[@]}"; do
  EXPECTED="${SYSCTL_CHECKS[$KEY]}"
  ACTUAL=$(sysctl -n "$KEY" 2>/dev/null || echo "N/A")
  if [[ "$ACTUAL" == "N/A" ]]; then
    warn "sysctl $KEY: not available"
  elif [[ "$ACTUAL" -eq "$EXPECTED" ]]; then
    pass "sysctl $KEY = $ACTUAL"
  elif [[ -n "${SYSCTL_MIN_OK[$KEY]+x}" ]] && [[ "$ACTUAL" -ge "${SYSCTL_MIN_OK[$KEY]}" ]]; then
    pass "sysctl $KEY = $ACTUAL (>=${SYSCTL_MIN_OK[$KEY]} — hardened)"
  else
    fail "sysctl $KEY = $ACTUAL (expected: $EXPECTED)"
  fi
done

sub_header "Strict/Optional"
for KEY in "${!SYSCTL_STRICT[@]}"; do
  EXPECTED="${SYSCTL_STRICT[$KEY]}"
  ACTUAL=$(sysctl -n "$KEY" 2>/dev/null || echo "N/A")
  if [[ "$ACTUAL" == "N/A" ]]; then
    info "sysctl $KEY: not available"
  elif [[ "$ACTUAL" -eq "$EXPECTED" ]]; then
    pass "sysctl $KEY = $ACTUAL (strict)"
  else
    info "sysctl $KEY = $ACTUAL (strict would be: $EXPECTED)"
  fi
done

# Magic SysRq Deep Check
SYSRQ_VAL=$(sysctl -n kernel.sysrq 2>/dev/null || echo "N/A")
if [[ "$SYSRQ_VAL" != "N/A" ]] && [[ "$SYSRQ_VAL" -ne 0 ]]; then
  # Decode bits
  SYSRQ_BITS=""
  [[ $((SYSRQ_VAL & 2)) -ne 0 ]] && SYSRQ_BITS+="console-loglevel "
  [[ $((SYSRQ_VAL & 4)) -ne 0 ]] && SYSRQ_BITS+="keyboard "
  [[ $((SYSRQ_VAL & 8)) -ne 0 ]] && SYSRQ_BITS+="debugging-dumps "
  [[ $((SYSRQ_VAL & 16)) -ne 0 ]] && SYSRQ_BITS+="sync "
  [[ $((SYSRQ_VAL & 32)) -ne 0 ]] && SYSRQ_BITS+="remount-ro "
  [[ $((SYSRQ_VAL & 64)) -ne 0 ]] && SYSRQ_BITS+="signal-processes "
  [[ $((SYSRQ_VAL & 128)) -ne 0 ]] && SYSRQ_BITS+="reboot "
  [[ $((SYSRQ_VAL & 256)) -ne 0 ]] && SYSRQ_BITS+="nice-all-RT "
  if [[ "$SYSRQ_VAL" -eq 1 ]]; then
    info "Magic SysRq: ALL functions enabled (value=1)"
  else
    info "Magic SysRq: value=$SYSRQ_VAL bits: $SYSRQ_BITS"
  fi
fi

# ip_forward (VPN exception)
IP_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
if [[ "${IP_FWD:-0}" -eq 1 ]]; then
  if [[ -n "$VPN_IFACES" ]]; then
    pass "ip_forward=1 (VPN active — expected)"
  else
    fail "ip_forward=1 WITHOUT active VPN!"
  fi
else
  pass "ip_forward=0"
fi

fi # end sysctl

###############################################################################
if ! should_skip "services"; then
header "07" "SERVICES & DAEMONS"
###############################################################################

# Service groups: list of equivalent-name aliases across distros.
# httpd (RHEL/Fedora) vs apache2 (Debian/Ubuntu); smb/smbd/nmb/nmbd vary.
# Each row is one logical service; any matching name being active = active.
_SVC_GROUPS_OFF=(
  "sshd ssh"
  "telnet.socket"
  "rsh.socket"
  "rlogin.socket"
  "rexec.socket"
  "vsftpd"
  "httpd apache2 apache"
  "nginx"
  "rpcbind"
  "nfs-server nfs-kernel-server"
  "smb smbd"
  "nmb nmbd"
)

# Desktop-relevant services: WARN with context on desktop, FAIL on server.
# cups (printing), avahi (mDNS/discovery), bluetooth (laptops) are normal
# desktop defaults and don't warrant FAIL diagnosis.
_SVC_GROUPS_DESKTOP=(
  "cups:printing"
  "avahi-daemon:Bonjour/mDNS discovery"
  "bluetooth.service:Bluetooth"
  "bluetooth.socket:Bluetooth"
)

for _grp in "${_SVC_GROUPS_OFF[@]}"; do
  # First name in group is the canonical display name
  _canonical="${_grp%% *}"
  # shellcheck disable=SC2086  # intentional word-split on space-separated group
  if _service_active_any $_grp; then
    fail "Service running: $_canonical"
  elif _service_masked_any $_grp; then
    pass "Service masked: $_canonical"
  elif _service_enabled_any $_grp; then
    warn "Service enabled but inactive: $_canonical"
  else
    pass "Service off: $_canonical"
  fi
done

# Desktop-relevant services with context-aware severity
for _entry in "${_SVC_GROUPS_DESKTOP[@]}"; do
  _svc="${_entry%%:*}"
  _ctx="${_entry##*:}"
  if systemctl is-active "$_svc" &>/dev/null; then
    if $_IS_DESKTOP; then
      info "Service running: $_svc (desktop default — $_ctx)"
    else
      warn "Service running: $_svc (consider disabling on server — $_ctx)"
    fi
  elif systemctl is-masked "$_svc" &>/dev/null; then
    pass "Service masked: $_svc"
  else
    pass "Service off: $_svc"
  fi
done

# wsdd (Web Services Discovery) check
# Distinguish between standalone wsdd.service and GNOME's gvfsd-wsdd (activated on-demand by GVFS)
_WSDD_SVC_ACTIVE=false
systemctl is-active wsdd.service &>/dev/null && _WSDD_SVC_ACTIVE=true
systemctl is-active wsdd2.service &>/dev/null && _WSDD_SVC_ACTIVE=true

# Check for standalone wsdd processes (not gvfsd-wsdd children).
# gvfsd-wsdd spawns wsdd with --no-host → does NOT announce this host on the LAN.
# Only flag wsdd processes that lack --no-host (true standalone broadcast daemons).
_WSDD_STANDALONE_PROC=false
while IFS= read -r _wpid; do
  _wcmd=$(tr '\0' ' ' < "/proc/$_wpid/cmdline" 2>/dev/null)
  if ! echo "$_wcmd" | grep -q -- '--no-host'; then
    _WSDD_STANDALONE_PROC=true
  fi
done < <(pgrep -x wsdd 2>/dev/null)

if $_WSDD_SVC_ACTIVE; then
  warn "wsdd.service active — WS-Discovery broadcasts hostname on local network"
elif $_WSDD_STANDALONE_PROC; then
  warn "wsdd process running (not via systemd service)"
else
  pass "wsdd (standalone): not running"
fi

# gvfsd-wsdd is part of GNOME's gvfs — started on-demand for network browsing.
# It is firewall-protected on hardened systems. Warn only if firewall is absent.
if pgrep -x gvfsd-wsdd &>/dev/null; then
  if systemctl is-active firewalld &>/dev/null || systemctl is-active ufw &>/dev/null; then
    info "gvfsd-wsdd (GNOME network browsing): running — firewall-protected"
  else
    warn "gvfsd-wsdd running without active firewall — WS-Discovery exposed on LAN"
  fi
fi

# Critical services that should be ON
SHOULD_BE_ON="firewalld auditd fail2ban"
for SVC in $SHOULD_BE_ON; do
  if systemctl is-active "$SVC" &>/dev/null; then
    pass "Service active: $SVC"
  elif ! require_cmd "$SVC" && ! systemctl cat "$SVC" &>/dev/null; then
    info "Service $SVC: not installed — skipped"
  else
    fail "Service INACTIVE: $SVC"
  fi
done

# Failed Services
FAILED_SVCS=$(systemctl --failed --no-legend 2>/dev/null | grep -v 'proc-sys-fs-binfmt_misc.mount')
FAILED=$(echo "$FAILED_SVCS" | grep -c '\S' || true)
if [[ "$FAILED" -eq 0 ]]; then
  pass "0 failed services"
else
  svc_names=$(echo "$FAILED_SVCS" | awk '{print ($1 == "●" || $1 == "×") ? $2 : $1}' | tr '\n' ', ' | sed 's/,$//')
  fail "$FAILED failed services: $svc_names"
  if ! $JSON_MODE; then
    while read -r line; do
      printf "       %s\n" "$line"
    done <<< "$FAILED_SVCS"
  fi
fi

# Timer Units
TIMER_COUNT=$(systemctl list-timers --all --no-legend 2>/dev/null | wc -l)
info "Active timers: $TIMER_COUNT"

fi # end services

###############################################################################
if ! should_skip "ports"; then
header "08" "OPEN PORTS & LISTENERS"
###############################################################################

sub_header "TCP"
while read -r line; do
  [[ -z "$line" ]] && continue
  ADDR=$(echo "$line" | awk '{print $4}')
  PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
  if echo "$ADDR" | grep -qE "^(127\.|::1|\[::1\]|\[?::ffff:127\.)"; then
    pass "TCP $ADDR ($PROC) — localhost only"
  else
    if has_firewall_block_on_phys; then
      warn "TCP $ADDR ($PROC) — externally bound, but firewall/kill-switch blocks"
    else
      fail "TCP $ADDR ($PROC) — EXTERNALLY REACHABLE"
    fi
  fi
done < <(ss -tlnp 2>/dev/null | tail -n+2)

sub_header "UDP"
while read -r line; do
  [[ -z "$line" ]] && continue
  ADDR=$(echo "$line" | awk '{print $4}')
  PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "kernel")
  if echo "$ADDR" | grep -qE "^(127\.|::1|\[::1\]|\[?::ffff:127\.)"; then
    pass "UDP $ADDR ($PROC) — localhost only"
  elif echo "$PROC" | grep -qiE "wireguard|wg|vpn"; then
    pass "UDP $ADDR (VPN/WireGuard)"
  elif [[ "$PROC" == "kernel" ]]; then
    # Kernel-owned UDP sockets can be WireGuard, IPVS, conntrack, etc.
    if ip link show type wireguard 2>/dev/null | grep -q .; then
      info "UDP $ADDR (kernel — likely WireGuard)"
    else
      info "UDP $ADDR (kernel — no WireGuard interfaces found)"
    fi
  else
    if has_firewall_block_on_phys; then
      info "UDP $ADDR ($PROC) — externally bound, but firewall/kill-switch blocks"
    else
      warn "UDP $ADDR ($PROC) — external"
    fi
  fi
done < <(ss -ulnp 2>/dev/null | tail -n+2)

# Connections to unusual ports
sub_header "Unusual destination ports"
UNUSUAL_PORTS=$(while read -r port; do
  case "$port" in
    80|443|53|993|465|8443|22|587|143|995|5222|5223) ;;
    *) echo "$port" ;;
  esac
done < <(ss -tnp state established 2>/dev/null | awk '{print $4}' | grep -oP ':\K\d+$' | sort -n | uniq))
if [[ -n "$UNUSUAL_PORTS" ]]; then
  info "Connections to non-standard ports: $(echo "$UNUSUAL_PORTS" | tr '\n' ' ')"
else
  pass "All connections on standard ports"
fi

# Raw Sockets
RAW=$(ss -wnp 2>/dev/null | tail -n+2 | wc -l)
if [[ "$RAW" -gt 0 ]]; then
  warn "Raw sockets: $RAW"
else
  pass "No raw sockets"
fi

fi # end ports

###############################################################################
if ! should_skip "ssh"; then
header "09" "SSH HARDENING"
###############################################################################

if { systemctl is-masked sshd &>/dev/null || systemctl is-masked ssh &>/dev/null; } || \
   [[ "$(systemctl is-enabled sshd 2>&1)" == "masked" ]] || [[ "$(systemctl is-enabled ssh 2>&1)" == "masked" ]]; then
  pass "SSH: masked + inactive — maximum security"
else
  SSHD_CONFIG="/etc/ssh/sshd_config"
  if [[ -f "$SSHD_CONFIG" ]]; then
    # PermitRootLogin
    VAL=$(sshd_cfg_val PermitRootLogin)
    if [[ "$VAL" == "no" ]]; then
      pass "SSH: PermitRootLogin no"
    else
      fail "SSH: PermitRootLogin ${VAL:-not set} (should be 'no')"
    fi

    # PasswordAuthentication
    VAL=$(sshd_cfg_val PasswordAuthentication)
    if [[ "$VAL" == "no" ]]; then
      pass "SSH: PasswordAuthentication no"
    else
      warn "SSH: PasswordAuthentication ${VAL:-not explicitly 'no'}"
    fi

    # PubkeyAuthentication (default is 'yes' in OpenSSH — only warn if explicitly disabled)
    VAL=$(sshd_cfg_val PubkeyAuthentication)
    if [[ "$VAL" == "yes" ]]; then
      pass "SSH: PubkeyAuthentication yes"
    elif [[ "$VAL" == "no" ]]; then
      warn "SSH: PubkeyAuthentication no (should be 'yes')"
    else
      # Not explicitly set — OpenSSH default is 'yes', which is correct
      pass "SSH: PubkeyAuthentication yes (default)"
    fi

    # X11Forwarding
    VAL=$(sshd_cfg_val X11Forwarding)
    if [[ "$VAL" == "no" ]]; then
      pass "SSH: X11Forwarding no"
    else
      warn "SSH: X11Forwarding ${VAL:-not set to 'no'}"
    fi

    # MaxAuthTries
    MAX_AUTH=$(sshd_cfg_val MaxAuthTries)
    MAX_AUTH=${MAX_AUTH:-6}
    if [[ "$MAX_AUTH" -le 3 ]]; then
      pass "SSH: MaxAuthTries $MAX_AUTH"
    else
      warn "SSH: MaxAuthTries $MAX_AUTH (recommended: <=3)"
    fi

    # AllowUsers/AllowGroups
    if grep -qhiE "^\s*(AllowUsers|AllowGroups)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
      pass "SSH: user/group whitelist active"
    else
      warn "SSH: no user/group whitelist"
    fi

    # LoginGraceTime (new)
    LGT=$(sshd_cfg_val LoginGraceTime)
    if [[ -n "$LGT" ]]; then
      # Convert to seconds: sshd -T returns seconds, but config fallback may return 1m/2m/1h
      LGT_SEC="$LGT"
      if [[ "$LGT" =~ ^([0-9]+)m$ ]]; then
        LGT_SEC=$(( BASH_REMATCH[1] * 60 ))
      elif [[ "$LGT" =~ ^([0-9]+)h$ ]]; then
        LGT_SEC=$(( BASH_REMATCH[1] * 3600 ))
      elif [[ "$LGT" =~ ^([0-9]+)s?$ ]]; then
        LGT_SEC="${BASH_REMATCH[1]}"
      fi
      if [[ "$LGT_SEC" =~ ^[0-9]+$ ]] && [[ "$LGT_SEC" -le 60 ]]; then
        pass "SSH: LoginGraceTime $LGT (${LGT_SEC}s)"
      else
        warn "SSH: LoginGraceTime $LGT (${LGT_SEC}s, recommended: <=60s)"
      fi
    else
      warn "SSH: LoginGraceTime not set (default 120s — too long)"
    fi

    # SSH Key Strength
    sub_header "SSH Key Strength"
    for USER_HOME in /home/* /root; do
      [[ -d "$USER_HOME" ]] || continue
      for KEY in "$USER_HOME"/.ssh/*.pub; do
        [[ -f "$KEY" ]] || continue
        _KEY_INFO=$(ssh-keygen -l -f "$KEY" 2>/dev/null) || continue
        BITS=$(echo "$_KEY_INFO" | awk '{print $1}')
        TYPE=$(echo "$_KEY_INFO" | awk '{print $NF}' | tr -d '()')
        # RSA thresholds: <2048 = insecure (NIST deprecated), <4096 = acceptable but 4096 recommended
        # Ed25519/ECDSA keys are always considered strong regardless of bit size
        if [[ "$TYPE" == "RSA" ]] && [[ "${BITS:-0}" -lt 2048 ]]; then
          fail "Weak SSH key: $KEY ($BITS bit $TYPE — minimum 2048)"
        elif [[ "$TYPE" == "RSA" ]] && [[ "${BITS:-0}" -lt 4096 ]]; then
          warn "SSH key: $KEY ($BITS bit $TYPE — 4096 recommended)"
        elif [[ -n "$TYPE" ]]; then
          pass "SSH key: $KEY ($BITS bit $TYPE)"
        fi
      done
    done
  fi
fi

fi # end ssh

###############################################################################
if ! should_skip "audit"; then
header "10" "AUDIT SYSTEM"
###############################################################################

if systemctl is-active auditd &>/dev/null; then
  pass "auditd: active"
elif ! require_cmd auditctl; then
  info "auditd not installed — skipped"
else
  fail "auditd: INACTIVE"
fi

if require_cmd auditctl; then
  AUDIT_RULES=$(auditctl -l 2>/dev/null | grep -cv "^No rules" || true)
  if [[ "$AUDIT_RULES" -ge 20 ]]; then
    pass "Audit rules: $AUDIT_RULES"
  elif [[ "$AUDIT_RULES" -gt 0 ]]; then
    warn "Audit rules: only $AUDIT_RULES (recommended: >=20)"
  else
    fail "Audit rules: 0"
  fi

  AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep -oP '(?:^enabled\s+|enabled=)\K[0-9]+' | head -1)
  if [[ "$AUDIT_ENABLED" == "2" ]]; then
    pass "Audit: immutable (enabled=2)"
  elif [[ "$AUDIT_ENABLED" == "1" ]]; then
    warn "Audit: enabled=1 (not immutable)"
  else
    fail "Audit: enabled=$AUDIT_ENABLED"
  fi

  CRITICAL_WATCHES="/etc/passwd /etc/shadow /etc/sudoers /etc/ssh /etc/pam.d"
  _AUDIT_RULES_CACHE=$(auditctl -l 2>/dev/null)
  for WATCH in $CRITICAL_WATCHES; do
    # Match both short form (-w /path) and long form (-F path=/path, -F dir=/path),
    # including sub-path matches (e.g. -F path=/etc/ssh/sshd_config covers /etc/ssh)
    if echo "$_AUDIT_RULES_CACHE" | grep -qE -- "(-w ${WATCH}( |$)|-F (path|dir)=${WATCH}(/|\s|$))"; then
      pass "Audit watch: $WATCH"
    else
      warn "Audit watch missing: $WATCH"
    fi
  done
fi

if [[ -f /var/log/audit/audit.log ]]; then
  AUDIT_SIZE=$(du -sh /var/log/audit/audit.log | awk '{print $1}')
  info "Audit log: $AUDIT_SIZE"
fi

fi # end audit

###############################################################################
if ! should_skip "users"; then
header "11" "USERS & AUTHENTICATION"
###############################################################################

# UID-0 Accounts
UID0_COUNT=$(awk -F: '$3==0' /etc/passwd | wc -l)
if [[ "$UID0_COUNT" -eq 1 ]]; then
  pass "Only 1 UID-0 account (root)"
else
  fail "$UID0_COUNT UID-0 accounts!"
  $JSON_MODE || awk -F: '$3==0 {print "       " $1}' /etc/passwd
fi

# Empty Passwords
EMPTY_PW=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | wc -l)
if [[ "$EMPTY_PW" -eq 0 ]]; then
  pass "No accounts with empty password"
else
  fail "$EMPTY_PW accounts with empty password (no authentication required!)"
fi

# PAM nullok
for PAM_FILE in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
  if [[ -f "$PAM_FILE" ]]; then
    if grep -q "nullok" "$PAM_FILE"; then
      fail "PAM nullok in $(basename "$PAM_FILE")"
    else
      pass "PAM nullok removed: $(basename "$PAM_FILE")"
    fi
  fi
done

# securetty — empty or missing file blocks root on all TTYs (hardened),
# but only if pam_securetty.so is in the PAM stack.
if [[ -f /etc/securetty ]]; then
  if [[ ! -s /etc/securetty ]]; then
    pass "securetty present and empty (root TTY login blocked)"
  else
    pass "securetty present"
  fi
else
  info "securetty absent (root TTY restriction depends on PAM config)"
fi

# Sudo group
WHEEL_MEMBERS=$(grep "^wheel:" /etc/group 2>/dev/null | cut -d: -f4)
if [[ -z "$WHEEL_MEMBERS" ]]; then
  WHEEL_MEMBERS=$(grep "^sudo:" /etc/group 2>/dev/null | cut -d: -f4)
fi
info "Wheel/sudo members: $WHEEL_MEMBERS"

# Shell users
SHELL_USERS=$(grep -cv '/nologin\|/false\|/sync\|/shutdown\|/halt' /etc/passwd)
info "Users with login shell: $SHELL_USERS"
if ! $JSON_MODE; then
  while IFS=: read -r user _ uid _ _ _ shell; do
    printf "       %s (UID=%s, Shell=%s)\n" "$user" "$uid" "$shell"
  done < <(grep -v '/nologin\|/false\|/sync\|/shutdown\|/halt' /etc/passwd)
fi

# Password Hashing Method
sub_header "Password Hashing"
_PW_HASH_METHOD=""
if [[ -f /etc/login.defs ]]; then
  _PW_HASH_METHOD=$(grep -i "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null | awk '{print $2}')
fi
# Also check PAM (pam_unix.so) for the actual hashing algorithm
_PAM_HASH=$(grep -hE "pam_unix\.so.*\b(yescrypt|sha512|sha256|md5|bigcrypt|blowfish)\b" /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null | grep -oE "(yescrypt|sha512|sha256|md5|bigcrypt|blowfish)" | head -1)
_EFFECTIVE_HASH="${_PAM_HASH:-$_PW_HASH_METHOD}"
if [[ "${_EFFECTIVE_HASH^^}" == "YESCRYPT" ]]; then
  pass "Password hashing: YESCRYPT (strongest)"
elif [[ "${_EFFECTIVE_HASH^^}" == "SHA512" ]]; then
  pass "Password hashing: SHA512 (strong)"
elif [[ "${_EFFECTIVE_HASH^^}" == "SHA256" ]]; then
  warn "Password hashing: SHA256 (consider SHA512 or YESCRYPT)"
elif [[ -n "$_EFFECTIVE_HASH" ]]; then
  fail "Password hashing: $_EFFECTIVE_HASH (weak — migrate to SHA512 or YESCRYPT)"
else
  info "Password hashing method: could not determine"
fi

# Password Hashing Rounds
_PW_ROUNDS=$(grep -i "^SHA_CRYPT_MAX_ROUNDS\|^YESCRYPT_COST_FACTOR" /etc/login.defs 2>/dev/null | tail -1 | awk '{print $2}')
if [[ -n "$_PW_ROUNDS" ]]; then
  info "Password hashing rounds/cost: $_PW_ROUNDS"
fi

# PAM password quality (pwquality/cracklib)
_PW_QUALITY=false
if grep -rqs "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null; then
  _PW_QUALITY=true
  pass "Password quality enforcement: pam_pwquality/pam_cracklib active"
else
  warn "No password quality enforcement (pam_pwquality/pam_cracklib not in PAM stack)"
fi

# Accounts without password expiry
sub_header "Password Expiry"
_NO_EXPIRE=0
while IFS=: read -r _user _ _uid _ _ _ _; do
  [[ "$_uid" -ge 1000 && "$_uid" -lt 65534 ]] || continue
  _max_days=$(chage -l "$_user" 2>/dev/null | grep "Maximum" | grep -oP '\d+$' || true)
  if [[ "${_max_days:-0}" -eq 99999 || "${_max_days:-0}" -eq -1 ]]; then
    ((_NO_EXPIRE++))
  fi
  # Check for expired passwords
  _pw_expired=$(chage -l "$_user" 2>/dev/null | grep "Password expires" | grep -ci "password must be changed\|expired" || true)
  if [[ "${_pw_expired:-0}" -gt 0 ]]; then
    warn "Password expired for user: $_user"
  fi
done < /etc/passwd
if [[ "$_NO_EXPIRE" -gt 0 ]]; then
  info "$_NO_EXPIRE user account(s) with no password expiry (perpetual passwords)"
else
  pass "All user accounts have password expiry configured"
fi

# Duplicate accounts
_DUP_UIDS=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
if [[ -n "$_DUP_UIDS" ]]; then
  fail "Duplicate UIDs found: $_DUP_UIDS"
else
  pass "No duplicate UIDs"
fi

# Duplicate group IDs
_DUP_GIDS=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
if [[ -n "$_DUP_GIDS" ]]; then
  warn "Duplicate GIDs found: $_DUP_GIDS"
else
  pass "No duplicate GIDs"
fi

# Password file consistency (pwck)
if require_cmd pwck; then
  _PWCK_OUT=$(pwck -rq 2>&1 || true)
  _PWCK_ERRORS=$(echo "$_PWCK_OUT" | grep -cvE "^$|^pwck:" || true)
  _PWCK_ERRORS=${_PWCK_ERRORS:-0}
  if [[ "$_PWCK_ERRORS" -eq 0 ]]; then
    pass "Password file consistency: OK (pwck)"
  else
    warn "Password file inconsistencies: $_PWCK_ERRORS (run 'pwck' to review)"
  fi
fi

# Locked user accounts
sub_header "Account Status"
_LOCKED_ACCOUNTS=0
while IFS=: read -r _lu_user _ _lu_uid _ _ _ _; do
  [[ "$_lu_uid" -ge 1000 && "$_lu_uid" -lt 65534 ]] || continue
  _lu_status=$(passwd -S "$_lu_user" 2>/dev/null | awk '{print $2}')
  if [[ "$_lu_status" == "L" || "$_lu_status" == "LK" ]]; then
    info "Account locked: $_lu_user"
    ((_LOCKED_ACCOUNTS++))
  fi
done < /etc/passwd
if [[ "$_LOCKED_ACCOUNTS" -gt 0 ]]; then
  info "$_LOCKED_ACCOUNTS user account(s) locked"
else
  pass "No locked user accounts"
fi

# Sudoers security
sub_header "Sudoers Security"
if [[ -f /etc/sudoers ]]; then
  # Check sudoers file permissions (should be 440)
  _SUDOERS_PERMS=$(stat -c %a /etc/sudoers 2>/dev/null)
  if [[ "$_SUDOERS_PERMS" == "440" ]]; then
    pass "sudoers permissions: $_SUDOERS_PERMS"
  else
    warn "sudoers permissions: $_SUDOERS_PERMS (should be 440)"
  fi
  # Check sudoers.d drop-in permissions
  if [[ -d /etc/sudoers.d ]]; then
    _SUDOERSD_BAD=0
    for _sf in /etc/sudoers.d/*; do
      [[ -f "$_sf" ]] || continue
      _sf_perms=$(stat -c %a "$_sf" 2>/dev/null)
      if [[ "$_sf_perms" != "440" && "$_sf_perms" != "400" ]]; then
        warn "sudoers.d/$(basename "$_sf"): permissions $_sf_perms (should be 440)"
        ((_SUDOERSD_BAD++))
      fi
    done
    [[ "$_SUDOERSD_BAD" -eq 0 ]] && pass "sudoers.d drop-ins: all permissions correct"
  fi
  # Check for NOPASSWD — F-107: properly skip commented lines including
  # tab-indented comments. Use anchored regex on file contents (not grep
  # output prefix-based filter which fails on tab-prefixed comments).
  _NOPASSWD=$(grep -rE -- '^[[:space:]]*[^#[:space:]].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)
  if [[ -n "$_NOPASSWD" ]]; then
    warn "NOPASSWD found in sudoers (passwordless sudo enabled)"
    if ! $JSON_MODE; then
      echo "$_NOPASSWD" | while read -r _np_line; do
        printf "       %s\n" "$_np_line"
      done
    fi
  else
    pass "No NOPASSWD in sudoers (all sudo requires password)"
  fi
  # Syntax check
  if require_cmd visudo; then
    if visudo -c &>/dev/null; then
      pass "sudoers syntax: valid (visudo -c)"
    else
      fail "sudoers syntax errors detected (run 'visudo -c')"
    fi
  fi
fi

# Password Aging
PASS_MAX=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
PASS_MIN=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
PASS_WARN=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
info "Password policy: MAX=$PASS_MAX, MIN=$PASS_MIN, WARN=$PASS_WARN"

# Umask Check (new)
UMASK_VAL=$(grep -hiE '^\s*umask\s+' /etc/login.defs /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh 2>/dev/null | tail -1 | awk '{print $2}')
if [[ -n "$UMASK_VAL" ]]; then
  if [[ "$UMASK_VAL" =~ ^0*27$ || "$UMASK_VAL" =~ ^0*77$ ]]; then
    pass "Default umask: $UMASK_VAL (restrictive)"
  else
    warn "Default umask: $UMASK_VAL (recommended: 027 or 077)"
  fi
else
  warn "Default umask not explicitly set"
fi

# Faillock
# faillock output format per user: "username:\nWhen  Type  Source  Valid\n2026-04-09 ... RHOST  V\n"
# Count only actual failure entries (lines starting with a date YYYY-MM-DD), not headers.
if require_cmd faillock; then
  _FAILLOCK_OUT=$(faillock --dir /var/run/faillock 2>/dev/null)
  LOCKED=$(echo "$_FAILLOCK_OUT" | grep -cE "^[0-9]{4}-[0-9]{2}-[0-9]{2}" || true)
  LOCKED=${LOCKED:-0}
  if [[ "$LOCKED" -gt 0 ]]; then
    # Count unique usernames with failures
    _LOCKED_USERS=$(echo "$_FAILLOCK_OUT" | grep -B50 "^[0-9]\{4\}-" | grep -c "^[a-zA-Z].*:" || true)
    _LOCKED_USERS=${_LOCKED_USERS:-0}
    warn "Faillock: $LOCKED failed attempt(s) across $_LOCKED_USERS account(s)"
  else
    pass "Faillock: no recorded failed login attempts"
  fi
fi

# History File Permissions (new)
sub_header "History File Permissions"
for USER_HOME in /home/* /root; do
  [[ -d "$USER_HOME" ]] || continue
  for HIST in .bash_history .zsh_history; do
    if [[ -f "$USER_HOME/$HIST" ]]; then
      PERMS=$(stat -c %a "$USER_HOME/$HIST" 2>/dev/null)
      if (( (8#${PERMS:-777} & 8#077) != 0 )); then
        warn "History file too open: $USER_HOME/$HIST ($PERMS, should be 600 or stricter)"
      else
        pass "History file: $USER_HOME/$HIST ($PERMS)"
      fi
    fi
  done
done

fi # end users

###############################################################################
if ! should_skip "filesystem"; then
header "12" "FILESYSTEM SECURITY"
###############################################################################

# SUID Files (uses _safe_find_root which excludes Snapper/Timeshift snapshots)
SUID_COUNT=$(_safe_find_root -perm -4000 -type f | wc -l)
if [[ "$SUID_COUNT" -le 30 ]]; then
  pass "SUID files: $SUID_COUNT"
elif [[ "$SUID_COUNT" -le 45 ]]; then
  warn "SUID files: $SUID_COUNT (>30, investigate)"
else
  fail "SUID files: $SUID_COUNT (>45)"
fi

# SGID Files
SGID_COUNT=$(_safe_find_root -perm -2000 -type f | wc -l)
if [[ "$SGID_COUNT" -le 10 ]]; then
  pass "SGID files: $SGID_COUNT"
elif [[ "$SGID_COUNT" -le 20 ]]; then
  warn "SGID files: $SGID_COUNT (>10)"
else
  fail "SGID files: $SGID_COUNT (>20)"
fi

# World-Writable
_WW_FIND_ARGS=(-perm -0002 -type f
  ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*")
WW_COUNT=$(_safe_find_root "${_WW_FIND_ARGS[@]}" | wc -l)
if [[ "$WW_COUNT" -eq 0 ]]; then
  pass "World-writable files: 0"
else
  fail "World-writable files: $WW_COUNT"
  if ! $JSON_MODE; then
    while read -r f; do
      printf "       %s\n" "$f"
    done < <(_safe_find_root "${_WW_FIND_ARGS[@]}" | head -5)
  fi
fi

# Unowned Files
UNOWNED=$(_safe_find_root -not -path '/var/lib/gdm/*' \( -nouser -o -nogroup \) | wc -l)
if [[ "$UNOWNED" -eq 0 ]]; then
  pass "Unowned files: 0"
elif [[ "$UNOWNED" -le 5 ]]; then
  warn "Unowned files: $UNOWNED (investigate)"
else
  fail "Unowned files: $UNOWNED (>5)"
fi

# Swappiness
_SWAPPINESS=$(sysctl -n vm.swappiness 2>/dev/null || echo "N/A")
if [[ "$_SWAPPINESS" != "N/A" ]]; then
  if [[ "$_SWAPPINESS" -le 10 ]]; then
    pass "Swappiness: $_SWAPPINESS (low — minimal swap usage)"
  elif [[ "$_SWAPPINESS" -le 60 ]]; then
    info "Swappiness: $_SWAPPINESS (default range)"
  else
    warn "Swappiness: $_SWAPPINESS (high — more data written to disk, recovery risk)"
  fi
fi

# ACL support on root filesystem
if require_cmd getfacl; then
  if mount | grep " / " | grep -qE "acl|posixacl"; then
    pass "ACL support: enabled on root filesystem"
  else
    # Most modern filesystems (ext4, xfs, btrfs) have ACL enabled by default
    _ROOT_FS_TYPE=$(df -T / 2>/dev/null | awk 'NR==2{print $2}')
    if [[ "$_ROOT_FS_TYPE" =~ ^(ext4|xfs|btrfs)$ ]]; then
      pass "ACL support: $_ROOT_FS_TYPE has ACL enabled by default"
    else
      info "ACL support: could not verify on $_ROOT_FS_TYPE"
    fi
  fi
fi

# /tmp Permissions
TMP_MOUNT=$(mount | grep " /tmp " || echo "")
if [[ -n "$TMP_MOUNT" ]]; then
  if echo "$TMP_MOUNT" | grep -q "nosuid"; then
    pass "/tmp: nosuid"
  else
    warn "/tmp: no nosuid"
  fi
  if echo "$TMP_MOUNT" | grep -q "noexec"; then
    pass "/tmp: noexec"
  else
    info "/tmp: no noexec (may break programs)"
  fi
else
  info "/tmp: not separately mounted"
fi

# Core Dumps
CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
CORE_ULIMIT=$(ulimit -c 2>/dev/null)
CORE_STORAGE=$(_systemd_conf_val /etc/systemd/coredump.conf Storage 2>/dev/null)
if [[ "$CORE_ULIMIT" == "0" ]] || echo "$CORE_PATTERN" | grep -q "|/dev/null" || [[ "$CORE_STORAGE" == "none" ]]; then
  pass "Core dumps: disabled"
else
  warn "Core dumps: possible (pattern: $CORE_PATTERN)"
fi

# Important file permissions
declare -A PERM_CHECKS=(
  ["/etc/passwd"]="644"
  ["/etc/shadow"]="640"
  ["/etc/gshadow"]="640"
  ["/etc/group"]="644"
  ["/etc/crontab"]="600"
  ["/etc/ssh/sshd_config"]="600"
)
# F-116: GRUB cfg path is distro-specific (/boot/grub2/ vs /boot/grub/).
# Use _grub_main_cfg() which probes both, plus EFI fallback locations.
_GRUB_CFG_PATH=$(_grub_main_cfg)
[[ -n "$_GRUB_CFG_PATH" ]] && PERM_CHECKS["$_GRUB_CFG_PATH"]="600"

for FILE in "${!PERM_CHECKS[@]}"; do
  if [[ -f "$FILE" ]]; then
    EXPECTED="${PERM_CHECKS[$FILE]}"
    ACTUAL=$(stat -c %a "$FILE" 2>/dev/null)
    if (( (8#${ACTUAL:-777} & ~8#$EXPECTED) == 0 )); then
      # Annotate when stricter-than-expected (e.g. shadow=0 vs expected 640)
      # to avoid users panicking at "Permissions /etc/shadow: 0" output (F-115)
      if [[ "$ACTUAL" -lt "$EXPECTED" ]] 2>/dev/null; then
        pass "Permissions $FILE: $ACTUAL (stricter than recommended $EXPECTED)"
      else
        pass "Permissions $FILE: $ACTUAL"
      fi
    else
      warn "Permissions $FILE: $ACTUAL (expected: <=$EXPECTED)"
    fi
  fi
done

# Banner Check (new)
sub_header "Login Banners"
for BANNER_FILE in /etc/issue /etc/issue.net /etc/motd; do
  if [[ -f "$BANNER_FILE" ]] && [[ -s "$BANNER_FILE" ]]; then
    if grep -qiE "(Linux kernel [0-9]|Fedora release|Ubuntu [0-9]|CentOS|Debian GNU|RHEL|Red Hat)" "$BANNER_FILE" 2>/dev/null; then
      warn "$BANNER_FILE leaks system info"
    else
      pass "$BANNER_FILE: no system info leaked"
    fi
  fi
done

fi # end filesystem

###############################################################################
if ! should_skip "crypto"; then
header "13" "ENCRYPTION & CRYPTO"
###############################################################################

if require_cmd cryptsetup; then
  for DEV in $(lsblk -rno NAME,TYPE 2>/dev/null | grep crypt | awk '{print $1}'); do
    CIPHER=$(cryptsetup status "$DEV" 2>/dev/null | grep "cipher:" | awk '{print $2}')
    KEYSIZE=$(cryptsetup status "$DEV" 2>/dev/null | grep "keysize:" | awk '{print $2}')
    info "LUKS $DEV: cipher=$CIPHER keysize=$KEYSIZE"
    if echo "$CIPHER" | grep -qE "aes-xts"; then
      pass "LUKS cipher: $CIPHER (strong)"
    elif echo "$CIPHER" | grep -qE "aes-cbc"; then
      warn "LUKS cipher: $CIPHER (aes-cbc has known weaknesses — consider migrating to aes-xts)"
    elif [[ -n "$CIPHER" ]]; then
      warn "LUKS cipher: $CIPHER (unusual)"
    fi
  done
else
  info "cryptsetup not installed — LUKS details skipped"
fi

# SSL/TLS Libraries
if require_cmd openssl; then
  OPENSSL_VER=$(openssl version 2>/dev/null)
  info "OpenSSL: $OPENSSL_VER"
fi

# GPG Keys
if require_cmd gpg; then
  GPG_KEYS=$(gpg --list-keys 2>/dev/null | grep -c "^pub" | ccount)
  info "GPG keys: $GPG_KEYS"
fi

# Entropy Check (new)
if [[ -f /proc/sys/kernel/random/entropy_avail ]]; then
  ENTROPY=$(< /proc/sys/kernel/random/entropy_avail)
  if [[ "$ENTROPY" -ge 256 ]]; then
    pass "Entropy: $ENTROPY (sufficient)"
  else
    warn "Entropy: $ENTROPY (low — minimum 256)"
  fi
fi

# Hardware Random Number Generator
if [[ -c /dev/hwrng ]]; then
  pass "Hardware RNG: /dev/hwrng present"
elif [[ -d /sys/class/misc/hw_random ]]; then
  pass "Hardware RNG: hw_random device available"
elif grep -q "rdrand\|rdseed" /proc/cpuinfo 2>/dev/null; then
  pass "Hardware RNG: CPU supports RDRAND/RDSEED"
else
  info "No hardware RNG detected (software entropy only)"
fi

# Swap Encryption (new)
SWAP_ACTIVE=$(swapon --show=NAME --noheadings 2>/dev/null | grep -c . || true)
SWAP_ACTIVE=${SWAP_ACTIVE:-0}
SWAP_ACTIVE="${SWAP_ACTIVE//[^0-9]/}"
SWAP_ACTIVE="${SWAP_ACTIVE:-0}"
SWAP_DEVS=$(swapon --show=NAME --noheadings 2>/dev/null)
if [[ "$SWAP_ACTIVE" -gt 0 ]]; then
  SWAP_ENCRYPTED=true
  SWAP_HAS_REAL=false
  while read -r swapdev; do
    [[ -z "$swapdev" ]] && continue
    # ZRAM is in-memory compression — not persistent storage, no encryption needed
    if [[ "$swapdev" =~ ^/dev/zram ]]; then
      info "Swap: $swapdev is ZRAM (in-memory compression — no encryption needed)"
      continue
    fi
    SWAP_HAS_REAL=true
    if ! lsblk -no TYPE "$swapdev" 2>/dev/null | grep -q crypt; then
      # Check if parent is crypt
      PARENT=$(lsblk -no PKNAME "$swapdev" 2>/dev/null | head -1)
      if [[ -n "$PARENT" ]] && lsblk -no TYPE "/dev/$PARENT" 2>/dev/null | grep -q crypt; then
        : # parent is encrypted
      elif [[ -f "$swapdev" ]]; then
        # Swapfile: check if the filesystem it resides on is LUKS-encrypted
        SWAP_FS_DEV=$(df -P "$swapdev" 2>/dev/null | awk 'NR==2{print $1}')
        if [[ -n "$SWAP_FS_DEV" ]] && lsblk -no TYPE "$SWAP_FS_DEV" 2>/dev/null | grep -q crypt; then
          : # swapfile on LUKS volume — encrypted at rest
        else
          SWAP_ENCRYPTED=false
        fi
      else
        SWAP_ENCRYPTED=false
      fi
    fi
  done <<< "$SWAP_DEVS"
  if ! $SWAP_HAS_REAL; then
    pass "Swap: ZRAM only (in-memory — no disk persistence risk)"
  elif $SWAP_ENCRYPTED; then
    pass "Swap: encrypted"
  else
    warn "Swap: NOT encrypted (memory contents at risk)"
  fi
else
  info "No swap configured"
fi

fi # end crypto

###############################################################################
if ! should_skip "updates"; then
header "14" "UPDATES & PACKAGES"
###############################################################################

UPDATES="?"
if require_cmd dnf5; then
  UPDATES=$(dnf5 check-upgrade --quiet 2>/dev/null | grep -cv "^$")
elif require_cmd dnf; then
  UPDATES=$(dnf check-update --quiet 2>/dev/null | grep -cv "^$")
elif require_cmd apt; then
  # No apt update — this is a read-only audit, don't write to /var/lib/apt/lists/
  UPDATES=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || true)
  UPDATES=${UPDATES:-0}
elif require_cmd pacman; then
  UPDATES=$(pacman -Qu 2>/dev/null | wc -l || true)
  UPDATES=${UPDATES:-0}
elif require_cmd zypper; then
  UPDATES=$(zypper -q lu 2>/dev/null | grep -c "^v" || true)
  UPDATES=${UPDATES:-0}
fi

if [[ "$UPDATES" == "0" ]]; then
  pass "System up to date (0 updates)"
elif [[ "$UPDATES" != "?" ]] && [[ "$UPDATES" -le 10 ]]; then
  warn "$UPDATES updates available"
elif [[ "$UPDATES" != "?" ]]; then
  warn "$UPDATES updates available!"
else
  info "Could not check for updates"
fi

# Security Updates
SEC_CHECKED=false
SEC_UPDATES=0
if require_cmd dnf5; then
  SEC_CHECKED=true
  SEC_UPDATES=$(dnf5 check-upgrade --security --quiet 2>/dev/null | grep -cv "^$" || true)
  SEC_UPDATES=${SEC_UPDATES:-0}
elif require_cmd dnf; then
  SEC_CHECKED=true
  SEC_UPDATES=$(dnf updateinfo list --security 2>/dev/null | grep -c "/" || true)
  SEC_UPDATES=${SEC_UPDATES:-0}
elif require_cmd apt-get; then
  SEC_CHECKED=true
  # Ubuntu: use apt-check if available (update-notifier-common), fallback to apt-get -s
  if [[ -x /usr/lib/update-notifier/apt-check ]]; then
    # apt-check without --human-readable outputs "UPDATES;SECURITY" to stderr (locale-independent)
    SEC_UPDATES=$(/usr/lib/update-notifier/apt-check 2>&1 | cut -d';' -f2 || true)
    SEC_UPDATES=${SEC_UPDATES:-0}
  else
    SEC_UPDATES=$(apt-get upgrade -s 2>/dev/null | grep -ciE "^Inst.*security" || true)
    SEC_UPDATES=${SEC_UPDATES:-0}
  fi
elif require_cmd pacman; then
  SEC_CHECKED=true
  # Arch: rolling release — all pending updates may contain security fixes
  SEC_UPDATES="${UPDATES:-0}"
elif require_cmd zypper; then
  SEC_CHECKED=true
  SEC_UPDATES=$(zypper -q lp --severity critical --severity important 2>/dev/null | grep -c "^v" || true)
  SEC_UPDATES=${SEC_UPDATES:-0}
fi
if $SEC_CHECKED; then
  SEC_UPDATES=$(echo "${SEC_UPDATES:-0}" | tr -dc '0-9')
  SEC_UPDATES=${SEC_UPDATES:-0}
  if [[ "${SEC_UPDATES}" -gt 0 ]]; then
    fail "Security updates: $SEC_UPDATES"
  else
    pass "No pending security updates"
  fi
else
  info "Security updates: could not check (unsupported package manager)"
fi

# Package count
if require_cmd rpm; then
  PKG_COUNT=$(rpm -qa 2>/dev/null | wc -l)
  info "Installed packages: $PKG_COUNT"
elif require_cmd dpkg; then
  PKG_COUNT=$(dpkg -l 2>/dev/null | grep -c "^ii")
  info "Installed packages: $PKG_COUNT"
elif require_cmd pacman; then
  PKG_COUNT=$(pacman -Q 2>/dev/null | wc -l)
  info "Installed packages: $PKG_COUNT"
else
  info "Package count: unsupported package manager"
fi

# RPM GPG Verification
if require_cmd rpm; then
  # Modern RPM (Fedora 31+) uses RSAHEADER for signatures; legacy uses SIGPGP/SIGGPG.
  # A package is unsigned only if ALL signature fields are (none).
  # gpg-pubkey meta-packages are keyring entries, not real packages — exclude them
  RPM_NOSIG=$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} RSA:%{RSAHEADER:pgpsig} PGP:%{SIGPGP:pgpsig} GPG:%{SIGGPG:pgpsig}\n' 2>/dev/null \
    | grep "RSA:(none) PGP:(none) GPG:(none)" | grep -cv "^gpg-pubkey-" | ccount)
  # Separate locally-built kernel modules (akmods/dkms) — these are built on the
  # user's machine and inherently cannot carry an RPM GPG signature. They are
  # typically MOK-signed for Secure Boot, which is a separate trust chain.
  RPM_NOSIG_KMOD=$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} RSA:%{RSAHEADER:pgpsig} PGP:%{SIGPGP:pgpsig} GPG:%{SIGGPG:pgpsig}\n' 2>/dev/null \
    | grep "RSA:(none) PGP:(none) GPG:(none)" | grep -cv "^gpg-pubkey-\|^kmod-" | ccount)
  RPM_NOSIG_KMOD_ONLY=$(( RPM_NOSIG - RPM_NOSIG_KMOD ))
  if [[ "$RPM_NOSIG" -eq 0 ]]; then
    pass "All RPM packages signed"
  elif [[ "$RPM_NOSIG_KMOD" -eq 0 && "$RPM_NOSIG_KMOD_ONLY" -gt 0 ]]; then
    info "$RPM_NOSIG unsigned RPM packages (all kmod — locally built, expected)"
  elif [[ "$RPM_NOSIG_KMOD" -gt 0 && "$RPM_NOSIG_KMOD_ONLY" -gt 0 ]]; then
    warn "$RPM_NOSIG_KMOD unsigned RPM packages (+ $RPM_NOSIG_KMOD_ONLY locally-built kmod)"
  else
    warn "$RPM_NOSIG unsigned RPM packages"
  fi

  # RPM GPG Key Count (new)
  GPG_KEY_COUNT=$(rpm -qa gpg-pubkey 2>/dev/null | wc -l)
  info "RPM GPG keys imported: $GPG_KEY_COUNT"
elif require_cmd dpkg; then
  # Debian/Ubuntu: check for unauthenticated packages and GPG key count
  APT_NOAUTH=$(apt list --installed 2>/dev/null | grep -c "\[.*local\]" || true)
  APT_NOAUTH=${APT_NOAUTH:-0}
  if [[ "$APT_NOAUTH" -eq 0 ]]; then
    pass "All APT packages from authenticated sources"
  else
    warn "$APT_NOAUTH APT packages from unauthenticated/local sources"
  fi

  # APT trusted key count
  APT_KEYS=$(apt-key list 2>/dev/null | grep -c "^pub" || true)
  if [[ "${APT_KEYS:-0}" -gt 0 ]]; then
    info "APT trusted keys: $APT_KEYS"
  else
    # Newer systems use /etc/apt/trusted.gpg.d/
    APT_KEYS=$(find /etc/apt/trusted.gpg.d/ /usr/share/keyrings/ -name "*.gpg" -o -name "*.asc" 2>/dev/null | wc -l || true)
    info "APT trusted keyrings: ${APT_KEYS:-0}"
  fi
elif require_cmd pacman; then
  # Arch: check pacman signature enforcement
  if grep -qE "^SigLevel\s*=.*Required" /etc/pacman.conf 2>/dev/null; then
    pass "Pacman: package signature verification required"
  elif grep -qE "^SigLevel\s*=.*Never" /etc/pacman.conf 2>/dev/null; then
    fail "Pacman: package signature verification DISABLED"
  else
    info "Pacman: default signature level (Optional)"
  fi
else
  info "Package signature verification: not available for this package manager"
fi

# Automated Security Updates
# dnf5-automatic (Fedora 41+) and legacy dnf-automatic (Fedora ≤40, RHEL)
if systemctl is-active dnf5-automatic.timer &>/dev/null || systemctl is-enabled dnf5-automatic.timer &>/dev/null; then
  # Check if configured for security-only updates
  _DNF5_AUTO_CONF="/etc/dnf/dnf5-plugins/automatic.conf"
  _DNF5_UPGRADE_TYPE=$(grep -i "^upgrade_type" "$_DNF5_AUTO_CONF" 2>/dev/null | cut -d= -f2 | tr -d ' ')
  if [[ "${_DNF5_UPGRADE_TYPE,,}" == "security" ]]; then
    pass "Automated updates: dnf5-automatic enabled (security-only)"
  else
    pass "Automated updates: dnf5-automatic enabled (upgrade_type=${_DNF5_UPGRADE_TYPE:-default})"
  fi
elif systemctl is-active dnf-automatic.timer &>/dev/null || systemctl is-enabled dnf-automatic.timer &>/dev/null; then
  pass "Automated updates: dnf-automatic enabled"
elif systemctl is-active unattended-upgrades &>/dev/null || [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
  pass "Automated updates: unattended-upgrades active"
elif require_cmd pacman; then
  if systemctl is-active pacman-filesdb-refresh.timer &>/dev/null; then
    info "Automated updates: pacman-filesdb-refresh timer active (partial)"
  else
    info "Automated updates: Arch uses rolling updates — manual 'pacman -Syu' recommended"
  fi
elif require_cmd zypper; then
  if systemctl is-active packagekit.service &>/dev/null; then
    pass "Automated updates: PackageKit service active"
  else
    warn "No automated security update mechanism detected"
  fi
else
  warn "No automated security update mechanism detected"
fi

# Flatpaks
if require_cmd flatpak; then
  FLATPAK_COUNT=$(flatpak list 2>/dev/null | wc -l)
  info "Flatpaks: $FLATPAK_COUNT"
fi

fi # end updates

###############################################################################
if ! should_skip "rootkit"; then
header "15" "ROOTKIT & MALWARE SCAN"
###############################################################################

# rkhunter (deprecated — last release 2018-02-24, signatures don't cover
# post-2018 rootkits like XZ Backdoor, Bootkitty, Kovid, BPFDoor).
# Recommend chkrootkit (last release 2025-05-12) which knows modern threats.
if require_cmd rkhunter; then
  info "rkhunter installed but UNMAINTAINED since 2018-02 — signatures miss XZ Backdoor, Bootkitty, BPFDoor; use chkrootkit instead"
else
  info "rkhunter not installed (chkrootkit + AIDE + IMA preferred for modern rootkit detection)"
fi

# chkrootkit with false-positive filter (timeout 120s prevents hangs).
# F-132: filtered FPs are surfaced as INFO so user can audit nothing's hidden.
if require_cmd chkrootkit; then
  $JSON_MODE || printf "  ${CYN}Running chkrootkit (max 120s)...${RST}\n"
  CHKRK_OUT=$(timeout 120 chkrootkit 2>/dev/null || echo "TIMEOUT")
  if [[ "$CHKRK_OUT" == "TIMEOUT" ]]; then
    warn "chkrootkit: timed out after 120s"
  else
    CHKRK_FP_PATTERN="bindshell|sniffer|chkutmp|w55808|slapper|scalper|wted|Xor\.DDoS|linux_ldiscs|suckit"
    CHKRK_INFECTED=$(echo "$CHKRK_OUT" | grep "INFECTED" | grep -viE "$CHKRK_FP_PATTERN" | wc -l | ccount)
    CHKRK_FP=$(echo "$CHKRK_OUT" | grep "INFECTED" | grep -ciE "$CHKRK_FP_PATTERN" | ccount)
    if [[ "$CHKRK_INFECTED" -eq 0 ]]; then
      pass "chkrootkit: clean (0 real INFECTED, $CHKRK_FP known false positives filtered)"
      # F-132: show filtered FPs as INFO so user can verify nothing legit was hidden
      if [[ "$CHKRK_FP" -gt 0 ]] && ! $JSON_MODE; then
        echo "$CHKRK_OUT" | grep "INFECTED" | grep -iE "$CHKRK_FP_PATTERN" | head -3 | while read -r fp; do
          printf "       (filtered FP) %s\n" "${fp:0:80}"
        done
      fi
    else
      fail "chkrootkit: $CHKRK_INFECTED INFECTED (after filtering $CHKRK_FP known FPs)"
      if ! $JSON_MODE; then
        while read -r i; do
          printf "       %s\n" "$i"
        done < <(echo "$CHKRK_OUT" | grep "INFECTED" | grep -viE "$CHKRK_FP_PATTERN" | head -5)
      fi
    fi
  fi
else
  info "chkrootkit not installed — skipped (recommended over rkhunter for 2026)"
fi

# Suspect Cron Jobs
sub_header "Cron jobs (all users)"
for USER_HOME in /home/* /root; do
  [[ -d "$USER_HOME" ]] || continue
  USER=$(basename "$USER_HOME")
  CRONTAB=$(crontab -l -u "$USER" 2>/dev/null | grep -v "^#" | grep -v "^$" || true)
  if [[ -n "$CRONTAB" ]]; then
    info "Crontab $USER:"
    while read -r line; do
      $JSON_MODE || printf "       %s\n" "$line"
      if echo "$line" | grep -qiE "curl|wget|nc |ncat|python.*http|bash.*http|/dev/tcp"; then
        warn "Suspicious cron entry: $line"
      fi
    done <<< "$CRONTAB"
  fi
done
for CRONDIR in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  if [[ -d "$CRONDIR" ]]; then
    COUNT=$(ls -1 "$CRONDIR" 2>/dev/null | wc -l)
    info "$CRONDIR: $COUNT entries"
  fi
done

fi # end rootkit

###############################################################################
if ! should_skip "processes"; then
header "16" "PROCESS SECURITY"
###############################################################################

# Suspicious processes
# F-136: Name-pattern matching is heuristic only — real attackers rename
# binaries. PASS gives false reassurance unless annotated.
SUSPECT_PROCS=$(ps aux 2>/dev/null | grep -iE "\bnc\s+-[a-z]*l|\bncat\s+-[a-z]*l|\bsocat\s+.*EXEC|\bsocat\s+.*TCP-LISTEN|\bmeterpreter\b|\breverse[_.-]shell\b|\bcobalt\s*strike\b|\bmimikatz\b|\blazagne\b|\bkeylog\b" | grep -v grep || true)
if [[ -z "$SUSPECT_PROCS" ]]; then
  pass "No obvious-named suspicious processes (real malware renames — see AIDE/IMA/chkrootkit for actual integrity)"
else
  fail "Suspicious processes found:"
  if ! $JSON_MODE; then
    while read -r p; do printf "       %s\n" "$p"; done <<< "$SUSPECT_PROCS"
  fi
fi

# Processes running as root
ROOT_PROCS=$(ps aux | awk '$1=="root" {print $11}' | sort -u | wc -l)
info "Root processes (unique): $ROOT_PROCS"

# Hidden Processes
PS_PIDS=$(ps -eo pid --no-headers | sed 's/ //g' | sort -u)
PROC_PIDS=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -u)
HIDDEN=$(comm -23 <(echo "$PROC_PIDS") <(echo "$PS_PIDS") | wc -l)
HIDDEN=${HIDDEN//[^0-9]/}
HIDDEN=${HIDDEN:-0}
if [[ "$HIDDEN" -le 10 ]]; then
  pass "Hidden processes: $HIDDEN (normal: race condition)"
else
  warn "Hidden processes: $HIDDEN"
fi

# Zombie / Dead Processes
_ZOMBIE_COUNT=$(ps aux 2>/dev/null | awk '$8 ~ /^Z/ {count++} END {print count+0}')
if [[ "$_ZOMBIE_COUNT" -eq 0 ]]; then
  pass "Zombie processes: 0"
elif [[ "$_ZOMBIE_COUNT" -le 5 ]]; then
  warn "Zombie processes: $_ZOMBIE_COUNT (investigate with: ps aux | grep ' Z ')"
else
  fail "Zombie processes: $_ZOMBIE_COUNT (resource leak or crashed processes)"
fi

# Deleted Binaries still running
# shellcheck disable=SC2010  # /proc/*/exe requires ls -l to show symlink targets
DELETED_BINS=$(ls -l /proc/*/exe 2>/dev/null | grep "(deleted)" | wc -l)
if [[ "$DELETED_BINS" -eq 0 ]]; then
  pass "No deleted binaries running"
else
  warn "Deleted binaries running: $DELETED_BINS"
  if ! $JSON_MODE; then
    # shellcheck disable=SC2010
    while read -r d; do
      printf "       %s\n" "$d"
    done < <(ls -l /proc/*/exe 2>/dev/null | grep "(deleted)" | head -5)
  fi
fi

fi # end processes

###############################################################################
if ! should_skip "network"; then
header "17" "NETWORK SECURITY (Advanced)"
###############################################################################

# Established Connections
ESTAB=$(ss -tnp state established 2>/dev/null | tail -n+2)
ESTAB_COUNT=$(echo "$ESTAB" | grep -c . || true)
ESTAB_COUNT=${ESTAB_COUNT:-0}
info "Established TCP connections: $ESTAB_COUNT"
if [[ "$ESTAB_COUNT" -gt 0 ]] && ! $JSON_MODE; then
  while read -r line; do
    printf "       %s\n" "$line"
  done < <(echo "$ESTAB" | head -10)
fi

# ICMP Redirect
ICMP_REDIR_ALL=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
ICMP_REDIR_DEF=$(sysctl -n net.ipv4.conf.default.accept_redirects 2>/dev/null)
if [[ "${ICMP_REDIR_ALL:-1}" -eq 0 ]] && [[ "${ICMP_REDIR_DEF:-1}" -eq 0 ]]; then
  pass "ICMP redirects: blocked (all+default)"
elif [[ "${ICMP_REDIR_ALL:-1}" -eq 0 ]]; then
  warn "ICMP redirects: conf.all=0, but conf.default=${ICMP_REDIR_DEF} (new interfaces may accept)"
else
  fail "ICMP redirects: accepted"
fi

# TCP Wrappers (new)
sub_header "TCP Wrappers"
if [[ -f /etc/hosts.allow ]]; then
  ALLOW_RULES=$(grep -v "^#" /etc/hosts.allow 2>/dev/null | grep -v "^$" | wc -l)
  DENY_RULES=$(grep -v "^#" /etc/hosts.deny 2>/dev/null | grep -v "^$" | wc -l)
  info "TCP wrappers: $ALLOW_RULES allow, $DENY_RULES deny rules"
  if [[ "$DENY_RULES" -eq 0 ]]; then
    info "hosts.deny: no deny rules (TCP wrappers deprecated on modern systems)"
  else
    pass "hosts.deny: $DENY_RULES deny rules"
  fi
else
  info "TCP wrappers: not configured (hosts.allow missing)"
fi

# Connections in WAIT state
sub_header "Connection States"
_WAIT_COUNT=$(ss -tn state time-wait 2>/dev/null | tail -n+2 | wc -l)
_WAIT_COUNT=${_WAIT_COUNT:-0}
if [[ "$_WAIT_COUNT" -gt 100 ]]; then
  warn "TCP TIME_WAIT connections: $_WAIT_COUNT (possible resource exhaustion)"
elif [[ "$_WAIT_COUNT" -gt 50 ]]; then
  info "TCP TIME_WAIT connections: $_WAIT_COUNT"
else
  pass "TCP TIME_WAIT connections: $_WAIT_COUNT"
fi

# ARP monitoring
sub_header "ARP Monitoring"
_ARP_MON_FOUND=false
for _arp_tool in arpwatch arpon addrwatch; do
  if require_cmd "$_arp_tool" || systemctl is-active "${_arp_tool}" &>/dev/null; then
    pass "ARP monitoring: $_arp_tool available"
    _ARP_MON_FOUND=true
    break
  fi
done
if ! $_ARP_MON_FOUND; then
  info "No ARP monitoring software detected (consider arpwatch)"
fi

fi # end network

###############################################################################
if ! should_skip "containers"; then
header "18" "CONTAINERS & VIRTUALIZATION"
###############################################################################

if require_cmd docker; then
  if systemctl is-active docker &>/dev/null; then
    # F-145: distinguish rootless (safe) from rootful (privileged daemon)
    if docker info 2>/dev/null | grep -qi "rootless"; then
      info "Docker rootless mode — minimal daemon attack surface"
    else
      warn "Docker daemon running (rootful) — consider rootless mode"
    fi
    CONTAINERS=$(docker ps -q 2>/dev/null | wc -l)
    info "Running containers: $CONTAINERS"
  else
    info "Docker installed, not active"
  fi
fi

if require_cmd podman; then
  PODMAN_ROOT=$(podman ps -q 2>/dev/null | wc -l)
  if [[ "$PODMAN_ROOT" -gt 0 ]]; then
    warn "Podman root containers: $PODMAN_ROOT"
  else
    pass "Podman containers (root): 0"
  fi
fi

if require_cmd virsh; then
  VM_COUNT=$(virsh list --all 2>/dev/null | grep -c "running\|paused" | ccount)
  info "Running VMs: $VM_COUNT"
fi

USER_NS=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "N/A")
info "Max user namespaces: $USER_NS"

fi # end containers

###############################################################################
if ! should_skip "logs"; then
header "19" "LOGS & MONITORING"
###############################################################################

JOURNAL_ERR=$(journalctl -p err --since "1 hour ago" --no-pager -q 2>/dev/null \
  | grep -E "^[A-Z][a-z]{2} " | grep -cvE "sudo|password is required|auth could not identify|systemd-coredump" || true)
JOURNAL_ERR=${JOURNAL_ERR:-0}
if [[ "$JOURNAL_ERR" -le 15 ]]; then
  pass "Journal errors (1h): $JOURNAL_ERR"
elif [[ "$JOURNAL_ERR" -le 50 ]]; then
  warn "Journal errors (1h): $JOURNAL_ERR"
else
  fail "Journal errors (1h): $JOURNAL_ERR"
fi

# journalctl short format: each actual entry starts with a 3-letter month (e.g. "Feb 26 ...").
# Multi-line entries (coredump stack traces + module lists) produce many continuation lines
# that are indented with spaces — these are NOT separate events and must not be counted.
# Filter to timestamp-prefixed lines only, then exclude known-benign sources.
_JCRIT_LINES=$(journalctl -p crit --since "24 hours ago" --no-pager -q 2>/dev/null)
# Filter known-benign critical messages:
#   sudo/auth         — normal sudo operations without TTY
#   systemd-coredump  — stack traces inflate count (filtered since v3.2.1)
#   watchdog.*did not stop — Intel iTCO watchdog always logs this at shutdown (harmless hardware quirk)
JOURNAL_CRIT=$(echo "$_JCRIT_LINES" \
  | grep -E "^[A-Z][a-z]{2} " \
  | grep -cvE "sudo|password is required|auth could not identify|systemd-coredump|watchdog.*did not stop" || true)
JOURNAL_CRIT=${JOURNAL_CRIT:-0}
if [[ "$JOURNAL_CRIT" -eq 0 ]]; then
  pass "Journal critical (24h): 0"
elif [[ "$JOURNAL_CRIT" -le 20 ]]; then
  warn "Journal critical (24h): $JOURNAL_CRIT"
else
  fail "Journal critical (24h): $JOURNAL_CRIT"
fi

# F-151: limit to recent (1h) — kernel ring buffer accumulates boot-time
# errors over months on long-uptime servers, inflating count
DMESG_ERR=$(dmesg --level=err,crit,alert,emerg --since "1 hour ago" 2>/dev/null | wc -l)
if [[ "$DMESG_ERR" -le 5 ]]; then
  pass "dmesg errors (1h): $DMESG_ERR"
else
  warn "dmesg errors (1h): $DMESG_ERR"
fi

OOM_KILLS=$(dmesg 2>/dev/null | grep -c "Out of memory" | ccount)
if [[ "$OOM_KILLS" -eq 0 ]]; then
  pass "OOM kills: 0"
else
  fail "OOM kills: $OOM_KILLS"
fi

SEGFAULTS=$(dmesg 2>/dev/null | grep -c "segfault" | ccount)
if [[ "$SEGFAULTS" -eq 0 ]]; then
  pass "Segfaults: 0"
else
  warn "Segfaults: $SEGFAULTS"
fi

if [[ -f /etc/logrotate.conf ]]; then
  pass "logrotate configured"
else
  warn "logrotate not configured"
fi

JOURNAL_STORAGE=$(journalctl --disk-usage 2>/dev/null | grep -oP '\d+\.?\d*[GMKT]' | head -1)
info "Journal disk usage: $JOURNAL_STORAGE"

# Systemd Journal Forwarding (new)
JOURNAL_FWD=$(grep -i "ForwardToSyslog" /etc/systemd/journald.conf 2>/dev/null | grep -v "^#" | head -1)
if [[ -n "$JOURNAL_FWD" ]]; then
  info "Journal forwarding: $JOURNAL_FWD"
else
  info "Journal forwarding: default (not explicitly configured)"
fi

# Deleted log files still in use (file handle open but file deleted — logs lost on restart)
_DELETED_LOGS=$(find /proc/*/fd -lname '*/log/*' -exec ls -la {} \; 2>/dev/null | grep "(deleted)" | wc -l || true)
_DELETED_LOGS=${_DELETED_LOGS:-0}
if [[ "$_DELETED_LOGS" -eq 0 ]]; then
  pass "No deleted log files in use"
elif [[ "$_DELETED_LOGS" -le 3 ]]; then
  info "Deleted log files still open: $_DELETED_LOGS (logrotate pending restart)"
else
  warn "Deleted log files still open: $_DELETED_LOGS (services holding stale file handles)"
fi

# F-155: only check empty syslog files if rsyslog/syslog-ng is actually
# active. On systemd-only systems (Fedora 40+, Arch, modern minimal installs)
# these files don't exist by design and shouldn't trigger warnings.
if systemctl is-active rsyslog syslog-ng &>/dev/null; then
  _EMPTY_LOGS=0
  for _logf in /var/log/messages /var/log/syslog /var/log/auth.log /var/log/secure /var/log/kern.log; do
    if [[ -f "$_logf" && ! -s "$_logf" ]]; then
      ((_EMPTY_LOGS++))
      warn "Empty log file: $_logf (logging may be broken)"
    fi
  done
  [[ "$_EMPTY_LOGS" -eq 0 ]] && pass "No empty log files detected"
else
  info "Syslog implementation not active — using systemd-journald only (modern default)"
fi

fi # end logs

###############################################################################
if ! should_skip "performance"; then
header "20" "PERFORMANCE & RESOURCES"
###############################################################################

UPTIME=$(uptime -p)
LOAD=$(awk '{print $1, $2, $3}' /proc/loadavg)
CPU_COUNT=$(nproc)
LOAD_1=$(echo "$LOAD" | awk '{print $1}')
info "Uptime: $UPTIME"
info "Load: $LOAD (CPUs: $CPU_COUNT)"

if require_cmd bc; then
  if (( $(echo "$LOAD_1 > $CPU_COUNT" | bc -l 2>/dev/null || true) )); then
    warn "Load ($LOAD_1) > CPU count ($CPU_COUNT)"
  else
    pass "Load OK: $LOAD_1 / $CPU_COUNT CPUs"
  fi
fi

MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
MEM_AVAIL=$(free -h | awk '/^Mem:/ {print $7}')
# F-158: use 'available' (column 7) instead of 'used' — Linux aggressively
# caches files which inflates 'used'. 'available' is what apps can claim
# without paging.
MEM_AVAIL_PCT=$(free | awk '/^Mem:/ {printf "%.0f", ($7/$2)*100}')
info "RAM: $MEM_USED / $MEM_TOTAL (${MEM_AVAIL_PCT}% available, $MEM_AVAIL free)"
if [[ "$MEM_AVAIL_PCT" -lt 5 ]]; then
  fail "RAM: only ${MEM_AVAIL_PCT}% available (critical)"
elif [[ "$MEM_AVAIL_PCT" -lt 15 ]]; then
  warn "RAM: ${MEM_AVAIL_PCT}% available"
else
  pass "RAM: ${MEM_AVAIL_PCT}% available"
fi

SWAP_TOTAL=$(free -h | awk '/^Swap:/ {print $2}')
SWAP_USED=$(free -h | awk '/^Swap:/ {print $3}')
if [[ "$SWAP_TOTAL" != "0B" ]] && [[ "$SWAP_TOTAL" != "0" ]]; then
  info "Swap: $SWAP_USED / $SWAP_TOTAL"
else
  info "No swap configured"
fi

sub_header "Disk Usage"
# Read-only filesystems (ISO loopbacks, squashfs, erofs, OverlayFS lowerdirs)
# are by definition always 100% full. Filter them to avoid false FAIL.
while read -r line; do
  [[ -z "$line" ]] && continue
  # df -h -T columns: 1=fs 2=type 3=size 4=used 5=avail 6=use% 7=mount
  PCT=$(echo "$line" | awk '{print $6}' | tr -d '%')
  MOUNT=$(echo "$line" | awk '{print $NF}')
  FSTYPE=$(echo "$line" | awk '{print $2}')
  # Bail if PCT is non-numeric (header row, malformed line)
  [[ "$PCT" =~ ^[0-9]+$ ]] || continue
  # Skip read-only image filesystems (always 100% by design)
  case "$FSTYPE" in
    iso9660|squashfs|erofs|cramfs|romfs)
      info "Disk $MOUNT: read-only $FSTYPE image (always 100% — skipped)"
      continue
      ;;
  esac
  # Skip explicitly read-only mounts (loopback ISOs etc.)
  if mount | grep -qE "on $MOUNT type [^ ]+ \(ro,"; then
    info "Disk $MOUNT: read-only mount (skipped)"
    continue
  fi
  if [[ "$PCT" -gt 90 ]]; then
    fail "Disk $MOUNT: ${PCT}% full!"
  elif [[ "$PCT" -gt 80 ]]; then
    if [[ "$MOUNT" == */efi* || "$MOUNT" == */firmware* ]]; then
      info "Disk $MOUNT: ${PCT}% (EFI/firmware — normal)"
    else
      warn "Disk $MOUNT: ${PCT}% full"
    fi
  else
    pass "Disk $MOUNT: ${PCT}% used"
  fi
done < <(df -h -T -x tmpfs -x devtmpfs -x squashfs -x iso9660 -x erofs -x overlay 2>/dev/null | tail -n+2)

INODE_PCT=$(df -i / | tail -1 | awk '{print $5}' | tr -d '%')
if [[ "$INODE_PCT" == "-" ]] || [[ -z "$INODE_PCT" ]]; then
  pass "Inodes /: N/A (Btrfs — dynamic)"
elif [[ "$INODE_PCT" -gt 90 ]]; then
  fail "Inodes /: ${INODE_PCT}%"
else
  pass "Inodes /: ${INODE_PCT}%"
fi

# F-161: read /proc/stat directly (instant, no 2-second blocking call,
# no column-position parsing, no fallback-magic-number).
# Format: cpu user nice system idle iowait irq softirq steal guest guest_nice
read -r _ _cpu_user _cpu_nice _cpu_sys _cpu_idle _cpu_iowait _ < /proc/stat
_cpu_total=$((_cpu_user + _cpu_nice + _cpu_sys + _cpu_idle + _cpu_iowait))
if [[ "$_cpu_total" -gt 0 ]]; then
  IOWAIT=$(awk -v w="$_cpu_iowait" -v t="$_cpu_total" 'BEGIN{printf "%.0f", (w/t)*100}')
else
  IOWAIT=0
fi
if [[ "${IOWAIT:-0}" -gt 20 ]]; then
  warn "I/O wait: ${IOWAIT}%"
else
  pass "I/O wait: ${IOWAIT:-0}%"
fi

sub_header "Top 5 CPU"
if ! $JSON_MODE; then
  while read -r USER CPU MEM CMD; do
    printf "       %s %s%% %s\n" "$USER" "$CPU" "$(echo "$CMD" | cut -c1-60)"
  done < <(ps -eo user,pcpu,pmem,args --sort=-pcpu 2>/dev/null | grep -v 'sort=-pcpu' | head -6 | tail -5)
fi

sub_header "Top 5 Memory"
if ! $JSON_MODE; then
  while read -r USER CPU MEM CMD; do
    printf "       %s %s%% %s\n" "$USER" "$MEM" "$(echo "$CMD" | cut -c1-60)"
  done < <(ps -eo user,pcpu,pmem,args --sort=-pmem 2>/dev/null | grep -v 'sort=-pmem' | head -6 | tail -5)
fi

fi # end performance

###############################################################################
if ! should_skip "hardware"; then
header "21" "HARDWARE & FIRMWARE"
###############################################################################

sub_header "CPU Vulnerabilities"
VULN_DIR="/sys/devices/system/cpu/vulnerabilities"
if [[ -d "$VULN_DIR" ]]; then
  for VULN in "$VULN_DIR"/*; do
    [[ -f "$VULN" ]] || continue
    NAME=$(basename "$VULN")
    STATUS=$(cat "$VULN" 2>/dev/null)
    if echo "$STATUS" | grep -qi "vulnerable"; then
      fail "CPU vuln $NAME: $STATUS"
    elif echo "$STATUS" | grep -qi "mitigation"; then
      pass "CPU vuln $NAME: mitigated"
    elif echo "$STATUS" | grep -qi "not affected"; then
      pass "CPU vuln $NAME: Not affected"
    else
      warn "CPU vuln $NAME: $STATUS"
    fi
  done
fi

# SMART Health
if require_cmd smartctl; then
  for DISK in $(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2=="disk"{print "/dev/"$1}'); do
    SMART=$(smartctl -H "$DISK" 2>/dev/null | grep -i "health\|result" | tail -1)
    if echo "$SMART" | grep -qi "passed\|ok"; then
      pass "SMART $DISK: OK"
    elif [[ -n "$SMART" ]]; then
      fail "SMART $DISK: $SMART"
    fi
  done
else
  info "smartctl not installed — SMART checks skipped"
fi

# Temperature (F-165: distinguish "not installed" from "installed but
# unconfigured" — silent skip on misconfigured sensors hides actual issue)
if require_cmd sensors; then
  _SENSORS_OUT=$(sensors 2>/dev/null)
  if [[ -z "$_SENSORS_OUT" ]] || ! echo "$_SENSORS_OUT" | grep -q "°C"; then
    info "lm_sensors installed but no readings — run 'sudo sensors-detect' to configure"
  else
    MAX_TEMP=$(echo "$_SENSORS_OUT" | grep -oP ':\s+\+\K\d+\.\d+(?=°C)' | sort -rn | head -1)
    if [[ -n "$MAX_TEMP" ]]; then
      TEMP_NUM=$(echo "$MAX_TEMP" | grep -oP '^\d+')
      if [[ "$TEMP_NUM" -gt 85 ]]; then
        fail "Max temperature: ${MAX_TEMP}°C (CRITICAL)"
      elif [[ "$TEMP_NUM" -gt 70 ]]; then
        warn "Max temperature: ${MAX_TEMP}°C (elevated)"
      else
        pass "Max temperature: ${MAX_TEMP}°C"
      fi
    fi
    # Show all sensor zones
    sub_header "Temperature Sensors"
    if ! $JSON_MODE; then
      while read -r line; do
        printf "       %s\n" "$line"
      done < <(echo "$_SENSORS_OUT" | grep -E "°C" | head -10)
    fi
  fi
else
  info "lm_sensors not installed — temperature checks skipped"
fi

# USB Devices
USB_COUNT=$(lsusb 2>/dev/null | wc -l)
info "USB devices: $USB_COUNT"

fi # end hardware

###############################################################################
if ! should_skip "interfaces"; then
header "22" "NETWORK INTERFACES (Detail)"
###############################################################################
# NOTE: This section makes network requests (dig).
# Use --skip interfaces to avoid network traffic from this section.

if ! $JSON_MODE; then
  while read -r IFACE STATE ADDRS; do
    printf "  ${CYN}%s${RST} (%s): %s\n" "$IFACE" "$STATE" "$ADDRS"
  done < <(ip -br addr 2>/dev/null)
fi

sub_header "Routing"
if ! $JSON_MODE; then
  while read -r route; do
    printf "       %s\n" "$route"
  done < <(ip route show 2>/dev/null)
fi

if require_cmd dig; then
  # F-167: query DNS root nameservers (no third-party tracked)
  DNS_TEST=$(dig +short . NS +time=3 2>/dev/null | head -1 || echo "FAIL")
  if [[ "$DNS_TEST" != "FAIL" ]] && [[ -n "$DNS_TEST" ]]; then
    pass "DNS resolution: working"
  else
    warn "DNS resolution: failed"
  fi
fi

fi # end interfaces

###############################################################################
if ! should_skip "certificates"; then
header "23" "CRYPTO & CERTIFICATES"
###############################################################################

# F-168: Cross-distro CA certificate count (trust is Fedora/RHEL-only)
if require_cmd trust; then
  CA_COUNT=$(trust list 2>/dev/null | grep -c "type: certificate" || echo "?")
  info "System CA certificates: $CA_COUNT"
elif [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
  CA_COUNT=$(grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt 2>/dev/null || echo "?")
  info "System CA certificates: $CA_COUNT (from ca-certificates.crt)"
elif [[ -d /etc/ssl/certs ]]; then
  CA_COUNT=$(find /etc/ssl/certs -maxdepth 1 \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | wc -l)
  info "System CA certificates: $CA_COUNT (from /etc/ssl/certs/)"
fi

if require_cmd openssl; then
  for _CERT_DIR in /etc/pki/tls/certs /etc/ssl/certs; do
    [[ -d "$_CERT_DIR" ]] || continue
    while read -r cert; do
      if ! openssl x509 -checkend 0 -in "$cert" -noout &>/dev/null; then
        warn "Expired certificate: $cert"
      fi
    done < <(find "$_CERT_DIR" -maxdepth 1 \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | grep -v "ca-bundle" | head -20)
  done
fi

sub_header "SSH Keys"
for USER_HOME in /home/* /root; do
  USER=$(basename "$USER_HOME")
  if [[ -d "$USER_HOME/.ssh" ]]; then
    KEY_COUNT=$(ls "$USER_HOME/.ssh/"*.pub 2>/dev/null | wc -l)
    AUTH_KEYS=$(wc -l "$USER_HOME/.ssh/authorized_keys" 2>/dev/null | awk '{print $1}' || true)
    AUTH_KEYS=${AUTH_KEYS:-0}
    if [[ "$KEY_COUNT" -gt 0 ]] || [[ "$AUTH_KEYS" -gt 0 ]]; then
      info "SSH keys for $USER: $KEY_COUNT keys, $AUTH_KEYS authorized"
    fi
  fi
done

fi # end certificates

###############################################################################
if ! should_skip "environment"; then
header "24" "ENVIRONMENT & SECRETS"
###############################################################################

# World-readable private keys
# Two-stage detection: filename candidates → content verification (magic strings).
# Filename ".key" alone is NOT sufficient (uBlock Origin IDB records, test
# fixtures, API config files all use this). Permission check uses 077 mask
# but excludes 640 (common for service-managed keys with group ownership).
EXPOSED_KEYS=$(while read -r key; do
  _is_real_private_key "$key" || continue
  PERMS=$(stat -c %a "$key" 2>/dev/null)
  # Only flag world-readable (other bits) — group=4 is often intentional
  # (e.g. libvirt's kvm:kvm group ownership)
  if (( (8#${PERMS:-777} & 8#007) != 0 )); then
    echo "$key ($PERMS)"
  fi
done < <(_safe_find_home \
  \( -name "*.key" -o -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" \) \
  ! -name "*.pub" \
  ! -path "*/cacert*" ! -path "*/ca-bundle*" \
  ! -path "*public_key*" ! -path "*/roots.pem"))
if [[ -z "$EXPOSED_KEYS" ]]; then
  pass "No exposed private keys"
else
  fail "Exposed private keys:"
  if ! $JSON_MODE; then
    while read -r k; do printf "       %s\n" "$k"; done <<< "$EXPOSED_KEYS"
  fi
fi

# .env files (uses _safe_find_home — same snapshot/cache excludes)
ENV_FILES=$(_safe_find_home \( -name ".env" -o -name ".env.local" -o -name ".env.production" \) -readable -size +0c | wc -l)
if [[ "$ENV_FILES" -gt 0 ]]; then
  info ".env files found: $ENV_FILES"
fi

# Credentials in configs
CRED_PATTERNS="password|passwd|secret|api_key|token|credential"
CRED_FOUND=$(find /etc -name "*.conf" -exec grep -liE "$CRED_PATTERNS" {} \; 2>/dev/null | wc -l)
info "Config files with credential patterns: $CRED_FOUND"

fi # end environment

###############################################################################
if ! should_skip "systemd"; then
header "25" "SYSTEMD SECURITY"
###############################################################################

if require_cmd systemd-analyze; then
  sub_header "systemd-analyze security"
  # Security services (need root — high score expected and acceptable)
  _SECURITY_SVCS="sshd firewalld fail2ban auditd usbguard chronyd"
  # Hardware/display services (inherently need broad access — high score expected)
  _HARDWARE_SVCS="gdm gdm3 thermald"
  # User-facing services (should be sandboxed — high score = problem)
  _USER_SVCS="NetworkManager ModemManager colord fwupd power-profiles-daemon switcheroo-control"
  for SVC in $_SECURITY_SVCS; do
    SCORE=$(systemd-analyze security "$SVC" 2>/dev/null | tail -1 | grep -oP '\d+\.\d+' || echo "N/A")
    if [[ "$SCORE" != "N/A" ]]; then
      info "systemd-security $SVC: $SCORE (security service, needs root)"
    fi
  done
  for SVC in $_HARDWARE_SVCS; do
    SCORE=$(systemd-analyze security "$SVC" 2>/dev/null | tail -1 | grep -oP '\d+\.\d+' || echo "N/A")
    if [[ "$SCORE" != "N/A" ]]; then
      info "systemd-security $SVC: $SCORE (system service, needs hardware access)"
    fi
  done
  _HIGH_EXPOSURE=0
  for SVC in $_USER_SVCS; do
    SCORE=$(systemd-analyze security "$SVC" 2>/dev/null | tail -1 | grep -oP '\d+\.\d+' || echo "N/A")
    [[ "$SCORE" == "N/A" ]] && continue
    SCORE_INT=$(echo "$SCORE" | cut -d. -f1)
    if [[ "$SCORE_INT" -le 4 ]]; then
      pass "systemd-security $SVC: $SCORE (well-sandboxed)"
    elif [[ "$SCORE_INT" -le 7 ]]; then
      info "systemd-security $SVC: $SCORE"
    else
      warn "systemd-security $SVC: $SCORE (high exposure — poor sandboxing)"
      ((_HIGH_EXPOSURE++))
    fi
  done
  if [[ "$_HIGH_EXPOSURE" -eq 0 ]]; then
    pass "No user-facing services with critical exposure scores"
  fi
fi

fi # end systemd

###############################################################################
if ! should_skip "desktop"; then
header "26" "DESKTOP & GUI SECURITY"
###############################################################################

# Wayland vs X11
if require_cmd loginctl; then
  SESSION_ID=$(loginctl list-sessions --no-legend 2>/dev/null | grep -E "seat[0-9]" | awk '{print $1}' | head -1)
  [[ -z "$SESSION_ID" ]] && SESSION_ID=$(loginctl list-sessions --no-legend 2>/dev/null | awk 'NR==1{print $1}')
  if [[ -n "$SESSION_ID" ]]; then
    SESSION_TYPE=$(loginctl show-session "$SESSION_ID" -p Type --value 2>/dev/null || echo "unknown")
    if [[ "$SESSION_TYPE" == "wayland" ]]; then
      pass "Display server: Wayland (more secure than X11)"
    elif [[ "$SESSION_TYPE" == "x11" ]]; then
      warn "Display server: X11 (keylogger risk — consider Wayland)"
    else
      info "Display server: $SESSION_TYPE"
    fi
  fi
fi

# Screen Lock (per-user, DE-aware: GNOME / KDE Plasma / XFCE / MATE / Cinnamon)
_de_lock_check_cb() {
  local user="$1" val
  val=$(echo "$3" | xargs | tr '[:upper:]' '[:lower:]')
  _DE_LOCK_FOUND=1
  case "$val" in
    true|1) pass "Screen lock: enabled [$user, $_DE_FAMILY]" ;;
    false|0) warn "Screen lock: disabled [$user, $_DE_FAMILY]" ;;
  esac
}
_DE_LOCK_FOUND=0
case "$_DE_FAMILY" in
  gnome|cinnamon|mate)
    require_cmd gsettings && _de_check_screen_lock _de_lock_check_cb
    ;;
  kde|xfce)
    _de_check_screen_lock _de_lock_check_cb
    ;;
esac
[[ "$_DE_LOCK_FOUND" -eq 0 && "$_DE_FAMILY" != "unknown" ]] && \
  info "Screen lock: no active $_DE_FAMILY session found for check"

# Auto-Login — detailed check in Section 39 (Desktop Session Security)
if [[ -f /etc/gdm/custom.conf ]] || [[ -f /etc/gdm3/custom.conf ]]; then
  if grep -qi '^\s*AutomaticLoginEnable[[:space:]]*=[[:space:]]*true' /etc/gdm*/custom.conf /etc/gdm*/daemon.conf 2>/dev/null; then
    fail "GDM auto-login enabled!"
  else
    pass "GDM: no auto-login"
  fi
fi

fi # end desktop

###############################################################################
if ! should_skip "ntp"; then
header "27" "TIME SYNC & NTP"
###############################################################################

if require_cmd timedatectl; then
  NTP_SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  if [[ "$NTP_SYNC" == "yes" ]]; then
    pass "NTP synchronized"
  else
    warn "NTP not synchronized"
  fi
  TZ=$(timedatectl show -p Timezone --value 2>/dev/null)
  info "Timezone: $TZ"
fi

if systemctl is-active chronyd &>/dev/null || systemctl is-active chrony &>/dev/null; then
  pass "chrony: active"
  if require_cmd chronyc; then
    CHRONY_SOURCES=$(chronyc sources 2>/dev/null | grep -c "^\^" || true)
    CHRONY_SOURCES=${CHRONY_SOURCES:-0}
    info "Chrony sources: $CHRONY_SOURCES"

    # Network Time Security (NTS) check
    # Primary: chronyc authdata shows "NTS" for authenticated sources (chrony 4.0+)
    NTS_SOURCES=$(chronyc -n authdata 2>/dev/null | awk '$3 == "NTS" {c++} END {print c+0}')
    if [[ "$NTS_SOURCES" -gt 0 ]]; then
      pass "NTS (Network Time Security): $NTS_SOURCES active source(s) using NTS"
    else
      # Fallback: check chrony.conf for 'nts' keyword on server/pool lines
      _NTS_CONF=false
      for _chrony_conf in /etc/chrony.conf /etc/chrony/chrony.conf; do
        [[ -f "$_chrony_conf" ]] || continue
        if grep -qiE "^(server|pool)\s+.*\bnts\b" "$_chrony_conf" 2>/dev/null; then
          _NTS_CONF=true
          break
        fi
      done
      if $_NTS_CONF; then
        pass "NTS (Network Time Security) configured in chrony.conf"
      else
        info "NTS (Network Time Security) not configured — consider adding 'nts' to chrony server lines"
      fi
    fi
  fi
  # NTP source quality (stratum 16 = unreachable, falsetickers)
  if require_cmd chronyc; then
    _BAD_SOURCES=0
    while read -r _cs_line; do
      # chronyc sources: field 3 is stratum, lines starting with ? or x are problematic
      if echo "$_cs_line" | grep -qE "^\?|^x"; then
        ((_BAD_SOURCES++))
      fi
    done < <(chronyc sources 2>/dev/null | tail -n+3)
    if [[ "$_BAD_SOURCES" -gt 0 ]]; then
      warn "NTP: $_BAD_SOURCES unreachable/falseticker source(s) (check 'chronyc sources')"
    else
      pass "NTP: all sources reachable and valid"
    fi
  fi
elif systemctl is-active systemd-timesyncd &>/dev/null; then
  pass "timesyncd: active"
else
  warn "No NTP service active"
fi

fi # end ntp

###############################################################################
if ! should_skip "fail2ban"; then
header "28" "FAIL2BAN"
###############################################################################

if systemctl is-active fail2ban &>/dev/null; then
  pass "fail2ban: active"

  if require_cmd fail2ban-client; then
    JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' | xargs)
    info "Active jails: $JAILS"

    for JAIL in $JAILS; do
      BANNED=$(fail2ban-client status "$JAIL" 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
      TOTAL_BANNED=$(fail2ban-client status "$JAIL" 2>/dev/null | grep "Total banned" | awk '{print $NF}')
      info "Jail $JAIL: $BANNED current, $TOTAL_BANNED total banned"
    done
  fi
elif ! require_cmd fail2ban-client; then
  info "fail2ban not installed — skipped"
else
  fail "fail2ban: INACTIVE"
fi

fi # end fail2ban

###############################################################################
if ! should_skip "logins"; then
header "29" "RECENT LOGINS & ACTIVITY"
###############################################################################

sub_header "Last 5 logins"
if ! $JSON_MODE; then
  while read -r line; do
    printf "       %s\n" "$line"
  done < <(last -n 5 2>/dev/null | head -5)
fi

sub_header "Failed logins"
# F-184: redact IPs to avoid leaking attack-source data when output is shared
if ! $JSON_MODE; then
  while read -r line; do
    [[ -z "$line" ]] && continue
    # Redact IPv4 addresses (privacy when sharing audit output)
    line_redacted=$(echo "$line" | sed 's/\b[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\b/X.X.X.X/g')
    printf "       %s\n" "$line_redacted"
  done < <(lastb -n 5 2>/dev/null | head -5)
fi

USERS_LOGGED=$(who | wc -l)
info "Currently logged in: $USERS_LOGGED users"

SUDO_USAGE=$(journalctl _COMM=sudo --since "1 hour ago" --no-pager 2>/dev/null | grep -c "COMMAND" || true)
SUDO_USAGE=${SUDO_USAGE:-0}
info "Sudo commands (1h): $SUDO_USAGE"

fi # end logins

###############################################################################
if ! should_skip "hardening"; then
header "30" "ADVANCED HARDENING"
###############################################################################

# Coredump Service Check (new)
sub_header "Core Dump Service"
if systemctl is-active systemd-coredump.socket &>/dev/null; then
  warn "systemd-coredump socket: active"
else
  pass "systemd-coredump socket: inactive"
fi
# Read effective storage setting — check drop-ins too (they override main config)
COREDUMP_STORAGE=$(_systemd_conf_val /etc/systemd/coredump.conf Storage)
if [[ "${COREDUMP_STORAGE,,}" == "none" ]]; then
  pass "Coredump storage: none (disabled)"
elif [[ -n "$COREDUMP_STORAGE" ]]; then
  warn "Coredump storage: $COREDUMP_STORAGE (should be 'none')"
else
  info "Coredump storage: default/external (not explicitly disabled)"
fi

# USB Guard (new)
sub_header "USB Guard"
if require_cmd usbguard; then
  if systemctl is-active usbguard &>/dev/null; then
    pass "USBGuard: active"
    POLICY_COUNT=$(usbguard list-rules 2>/dev/null | wc -l)
    info "USBGuard rules: $POLICY_COUNT"
  else
    warn "USBGuard installed but inactive"
  fi
else
  info "USBGuard not installed — USB devices unrestricted"
fi

# Compiler Check (new)
sub_header "Development Tools"
COMPILERS_FOUND=""
for COMP in gcc g++ cc make as; do
  if require_cmd "$COMP"; then
    COMPILERS_FOUND+="$COMP "
  fi
done
if [[ -n "$COMPILERS_FOUND" ]]; then
  if [[ -n "$DESKTOP_ENV" && "$DESKTOP_ENV" != "unknown" ]]; then
    info "Compilers/build tools present: $COMPILERS_FOUND(normal for development desktop)"
  else
    warn "Compilers/build tools present: $COMPILERS_FOUND(risk on production systems)"
  fi
else
  pass "No compilers/build tools found"
fi

# Prelink Check (new)
if require_cmd prelink; then
  warn "prelink is installed (can interfere with AIDE/security)"
else
  pass "prelink not installed"
fi

# AIDE/Tripwire — File Integrity Monitoring (new)
sub_header "File Integrity Monitoring"
FIM_FOUND=false
if require_cmd aide; then
  pass "AIDE installed (file integrity monitoring)"
  FIM_FOUND=true
fi
if require_cmd tripwire; then
  pass "Tripwire installed (file integrity monitoring)"
  FIM_FOUND=true
fi
if ! $FIM_FOUND; then
  warn "No file integrity monitoring (AIDE/Tripwire) installed"
fi

# Cron Permission Check (new)
sub_header "Cron/At Permissions"
if [[ -f /etc/cron.allow ]]; then
  pass "cron.allow exists (whitelist approach)"
elif [[ -f /etc/cron.deny ]]; then
  info "cron.deny exists (blacklist approach — cron.allow preferred)"
else
  warn "Neither cron.allow nor cron.deny exists"
fi

# At Permission Check (new)
if require_cmd at; then
  if [[ -f /etc/at.allow ]]; then
    pass "at.allow exists (whitelist approach)"
  elif [[ -f /etc/at.deny ]]; then
    info "at.deny exists (blacklist approach — at.allow preferred)"
  else
    warn "Neither at.allow nor at.deny exists"
  fi
fi

# IMA/EVM (Integrity Measurement Architecture / Extended Verification Module)
sub_header "Kernel Integrity (IMA/EVM)"
_IMA_ACTIVE=false
if [[ -d /sys/kernel/security/ima ]]; then
  _IMA_ACTIVE=true
  _IMA_POLICY=$(cat /sys/kernel/security/ima/policy_name 2>/dev/null || echo "custom")
  pass "IMA: active (policy: $_IMA_POLICY)"
  _IMA_VIOLATIONS=$(cat /sys/kernel/security/ima/violations 2>/dev/null || echo "0")
  if [[ "${_IMA_VIOLATIONS:-0}" -gt 0 ]]; then
    warn "IMA violations: $_IMA_VIOLATIONS"
  else
    pass "IMA violations: 0"
  fi
else
  if grep -q "ima" /proc/cmdline 2>/dev/null; then
    info "IMA: configured in cmdline but /sys/kernel/security/ima not found"
  else
    info "IMA: not active (consider adding ima_policy=appraise_tcb to kernel cmdline)"
  fi
fi
# EVM
if [[ -f /sys/kernel/security/evm ]]; then
  _EVM_STATUS=$(cat /sys/kernel/security/evm 2>/dev/null)
  if [[ "$_EVM_STATUS" -ge 1 ]]; then
    pass "EVM: active (status=$_EVM_STATUS)"
  else
    info "EVM: present but not initialized (status=$_EVM_STATUS)"
  fi
else
  info "EVM: not available"
fi

# binfmt_misc (non-native binary execution)
sub_header "Binary Format Registration"
if [[ -d /proc/sys/fs/binfmt_misc ]]; then
  _BINFMT_COUNT=0
  for _bf_entry in /proc/sys/fs/binfmt_misc/*; do
    [[ -e "$_bf_entry" ]] || continue
    case "$(basename "$_bf_entry")" in register|status) continue ;; esac
    ((_BINFMT_COUNT++))
  done
  _BINFMT_COUNT=${_BINFMT_COUNT:-0}
  if [[ "$_BINFMT_COUNT" -eq 0 ]]; then
    pass "binfmt_misc: no non-native binary formats registered"
  else
    info "binfmt_misc: $_BINFMT_COUNT registered format(s)"
    if ! $JSON_MODE; then
      for _bf in /proc/sys/fs/binfmt_misc/*; do
        [[ "$(basename "$_bf")" =~ ^(register|status)$ ]] && continue
        [[ -f "$_bf" ]] || continue
        printf "       %s\n" "$(basename "$_bf")"
      done
    fi
  fi
else
  pass "binfmt_misc: not mounted"
fi

# FireWire (IEEE 1394) DMA attack surface
sub_header "FireWire / IEEE 1394"
if lsmod 2>/dev/null | grep -qE "^firewire_core|^ohci1394|^sbp2"; then
  fail "FireWire module loaded — DMA attack risk"
elif grep -rqsE "install\s+(firewire[-_]core|ohci1394|sbp2)\s+/(usr/)?s?bin/(false|true)|blacklist\s+(firewire[-_]core|ohci1394|sbp2)" /etc/modprobe.d/ 2>/dev/null; then
  pass "FireWire modules: blacklisted"
else
  pass "FireWire modules: not loaded"
fi

# Home directory permissions
sub_header "Home Directory Security"
while IFS=: read -r _huser _ _huid _ _ _hhome _; do
  [[ "$_huid" -ge 1000 && "$_huid" -lt 65534 ]] || continue
  [[ -d "$_hhome" ]] || continue
  _HPERMS=$(stat -c %a "$_hhome" 2>/dev/null)
  [[ -z "$_HPERMS" ]] && continue
  # Severity tiering: 0xx (no o/g) = pass, 0x5 (group-only) = pass, 755 (Linux
  # default, group+other read) = INFO with note, anything writable = warn.
  # 755 is the install default on Fedora/Ubuntu — flagging it as WARN creates
  # systematic alarm fatigue (F-196).
  if (( (8#${_HPERMS} & 8#022) != 0 )); then
    warn "Home directory $_hhome: $_HPERMS (group/other writable — fix with chmod 750)"
  elif (( (8#${_HPERMS} & 8#005) != 0 )); then
    info "Home directory $_hhome: $_HPERMS (Linux default — chmod 750 for stricter privacy)"
  else
    pass "Home directory $_hhome: $_HPERMS (private)"
  fi
  # Check ownership
  _HOWNER=$(stat -c %U "$_hhome" 2>/dev/null)
  if [[ "$_HOWNER" != "$_huser" ]]; then
    fail "Home directory $_hhome owned by $_HOWNER (should be $_huser)"
  fi
done < /etc/passwd

# Shell idle timeout (TMOUT)
sub_header "Shell Idle Timeout"
_TMOUT_SET=false
for _tmout_file in /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc; do
  [[ -f "$_tmout_file" ]] || continue
  if grep -qE "^(export\s+)?TMOUT=" "$_tmout_file" 2>/dev/null; then
    _TMOUT_VAL=$(grep -oP '^(export\s+)?TMOUT=\K\d+' "$_tmout_file" 2>/dev/null | tail -1)
    if [[ -n "$_TMOUT_VAL" && "$_TMOUT_VAL" -gt 0 ]]; then
      _TMOUT_SET=true
      if [[ "$_TMOUT_VAL" -le 900 ]]; then
        pass "Shell TMOUT=${_TMOUT_VAL}s (in $(basename "$_tmout_file"))"
      else
        warn "Shell TMOUT=${_TMOUT_VAL}s (recommended: ≤900s)"
      fi
      break
    fi
  fi
done
if ! $_TMOUT_SET; then
  info "Shell TMOUT not set (idle sessions never timeout)"
fi

# AIDE database existence
sub_header "AIDE Database"
if require_cmd aide; then
  _AIDE_DB=""
  for _db_path in /var/lib/aide/aide.db.gz /var/lib/aide/aide.db /var/lib/aide/aide.db.new.gz; do
    if [[ -f "$_db_path" ]]; then
      _AIDE_DB="$_db_path"
      break
    fi
  done
  if [[ -n "$_AIDE_DB" ]]; then
    _AIDE_DB_SIZE=$(stat -c%s "$_AIDE_DB" 2>/dev/null || echo "0")
    if [[ "${_AIDE_DB_SIZE:-0}" -gt 0 ]]; then
      pass "AIDE database: $_AIDE_DB ($(_human_size "$_AIDE_DB_SIZE"))"
    else
      warn "AIDE database exists but is empty: $_AIDE_DB"
    fi
  else
    warn "AIDE installed but no database found (run: sudo aide --init)"
  fi
fi

# Suspicious shell history entries
sub_header "Shell History Analysis"
_SUSPICIOUS_HIST=0
while IFS=: read -r _huser _ _huid _ _ _hhome _; do
  [[ "$_huid" -ge 1000 && "$_huid" -lt 65534 ]] || continue
  for _histf in "$_hhome/.bash_history" "$_hhome/.zsh_history"; do
    [[ -f "$_histf" ]] || continue
    _SH_PATTERN="curl.*\|.*bash|wget.*\|.*sh|curl.*-o.*/tmp|wget.*/tmp|chmod\s+\+x.*/tmp|/dev/tcp|nc\s+-e|ncat\s+-e"
    _SH_SUSP=$(grep -ciE "$_SH_PATTERN" "$_histf" 2>/dev/null || true)
    _SH_SUSP=${_SH_SUSP:-0}
    if [[ "$_SH_SUSP" -gt 0 ]]; then
      warn "$_SH_SUSP suspicious entries in $_histf (curl|bash, wget, /dev/tcp patterns)"
      # F-200: show first 3 examples (truncated) so user can audit instead of guess
      if ! $JSON_MODE; then
        grep -nE "$_SH_PATTERN" "$_histf" 2>/dev/null | head -3 | while read -r line; do
          printf "       %s\n" "${line:0:90}"
        done
      fi
      ((_SUSPICIOUS_HIST += _SH_SUSP))
    fi
  done
done < /etc/passwd
if [[ "$_SUSPICIOUS_HIST" -eq 0 ]]; then
  pass "No suspicious shell history entries found"
fi

fi # end hardening

###############################################################################
if ! should_skip "modules"; then
header "31" "KERNEL MODULES & INTEGRITY"
###############################################################################

# Suspicious kernel modules (basic heuristic — real rootkits use innocuous names)
sub_header "Suspicious Module Check"
# F-201: Same anti-pattern as F-136 — real rootkits don't advertise themselves
# with obvious names. AIDE/IMA file-integrity checks are the reliable signal.
SUSPICIOUS_MODS=$(lsmod 2>/dev/null | awk '{print $1}' | grep -iE "backdoor|rootkit|hide|keylog|sniff|inject" || true)
if [[ -z "$SUSPICIOUS_MODS" ]]; then
  pass "No obvious-named suspicious modules (real rootkits hide — rely on IMA/AIDE for integrity)"
else
  fail "Suspicious kernel modules: $SUSPICIOUS_MODS"
fi

# Unnecessary filesystem modules (new)
sub_header "Disabled Filesystem Modules"
for FS_MOD in cramfs freevxfs jffs2 hfs hfsplus squashfs udf affs befs sysv qnx4 qnx6; do
  if grep -rqsE "install\s+$FS_MOD\s+/(usr/)?s?bin/(false|true)|blacklist\s+$FS_MOD" /etc/modprobe.d/ 2>/dev/null; then
    pass "Module $FS_MOD: disabled"
  elif [[ "$FS_MOD" == "squashfs" ]] && command -v flatpak &>/dev/null; then
    if lsmod 2>/dev/null | grep -q "^squashfs\s"; then
      info "Module squashfs: loaded (required by Flatpak)"
    else
      info "Module squashfs: not disabled but not loaded (Flatpak installed)"
    fi
  else
    if lsmod 2>/dev/null | grep -q "^${FS_MOD}\s"; then
      warn "Module $FS_MOD: loaded (should be disabled)"
    else
      info "Module $FS_MOD: not explicitly disabled (not loaded)"
    fi
  fi
done

# USB storage module
if grep -rqsE "install\s+usb[-_]storage\s+/(usr/)?s?bin/(false|true)|blacklist\s+usb[-_]storage" /etc/modprobe.d/ 2>/dev/null; then
  pass "USB storage module: disabled"
else
  warn "USB storage module: not disabled"
fi

# Module loading status
if [[ -f /proc/sys/kernel/modules_disabled ]]; then
  MOD_DISABLED=$(< /proc/sys/kernel/modules_disabled)
  if [[ "$MOD_DISABLED" -eq 1 ]]; then
    pass "Kernel module loading: disabled (locked down)"
  else
    info "Kernel module loading: enabled (modules_disabled=0)"
  fi
fi

fi # end modules

###############################################################################
if ! should_skip "permissions"; then
header "32" "PERMISSIONS & ACCESS CONTROL"
###############################################################################

# Cron permissions
for CRONDIR in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  if [[ -e "$CRONDIR" ]]; then
    OWNER=$(stat -c '%U' "$CRONDIR" 2>/dev/null)
    PERMS=$(stat -c '%a' "$CRONDIR" 2>/dev/null)
    if [[ "$OWNER" != "root" ]]; then
      fail "$CRONDIR owner: $OWNER (should be root)"
    elif [[ -d "$CRONDIR" ]]; then
      if (( (8#${PERMS:-777} & ~8#755) == 0 )); then
        pass "$CRONDIR: owner=$OWNER, perms=$PERMS"
      else
        warn "$CRONDIR permissions: $PERMS (too open for directory)"
      fi
    elif [[ -f "$CRONDIR" ]]; then
      # Allow read for group/other (644), warn on write/execute for group/other
      if (( (8#${PERMS:-777} & 8#033) != 0 )); then
        warn "$CRONDIR permissions: $PERMS (write/execute for group/other)"
      elif (( (8#${PERMS:-777} & ~8#644) != 0 )); then
        warn "$CRONDIR permissions: $PERMS (expected: <=644)"
      else
        pass "$CRONDIR: owner=$OWNER, perms=$PERMS"
      fi
    fi
  fi
done

# /etc/securetty
if [[ -f /etc/securetty ]]; then
  TTY_COUNT=$(grep -v "^#" /etc/securetty 2>/dev/null | grep -v "^$" | wc -l)
  info "securetty: $TTY_COUNT TTYs allowed"
fi

# /etc/security/limits.conf — core dump limits
if grep -qE "^\s*\*\s+hard\s+core\s+0" /etc/security/limits.conf 2>/dev/null; then
  pass "limits.conf: hard core 0 (core dumps disabled)"
else
  warn "limits.conf: core dumps not disabled via limits"
fi

fi # end permissions

###############################################################################
if ! should_skip "boot"; then
header "33" "BOOT SECURITY & INTEGRITY"
###############################################################################

# UEFI vs BIOS
if [[ -d /sys/firmware/efi ]]; then
  pass "Boot mode: UEFI"
else
  info "Boot mode: Legacy BIOS"
fi

# Kernel module signing — checks compile-time AND runtime enforcement (F-208).
# Modern distros often build with CONFIG_MODULE_SIG=y but enforce at runtime
# via Secure Boot or kernel cmdline (module.sig_enforce=1). Pure compile-time
# detection misses these.
if [[ -f /proc/sys/kernel/tainted ]]; then
  _SIG_ENFORCED=false
  _SIG_REASON=""
  if grep -q "CONFIG_MODULE_SIG_FORCE=y" /boot/config-"$(uname -r)" 2>/dev/null; then
    _SIG_ENFORCED=true
    _SIG_REASON="compile-time"
  elif [[ -f /sys/module/module/parameters/sig_enforce ]] && \
       [[ "$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null)" == "Y" ]]; then
    _SIG_ENFORCED=true
    _SIG_REASON="runtime (likely Secure Boot)"
  elif grep -qw "module.sig_enforce=1" /proc/cmdline 2>/dev/null; then
    _SIG_ENFORCED=true
    _SIG_REASON="runtime (kernel cmdline)"
  fi
  if $_SIG_ENFORCED; then
    pass "Kernel module signing: enforced ($_SIG_REASON)"
  else
    info "Kernel module signing: not enforced"
  fi
fi

# Check for multiple kernels
KERNEL_COUNT=$(ls /boot/vmlinuz-* 2>/dev/null | wc -l)
info "Installed kernels: $KERNEL_COUNT"

# systemd-analyze blame top 5 (new)
if require_cmd systemd-analyze; then
  sub_header "Boot Security Analysis"
  # Check for rescue/emergency shell (only report if NOT using sulogin for password protection)
  for _rescue_unit in rescue.service emergency.service; do
    _rescue_exec=$(systemctl show -p ExecStart "$_rescue_unit" 2>/dev/null | grep -oP 'path=\K[^;]+' || true)
    if [[ -n "$_rescue_exec" && "$_rescue_exec" != *sulogin* ]]; then
      info "${_rescue_unit%.service} shell: no password required (physical access risk)"
    fi
  done
fi

fi # end boot

###############################################################################
if ! should_skip "integrity"; then
header "34" "SYSTEM INTEGRITY CHECKS"
###############################################################################

# File Integrity — key system binaries
sub_header "Critical Binary Integrity"
if require_cmd rpm; then
  $JSON_MODE || printf "  ${CYN}Running rpm -Va (full package verify, max 90s)...${RST}\n"
  # Timeout prevents 5+ minute hangs on large package sets (F-211)
  RPM_VA_OUTPUT=$(timeout 90 rpm -Va 2>/dev/null || echo "TIMEOUT")
  if [[ "$RPM_VA_OUTPUT" == "TIMEOUT" ]]; then
    warn "RPM verify: timed out after 90s (large package set or DB locked)"
  else
    RPM_VERIFY_ALL=$(echo "$RPM_VA_OUTPUT" | grep -cE "^..5" || true)
    RPM_VERIFY_ALL=${RPM_VERIFY_ALL:-0}
    RPM_VERIFY_BIN=$(echo "$RPM_VA_OUTPUT" | grep -E "^..5" | grep -v " c " \
      | grep -cv "\.pyc\b\|/__pycache__/\|/usr/lib/issue" || true)
    RPM_VERIFY_BIN=${RPM_VERIFY_BIN:-0}
    if [[ "$RPM_VERIFY_ALL" -eq 0 ]]; then
      pass "RPM verify: all package files intact"
    elif [[ "$RPM_VERIFY_BIN" -eq 0 ]]; then
      pass "RPM verify: $RPM_VERIFY_ALL config files changed (no binaries — normal after hardening)"
    elif [[ "$RPM_VERIFY_BIN" -le 5 ]]; then
      warn "RPM verify: $RPM_VERIFY_BIN binaries + $((RPM_VERIFY_ALL - RPM_VERIFY_BIN)) configs changed"
    else
      fail "RPM verify: $RPM_VERIFY_BIN binaries with changed checksums!"
    fi
  fi
elif require_cmd debsums; then
  DEB_VERIFY=$(debsums -s 2>/dev/null | wc -l)
  if [[ "$DEB_VERIFY" -eq 0 ]]; then
    pass "debsums: all package files intact"
  else
    warn "debsums: $DEB_VERIFY files modified"
  fi
elif [[ "$DISTRO_FAMILY" == "debian" ]]; then
  info "Package integrity: install 'debsums' for Debian file verification (apt install debsums)"
elif require_cmd pacman; then
  # Arch: verify installed package files
  PAC_VERIFY=$(pacman -Qkk 2>/dev/null | grep -c "MODIFIED" || true)
  PAC_VERIFY=${PAC_VERIFY:-0}
  if [[ "$PAC_VERIFY" -eq 0 ]]; then
    pass "Pacman verify: all package files intact"
  elif [[ "$PAC_VERIFY" -le 10 ]]; then
    warn "Pacman verify: $PAC_VERIFY modified files"
  else
    fail "Pacman verify: $PAC_VERIFY modified files!"
  fi
fi

# Check PATH for world-writable dirs AND `.`/empty/relative entries (F-214).
# `.` in PATH is a classic privilege-escalation vector — running `ls` in an
# attacker-controlled directory could execute their malicious binary.
sub_header "PATH Security"
PATH_ISSUES=0
IFS=: read -ra PATH_DIRS <<< "$PATH"
for DIR in "${PATH_DIRS[@]}"; do
  if [[ -z "$DIR" ]]; then
    fail "PATH contains empty entry (equivalent to '.' — privilege escalation risk)"
    ((PATH_ISSUES++))
    continue
  fi
  if [[ "$DIR" == "." ]]; then
    fail "PATH contains '.' (current directory — privilege escalation risk)"
    ((PATH_ISSUES++))
    continue
  fi
  if [[ "$DIR" != /* ]]; then
    fail "PATH contains relative entry: $DIR (privilege escalation risk)"
    ((PATH_ISSUES++))
    continue
  fi
  # Skip symlinks (e.g. /sbin -> /usr/sbin on Fedora)
  [[ -L "$DIR" ]] && continue
  if [[ -d "$DIR" ]] && [[ "$(stat -c %a "$DIR" 2>/dev/null)" =~ [2367]$ ]]; then
    warn "World-writable directory in PATH: $DIR"
    ((PATH_ISSUES++))
  fi
done
if [[ "$PATH_ISSUES" -eq 0 ]]; then
  pass "PATH security: no world-writable, '.', or relative entries"
fi

# Duplicate lines in /etc/hosts
sub_header "/etc/hosts Integrity"
if [[ -f /etc/hosts ]]; then
  _HOSTS_DUPS=$(grep -v "^#" /etc/hosts 2>/dev/null | grep -v "^$" | sort | uniq -d | wc -l)
  _HOSTS_DUPS=${_HOSTS_DUPS:-0}
  if [[ "$_HOSTS_DUPS" -eq 0 ]]; then
    pass "/etc/hosts: no duplicate entries"
  else
    warn "/etc/hosts: $_HOSTS_DUPS duplicate entries"
  fi
  # Verify localhost entry
  if grep -qE "^127\.0\.0\.1\s+localhost" /etc/hosts 2>/dev/null; then
    pass "/etc/hosts: localhost entry present"
  else
    warn "/etc/hosts: missing 127.0.0.1 localhost entry"
  fi
fi

# AIDE checksum algorithm
if require_cmd aide; then
  _AIDE_CONF=""
  for _ac in /etc/aide.conf /etc/aide/aide.conf; do
    [[ -f "$_ac" ]] && _AIDE_CONF="$_ac" && break
  done
  if [[ -n "$_AIDE_CONF" ]]; then
    if grep -qE "sha512|sha256" "$_AIDE_CONF" 2>/dev/null; then
      _AIDE_HASH=$(grep -oE "sha512|sha256" "$_AIDE_CONF" 2>/dev/null | head -1)
      pass "AIDE checksum: $_AIDE_HASH (strong)"
    elif grep -qE "md5" "$_AIDE_CONF" 2>/dev/null; then
      fail "AIDE checksum: MD5 (weak — switch to sha512)"
    else
      info "AIDE checksum algorithm: could not determine from $_AIDE_CONF"
    fi
  fi
fi

# Available valid shells
sub_header "Valid Shells"
if [[ -f /etc/shells ]]; then
  _SHELL_COUNT=$(grep -cv "^#\|^$" /etc/shells 2>/dev/null || true)
  info "Valid shells in /etc/shells: ${_SHELL_COUNT:-0}"
  # Check for insecure shells
  for _ishell in /bin/csh /bin/tcsh; do
    if grep -q "^${_ishell}$" /etc/shells 2>/dev/null; then
      info "Legacy shell available: $_ishell"
    fi
  done
fi

fi # end integrity

###############################################################################
# Section 35: Browser Privacy
###############################################################################
check_browser_privacy() {
  should_skip "browser" && return
  header "35" "BROWSER PRIVACY"

  local found_any=false

  _bp_check_user() {
    local user="$1" uid="$2" home="$3"
    # Firefox-family profile locations (use prefs.js syntax).
    # Privacy users (this tool's audience) often run LibreWolf/Tor Browser
    # rather than vanilla Firefox — covered explicitly here.
    local ff_dirs=(
      # Firefox standard + XDG + Flatpak
      "$home/.mozilla/firefox"
      "$home/.config/mozilla/firefox"
      "$home/.var/app/org.mozilla.firefox/.mozilla/firefox"
      # LibreWolf (Firefox fork with hardened defaults)
      "$home/.librewolf"
      "$home/.var/app/io.gitlab.librewolf-community/.librewolf"
      # Tor Browser (Firefox-based)
      "$home/.local/share/torbrowser/tbb/x86_64/tor-browser/Browser/TorBrowser/Data/Browser"
      "$home/.var/app/com.github.micahflee.torbrowser-launcher/data/.tor-browser/app/Browser/TorBrowser/Data/Browser"
      # Waterfox
      "$home/.waterfox"
    )

    local prefs_files=()
    local ff_dir
    for ff_dir in "${ff_dirs[@]}"; do
      [[ -d "$ff_dir" ]] || continue
      while IFS= read -r -d '' f; do
        prefs_files+=("$f")
      done < <(find "$ff_dir" -maxdepth 2 -name "prefs.js" -print0 2>/dev/null)
    done

    [[ ${#prefs_files[@]} -eq 0 ]] && return
    found_any=true

    local pf
    for pf in "${prefs_files[@]}"; do
      local profile_dir
      profile_dir="$(dirname "$pf")"
      local profile_name
      profile_name="$(basename "$profile_dir")"

      local label="${user}/${profile_name}"

      local val
      val="$(_ff_pref "$pf" "toolkit.telemetry.enabled")"
      if [[ "$val" == "true" ]]; then
        fail "Firefox telemetry explicitly enabled [$label]"
      elif [[ "$val" == "false" ]]; then
        pass "Firefox telemetry disabled [$label]"
      else
        info "Firefox telemetry not explicitly set (default: disabled on most distros) [$label]"
      fi

      val="$(_ff_pref "$pf" "datareporting.healthreport.uploadEnabled")"
      if [[ "$val" == "false" ]]; then
        pass "Firefox health report disabled [$label]"
      elif [[ "$val" == "true" ]]; then
        fail "Firefox health report upload enabled [$label]"
      else
        warn "Firefox health report not explicitly disabled [$label]"
      fi

      val="$(_ff_pref "$pf" "media.peerconnection.enabled")"
      if [[ "$val" == "false" ]]; then
        pass "WebRTC disabled — no IP leak [$label]"
      else
        warn "WebRTC enabled — may leak real IP behind VPN [$label]"
      fi

      val="$(_ff_pref "$pf" "network.trr.mode")"
      if [[ "$val" == "2" ]]; then
        pass "DNS-over-HTTPS enabled (mode 2 — DoH first, fallback to native DNS) [$label]"
      elif [[ "$val" == "3" ]]; then
        pass "DNS-over-HTTPS strict (mode 3 — DoH only, no fallback) [$label]"
      elif [[ -z "$val" || "$val" == "0" ]]; then
        warn "DNS-over-HTTPS not configured [$label]"
      else
        info "DNS-over-HTTPS mode $val [$label]"
      fi

      val="$(_ff_pref "$pf" "browser.contentblocking.category")"
      if [[ "$val" == "strict" ]]; then
        pass "Tracking protection set to strict [$label]"
      elif [[ "$val" == "custom" ]]; then
        info "Tracking protection custom [$label]"
      else
        warn "Tracking protection not strict (${val:-standard}) [$label]"
      fi

      val="$(_ff_pref "$pf" "network.cookie.cookieBehavior")"
      if [[ "$val" == "5" ]]; then
        pass "Third-party cookies blocked (Total Cookie Protection) [$label]"
      elif [[ "$val" == "4" ]]; then
        pass "Third-party cookies blocked [$label]"
      elif [[ "$val" == "1" ]]; then
        info "Third-party cookies blocked (legacy) [$label]"
      elif [[ -z "$val" ]]; then
        info "Cookie behavior not set (default: Total Cookie Protection with ETP) [$label]"
      else
        warn "Third-party cookies allowed (behavior=${val}) [$label]"
      fi

      local ext_json="$profile_dir/extensions.json"
      if [[ -f "$ext_json" ]]; then
        if grep -q "uBlock0@raymondhill.net" "$ext_json" 2>/dev/null; then
          pass "uBlock Origin installed [$label]"
        else
          warn "uBlock Origin not found [$label]"
        fi
      else
        info "No extensions data found [$label]"
      fi

      val="$(_ff_pref "$pf" "app.shield.optoutstudies.enabled")"
      if [[ "$val" == "false" ]]; then
        pass "Shield Studies disabled [$label]"
      elif [[ "$val" == "true" ]]; then
        warn "Shield Studies enabled [$label]"
      else
        info "Shield Studies not explicitly configured [$label]"
      fi

      val="$(_ff_pref "$pf" "signon.rememberSignons")"
      if [[ "$val" == "false" ]]; then
        pass "Browser password saving disabled [$label]"
      elif [[ -z "$val" ]]; then
        warn "Browser password saving not disabled (default: on) [$label]"
      else
        warn "Browser password saving enabled — use a password manager [$label]"
      fi
    done
  }

  _for_each_user _bp_check_user

  # F-220: Chromium-family browser detection covers tracking-heavy and
  # privacy-focused alternatives. Severity differs:
  # - Chrome/Edge/Vivaldi/Opera: warn (telemetry to vendor)
  # - Brave: info (privacy-focused defaults but Chromium-based)
  # - Chromium: info (no Google services by default on most builds)
  local chrome_bin
  local -A chrome_seen=()
  for chrome_bin in google-chrome google-chrome-stable microsoft-edge \
                    microsoft-edge-stable opera vivaldi vivaldi-stable; do
    if command -v "$chrome_bin" &>/dev/null; then
      local chrome_real
      chrome_real="$(realpath "$(command -v "$chrome_bin")" 2>/dev/null || echo "$chrome_bin")"
      [[ -n "${chrome_seen[$chrome_real]:-}" ]] && continue
      chrome_seen["$chrome_real"]=1
      warn "$chrome_bin installed — vendor telemetry/tracking risk"
    fi
  done
  for chrome_bin in chromium chromium-browser; do
    if command -v "$chrome_bin" &>/dev/null; then
      local chrome_real
      chrome_real="$(realpath "$(command -v "$chrome_bin")" 2>/dev/null || echo "$chrome_bin")"
      [[ -n "${chrome_seen[$chrome_real]:-}" ]] && continue
      chrome_seen["$chrome_real"]=1
      info "$chrome_bin installed (Chromium upstream — no Google services by default)"
    fi
  done
  for chrome_bin in brave-browser brave; do
    if command -v "$chrome_bin" &>/dev/null; then
      local chrome_real
      chrome_real="$(realpath "$(command -v "$chrome_bin")" 2>/dev/null || echo "$chrome_bin")"
      [[ -n "${chrome_seen[$chrome_real]:-}" ]] && continue
      chrome_seen["$chrome_real"]=1
      info "$chrome_bin installed (privacy-focused Chromium fork)"
    fi
  done
  # Flatpak Brave/Edge/Opera presence
  if command -v flatpak &>/dev/null; then
    if flatpak list --app --columns=application 2>/dev/null | grep -qE '^com\.brave\.Browser$'; then
      info "Brave Browser installed (flatpak)"
    fi
    if flatpak list --app --columns=application 2>/dev/null | grep -qE '^com\.microsoft\.Edge$'; then
      warn "Microsoft Edge installed (flatpak) — vendor telemetry"
    fi
  fi

  if [[ "$found_any" == false ]]; then
    info "No Firefox-family browser profiles found"
  fi
}

###############################################################################
# Section 36: Application Telemetry & Privacy
###############################################################################
check_app_telemetry() {
  should_skip "telemetry" && return
  header "36" "APPLICATION TELEMETRY & PRIVACY"

  _at_check_user() {
    local user="$1" uid="$2" home="$3"
    [[ -S "/run/user/${uid}/bus" ]] || return

    local val

    val="$(_gsettings_user "$user" "$uid" "org.gnome.system.location" "enabled" 2>/dev/null)"
    if [[ "$val" == "true" ]]; then
      warn "GNOME Location Services enabled [$user]"
    elif [[ "$val" == "false" ]]; then
      pass "GNOME Location Services disabled [$user]"
    fi

    val="$(_gsettings_user "$user" "$uid" "org.gnome.desktop.privacy" "report-technical-problems" 2>/dev/null)"
    if [[ "$val" == "true" ]]; then
      warn "GNOME problem reporting enabled [$user]"
    elif [[ "$val" == "false" ]]; then
      pass "GNOME problem reporting disabled [$user]"
    fi

    val="$(_gsettings_user "$user" "$uid" "org.gnome.desktop.privacy" "remember-recent-files" 2>/dev/null)"
    if [[ "$val" == "true" ]]; then
      local age
      age="$(_gsettings_user "$user" "$uid" "org.gnome.desktop.privacy" "recent-files-max-age" 2>/dev/null)"
      age="${age##*uint32 }"    # Strip GVariant type prefix (e.g. "uint32 30" → "30")
      age="${age//[^0-9]/}"
      if [[ "$age" == "0" ]]; then
        pass "Recent files: max-age=0 (list always empty) [$user]"
      elif [[ -n "$age" && "$age" -le 7 && "$age" -gt 0 ]]; then
        pass "Recent files kept for ${age} days [$user]"
      elif [[ -n "$age" && "$age" -le 30 ]]; then
        info "Recent files kept for ${age} days [$user]"
      else
        warn "Recent files enabled (max age: ${age:-unlimited} days) [$user]"
      fi
    elif [[ "$val" == "false" ]]; then
      pass "Recent files tracking disabled [$user]"
    fi

    val="$(_gsettings_user "$user" "$uid" "org.gnome.desktop.privacy" "send-software-usage-stats" 2>/dev/null)"
    if [[ "$val" == "true" ]]; then
      warn "GNOME software usage stats enabled [$user]"
    elif [[ "$val" == "false" ]]; then
      pass "GNOME software usage stats disabled [$user]"
    fi
  }

  _for_each_user _at_check_user

  # File indexer detection — DE-aware (GNOME Tracker, KDE Baloo, Recoll, ...)
  local _idx_name _idx_rc
  _idx_name=$(_de_check_file_indexer)
  _idx_rc=$?
  if [[ "$_idx_rc" -eq 0 ]]; then
    warn "$_idx_name file indexer active — indexes file contents (privacy: stores in user DB)"
  else
    pass "$_idx_name file indexer not running"
  fi

  if command -v flatpak &>/dev/null; then
    local dangerous=0
    local app
    while IFS= read -r app; do
      [[ -z "$app" ]] && continue
      local perms
      perms="$(flatpak info --show-permissions "$app" 2>/dev/null)"
      if echo "$perms" | grep -qE "filesystems=(host([;,[:space:]]|$)|.*[;,]host([;,[:space:]]|$))|filesystems=(host-os([;,[:space:]]|$)|.*[;,]host-os([;,[:space:]]|$))|filesystems=(home([;,[:space:]]|$)|.*[;,]home([;,[:space:]]|$))|org\.freedesktop\.Flatpak=talk"; then
        warn "Flatpak '$app' has dangerous permissions (host/home filesystem or Flatpak portal)"
        ((dangerous++))
      fi
    done < <(flatpak list --app --columns=application 2>/dev/null)
    if [[ "$dangerous" -eq 0 ]]; then
      pass "No Flatpak apps with dangerous permissions"
    fi
  else
    info "Flatpak not installed"
  fi

  if command -v snap &>/dev/null; then
    if snap get system experimental.telemetry 2>/dev/null | grep -qi "true"; then
      warn "Snap telemetry enabled"
    else
      pass "Snap telemetry not enabled"
    fi
  fi

  local abrt_active
  abrt_active="$(systemctl list-units --state=active --no-legend 'abrt-*' 2>/dev/null | wc -l | ccount)"
  if [[ "$abrt_active" -gt 0 ]]; then
    warn "ABRT crash reporter active ($abrt_active services) — sends crash data"
  else
    pass "ABRT crash reporter not active"
  fi

  if [[ "$DISTRO_FAMILY" == "rhel" ]]; then
    local dnf_conf="/etc/dnf/dnf.conf"
    if [[ -f "$dnf_conf" ]] && grep -qi "^countme[[:space:]]*=[[:space:]]*true" "$dnf_conf" 2>/dev/null; then
      warn "Fedora countme enabled in dnf.conf"
    elif [[ -f "$dnf_conf" ]] && grep -qi "^countme[[:space:]]*=[[:space:]]*false" "$dnf_conf" 2>/dev/null; then
      pass "Fedora countme disabled in dnf.conf"
    else
      info "Fedora countme not explicitly set in dnf.conf (default: disabled since Fedora 36)"
    fi
  fi

  if [[ "$DISTRO_FAMILY" == "debian" ]]; then
    if dpkg -l popularity-contest 2>/dev/null | grep -q "^ii"; then
      local popcon_conf="/etc/popularity-contest.conf"
      if [[ -f "$popcon_conf" ]] && grep -q 'PARTICIPATE="yes"' "$popcon_conf" 2>/dev/null; then
        warn "Ubuntu popularity-contest active — reports installed packages"
      else
        info "popularity-contest installed but not participating"
      fi
    else
      pass "popularity-contest not installed"
    fi
  fi

  # Check all NM config files for connectivity settings (main + conf.d drop-ins)
  local _nm_connectivity_found=false
  local _nm_connectivity_disabled=false
  local _nm_files=()
  [[ -f "/etc/NetworkManager/NetworkManager.conf" ]] && _nm_files+=("/etc/NetworkManager/NetworkManager.conf")
  for _nmf in /etc/NetworkManager/conf.d/*.conf; do
    [[ -f "$_nmf" ]] && _nm_files+=("$_nmf")
  done

  for _nmf in "${_nm_files[@]}"; do
    if grep -qi "^\[connectivity\]" "$_nmf" 2>/dev/null; then
      _nm_connectivity_found=true
      # Check if enabled=false is set
      local _nm_enabled
      _nm_enabled="$(sed -n '/^\[connectivity\]/,/^\[/{ s/^enabled[[:space:]]*=[[:space:]]*//p; }' "$_nmf" 2>/dev/null | tail -1)"
      if [[ "$_nm_enabled" == "false" ]]; then
        _nm_connectivity_disabled=true
        pass "NetworkManager connectivity check disabled (in $(basename "$_nmf"))"
        break
      fi
      # Check uri setting
      local _nm_uri
      _nm_uri="$(sed -n '/^\[connectivity\]/,/^\[/{ s/^uri[[:space:]]*=[[:space:]]*//p; }' "$_nmf" 2>/dev/null | tail -1)"
      if [[ -n "$_nm_uri" ]]; then
        info "NetworkManager connectivity check active (pings $_nm_uri, in $(basename "$_nmf"))"
        break
      fi
    fi
  done

  if $_nm_connectivity_disabled; then
    : # already reported pass above
  elif $_nm_connectivity_found; then
    info "NetworkManager [connectivity] section found but no explicit disable — connectivity check likely active"
  else
    info "NetworkManager connectivity check uses default (may phone home)"
  fi
}

###############################################################################
# Section 37: Network Privacy
###############################################################################
check_network_privacy() {
  should_skip "netprivacy" && return
  header "37" "NETWORK PRIVACY"

  local nm_wifi_rand=""
  local conf_file
  for conf_file in /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/conf.d/*.conf; do
    [[ -f "$conf_file" ]] || continue
    local val
    val="$(sed -n '/^\[device\]/,/^\[/{ s/^wifi\.scan-rand-mac-address[[:space:]]*=[[:space:]]*//p; }' "$conf_file" 2>/dev/null)"
    [[ -n "$val" ]] && nm_wifi_rand="$val"
  done
  if [[ "$nm_wifi_rand" == "yes" || "$nm_wifi_rand" == "true" ]]; then
    pass "WiFi scan MAC randomization enabled"
  elif [[ "$nm_wifi_rand" == "no" || "$nm_wifi_rand" == "false" ]]; then
    fail "WiFi scan MAC randomization disabled"
  else
    info "WiFi scan MAC randomization not configured (default: yes since NM 1.4)"
  fi

  local eth_clone=""
  for conf_file in /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/conf.d/*.conf; do
    [[ -f "$conf_file" ]] || continue
    local val
    val="$(sed -n '/^\[connection\]/,/^\[/{ s/^ethernet\.cloned-mac-address[[:space:]]*=[[:space:]]*//p; }' "$conf_file" 2>/dev/null)"
    [[ -n "$val" ]] && eth_clone="$val"
  done
  if [[ "$eth_clone" == "random" ]]; then
    pass "Ethernet MAC randomization: random (new MAC on each connection)"
  elif [[ "$eth_clone" == "stable" ]]; then
    # 'stable' derives a consistent MAC from connection-UUID — not truly random.
    # With a static IP it provides no privacy benefit (IP is the stable identifier).
    info "Ethernet MAC: stable (consistent per connection — not truly random; with static IP, IP is the identifier)"
  elif [[ -n "$eth_clone" ]]; then
    info "Ethernet cloned-mac-address=$eth_clone"
  else
    info "Ethernet MAC randomization not configured (uses permanent hardware MAC)"
  fi

  if systemctl is-active --quiet avahi-daemon.service 2>/dev/null; then
    warn "Avahi (mDNS) active — broadcasts hostname on local network"
  else
    pass "Avahi (mDNS) not running"
  fi

  local avahi_conf="/etc/avahi/avahi-daemon.conf"
  if [[ -f "$avahi_conf" ]]; then
    # Only meaningful if avahi can actually run (not masked or statically disabled)
    # NOTE: systemctl is-enabled exits non-zero for masked/disabled, so we use || true
    # NOT || echo "disabled" which would append "disabled" to the captured output.
    local avahi_enabled
    avahi_enabled=$(systemctl is-enabled avahi-daemon.service 2>/dev/null) || true
    [[ -z "$avahi_enabled" ]] && avahi_enabled="unknown"
    if [[ "$avahi_enabled" == "masked" || "$avahi_enabled" == "disabled" || "$avahi_enabled" == "static" ]]; then
      info "Avahi is $avahi_enabled — config check skipped"
    else
      local pub_host
      pub_host="$(sed -n '/^\[publish\]/,/^\[/{ s/^publish-hostname[[:space:]]*=[[:space:]]*//p; }' "$avahi_conf" 2>/dev/null)"
      if [[ "$pub_host" == "no" ]]; then
        pass "Avahi hostname publishing disabled"
      else
        warn "Avahi publishes hostname (publish-hostname=${pub_host:-yes})"
      fi
    fi
  fi

  local resolved_conf="/etc/systemd/resolved.conf"
  local llmnr_val=""
  if [[ -f "$resolved_conf" ]]; then
    llmnr_val="$(grep -i "^LLMNR\s*=" "$resolved_conf" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')"
  fi
  # Also check drop-in files (last value wins in systemd)
  for dropin in /etc/systemd/resolved.conf.d/*.conf; do
    [[ -f "$dropin" ]] || continue
    local dval
    dval="$(grep -i "^LLMNR\s*=" "$dropin" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')"
    [[ -n "$dval" ]] && llmnr_val="$dval"
  done
  if [[ "$llmnr_val" == "no" || "$llmnr_val" == "false" ]]; then
    pass "LLMNR disabled in resolved.conf"
  elif [[ -z "$llmnr_val" ]]; then
    if [[ -f "$resolved_conf" ]]; then
      warn "LLMNR not configured (default: enabled — leaks hostname)"
    else
      warn "resolved.conf not found — LLMNR status unknown (likely enabled by default)"
    fi
  else
    info "LLMNR set to '$llmnr_val'"
  fi

  local hostname
  hostname="$(hostname 2>/dev/null)"
  local real_names=false
  # Word-boundary match (require name as standalone word, not substring).
  # Min 5 chars to avoid FPs on short common names (Ann, Fox, Eve, Tim).
  # Original 3-char threshold caused systematic FP on hostnames like
  # "firefox-test" matching user "Fox".
  _name_in_hostname() {
    local name="$1" host="$2"
    [[ ${#name} -ge 5 ]] || return 1
    [[ "${host,,}" =~ (^|[-_.])${name,,}([-_.]|$) ]]
  }
  while IFS=: read -r user _ uid _ gecos _ _; do
    [[ "$uid" -ge 1000 ]] || continue
    local full_name="${gecos%%,*}"
    local first_name="${full_name%% *}"
    local last_name="${full_name##* }"
    [[ -z "$first_name" ]] && first_name="$user"
    if _name_in_hostname "$first_name" "$hostname" || \
       { [[ -n "$last_name" && "$last_name" != "$first_name" ]] && _name_in_hostname "$last_name" "$hostname"; }; then
      real_names=true
      break
    fi
  done < /etc/passwd
  if [[ "$real_names" == true ]]; then
    warn "Hostname '$hostname' may contain real name — reveals identity on networks"
  else
    pass "Hostname '$hostname' does not appear to contain real names"
  fi

  local ipv6_disabled
  ipv6_disabled="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)"
  # Also check NetworkManager: ipv6.method=disabled means NM prevents IPv6 on that interface
  # even if the kernel sysctl is not set. This is the standard Fedora/RHEL way to disable IPv6.
  local _ipv6_nm_disabled=true
  if require_cmd nmcli; then
    local _has_active=false
    while IFS= read -r _cname; do
      [[ -z "$_cname" ]] && continue
      # Skip VPN/killswitch interfaces — their IPv6 is internal, not internet-facing
      local _conn_iface
      _conn_iface=$(nmcli -t -f GENERAL.DEVICES connection show "$_cname" 2>/dev/null | grep -oP '(?<=GENERAL\.DEVICES:).*' | head -1)
      if echo "$_conn_iface" | grep -qE "^(tun|wg|proton|pvpn)"; then
        continue
      fi
      _has_active=true
      local _ipv6method
      _ipv6method=$(nmcli -t -f ipv6.method connection show "$_cname" 2>/dev/null | grep -oP '(?<=ipv6\.method:).*' | head -1)
      # disabled = off; manual only counts as off if no IPv6 addresses configured
      if [[ "$_ipv6method" == "disabled" ]]; then
        continue
      elif [[ "$_ipv6method" == "manual" || "$_ipv6method" == "link-local" ]]; then
        # Check if actual IPv6 addresses (non-link-local) are configured
        local _v6addrs
        _v6addrs=$(nmcli -t -f ipv6.addresses connection show "$_cname" 2>/dev/null | grep -oP '(?<=ipv6\.addresses:).*' | head -1)
        [[ -z "$_v6addrs" ]] && continue
      fi
      _ipv6_nm_disabled=false
      break
    done < <(nmcli -t -f NAME connection show --active 2>/dev/null | grep -v '^lo$')
    $_has_active || _ipv6_nm_disabled=false
  else
    _ipv6_nm_disabled=false
  fi
  if [[ "$ipv6_disabled" == "1" ]] || $_ipv6_nm_disabled; then
    pass "IPv6 disabled — privacy extensions not needed"
  else
    local tempaddr
    tempaddr="$(sysctl -n net.ipv6.conf.default.use_tempaddr 2>/dev/null)"
    if [[ "$tempaddr" == "2" ]]; then
      pass "IPv6 privacy extensions enabled (prefer temporary addresses)"
    elif [[ "$tempaddr" == "1" ]]; then
      info "IPv6 privacy extensions enabled but not preferred"
    else
      warn "IPv6 privacy extensions disabled — stable address reveals identity"
    fi
  fi

  # Check if any active connection actually uses DHCP (static IP = no DHCP at all)
  local _uses_dhcp=false
  if require_cmd nmcli; then
    while IFS= read -r _cname; do
      [[ -z "$_cname" ]] && continue
      local _method
      _method=$(nmcli -t -f ipv4.method connection show "$_cname" 2>/dev/null | grep -oP '(?<=ipv4\.method:).*' | head -1)
      if [[ "$_method" == "auto" ]]; then
        _uses_dhcp=true
        break
      fi
    done < <(nmcli -t -f NAME connection show --active 2>/dev/null)
  else
    _uses_dhcp=true  # can't check — assume DHCP
  fi

  if ! $_uses_dhcp; then
    pass "DHCP hostname: N/A (all connections use static IP — no DHCP sent)"
  else
    local dhcp_hostname=""
    # Check global NM config ([connection] section with dotted key)
    for conf_file in /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/conf.d/*.conf; do
      [[ -f "$conf_file" ]] || continue
      local val
      val="$(sed -n '/^\[connection\]/,/^\[/{ s/^ipv4\.dhcp-send-hostname[[:space:]]*=[[:space:]]*//p; }' "$conf_file" 2>/dev/null)"
      [[ -n "$val" ]] && dhcp_hostname="$val"
    done
    # Check per-connection files ([ipv4] section with plain key)
    # Any single connection with dhcp-send-hostname=true is a leak
    if [[ -z "$dhcp_hostname" ]]; then
      local _dhcp_any_leak=false
      for conn_file in /etc/NetworkManager/system-connections/*.nmconnection; do
        [[ -f "$conn_file" ]] || continue
        local val
        val="$(sed -n '/^\[ipv4\]/,/^\[/{ s/^dhcp-send-hostname[[:space:]]*=[[:space:]]*//p; }' "$conn_file" 2>/dev/null)"
        if [[ -n "$val" ]] && [[ "$val" != "false" && "$val" != "no" && "$val" != "0" ]]; then
          _dhcp_any_leak=true
          dhcp_hostname="$val"
          break
        fi
        [[ -n "$val" ]] && dhcp_hostname="$val"
      done
      $_dhcp_any_leak && dhcp_hostname="true"
    fi
    if [[ "$dhcp_hostname" == "false" || "$dhcp_hostname" == "no" || "$dhcp_hostname" == "0" ]]; then
      pass "DHCP hostname sending disabled"
    else
      warn "DHCP sends hostname to network (dhcp-send-hostname=${dhcp_hostname:-true})"
    fi
  fi

  local mdns_val=""
  if [[ -f "$resolved_conf" ]]; then
    mdns_val="$(grep -i "^MulticastDNS\s*=" "$resolved_conf" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')"
  fi
  for dropin in /etc/systemd/resolved.conf.d/*.conf; do
    [[ -f "$dropin" ]] || continue
    local dval
    dval="$(grep -i "^MulticastDNS\s*=" "$dropin" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')"
    [[ -n "$dval" ]] && mdns_val="$dval"
  done
  if [[ "$mdns_val" == "no" || "$mdns_val" == "false" ]]; then
    pass "Multicast DNS disabled in resolved.conf"
  elif [[ -z "$mdns_val" ]]; then
    if [[ -f "$resolved_conf" ]]; then
      info "Multicast DNS not configured in resolved.conf"
    else
      info "resolved.conf not found — Multicast DNS status unknown"
    fi
  else
    info "Multicast DNS set to '$mdns_val'"
  fi

  # Conservative: flags any active cups-browsed regardless of patch level.
  # Patched builds (cups-filters >= 2.0.1) are not vulnerable to CVE-2024-47176.
  if systemctl is-active --quiet cups-browsed.service 2>/dev/null; then
    warn "cups-browsed active — check if patched for CVE-2024-47176 (cups-filters >= 2.0.1)"
  elif systemctl is-enabled --quiet cups-browsed.service 2>/dev/null; then
    warn "cups-browsed enabled but not running — consider disabling"
  else
    pass "cups-browsed not active"
  fi
}

###############################################################################
# Section 38: Data & Disk Privacy
###############################################################################
check_data_privacy() {
  should_skip "dataprivacy" && return
  header "38" "DATA & DISK PRIVACY"

  _dp_check_user() {
    local user="$1" uid="$2" home="$3"

    local recent_file="$home/.local/share/recently-used.xbel"
    if [[ -f "$recent_file" ]]; then
      local size
      size="$(stat -c%s "$recent_file" 2>/dev/null || true)"
      size=${size:-0}
      if [[ "$size" -gt 1048576 ]]; then
        warn "recently-used.xbel is $(_human_size "$size") [$user] — consider clearing"
      elif [[ "$size" -gt 102400 ]]; then
        info "recently-used.xbel is $(_human_size "$size") [$user]"
      else
        pass "recently-used.xbel small ($(_human_size "$size")) [$user]"
      fi
    fi

    local thumb_dir="$home/.cache/thumbnails"
    if [[ -d "$thumb_dir" ]]; then
      local size
      size="$(du -sb "$thumb_dir" 2>/dev/null | cut -f1)"
      size="${size:-0}"
      if [[ "$size" -gt 104857600 ]]; then
        warn "Thumbnail cache $(_human_size "$size") [$user] — reveals viewed images"
      elif [[ "$size" -gt 10485760 ]]; then
        info "Thumbnail cache $(_human_size "$size") [$user]"
      fi
    fi

    local trash_dir="$home/.local/share/Trash"
    if [[ -d "$trash_dir" ]]; then
      local size
      size="$(du -sb "$trash_dir" 2>/dev/null | cut -f1)"
      size="${size:-0}"
      if [[ "$size" -gt 104857600 ]]; then
        warn "Trash is $(_human_size "$size") [$user] — deleted files still on disk"
      elif [[ "$size" -gt 1048576 ]]; then
        info "Trash is $(_human_size "$size") [$user]"
      fi
    fi

    # F-243: scan history files for sensitive content patterns instead of
    # raw line count (10000 lines is arbitrary; long-time users hit it
    # without it being a privacy issue. Real concern is content.)
    local hist_files=(
      "$home/.bash_history"
      "$home/.zsh_history"
      "$home/.fish_history"
      "$home/.python_history"
      "$home/.psql_history"
      "$home/.mysql_history"
      "$home/.sqlite_history"
      "$home/.node_repl_history"
    )
    local hf
    for hf in "${hist_files[@]}"; do
      [[ -f "$hf" ]] || continue
      local sensitive
      sensitive=$(grep -ciE 'password=[^[:space:]]+|token=[^[:space:]]+|api[_-]?key=[^[:space:]]+|secret=[^[:space:]]+|export.*KEY=' "$hf" 2>/dev/null || true)
      sensitive=${sensitive:-0}
      if [[ "$sensitive" -gt 0 ]]; then
        warn "$sensitive potential secrets in $hf [$user]"
      fi
    done
    local bashrc="$home/.bashrc"
    if [[ -f "$bashrc" ]]; then
      local histsize
      histsize="$(grep -oP '^(export\s+)?HISTSIZE=\K\d+' "$bashrc" 2>/dev/null | tail -1)"
      if [[ -n "$histsize" && "$histsize" -gt 10000 ]]; then
        info "HISTSIZE=$histsize (large — consider scrubbing periodically) [$user]"
      fi
    fi
  }

  _for_each_user _dp_check_user

  # F-244: klipper is KDE Plasma's default clipboard manager; flagging it as
  # WARN on every Plasma install is alarm fatigue. Use INFO with config-check.
  local clip_procs=("gpaste-daemon" "clipman" "clipit" "parcellite" "copyq" "greenclip")
  local clip_found=false
  local proc
  for proc in "${clip_procs[@]}"; do
    if pgrep -x "$proc" &>/dev/null; then
      warn "Clipboard manager '$proc' running — may store passwords in memory"
      clip_found=true
    fi
  done
  # KDE klipper: read klipperrc to determine if history is actually disabled
  if pgrep -x klipper &>/dev/null; then
    if [[ "$_DE_FAMILY" == "kde" ]]; then
      _kde_klipper_history_check() {
        local val
        val=$(echo "$3" | xargs | tr '[:upper:]' '[:lower:]')
        # KeepClipboardContents=false → history disabled (good for privacy)
        case "$val" in
          false|0) pass "Klipper running with history disabled [$1, KDE]" ;;
          true|1)  info "Klipper running with history (KDE default — disable in System Settings → Clipboard) [$1]" ;;
        esac
      }
      _kreadconfig_for_users "klipperrc" "General" "KeepClipboardContents" _kde_klipper_history_check
    else
      warn "Klipper running outside KDE — may store passwords in memory"
    fi
    clip_found=true
  fi
  if [[ "$clip_found" == false ]]; then
    pass "No clipboard manager daemon detected"
  fi

  local core_pattern
  core_pattern="$(sysctl -n kernel.core_pattern 2>/dev/null)"
  local core_soft
  core_soft="$(ulimit -Sc 2>/dev/null)"
  if [[ "$core_pattern" == *"systemd-coredump"* ]]; then
    local core_storage
    # Read effective setting — drop-ins override main config
    core_storage="$(_systemd_conf_val /etc/systemd/coredump.conf Storage)"
    if [[ "${core_storage,,}" == "none" ]]; then
      info "Core dumps: systemd-coredump storage=none (checked in filesystem section)"
    else
      info "Core dumps: systemd-coredump storage=${core_storage:-external} (checked in filesystem section)"
    fi
  elif [[ "$core_pattern" == "|"* ]]; then
    info "Core dumps piped to: ${core_pattern:0:60}"
  elif [[ "$core_soft" == "0" ]]; then
    info "Core dumps: ulimit=0 (checked in filesystem section)"
  else
    info "Core dumps: enabled (checked in filesystem section)"
  fi

  local journal_dir="/var/log/journal"
  if [[ -d "$journal_dir" ]]; then
    local jsize
    jsize="$(du -sb "$journal_dir" 2>/dev/null | cut -f1)"
    jsize="${jsize:-0}"
    if [[ "$jsize" -gt 536870912 ]]; then
      warn "Persistent journal is $(_human_size "$jsize") — may contain sensitive data"
    else
      info "Persistent journal is $(_human_size "$jsize")"
    fi
  else
    pass "No persistent journal (logs in volatile memory only)"
  fi

  local tmp_fs
  tmp_fs="$(df -T /tmp 2>/dev/null | awk 'NR==2{print $2}')"
  if [[ "$tmp_fs" == "tmpfs" ]]; then
    pass "/tmp is tmpfs (cleared on reboot)"
  else
    warn "/tmp is $tmp_fs — temporary files survive reboot"
  fi
}

###############################################################################
# Section 39: Desktop Session Security
###############################################################################
check_desktop_session() {
  should_skip "session" && return
  header "39" "DESKTOP SESSION SECURITY"

  # Section 39 lock-related checks — DE-aware via dispatchers (F-246/247/248/254).
  # KDE LockGrace, Timeout, LockOnResume; XFCE /lock/delay-from-activation,
  # /idle-activation/delay; MATE/Cinnamon use their own gsettings schemas.

  local found_lock_delay=0
  _de_lock_delay_cb() {
    found_lock_delay=1
    local delay
    delay=$(echo "$3" | sed "s/uint32 //;s/'//g" | tr -d ' ')
    [[ "$delay" =~ ^[0-9]+$ ]] || return
    if [[ "$delay" == "0" ]]; then
      pass "Screen lock delay is 0 (instant) for $1 [$_DE_FAMILY]"
    else
      fail "Screen lock delay is ${delay}s for $1 (should be 0) [$_DE_FAMILY]"
    fi
  }
  case "$_DE_FAMILY" in
    gnome)    _gsettings_for_users  "org.gnome.desktop.screensaver" "lock-delay"            _de_lock_delay_cb ;;
    kde)      _kreadconfig_for_users "kscreenlockerrc" "Daemon"      "LockGrace"             _de_lock_delay_cb ;;
    xfce)     _xfconf_for_users     "xfce4-screensaver" "/lock/delay-from-activation"        _de_lock_delay_cb ;;
    mate)     _gsettings_for_users  "org.mate.screensaver" "lock-delay"                      _de_lock_delay_cb ;;
    cinnamon) _gsettings_for_users  "org.cinnamon.desktop.screensaver" "lock-delay"          _de_lock_delay_cb ;;
  esac
  [[ "$found_lock_delay" -eq 0 && "$_DE_FAMILY" != "unknown" ]] && \
    info "No active $_DE_FAMILY sessions found for lock-delay check"

  local found_idle=0
  _de_idle_cb() {
    found_idle=1
    local raw
    raw=$(echo "$3" | sed "s/uint32 //;s/'//g" | tr -d ' ')
    [[ "$raw" =~ ^[0-9]+$ ]] || return
    # KDE Timeout and XFCE /idle-activation/delay are in MINUTES, normalize to seconds
    local delay="$raw"
    case "$_DE_FAMILY" in
      kde|xfce) delay=$((raw * 60)) ;;
    esac
    if [[ "$delay" == "0" ]]; then
      warn "Idle timeout disabled for $1 (screen never blanks) [$_DE_FAMILY]"
    elif [[ "$delay" -le 300 ]]; then
      pass "Idle timeout is ${delay}s for $1 [$_DE_FAMILY]"
    else
      fail "Idle timeout is ${delay}s for $1 (should be ≤ 300) [$_DE_FAMILY]"
    fi
  }
  case "$_DE_FAMILY" in
    gnome)    _gsettings_for_users  "org.gnome.desktop.session"      "idle-delay"     _de_idle_cb ;;
    kde)      _kreadconfig_for_users "kscreenlockerrc" "Daemon"        "Timeout"        _de_idle_cb ;;
    xfce)     _xfconf_for_users     "xfce4-screensaver" "/idle-activation/delay"      _de_idle_cb ;;
    mate)     _gsettings_for_users  "org.mate.session"               "idle-delay"      _de_idle_cb ;;
    cinnamon) _gsettings_for_users  "org.cinnamon.desktop.session"   "idle-delay"      _de_idle_cb ;;
  esac
  [[ "$found_idle" -eq 0 && "$_DE_FAMILY" != "unknown" ]] && \
    info "No active $_DE_FAMILY sessions found for idle-delay check"

  local found_lock_suspend=0
  _de_lock_suspend_cb() {
    found_lock_suspend=1
    local val
    val=$(echo "$3" | xargs | tr '[:upper:]' '[:lower:]')
    case "$val" in
      true|1)  pass "Lock on suspend enabled for $1 [$_DE_FAMILY]" ;;
      false|0) fail "Lock on suspend disabled for $1 [$_DE_FAMILY]" ;;
    esac
  }
  case "$_DE_FAMILY" in
    gnome)
      _gsettings_for_users "org.gnome.desktop.screensaver" "ubuntu-lock-on-suspend" _de_lock_suspend_cb
      # Fallback — Ubuntu's lock-on-suspend key is missing on upstream GNOME
      [[ "$found_lock_suspend" -eq 0 ]] && \
        _gsettings_for_users "org.gnome.desktop.screensaver" "lock-enabled" _de_lock_suspend_cb
      ;;
    kde)
      _kreadconfig_for_users "kscreenlockerrc" "Daemon" "LockOnResume" _de_lock_suspend_cb
      # KDE default is true if key absent — assume enabled when sessions exist but key unset
      ;;
    xfce|mate|cinnamon)
      # No equivalent — fall back to "screen lock enabled" as proxy for lock-on-suspend
      _de_check_screen_lock _de_lock_suspend_cb
      ;;
  esac
  [[ "$found_lock_suspend" -eq 0 && "$_DE_FAMILY" != "unknown" ]] && \
    info "No active $_DE_FAMILY sessions found for lock-on-suspend check"

  local found_notif=0
  _de_notif_cb() {
    found_notif=1
    local val
    val=$(echo "$3" | xargs | tr '[:upper:]' '[:lower:]')
    case "$_DE_FAMILY" in
      gnome|cinnamon)
        # show-in-lock-screen=false → notifications hidden (good)
        case "$val" in
          false|0) pass "Lock screen notifications hidden for $1 [$_DE_FAMILY]" ;;
          true|1)  warn "Lock screen shows notification previews for $1 [$_DE_FAMILY]" ;;
        esac
        ;;
      kde)
        # plasmanotifyrc DoNotDisturb/WhenScreenLocked=true → notifications hidden (good)
        case "$val" in
          true|1)  pass "Lock screen notifications hidden for $1 [KDE DND]" ;;
          false|0) warn "Lock screen shows notifications for $1 [KDE DND]" ;;
        esac
        ;;
    esac
  }
  case "$_DE_FAMILY" in
    gnome)    _gsettings_for_users  "org.gnome.desktop.notifications" "show-in-lock-screen"  _de_notif_cb ;;
    kde)      _kreadconfig_for_users "plasmanotifyrc" "DoNotDisturb"  "WhenScreenLocked"   _de_notif_cb ;;
    cinnamon) _gsettings_for_users  "org.cinnamon.desktop.notifications" "display-notifications-on-lock-screen" _de_notif_cb ;;
  esac
  [[ "$found_notif" -eq 0 && "$_DE_FAMILY" != "unknown" ]] && \
    info "Lock screen notification check not available for $_DE_FAMILY"

  local autologin_found=0
  for conf in /etc/gdm*/custom.conf /etc/gdm*/daemon.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qi '^\s*AutomaticLoginEnable[[:space:]]*=[[:space:]]*true' "$conf" 2>/dev/null; then
      local autouser
      autouser=$(grep -iP '^\s*AutomaticLogin\s*=(?!Enable)' "$conf" | head -1 | cut -d= -f2 | xargs)
      fail "Auto-login enabled in $conf${autouser:+ (user: $autouser)}"
      autologin_found=1
    fi
  done
  [[ "$autologin_found" -eq 0 ]] && pass "No GDM auto-login configured"

  local guest_found=0
  if [[ -d /etc/lightdm ]]; then
    if grep -rqs '^\s*allow-guest[[:space:]]*=[[:space:]]*true' /etc/lightdm/; then
      fail "LightDM guest account enabled"
      guest_found=1
    fi
  fi
  for conf in /etc/gdm*/custom.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qi '^\s*TimedLoginEnable[[:space:]]*=[[:space:]]*true' "$conf" 2>/dev/null; then
      warn "GDM timed login enabled in $conf"
      guest_found=1
    fi
  done
  [[ "$guest_found" -eq 0 ]] && pass "No guest/timed login enabled"

  local remote_found=0
  if systemctl is-active --quiet gnome-remote-desktop.service 2>/dev/null; then
    warn "gnome-remote-desktop service is active"
    remote_found=1
  fi
  if command -v ss &>/dev/null; then
    # Only flag externally-bound VNC/RDP — localhost-only (qemu SPICE console,
    # etc.) is not a remote-access risk
    local vnc_external
    vnc_external=$(ss -tlnp 2>/dev/null | grep -E ':590[0-9]|:3389' | grep -vE '127\.0\.0\.1|::1' | head -3)
    local vnc_local
    vnc_local=$(ss -tlnp 2>/dev/null | grep -E ':590[0-9]|:3389' | grep -E '127\.0\.0\.1|::1' | head -3)
    if [[ -n "$vnc_external" ]]; then
      warn "VNC/RDP port listening EXTERNALLY"
      remote_found=1
    elif [[ -n "$vnc_local" ]]; then
      info "VNC/RDP port listening on localhost only (likely qemu SPICE/VNC console)"
    fi
  fi
  _gs_rdp_cb() {
    local val
    val=$(echo "$3" | xargs)
    if [[ "$val" == "true" ]]; then
      warn "GNOME RDP sharing enabled for $1"
      remote_found=1
    fi
  }
  _gsettings_for_users "org.gnome.desktop.remote-desktop.rdp" "enable" _gs_rdp_cb
  [[ "$remote_found" -eq 0 ]] && pass "No remote desktop services detected"

  local total_autostart=0 user_autostart=0
  local sys_count=0
  sys_count=$(find /etc/xdg/autostart/ -name '*.desktop' 2>/dev/null | wc -l)
  total_autostart=$((total_autostart + sys_count))

  while IFS=: read -r user _ uid _ _ home _; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    local ucount=0
    ucount=$(find "$home/.config/autostart/" -name '*.desktop' 2>/dev/null | wc -l)
    if [[ "$ucount" -gt 0 ]]; then
      user_autostart=$((user_autostart + ucount))
      total_autostart=$((total_autostart + ucount))
      [[ "$ucount" -gt 10 ]] && warn "$user has $ucount autostart programs"
    fi
  done < /etc/passwd

  if [[ "$total_autostart" -gt 20 ]]; then
    warn "$total_autostart total autostart entries (${sys_count} system, ${user_autostart} user)"
  else
    info "$total_autostart autostart entries (${sys_count} system, ${user_autostart} user)"
  fi

  local found_switch=0
  _de_switch_cb() {
    found_switch=1
    local val
    val=$(echo "$3" | xargs | tr '[:upper:]' '[:lower:]')
    case "$_DE_FAMILY" in
      gnome|cinnamon)
        # disable-user-switching=true → restricted (good for kiosk/lab)
        case "$val" in
          true|1)  pass "User switching restricted for $1 [$_DE_FAMILY]" ;;
          false|0) info "User switching allowed for $1 [$_DE_FAMILY]" ;;
        esac
        ;;
      kde)
        # KDE Action Restrictions/action/start_new_session: false=restricted (good)
        case "$val" in
          false|0) pass "User switching restricted for $1 [KDE]" ;;
          true|1)  info "User switching allowed for $1 [KDE]" ;;
        esac
        ;;
    esac
  }
  case "$_DE_FAMILY" in
    gnome)    _gsettings_for_users  "org.gnome.desktop.lockdown" "disable-user-switching"        _de_switch_cb ;;
    kde)      _kreadconfig_for_users "kdeglobals" "KDE Action Restrictions" "action/start_new_session" _de_switch_cb ;;
    cinnamon) _gsettings_for_users  "org.cinnamon.desktop.lockdown" "disable-user-switching"     _de_switch_cb ;;
  esac
  [[ "$found_switch" -eq 0 && "$_DE_FAMILY" != "unknown" ]] && \
    info "No user-switching policy found for $_DE_FAMILY sessions"

  local userlist_checked=0
  for conf in /etc/gdm*/custom.conf /etc/gdm*/daemon.conf; do
    [[ -f "$conf" ]] || continue
    userlist_checked=1
    break
  done
  if [[ "$userlist_checked" -eq 1 ]]; then
    local db="/etc/dconf/db/gdm.d"
    local userlist_disabled=0
    if [[ -d "$db" ]]; then
      if grep -rqs 'disable-user-list[[:space:]]*=[[:space:]]*true' "$db/"; then
        userlist_disabled=1
      fi
    fi
    if [[ -S "/run/user/$(id -u gdm 2>/dev/null)/bus" ]] 2>/dev/null; then
      local gdm_uid
      gdm_uid=$(id -u gdm 2>/dev/null)
      local val
      val=$(sudo -u gdm DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$gdm_uid/bus" \
        gsettings get org.gnome.login-screen disable-user-list 2>/dev/null | xargs)
      [[ "$val" == "true" ]] && userlist_disabled=1
    fi
    if [[ "$userlist_disabled" -eq 1 ]]; then
      pass "User list hidden on login screen"
    else
      if lsblk -o TYPE 2>/dev/null | grep -q crypt; then
        info "User list visible on login screen (LUKS encryption limits physical access risk)"
      else
        warn "User list visible on login screen (attackers can enumerate users)"
      fi
    fi
  else
    info "GDM not found — skipping user-list check"
  fi
}

###############################################################################
# Section 40: Webcam & Audio Privacy
###############################################################################
check_media_privacy() {
  should_skip "media" && return
  header "40" "WEBCAM & AUDIO PRIVACY"

  local webcams
  webcams=( /dev/video* )
  if [[ -e "${webcams[0]}" ]]; then
    local cam_count=${#webcams[@]}
    local cam_names=""
    for dev in "${webcams[@]}"; do
      local name
      name=$(cat "/sys/class/video4linux/$(basename "$dev")/name" 2>/dev/null)
      [[ -n "$name" ]] && cam_names="${cam_names:+$cam_names, }$name"
    done
    info "$cam_count webcam device(s) found${cam_names:+ ($cam_names)}"
    if lsmod 2>/dev/null | grep -q uvcvideo; then
      info "uvcvideo kernel module loaded"
    fi
  else
    pass "No webcam devices found"
  fi

  local mic_checked=0
  if command -v wpctl &>/dev/null; then
    while IFS=: read -r user _ uid _ _ _ shell; do
      [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
      [[ "$shell" == */nologin || "$shell" == */false ]] && continue
      [[ -S "/run/user/$uid/bus" ]] || continue
      local vol
      vol=$(sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$uid" wpctl get-volume @DEFAULT_AUDIO_SOURCE@ 2>/dev/null)
      if [[ -n "$vol" ]]; then
        mic_checked=1
        if echo "$vol" | grep -qi 'muted'; then
          pass "Microphone muted for $user"
        else
          info "Microphone active for $user: $vol"
        fi
      fi
    done < /etc/passwd
  elif command -v pactl &>/dev/null; then
    while IFS=: read -r user _ uid _ _ _ shell; do
      [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
      [[ "$shell" == */nologin || "$shell" == */false ]] && continue
      [[ -S "/run/user/$uid/bus" ]] || continue
      local muted
      muted=$(sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$uid" \
        pactl get-source-mute @DEFAULT_SOURCE@ 2>/dev/null | awk '{print $2}')
      if [[ -n "$muted" ]]; then
        mic_checked=1
        if [[ "$muted" == "yes" ]]; then
          pass "Microphone muted for $user"
        else
          info "Microphone not muted for $user"
        fi
      fi
    done < /etc/passwd
  fi
  [[ "$mic_checked" -eq 0 ]] && info "Could not check microphone status (no wpctl/pactl or no active sessions)"

  local net_audio=0
  if pgrep -x pulseaudio &>/dev/null; then
    if grep -rqs 'module-native-protocol-tcp' /etc/pulse/ /etc/pulseaudio/ 2>/dev/null; then
      fail "PulseAudio network audio (module-native-protocol-tcp) enabled in config"
      net_audio=1
    fi
    while IFS=: read -r user _ uid _ _ _ shell; do
      [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
      [[ "$shell" == */nologin || "$shell" == */false ]] && continue
      [[ -S "/run/user/$uid/bus" ]] || continue
      if sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$uid" \
        pactl list modules short 2>/dev/null | grep -q 'module-native-protocol-tcp'; then
        fail "PulseAudio TCP module loaded for $user"
        net_audio=1
      fi
    done < /etc/passwd
  fi
  if pgrep -x pipewire &>/dev/null; then
    if grep -rhE 'tcp:[0-9]|module-native-protocol-tcp' /etc/pipewire/ /usr/share/pipewire/ 2>/dev/null | grep -vE '^\s*#' | grep -qE 'tcp:[0-9]|module-native-protocol-tcp'; then
      fail "PipeWire network audio protocol enabled in config"
      net_audio=1
    fi
  fi
  [[ "$net_audio" -eq 0 ]] && pass "No network audio modules detected"

  local pw_remote=0
  for confdir in /etc/pipewire /usr/share/pipewire; do
    [[ -d "$confdir" ]] || continue
    if grep -rqs '"access.allowed"' "$confdir/" 2>/dev/null; then
      info "PipeWire access control rules found in $confdir"
    fi
    if grep -rs 'module-protocol-native.*socket' "$confdir/" 2>/dev/null | grep -qv '/run/user'; then
      warn "PipeWire may expose socket beyond local user"
      pw_remote=1
    fi
  done
  if ss -tlnp 2>/dev/null | grep -q 'pipewire'; then
    warn "PipeWire listening on TCP"
    pw_remote=1
  fi
  [[ "$pw_remote" -eq 0 ]] && pass "No PipeWire remote access detected"

  if pgrep -f xdg-desktop-portal &>/dev/null; then
    info "xdg-desktop-portal is running (screen sharing available when requested)"
  else
    info "xdg-desktop-portal not running"
  fi
}

###############################################################################
# Section 41: Bluetooth Privacy
###############################################################################
check_bluetooth_privacy() {
  should_skip "btprivacy" && return
  header "41" "BLUETOOTH PRIVACY"

  if ! command -v bluetoothctl &>/dev/null || ! systemctl list-unit-files bluetooth.service &>/dev/null; then
    info "Bluetooth not available on this system"
    return
  fi

  local bt_active=0
  if systemctl is-active --quiet bluetooth.service 2>/dev/null; then
    bt_active=1
    info "Bluetooth service is active"
  else
    pass "Bluetooth service is not running"
  fi

  if [[ "$bt_active" -eq 0 ]]; then
    return
  fi

  local bt_info
  bt_info=$(timeout 3 bluetoothctl show 2>/dev/null)
  if [[ -z "$bt_info" ]]; then
    warn "Could not query bluetooth controller (timeout or no adapter)"
    return
  fi

  local discoverable
  discoverable=$(echo "$bt_info" | grep -i 'Discoverable:' | awk '{print $2}')
  if [[ "$discoverable" == "yes" ]]; then
    fail "Bluetooth is discoverable (visible to nearby devices)"
  elif [[ "$discoverable" == "no" ]]; then
    pass "Bluetooth is not discoverable"
  else
    info "Could not determine discoverable status"
  fi

  local pairable
  pairable=$(echo "$bt_info" | grep -i 'Pairable:' | awk '{print $2}')

  local paired_count=0
  local paired_devices
  paired_devices=$(timeout 3 bluetoothctl devices Paired 2>/dev/null || timeout 3 bluetoothctl paired-devices 2>/dev/null)
  if [[ -n "$paired_devices" ]]; then
    paired_count=$(echo "$paired_devices" | grep -c 'Device')
  fi
  info "$paired_count paired Bluetooth device(s)"

  if [[ "$pairable" == "yes" ]]; then
    if [[ "$paired_count" -eq 0 ]]; then
      warn "Bluetooth pairable but no paired devices (unnecessary attack surface)"
    else
      info "Bluetooth pairable with $paired_count paired device(s)"
    fi
  elif [[ "$pairable" == "no" ]]; then
    pass "Bluetooth pairing disabled"
  fi

  if [[ "$paired_count" -eq 0 && "$pairable" != "yes" ]]; then
    warn "Bluetooth active with no paired devices — consider disabling"
  fi
}

###############################################################################
# Section 42: Password & Keyring Security
###############################################################################
check_keyring_security() {
  should_skip "keyring" && return
  header "42" "PASSWORD & KEYRING SECURITY"

  # F-263: extended password manager list (KeeWeb, Buttercup, qtpass, NordPass,
  # LessPass plus established ones).
  local pm_found=0
  local pm_list=""
  for pm in keepassxc keepass2 keepass keeweb bitwarden bitwarden-cli rbw \
            1password op pass gopass passmenu lesspass nordpass \
            buttercup qtpass enpass; do
    if command -v "$pm" &>/dev/null; then
      pm_found=1
      pm_list="${pm_list:+$pm_list, }$pm"
    fi
  done
  if flatpak list 2>/dev/null | grep -qiE 'bitwarden|keepass|1password|keeweb|buttercup|enpass|nordpass|proton-pass'; then
    pm_found=1
    pm_list="${pm_list:+$pm_list, }(flatpak)"
  fi
  if snap list 2>/dev/null | grep -qiE 'bitwarden|keepass|1password|keeweb|buttercup|enpass|nordpass'; then
    pm_found=1
    pm_list="${pm_list:+$pm_list, }(snap)"
  fi
  if [[ "$pm_found" -eq 1 ]]; then
    pass "Password manager installed: $pm_list"
  else
    warn "No password manager detected (consider keepassxc, bitwarden, or pass)"
  fi

  # F-264: Cross-DE keyring PAM detection — GNOME Keyring + KDE KWallet (pam_kwallet5)
  local keyring_pam=0
  for pamfile in /etc/pam.d/gdm-password /etc/pam.d/gdm-autologin /etc/pam.d/login \
                 /etc/pam.d/lightdm /etc/pam.d/sddm /etc/pam.d/sddm-autologin \
                 /etc/pam.d/kde /etc/pam.d/kdm; do
    [[ -f "$pamfile" ]] || continue
    if grep -qs 'pam_gnome_keyring.so' "$pamfile"; then
      keyring_pam=1
      info "GNOME Keyring auto-unlock configured in $(basename "$pamfile")"
    fi
    if grep -qs -E 'pam_kwallet5?\.so' "$pamfile"; then
      keyring_pam=1
      info "KDE KWallet auto-unlock configured in $(basename "$pamfile")"
    fi
  done
  [[ "$keyring_pam" -eq 0 ]] && info "No keyring PAM auto-unlock found (GNOME Keyring/KWallet)"

  local ssh_checked=0
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    local ssh_conf="$home/.ssh/config"
    local agent_conf=""
    if [[ -f "$ssh_conf" ]]; then
      agent_conf=$(grep -i 'AddKeysToAgent' "$ssh_conf" 2>/dev/null | head -1)
    fi
    local global_agent=""
    if [[ -f /etc/ssh/ssh_config ]]; then
      global_agent=$(grep -i 'AddKeysToAgent' /etc/ssh/ssh_config 2>/dev/null | head -1)
    fi

    local effective="${agent_conf:-$global_agent}"
    if [[ -n "$effective" ]]; then
      ssh_checked=1
      if echo "$effective" | grep -qi 'confirm\|[0-9]'; then
        pass "SSH AddKeysToAgent has timeout/confirm for $user"
      elif echo "$effective" | grep -qi 'yes'; then
        warn "SSH AddKeysToAgent=yes for $user (keys persist until agent dies)"
      fi
    fi
  done < /etc/passwd
  [[ "$ssh_checked" -eq 0 ]] && info "No AddKeysToAgent config found (keys persist by default when added)"

  local gpg_checked=0
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    local gpg_conf="$home/.gnupg/gpg-agent.conf"
    [[ -f "$gpg_conf" ]] || continue
    gpg_checked=1
    local ttl
    ttl=$(grep -i 'default-cache-ttl' "$gpg_conf" 2>/dev/null | awk '{print $2}' | head -1)
    if [[ -n "$ttl" ]]; then
      if [[ "$ttl" -le 600 ]]; then
        pass "GPG cache TTL is ${ttl}s for $user"
      else
        warn "GPG cache TTL is ${ttl}s for $user (consider ≤ 600)"
      fi
    else
      info "No GPG cache TTL set for $user (default: 600s)"
    fi
  done < /etc/passwd
  [[ "$gpg_checked" -eq 0 ]] && info "No gpg-agent.conf found for any user"

  # F-267: subdirectory search for secret files (most .env files live in
  # project subdirs, not directly in home). _safe_find_home excludes
  # .snapshots, node_modules, .git, .cache, .venv.
  # Severity-tier by permissions: FAIL on world-readable, WARN on group-readable,
  # INFO on private (600/400) — dev .env files with 600 are normal.
  local secrets_found=0
  local secrets_warn=0
  local secrets_info=0
  while read -r f; do
    [[ -z "$f" ]] && continue
    local fperms
    fperms=$(stat -c '%a' "$f" 2>/dev/null)
    if (( (8#${fperms:-777} & 8#007) != 0 )); then
      fail "Plaintext secret file (world-accessible $fperms): $f"
      secrets_found=1
    elif (( (8#${fperms:-777} & 8#070) != 0 )); then
      warn "Plaintext secret file (group-accessible $fperms): $f"
      ((secrets_warn++))
    else
      info "Plaintext secret file (private $fperms — consider encrypting): $f"
      ((secrets_info++))
    fi
  done < <(_safe_find_home -maxdepth 6 -type f -size +0c \
    \( -name ".env" -o -name ".env.local" -o -name ".env.production" \
       -o -name ".env.development" -o -name ".password" -o -name ".secret" \
       -o -name ".credentials" -o -name "passwords.txt" -o -name "secrets.txt" \
       -o -name "credentials.json" \))
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    [[ -d "$home" ]] || continue
    if [[ -f "$home/.netrc" ]]; then
      local perms
      perms=$(stat -c '%a' "$home/.netrc" 2>/dev/null)
      if [[ "$perms" != "600" && "$perms" != "400" ]]; then
        fail ".netrc has insecure permissions ($perms) for $user"
      fi
    fi
  done < /etc/passwd
  [[ "$secrets_found" -eq 0 ]] && pass "No obvious plaintext secret files found"
}

# --- Run Privacy & Desktop Sections ---
check_browser_privacy
check_app_telemetry
check_network_privacy
check_data_privacy
check_desktop_session
check_media_privacy
check_bluetooth_privacy
check_keyring_security

# --- Firmware & Thunderbolt (independent of --skip keyring) ---
CURRENT_SECTION="FIRMWARE & THUNDERBOLT"
if command -v fwupdmgr &>/dev/null; then
  fw_output=$(timeout 15 fwupdmgr get-updates --no-unreported-check 2>/dev/null)
  fw_exit=$?
  if [[ $fw_exit -eq 0 && -n "$fw_output" ]]; then
    update_count=$(echo "$fw_output" | grep -c '│\|New version')
    if [[ "$update_count" -gt 0 ]]; then
      warn "Firmware updates available (run: fwupdmgr update)"
    else
      pass "Firmware is up to date"
    fi
  elif [[ $fw_exit -eq 2 ]]; then
    pass "Firmware is up to date"
  elif echo "$fw_output" | grep -qi 'no upgrades\|no updates'; then
    pass "Firmware is up to date"
  else
    info "Could not check firmware updates"
  fi
else
  info "fwupdmgr not installed — cannot check firmware updates"
fi

tb_found=0
for dev in /sys/bus/thunderbolt/devices/*/security; do
  [[ -f "$dev" ]] || continue
  tb_found=1
  level=$(cat "$dev" 2>/dev/null)
  devname=$(basename "$(dirname "$dev")")
  case "$level" in
    none)  fail "Thunderbolt device $devname: security level NONE (DMA attacks possible)" ;;
    user)  pass "Thunderbolt device $devname: user authorization required" ;;
    secure) pass "Thunderbolt device $devname: secure connect (key verification)" ;;
    dponly) pass "Thunderbolt device $devname: DisplayPort only (no PCIe tunneling)" ;;
    *)     info "Thunderbolt device $devname: security level '$level'" ;;
  esac
done
if [[ "$tb_found" -eq 0 ]]; then
  if [[ -d /sys/bus/thunderbolt ]]; then
    info "Thunderbolt bus present but no devices connected"
  else
    info "No Thunderbolt controller detected"
  fi
fi

###############################################################################
if ! should_skip "summary"; then
CURRENT_SECTION="SUMMARY"
if ! $JSON_MODE; then
  printf "\n${BOLD}${MAG}━━━ SUMMARY ━━━${RST}\n"
fi
###############################################################################

TOTAL_END=$(date +%s)
DURATION=$((TOTAL_END - TOTAL_START))

# Weighted Score: PASS*100 / (PASS + FAIL*2 + WARN)
# FAIL is weighted 2x because failures are more critical than warnings.
# INFO is excluded from the score — it's purely informational.
# Example: 200 PASS, 5 FAIL, 10 WARN → 200*100 / (200 + 10 + 10) = 91%
SCORE_DENOM=$((PASS + FAIL * 2 + WARN))
if [[ "$SCORE_DENOM" -gt 0 ]]; then
  SCORE=$(( (PASS * 100 + SCORE_DENOM / 2) / SCORE_DENOM ))
else
  SCORE=0
fi

# Rating
if [[ "$SCORE" -ge 95 ]]; then
  RATING="🏰 FORTRESS"
  RATING_COLOR="$GRN"
elif [[ "$SCORE" -ge 90 ]]; then
  RATING="🛡️ EXCELLENT"
  RATING_COLOR="$GRN"
elif [[ "$SCORE" -ge 80 ]]; then
  RATING="🛡️ SOLID"
  RATING_COLOR="$GRN"
elif [[ "$SCORE" -ge 70 ]]; then
  RATING="⚠️  NEEDS WORK"
  RATING_COLOR="$YLW"
else
  RATING="🔴 CRITICAL"
  RATING_COLOR="$RED"
fi

# Build AI prompt text once if --ai is set (used by both JSON and text modes)
_AI_TEXT=""
if $AI_MODE; then
  _ai_ctx=""
  lsblk -o TYPE 2>/dev/null | grep -q crypt && _ai_ctx="${_ai_ctx}, LUKS"
  [[ -n "$VPN_IFACES" ]] && _ai_ctx="${_ai_ctx}, VPN active"
  command -v flatpak &>/dev/null && _ai_ctx="${_ai_ctx}, Flatpak"
  $HAS_SELINUX && _ai_ctx="${_ai_ctx}, SELinux"
  $HAS_APPARMOR && _ai_ctx="${_ai_ctx}, AppArmor"
  _AI_TEXT="I ran NoID Privacy for Linux v${NOID_PRIVACY_VERSION} — a 390+ check privacy & security audit.
Tool: https://github.com/NexusOne23/noid-privacy-linux

System: ${DISTRO_PRETTY} ${KERNEL} ${DESKTOP_ENV}"
  [[ -n "$_ai_ctx" ]] && _AI_TEXT="${_AI_TEXT}
Context: ${_ai_ctx#, }"
  _AI_TEXT="${_AI_TEXT}
Score: ${SCORE}% ${RATING} (${PASS} pass, ${FAIL} fail, ${WARN} warn, ${INFO} info)
"
  if [[ ${#FAIL_MSGS[@]} -gt 0 ]]; then
    _AI_TEXT="${_AI_TEXT}
FAILED (${#FAIL_MSGS[@]}):"
    for msg in "${FAIL_MSGS[@]}"; do
      _AI_TEXT="${_AI_TEXT}
  - $msg"
    done
  fi
  if [[ ${#WARN_MSGS[@]} -gt 0 ]]; then
    _AI_TEXT="${_AI_TEXT}

WARNINGS (${#WARN_MSGS[@]}):"
    for msg in "${WARN_MSGS[@]}"; do
      _AI_TEXT="${_AI_TEXT}
  - $msg"
    done
  fi
  if [[ ${#FAIL_MSGS[@]} -eq 0 && ${#WARN_MSGS[@]} -eq 0 ]]; then
    _AI_TEXT="${_AI_TEXT}

No issues found. System is fully hardened."
  fi
  _AI_TEXT="${_AI_TEXT}

For each finding: explain the risk, show the exact fix command,
warn if it could break anything, and ask before applying.
Verify each command against current system state before suggesting.
If you cannot verify a fact, say so."
fi

if $JSON_MODE; then
  # --- JSON Output ---
  TOTAL=$((PASS + FAIL + WARN + INFO))
  JSON_TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S')
  printf '{\n'
  printf '  "version": "%s",\n' "$NOID_PRIVACY_VERSION"
  printf '  "timestamp": "%s",\n' "$JSON_TIMESTAMP"
  printf '  "system": {\n'
  printf '    "distro": "%s",\n' "$(_json_escape "$DISTRO_PRETTY")"
  printf '    "kernel": "%s",\n' "$(_json_escape "$KERNEL")"
  printf '    "hostname": "%s",\n' "$(_json_escape "$HOSTNAME")"
  printf '    "desktop": "%s"\n' "$(_json_escape "$DESKTOP_ENV")"
  printf '  },\n'
  printf '  "summary": {\n'
  printf '    "total": %d,\n' "$TOTAL"
  printf '    "pass": %d,\n' "$PASS"
  printf '    "fail": %d,\n' "$FAIL"
  printf '    "warn": %d,\n' "$WARN"
  printf '    "info": %d,\n' "$INFO"
  printf '    "score": %d\n' "$SCORE"
  printf '  },\n'
  printf '  "findings": [\n'
  for ((i=0; i<${#JSON_FINDINGS[@]}; i++)); do
    if [[ $i -lt $((${#JSON_FINDINGS[@]} - 1)) ]]; then
      printf '    %s,\n' "${JSON_FINDINGS[$i]}"
    else
      printf '    %s\n' "${JSON_FINDINGS[$i]}"
    fi
  done
  printf '  ]'
  # F-273: embed ai_prompt as JSON field when --ai was set
  if $AI_MODE && [[ -n "$_AI_TEXT" ]]; then
    printf ',\n  "ai_prompt": "%s"\n' "$(_json_escape "$_AI_TEXT")"
  else
    printf '\n'
  fi
  printf '}\n'
else
  # --- Normal Summary Output ---
  echo ""
  printf "${BOLD}${WHT}╔══════════════════════════════════════════════════════════════════════╗${RST}\n"
  printf "${BOLD}${WHT}║                          FINAL RESULTS                               ║${RST}\n"
  printf "${BOLD}${WHT}╠══════════════════════════════════════════════════════════════════════╣${RST}\n"
  printf "${BOLD}${WHT}║${RST}  Total checks:      ${BOLD}$((PASS + FAIL + WARN + INFO))${RST} ($PASS pass, $FAIL fail, $WARN warn, $INFO info)\n"
  printf "${BOLD}${WHT}║${RST}  ${GRN}✅ Passed:${RST}           ${BOLD}$PASS${RST}\n"
  printf "${BOLD}${WHT}║${RST}  ${RED}🔴 Failed:${RST}           ${BOLD}$FAIL${RST}\n"
  printf "${BOLD}${WHT}║${RST}  ${YLW}⚠️  Warnings:${RST}        ${BOLD}$WARN${RST}\n"
  printf "${BOLD}${WHT}║${RST}  ${CYN}ℹ️  Info:${RST}             ${BOLD}$INFO${RST}\n"
  printf "${BOLD}${WHT}╠══════════════════════════════════════════════════════════════════════╣${RST}\n"
  printf "${BOLD}${WHT}║${RST}  Score formula:     PASS×100 / (PASS + FAIL×2 + WARN)\n"
  printf "${BOLD}${WHT}║${RST}  ${BOLD}SECURITY & PRIVACY SCORE:${RST}    ${RATING_COLOR}${BOLD}${SCORE}%% ${RATING}${RST}\n"
  printf "${BOLD}${WHT}║${RST}  Kernel:            %s\n" "$KERNEL"
  printf "${BOLD}${WHT}║${RST}  Uptime:            %s\n" "$(uptime -p 2>/dev/null || echo 'N/A')"
  printf "${BOLD}${WHT}║${RST}  Scan duration:     %s seconds\n" "$DURATION"
  printf "${BOLD}${WHT}╚══════════════════════════════════════════════════════════════════════╝${RST}\n"
  echo ""
  printf "${CYN}Report generated: $NOW${RST}\n"
  printf "${CYN}by NexusOne23 — NoID Privacy for Linux v${NOID_PRIVACY_VERSION} | https://noid-privacy.com/linux.html${RST}\n"

  # --- AI Mode Output (uses _AI_TEXT built earlier) ---
  if $AI_MODE && [[ -n "$_AI_TEXT" ]]; then
    echo ""
    echo ""
    echo -e "${BOLD}${CYN}╔══════════════════════════════════════════════════════════════════════╗${RST}"
    echo -e "${BOLD}${CYN}║${RST}  🤖 ${BOLD}AI ASSISTANT PROMPT${RST}"
    echo -e "${BOLD}${CYN}║${RST}  Copy everything below and paste it to your AI assistant"
    echo -e "${BOLD}${CYN}║${RST}  ${YLW}ChatGPT${RST} · ${YLW}Claude${RST} · ${YLW}Gemini${RST} · ${YLW}any LLM${RST}"
    echo -e "${BOLD}${CYN}╚══════════════════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo "▼▼▼ COPY FROM HERE ▼▼▼"
    echo ""
    echo "$_AI_TEXT"
    echo ""
    echo "▲▲▲ COPY TO HERE ▲▲▲"
  fi
fi

fi # end summary

# F-007: explicit exit code so CI/automation can distinguish results.
# Convention (matches Lynis/OpenSCAP/Tripwire):
#   0 = clean (no FAIL)
#   1 = FAIL findings present
#   2 = WARN-only (informational signal — no failures but issues to review)
# entrypoint.sh wraps this for the GitHub Action, so exit codes here are
# stable contract for shell users and CI consumers.
if [[ "${FAIL:-0}" -gt 0 ]]; then
  exit 1
elif [[ "${WARN:-0}" -gt 0 ]]; then
  exit 2
fi
exit 0
