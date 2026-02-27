#!/usr/bin/env bash
###############################################################################
#  NoID Privacy for Linux v3.1.0 — Privacy & Security Audit
#  https://noid-privacy.com/linux.html | https://github.com/NexusOne23/noid-privacy-linux
#  Fedora / RHEL / Debian / Ubuntu — Full-Spectrum Audit
#  300+ checks across 42 sections
#  Requires: root
###############################################################################
NOID_PRIVACY_VERSION="3.2.0"
set +e          # Don't exit on errors — we handle them ourselves

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

300+ checks. Requires root. Tested on Fedora 43, RHEL 9, Debian 12, Ubuntu 24.04.
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
    *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
  esac
done

if $AI_MODE && $JSON_MODE; then
  echo "Error: --ai and --json are mutually exclusive"; exit 1
fi

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
txtf() { $JSON_MODE || printf "$@"; }

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
    [[ "$uid" -ge 1000 ]] || continue
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
          if echo "$pcontent" | grep -q '"EnableTrackingProtection"' 2>/dev/null; then
            echo "$pcontent" | grep -q '"Value".*true' 2>/dev/null && pol_val="strict"
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
  local bus="unix:path=/run/user/${uid}/bus"
  [[ -S "/run/user/${uid}/bus" ]] || return 1
  sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="$bus" gsettings get "$schema" "$key" 2>/dev/null
}

_human_size() {
  local bytes="$1"
  if [[ "$bytes" -ge 1073741824 ]]; then
    echo "$(( bytes / 1073741824 ))GB"
  elif [[ "$bytes" -ge 1048576 ]]; then
    echo "$(( bytes / 1048576 ))MB"
  elif [[ "$bytes" -ge 1024 ]]; then
    echo "$(( bytes / 1024 ))KB"
  else
    echo "${bytes}B"
  fi
}

# Read effective systemd drop-in config value (main config + drop-in dirs, last wins)
# Usage: _systemd_conf_val <unit_conf> <key>
# Example: _systemd_conf_val /etc/systemd/coredump.conf Storage
_systemd_conf_val() {
  local base_conf="$1" key="$2" val=""
  local dropin_dir="${base_conf%.conf}.conf.d"
  # Main config
  if [[ -f "$base_conf" ]]; then
    val=$(grep -i "^${key}\s*=" "$base_conf" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
  fi
  # Drop-in overrides (alphabetical, last one wins)
  for dropin in "${dropin_dir}"/*.conf; do
    [[ -f "$dropin" ]] || continue
    local dval
    dval=$(grep -i "^${key}\s*=" "$dropin" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
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

[[ $EUID -ne 0 ]] && { echo "Requires root. Run with: sudo bash \"$0\""; exit 1; }

# --- Distro Detection ---
DISTRO="unknown"
DISTRO_FAMILY="unknown"
DISTRO_PRETTY="Unknown Linux"
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
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
echo "║  Checks: 300+ across $TOTAL_SECTIONS sections"
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

# Secure Boot
if require_cmd mokutil; then
  if mokutil --sb-state 2>/dev/null | grep -q "enabled"; then
    pass "Secure Boot: ENABLED"
  else
    fail "Secure Boot: DISABLED"
  fi
else
  warn "mokutil not installed — cannot check Secure Boot"
fi

# Kernel Lockdown
if [[ -f /sys/kernel/security/lockdown ]]; then
  LOCKDOWN=$(cat /sys/kernel/security/lockdown | grep -oP '\[\K[^\]]+')
  if [[ "$LOCKDOWN" == "none" ]]; then
    warn "Kernel Lockdown: none (despite Secure Boot)"
  else
    pass "Kernel Lockdown: $LOCKDOWN"
  fi
else
  warn "Kernel Lockdown: not available"
fi

# Kernel Taint
TAINT=$(cat /proc/sys/kernel/tainted)
if [[ "$TAINT" -eq 0 ]]; then
  pass "Kernel Taint: 0 (clean)"
else
  if [[ "$TAINT" -eq 4096 ]]; then
    info "Kernel Taint: $TAINT (NVIDIA proprietary — expected)"
  else
    warn "Kernel Taint: $TAINT (proprietary modules?)"
  fi
fi

# Insecure boot parameters check
CMDLINE=$(cat /proc/cmdline)
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

# GRUB Password
if [[ -f /boot/grub2/grub.cfg ]] || [[ -f /boot/grub/grub.cfg ]]; then
  if [[ -f /boot/grub2/user.cfg ]] || grep -q "password" /etc/grub.d/40_custom 2>/dev/null; then
    pass "GRUB password set"
  else
    if lsblk -o TYPE 2>/dev/null | grep -q crypt; then
      info "GRUB no password (LUKS encryption protects)"
    else
      warn "GRUB no password (physical access = root)"
    fi
  fi
fi

fi # end kernel

###############################################################################
if ! should_skip "selinux"; then

# Detect which MAC system is available (tool-based, not distro-based)
HAS_SELINUX=false
HAS_APPARMOR=false
require_cmd getenforce && HAS_SELINUX=true
require_cmd aa-status && HAS_APPARMOR=true

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
if require_cmd ausearch; then
  SE_DENIALS=$(ausearch -m avc --start recent 2>/dev/null | grep -c "type=AVC" || true)
  SE_DENIALS=${SE_DENIALS//[^0-9]/}
  SE_DENIALS=${SE_DENIALS:-0}
  if [[ "$SE_DENIALS" -gt 0 ]]; then
    warn "SELinux: $SE_DENIALS AVC denials (recent)"
  else
    pass "SELinux: 0 AVC denials (recent)"
  fi
fi

elif $HAS_APPARMOR; then
  header "02" "APPARMOR & MAC"

  AA_ENFORCED=$(aa-status 2>/dev/null | grep -c "enforce" || true)
  AA_ENFORCED=${AA_ENFORCED:-0}
  AA_COMPLAIN=$(aa-status 2>/dev/null | grep -c "complain" || true)
  AA_COMPLAIN=${AA_COMPLAIN:-0}
  if [[ "$AA_ENFORCED" -gt 0 ]]; then
    pass "AppArmor: $AA_ENFORCED profiles enforcing, $AA_COMPLAIN complaining"
  else
    warn "AppArmor: no enforcing profiles"
  fi

else
  header "02" "MANDATORY ACCESS CONTROL"
  warn "No MAC system (SELinux/AppArmor) detected"
fi
fi # end selinux

###############################################################################
if ! should_skip "firewall"; then
header "03" "FIREWALL"
###############################################################################

if require_cmd firewall-cmd && systemctl is-active firewalld &>/dev/null; then
  pass "firewalld: active"

  # Check zones
  for ZONE in public external dmz block drop FedoraWorkstation; do
    TARGET=$(firewall-cmd --zone="$ZONE" --get-target --permanent 2>/dev/null || echo "")
    [[ -z "$TARGET" ]] && continue  # zone doesn't exist
    SERVICES=$(firewall-cmd --zone="$ZONE" --list-services --permanent 2>/dev/null || echo "")
    PORTS=$(firewall-cmd --zone="$ZONE" --list-ports --permanent 2>/dev/null || echo "")
    IFACES=$(firewall-cmd --zone="$ZONE" --list-interfaces --permanent 2>/dev/null || echo "")

    # Get default zone to know which applies to unassigned interfaces
    _DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "")

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
        info "Zone $ZONE (default): target=$TARGET, no interfaces assigned"
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
      if [[ -n "$PORTS" ]] && ! $_ALL_VPN; then
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
      PINGRESS=$(firewall-cmd --policy="$policy" --query-ingress-zone=HOST 2>/dev/null && echo "HOST→" || true)
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
  IPTABLES_RULES=$(iptables -L -n 2>/dev/null | grep -c "^[A-Z]" || true)
  IPTABLES_RULES=${IPTABLES_RULES:-0}
  if [[ "$IPTABLES_RULES" -gt 3 ]]; then
    pass "iptables: $IPTABLES_RULES chains with rules"
  else
    warn "iptables: minimal rules"
  fi
  info "Firewall: iptables (firewalld not available)"
else
  fail "No firewall detected (firewalld/ufw/iptables)"
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

# Internet Connectivity Test
if ping -c1 -W5 1.1.1.1 &>/dev/null; then
  pass "Internet connectivity: OK"
else
  warn "Internet connectivity: FAIL (ping 1.1.1.1 timeout)"
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
DEF_ROUTE=$(ip route show default | head -1)
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

# DNS Leak Test & External IP (makes network requests — skippable with --skip netleaks)
if ! should_skip "netleaks"; then
  if require_cmd dig; then
    RESOLVED_IP=$(dig +short whoami.akamai.net @ns1-1.akamaitech.net 2>/dev/null || echo "timeout")
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

# IPv6 (filter link-local fe80 and multicast ff to avoid false positives)
if [[ -f /proc/net/if_inet6 ]]; then
  IPV6_GLOBAL=$(grep -cvE '^fe80|^ff|^fd|^0000000000000000' /proc/net/if_inet6 2>/dev/null || true)
  IPV6_GLOBAL=${IPV6_GLOBAL:-0}
  IPV6_TOTAL=$(wc -l < /proc/net/if_inet6)
  if [[ "$IPV6_GLOBAL" -gt 0 ]]; then
    warn "IPv6 active ($IPV6_GLOBAL global addresses, $IPV6_TOTAL total) — leak risk"
  else
    pass "IPv6: disabled/minimal ($IPV6_TOTAL link-local only)"
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
  echo "$TESTED_GWS" | grep -qw "$GW" && continue
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

# Promiscuous Mode
PROMISC=$(ip -o link show | grep -i promisc || true)
if [[ -z "$PROMISC" ]]; then
  pass "No promiscuous mode"
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
    warn "Magic SysRq: ALL functions enabled (value=1)"
  else
    info "Magic SysRq: value=$SYSRQ_VAL bits: $SYSRQ_BITS"
  fi
fi

# ip_forward (VPN exception)
IP_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [[ "$IP_FWD" -eq 1 ]]; then
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

SHOULD_BE_OFF="sshd telnet.socket rsh.socket rlogin.socket rexec.socket vsftpd httpd nginx cups avahi-daemon bluetooth.service rpcbind nfs-server smb nmb"
for SVC in $SHOULD_BE_OFF; do
  if systemctl is-active "$SVC" &>/dev/null; then
    fail "Service running: $SVC"
  elif systemctl is-masked "$SVC" &>/dev/null; then
    pass "Service masked: $SVC"
  elif systemctl is-enabled "$SVC" &>/dev/null 2>&1; then
    warn "Service enabled but inactive: $SVC"
  else
    pass "Service off: $SVC"
  fi
done

# wsdd (Web Services Discovery) check
# Distinguish between standalone wsdd.service and GNOME's gvfsd-wsdd (activated on-demand by GVFS)
_WSDD_SVC_ACTIVE=false
systemctl is-active wsdd.service &>/dev/null && _WSDD_SVC_ACTIVE=true
systemctl is-active wsdd2.service &>/dev/null && _WSDD_SVC_ACTIVE=true

if $_WSDD_SVC_ACTIVE; then
  warn "wsdd.service active — WS-Discovery broadcasts hostname on local network"
elif pgrep -x wsdd &>/dev/null; then
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
FAILED_SVCS=$(systemctl --failed --no-legend 2>/dev/null)
FAILED=$(echo "$FAILED_SVCS" | grep -c '\S' || true)
if [[ "$FAILED" -eq 0 ]]; then
  pass "0 failed services"
else
  svc_names=$(echo "$FAILED_SVCS" | awk '{print $2}' | tr '\n' ', ' | sed 's/,$//')
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
    if has_nft_drop_on_phys; then
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
    info "UDP $ADDR (kernel — likely WireGuard)"
  else
    if has_nft_drop_on_phys; then
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
done < <(ss -tnp state established 2>/dev/null | awk '{print $5}' | grep -oP ':\K\d+$' | sort -n | uniq))
if [[ -n "$UNUSUAL_PORTS" ]]; then
  info "Connections to non-standard ports: $(echo $UNUSUAL_PORTS | tr '\n' ' ')"
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

if systemctl is-masked sshd &>/dev/null || [[ "$(systemctl is-enabled sshd 2>&1)" == "masked" ]]; then
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

    # PubkeyAuthentication
    VAL=$(sshd_cfg_val PubkeyAuthentication)
    if [[ "$VAL" == "yes" ]]; then
      pass "SSH: PubkeyAuthentication yes"
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
      # Convert to seconds for comparison
      LGT_NUM=$(echo "$LGT" | grep -oP '^\d+')
      if [[ -n "$LGT_NUM" ]] && [[ "$LGT_NUM" -le 60 ]]; then
        pass "SSH: LoginGraceTime $LGT"
      else
        warn "SSH: LoginGraceTime $LGT (recommended: <=60s)"
      fi
    else
      warn "SSH: LoginGraceTime not set (default 120s — too long)"
    fi

    # SSH Key Strength
    sub_header "SSH Key Strength"
    for USER_HOME in /home/* /root; do
      for KEY in "$USER_HOME"/.ssh/*.pub; do
        [[ -f "$KEY" ]] || continue
        BITS=$(ssh-keygen -l -f "$KEY" 2>/dev/null | awk '{print $1}')
        TYPE=$(ssh-keygen -l -f "$KEY" 2>/dev/null | awk '{print $4}' | tr -d '()')
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
  AUDIT_RULES=$(auditctl -l 2>/dev/null | wc -l)
  if [[ "$AUDIT_RULES" -ge 20 ]]; then
    pass "Audit rules: $AUDIT_RULES"
  elif [[ "$AUDIT_RULES" -gt 0 ]]; then
    warn "Audit rules: only $AUDIT_RULES (recommended: >=20)"
  else
    fail "Audit rules: 0"
  fi

  AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep "enabled" | awk '{print $2}')
  if [[ "$AUDIT_ENABLED" == "2" ]]; then
    pass "Audit: immutable (enabled=2)"
  elif [[ "$AUDIT_ENABLED" == "1" ]]; then
    warn "Audit: enabled=1 (not immutable)"
  else
    fail "Audit: enabled=$AUDIT_ENABLED"
  fi

  CRITICAL_WATCHES="/etc/passwd /etc/shadow /etc/sudoers /etc/ssh /etc/pam.d"
  for WATCH in $CRITICAL_WATCHES; do
    if auditctl -l 2>/dev/null | grep -q "$WATCH"; then
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
EMPTY_PW=$(awk -F: '$2 == "" && $1 != "root" {print $1}' /etc/shadow 2>/dev/null | wc -l)
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

# securetty
if [[ -f /etc/securetty ]]; then
  pass "securetty present"
else
  warn "securetty missing (root login on any TTY possible)"
fi

# Sudo group
WHEEL_MEMBERS=$(grep "^wheel:" /etc/group 2>/dev/null | cut -d: -f4)
if [[ -z "$WHEEL_MEMBERS" ]]; then
  WHEEL_MEMBERS=$(grep "^sudo:" /etc/group 2>/dev/null | cut -d: -f4)
fi
info "Wheel/sudo members: $WHEEL_MEMBERS"

# Shell users
SHELL_USERS=$(grep -v '/nologin\|/false\|/sync\|/shutdown\|/halt' /etc/passwd | wc -l)
info "Users with login shell: $SHELL_USERS"
if ! $JSON_MODE; then
  while IFS=: read -r user _ uid _ _ _ shell; do
    printf "       %s (UID=%s, Shell=%s)\n" "$user" "$uid" "$shell"
  done < <(grep -v '/nologin\|/false\|/sync\|/shutdown\|/halt' /etc/passwd)
fi

# Password Aging
PASS_MAX=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
PASS_MIN=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
PASS_WARN=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
info "Password policy: MAX=$PASS_MAX, MIN=$PASS_MIN, WARN=$PASS_WARN"

# Umask Check (new)
UMASK_VAL=$(grep -hiE '^\s*umask\s+' /etc/login.defs /etc/profile /etc/bashrc 2>/dev/null | tail -1 | awk '{print $2}')
if [[ -n "$UMASK_VAL" ]]; then
  if [[ "$UMASK_VAL" -ge 27 ]] 2>/dev/null || [[ "$UMASK_VAL" == "027" ]] || [[ "$UMASK_VAL" == "077" ]]; then
    pass "Default umask: $UMASK_VAL (restrictive)"
  else
    warn "Default umask: $UMASK_VAL (recommended: >=027)"
  fi
else
  warn "Default umask not explicitly set"
fi

# Faillock
if require_cmd faillock; then
  LOCKED=$(faillock --dir /var/run/faillock 2>/dev/null | grep -c "When" | ccount)
  if [[ "$LOCKED" -gt 0 ]]; then
    warn "Faillock: $LOCKED locked accounts"
  else
    pass "Faillock: no locked accounts"
  fi
fi

# History File Permissions (new)
sub_header "History File Permissions"
for USER_HOME in /home/* /root; do
  for HIST in .bash_history .zsh_history; do
    if [[ -f "$USER_HOME/$HIST" ]]; then
      PERMS=$(stat -c %a "$USER_HOME/$HIST" 2>/dev/null)
      if [[ "$PERMS" -gt 600 ]]; then
        warn "History file too open: $USER_HOME/$HIST ($PERMS, should be <=600)"
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

# SUID Files
SUID_COUNT=$(find / -xdev -perm -4000 -type f 2>/dev/null | wc -l)
if [[ "$SUID_COUNT" -le 30 ]]; then
  pass "SUID files: $SUID_COUNT"
else
  warn "SUID files: $SUID_COUNT (>30)"
fi

# SGID Files
SGID_COUNT=$(find / -xdev -perm -2000 -type f 2>/dev/null | wc -l)
if [[ "$SGID_COUNT" -le 15 ]]; then
  pass "SGID files: $SGID_COUNT"
else
  warn "SGID files: $SGID_COUNT (>15)"
fi

# World-Writable
WW_COUNT=$(find / -xdev -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | wc -l)
if [[ "$WW_COUNT" -eq 0 ]]; then
  pass "World-writable files: 0"
else
  fail "World-writable files: $WW_COUNT"
  if ! $JSON_MODE; then
    while read -r f; do
      printf "       %s\n" "$f"
    done < <(find / -xdev -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -5)
  fi
fi

# Unowned Files
UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l)
if [[ "$UNOWNED" -le 25 ]]; then
  pass "Unowned files: $UNOWNED"
else
  warn "Unowned files: $UNOWNED (>25)"
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
if [[ "$CORE_ULIMIT" == "0" ]] || echo "$CORE_PATTERN" | grep -q "|/dev/null"; then
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
  ["/boot/grub2/grub.cfg"]="600"
  ["/etc/crontab"]="600"
  ["/etc/ssh/sshd_config"]="600"
)

for FILE in "${!PERM_CHECKS[@]}"; do
  if [[ -f "$FILE" ]]; then
    EXPECTED="${PERM_CHECKS[$FILE]}"
    ACTUAL=$(stat -c %a "$FILE" 2>/dev/null)
    if [[ "$ACTUAL" -le "$EXPECTED" ]]; then
      pass "Permissions $FILE: $ACTUAL"
    else
      warn "Permissions $FILE: $ACTUAL (expected: <=$EXPECTED)"
    fi
  fi
done

# Banner Check (new)
sub_header "Login Banners"
for BANNER_FILE in /etc/issue /etc/issue.net /etc/motd; do
  if [[ -f "$BANNER_FILE" ]] && [[ -s "$BANNER_FILE" ]]; then
    if grep -qiE "(kernel|version|ubuntu|fedora|centos|debian|rhel)" "$BANNER_FILE" 2>/dev/null; then
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
    if echo "$CIPHER" | grep -qE "aes-xts|aes-cbc"; then
      pass "LUKS cipher: $CIPHER (strong)"
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
  ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail)
  if [[ "$ENTROPY" -ge 256 ]]; then
    pass "Entropy: $ENTROPY (sufficient)"
  else
    warn "Entropy: $ENTROPY (low — minimum 256)"
  fi
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
  UPDATES=$(dnf5 check-upgrade --quiet 2>/dev/null | grep -v "^$" | wc -l)
elif require_cmd dnf; then
  UPDATES=$(dnf check-update --quiet 2>/dev/null | grep -v "^$" | wc -l)
elif require_cmd apt; then
  apt update -qq &>/dev/null
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
  SEC_UPDATES=$(dnf5 check-upgrade --security --quiet 2>/dev/null | grep -v "^$" | wc -l || true)
  SEC_UPDATES=${SEC_UPDATES:-0}
elif require_cmd dnf; then
  SEC_CHECKED=true
  SEC_UPDATES=$(dnf updateinfo list --security 2>/dev/null | grep -c "/" || true)
  SEC_UPDATES=${SEC_UPDATES:-0}
elif require_cmd apt-get; then
  SEC_CHECKED=true
  # Ubuntu: use apt-check if available (update-notifier-common), fallback to apt-get -s
  if [[ -x /usr/lib/update-notifier/apt-check ]]; then
    SEC_UPDATES=$(/usr/lib/update-notifier/apt-check --human-readable 2>&1 | grep -oP '^\d+(?=.*security)' || true)
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
  RPM_NOSIG=$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n' 2>/dev/null | grep -c "not signed" | ccount)
  if [[ "$RPM_NOSIG" -eq 0 ]]; then
    pass "All RPM packages signed"
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
if systemctl is-active dnf5-automatic.timer &>/dev/null || systemctl is-enabled dnf5-automatic.timer &>/dev/null 2>&1; then
  # Check if configured for security-only updates
  _DNF5_AUTO_CONF="/etc/dnf/dnf5-plugins/automatic.conf"
  _DNF5_UPGRADE_TYPE=$(grep -i "^upgrade_type" "$_DNF5_AUTO_CONF" 2>/dev/null | cut -d= -f2 | tr -d ' ')
  if [[ "${_DNF5_UPGRADE_TYPE,,}" == "security" ]]; then
    pass "Automated updates: dnf5-automatic enabled (security-only)"
  else
    pass "Automated updates: dnf5-automatic enabled (upgrade_type=${_DNF5_UPGRADE_TYPE:-default})"
  fi
elif systemctl is-active dnf-automatic.timer &>/dev/null || systemctl is-enabled dnf-automatic.timer &>/dev/null 2>&1; then
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

# rkhunter
if require_cmd rkhunter; then
  $JSON_MODE || printf "  ${CYN}Running rkhunter...${RST}\n"
  RKH_OUT=$(rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null || true)
  RKH_WARNS=$(echo "$RKH_OUT" | grep -c "Warning:" || true)
  RKH_WARNS=${RKH_WARNS:-0}
  if [[ "$RKH_WARNS" -eq 0 ]]; then
    pass "rkhunter: clean"
  else
    warn "rkhunter: $RKH_WARNS warnings"
    if ! $JSON_MODE; then
      while read -r w; do
        printf "       %s\n" "$w"
      done < <(echo "$RKH_OUT" | grep "Warning:" | head -5)
    fi
  fi
else
  info "rkhunter not installed — skipped"
fi

# chkrootkit with false-positive filter
if require_cmd chkrootkit; then
  $JSON_MODE || printf "  ${CYN}Running chkrootkit...${RST}\n"
  CHKRK_OUT=$(chkrootkit 2>/dev/null || true)
  # Filter known false positives
  CHKRK_FP_PATTERN="bindshell|sniffer|chkutmp|w55808|slapper|scalper|amd|wted|Xor\.DDoS"
  CHKRK_INFECTED=$(echo "$CHKRK_OUT" | grep "INFECTED" | grep -viE "$CHKRK_FP_PATTERN" | wc -l | ccount)
  CHKRK_FP=$(echo "$CHKRK_OUT" | grep "INFECTED" | grep -ciE "$CHKRK_FP_PATTERN" | ccount)
  if [[ "$CHKRK_INFECTED" -eq 0 ]]; then
    pass "chkrootkit: clean (0 real INFECTED, $CHKRK_FP known false positives filtered)"
  else
    fail "chkrootkit: $CHKRK_INFECTED INFECTED (after filtering $CHKRK_FP known FPs)"
    if ! $JSON_MODE; then
      while read -r i; do
        printf "       %s\n" "$i"
      done < <(echo "$CHKRK_OUT" | grep "INFECTED" | grep -viE "bindshell|sniffer|chkutmp|w55808|slapper|scalper|amd|wted" | head -5)
    fi
  fi
else
  info "chkrootkit not installed — skipped"
fi

# Suspect Cron Jobs
sub_header "Cron jobs (all users)"
for USER_HOME in /home/* /root; do
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
SUSPECT_PROCS=$(ps aux 2>/dev/null | grep -iE "\bnc -l\b|\bncat -l\b|\bsocat\b|\bmeterpreter\b|\breverse.shell\b|\bcobalt\b|\bmimikatz\b|\blazagne\b|\bkeylog\b" | grep -v grep || true)
if [[ -z "$SUSPECT_PROCS" ]]; then
  pass "No suspicious processes"
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
PS_PIDS=$(ps -eo pid --no-headers | sed 's/ //g' | sort -n -u)
PROC_PIDS=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n -u)
HIDDEN=$(comm -23 <(echo "$PROC_PIDS") <(echo "$PS_PIDS") | wc -l)
HIDDEN=${HIDDEN//[^0-9]/}
HIDDEN=${HIDDEN:-0}
if [[ "$HIDDEN" -le 10 ]]; then
  pass "Hidden processes: $HIDDEN (normal: race condition)"
else
  warn "Hidden processes: $HIDDEN"
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
ICMP_REDIR=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
if [[ "$ICMP_REDIR" -eq 0 ]]; then
  pass "ICMP redirects: blocked"
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
    warn "hosts.deny: no deny rules (consider ALL: ALL)"
  else
    pass "hosts.deny: $DENY_RULES deny rules"
  fi
else
  info "TCP wrappers: not configured (hosts.allow missing)"
fi

fi # end network

###############################################################################
if ! should_skip "containers"; then
header "18" "CONTAINERS & VIRTUALIZATION"
###############################################################################

if require_cmd docker; then
  if systemctl is-active docker &>/dev/null; then
    warn "Docker daemon running"
    CONTAINERS=$(docker ps -q 2>/dev/null | wc -l)
    info "Running containers: $CONTAINERS"
  else
    info "Docker installed, not active"
  fi
fi

if require_cmd podman; then
  PODMAN_CONTAINERS=$(podman ps -q 2>/dev/null | wc -l)
  info "Podman containers (user): $PODMAN_CONTAINERS"
  PODMAN_ROOT=$(sudo podman ps -q 2>/dev/null | wc -l)
  if [[ "$PODMAN_ROOT" -gt 0 ]]; then
    warn "Podman root containers: $PODMAN_ROOT"
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

JOURNAL_ERR=$(journalctl -p err --since "1 hour ago" --no-pager -q 2>/dev/null | wc -l | ccount)
if [[ "$JOURNAL_ERR" -le 10 ]]; then
  pass "Journal errors (1h): $JOURNAL_ERR"
elif [[ "$JOURNAL_ERR" -le 50 ]]; then
  warn "Journal errors (1h): $JOURNAL_ERR"
else
  fail "Journal errors (1h): $JOURNAL_ERR"
fi

JOURNAL_CRIT=$(journalctl -p crit --since "24 hours ago" --no-pager -q 2>/dev/null | grep -cvE "sudo|password is required|auth could not identify" || true)
JOURNAL_CRIT=${JOURNAL_CRIT:-0}
if [[ "$JOURNAL_CRIT" -eq 0 ]]; then
  pass "Journal critical (24h): 0"
elif [[ "$JOURNAL_CRIT" -le 20 ]]; then
  warn "Journal critical (24h): $JOURNAL_CRIT"
else
  fail "Journal critical (24h): $JOURNAL_CRIT"
fi

DMESG_ERR=$(dmesg --level=err,crit,alert,emerg 2>/dev/null | wc -l)
if [[ "$DMESG_ERR" -le 5 ]]; then
  pass "dmesg errors: $DMESG_ERR"
else
  warn "dmesg errors: $DMESG_ERR"
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

fi # end logs

###############################################################################
if ! should_skip "performance"; then
header "20" "PERFORMANCE & RESOURCES"
###############################################################################

UPTIME=$(uptime -p)
LOAD=$(cat /proc/loadavg | awk '{print $1, $2, $3}')
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
MEM_PCT=$(free | awk '/^Mem:/ {printf "%.0f", ($3/$2)*100}')
info "RAM: $MEM_USED / $MEM_TOTAL (${MEM_PCT}% used, $MEM_AVAIL available)"
if [[ "$MEM_PCT" -gt 90 ]]; then
  fail "RAM: ${MEM_PCT}% used!"
elif [[ "$MEM_PCT" -gt 75 ]]; then
  warn "RAM: ${MEM_PCT}% used"
else
  pass "RAM: ${MEM_PCT}% used"
fi

SWAP_TOTAL=$(free -h | awk '/^Swap:/ {print $2}')
SWAP_USED=$(free -h | awk '/^Swap:/ {print $3}')
if [[ "$SWAP_TOTAL" != "0B" ]] && [[ "$SWAP_TOTAL" != "0" ]]; then
  info "Swap: $SWAP_USED / $SWAP_TOTAL"
else
  info "No swap configured"
fi

sub_header "Disk Usage"
while read -r line; do
  [[ -z "$line" ]] && continue
  PCT=$(echo "$line" | awk '{print $5}' | tr -d '%')
  MOUNT=$(echo "$line" | awk '{print $6}')
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
done < <(df -h -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n+2)

INODE_PCT=$(df -i / | tail -1 | awk '{print $5}' | tr -d '%')
if [[ "$INODE_PCT" == "-" ]] || [[ -z "$INODE_PCT" ]]; then
  pass "Inodes /: N/A (Btrfs — dynamic)"
elif [[ "$INODE_PCT" -gt 90 ]]; then
  fail "Inodes /: ${INODE_PCT}%"
else
  pass "Inodes /: ${INODE_PCT}%"
fi

IOWAIT=$(vmstat 1 2 2>/dev/null | tail -1 | awk '{print $16}')
if [[ "${IOWAIT:-0}" -gt 20 ]]; then
  warn "I/O wait: ${IOWAIT}%"
else
  pass "I/O wait: ${IOWAIT:-0}%"
fi

sub_header "Top 5 CPU"
if ! $JSON_MODE; then
  while read -r USER CPU MEM CMD; do
    printf "       %s %s%% %s\n" "$USER" "$CPU" "$(echo "$CMD" | cut -c1-60)"
  done < <(ps -eo user,pcpu,pmem,args --sort=-pcpu 2>/dev/null | head -6 | tail -5)
fi

sub_header "Top 5 Memory"
if ! $JSON_MODE; then
  while read -r USER CPU MEM CMD; do
    printf "       %s %s%% %s\n" "$USER" "$MEM" "$(echo "$CMD" | cut -c1-60)"
  done < <(ps -eo user,pcpu,pmem,args --sort=-pmem 2>/dev/null | head -6 | tail -5)
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
    else
      pass "CPU vuln $NAME: $STATUS"
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

# Temperature (new — enhanced)
if require_cmd sensors; then
  # Extract only actual temp readings (value right after "Label: +"), not thresholds
  # in parentheses (high/crit/low values are preceded by "= +" not ": +")
  MAX_TEMP=$(sensors 2>/dev/null | grep -oP ':\s+\+\K\d+\.\d+(?=°C)' | sort -rn | head -1)
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
    done < <(sensors 2>/dev/null | grep -E "°C" | head -10)
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
  DNS_TEST=$(dig +short google.com @1.1.1.1 +time=3 2>/dev/null | head -1 || echo "FAIL")
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

if require_cmd trust; then
  CA_COUNT=$(trust list 2>/dev/null | grep -c "type: certificate" || echo "?")
  info "System CA certificates: $CA_COUNT"
fi

if require_cmd openssl; then
  while read -r cert; do
    if openssl x509 -checkend 0 -in "$cert" -noout 2>&1 | grep -q "will expire"; then
      warn "Expired certificate: $cert"
    fi
  done < <(find /etc/pki/tls/certs -maxdepth 1 \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | grep -v "ca-bundle" | head -20)
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
EXPOSED_KEYS=$(while read -r key; do
  PERMS=$(stat -c %a "$key" 2>/dev/null)
  if [[ "$PERMS" -gt 600 ]]; then
    echo "$key ($PERMS)"
  fi
done < <(find /home /root \( -name "*.key" -o -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \) ! -name "*.pub" ! -path "*/cacert*" ! -path "*/ca-bundle*" ! -path "*public_key*" ! -path "*/roots.pem" 2>/dev/null))
if [[ -z "$EXPOSED_KEYS" ]]; then
  pass "No exposed private keys"
else
  fail "Exposed private keys:"
  if ! $JSON_MODE; then
    while read -r k; do printf "       %s\n" "$k"; done <<< "$EXPOSED_KEYS"
  fi
fi

ENV_FILES=$(find /home /root /opt /srv -name ".env" -readable 2>/dev/null | wc -l)
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
  sub_header "systemd-analyze security (excerpt)"
  for SVC in openclaw-gateway firewalld fail2ban auditd; do
    SCORE=$(systemd-analyze security "$SVC" 2>/dev/null | tail -1 | grep -oP '\d+\.\d+' || echo "N/A")
    if [[ "$SCORE" != "N/A" ]]; then
      SCORE_INT=$(echo "$SCORE" | cut -d. -f1)
      if [[ "$SCORE_INT" -le 3 ]]; then
        pass "systemd-security $SVC: $SCORE"
      elif [[ "$SCORE_INT" -le 6 ]]; then
        info "systemd-security $SVC: $SCORE"
      else
        if [[ "$SVC" == "firewalld" || "$SVC" == "fail2ban" || "$SVC" == "auditd" ]]; then
          info "systemd-security $SVC: $SCORE (security service, needs root)"
        else
          warn "systemd-security $SVC: $SCORE (poor)"
        fi
      fi
    fi
  done
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

# Screen Lock (per-user via DBUS)
if require_cmd gsettings; then
  _gs_lock_check_cb() {
    local user="$1" uid="$2" val
    val=$(echo "$3" | xargs)
    if [[ "$val" == "true" ]]; then
      local delay
      delay=$(_gsettings_user "$user" "$uid" "org.gnome.desktop.screensaver" "lock-delay" 2>/dev/null)
      pass "Screen lock: enabled (delay: ${delay:-?}) [$user]"
    elif [[ "$val" == "false" ]]; then
      warn "Screen lock: disabled [$user]"
    fi
  }
  _gsettings_for_users "org.gnome.desktop.screensaver" "lock-enabled" _gs_lock_check_cb
fi

# Auto-Login
if [[ -f /etc/gdm/custom.conf ]]; then
  if grep -q "AutomaticLoginEnable=True\|AutomaticLoginEnable=true" /etc/gdm/custom.conf 2>/dev/null; then
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

if systemctl is-active chronyd &>/dev/null; then
  pass "chronyd: active"
  if require_cmd chronyc; then
    CHRONY_SOURCES=$(chronyc sources 2>/dev/null | grep -c "^\^" || true)
    CHRONY_SOURCES=${CHRONY_SOURCES:-0}
    info "Chrony sources: $CHRONY_SOURCES"

    # Network Time Security (NTS) check
    # Primary: chronyc authdata shows "NTS" for authenticated sources (chrony 4.0+)
    NTS_SOURCES=$(chronyc -n authdata 2>/dev/null | grep -c "NTS" | ccount)
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
if ! $JSON_MODE; then
  while read -r line; do
    [[ -n "$line" ]] && printf "       %s\n" "$line"
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
if [[ -f /etc/at.allow ]]; then
  pass "at.allow exists (whitelist approach)"
elif [[ -f /etc/at.deny ]]; then
  info "at.deny exists (blacklist approach — at.allow preferred)"
else
  warn "Neither at.allow nor at.deny exists"
fi

fi # end hardening

###############################################################################
if ! should_skip "modules"; then
header "31" "KERNEL MODULES & INTEGRITY"
###############################################################################

# Suspicious kernel modules (new)
sub_header "Suspicious Module Check"
SUSPICIOUS_MODS=$(lsmod 2>/dev/null | awk '{print $1}' | grep -iE "backdoor|rootkit|hide|keylog|sniff|inject" || true)
if [[ -z "$SUSPICIOUS_MODS" ]]; then
  pass "No suspicious kernel modules loaded"
else
  fail "Suspicious kernel modules: $SUSPICIOUS_MODS"
fi

# Unnecessary filesystem modules (new)
sub_header "Disabled Filesystem Modules"
for FS_MOD in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
  if grep -rqs "install $FS_MOD /bin/false\|install $FS_MOD /bin/true" /etc/modprobe.d/ 2>/dev/null; then
    pass "Module $FS_MOD: disabled"
  elif [[ "$FS_MOD" == "squashfs" ]] && command -v flatpak &>/dev/null; then
    info "Module squashfs: loaded (required by Flatpak)"
  else
    if lsmod 2>/dev/null | grep -q "^${FS_MOD}\s"; then
      warn "Module $FS_MOD: loaded (should be disabled)"
    else
      info "Module $FS_MOD: not explicitly disabled (not loaded)"
    fi
  fi
done

# USB storage module
if grep -rqs "install usb[-_]storage /bin/false\|install usb[-_]storage /bin/true\|blacklist usb[-_]storage" /etc/modprobe.d/ 2>/dev/null; then
  pass "USB storage module: disabled"
else
  warn "USB storage module: not disabled"
fi

# Module loading status
if [[ -f /proc/sys/kernel/modules_disabled ]]; then
  MOD_DISABLED=$(cat /proc/sys/kernel/modules_disabled)
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
    elif [[ -d "$CRONDIR" ]] && [[ "$PERMS" -le 755 ]]; then
      pass "$CRONDIR: owner=$OWNER, perms=$PERMS"
    elif [[ -f "$CRONDIR" ]] && [[ "$PERMS" -gt 600 ]]; then
      warn "$CRONDIR permissions: $PERMS (too open for file)"
    else
      pass "$CRONDIR: owner=$OWNER, perms=$PERMS"
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

# Kernel module signing
if [[ -f /proc/sys/kernel/tainted ]]; then
  if grep -q "CONFIG_MODULE_SIG_FORCE=y" /boot/config-"$(uname -r)" 2>/dev/null; then
    pass "Kernel module signature enforcement: enabled"
  else
    info "Kernel module signature enforcement: not forced"
  fi
fi

# Check for multiple kernels
KERNEL_COUNT=$(ls /boot/vmlinuz-* 2>/dev/null | wc -l)
info "Installed kernels: $KERNEL_COUNT"

# systemd-analyze blame top 5 (new)
if require_cmd systemd-analyze; then
  sub_header "Boot Security Analysis"
  # Check for rescue/emergency shell
  if systemctl is-enabled rescue.service &>/dev/null 2>&1; then
    info "Rescue shell: enabled (physical access risk)"
  fi
  if systemctl is-enabled emergency.service &>/dev/null 2>&1; then
    info "Emergency shell: enabled (physical access risk)"
  fi
fi

fi # end boot

###############################################################################
if ! should_skip "integrity"; then
header "34" "SYSTEM INTEGRITY CHECKS"
###############################################################################

# File Integrity — key system binaries
sub_header "Critical Binary Integrity"
if require_cmd rpm; then
  RPM_VA_OUTPUT=$(rpm -Va 2>/dev/null || true)
  RPM_VERIFY_ALL=$(echo "$RPM_VA_OUTPUT" | grep -cE "^..5" || true)
  RPM_VERIFY_ALL=${RPM_VERIFY_ALL:-0}
  RPM_VERIFY_BIN=$(echo "$RPM_VA_OUTPUT" | grep -E "^..5" | grep -cv " c " || true)
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

# Check for world-writable directories in PATH
sub_header "PATH Security"
WW_PATH=0
IFS=: read -ra PATH_DIRS <<< "$PATH"
for DIR in "${PATH_DIRS[@]}"; do
  # Skip symlinks (e.g. /sbin -> /usr/sbin on Fedora)
  [[ -L "$DIR" ]] && continue
  if [[ -d "$DIR" ]] && [[ "$(stat -c %a "$DIR" 2>/dev/null)" =~ [2367]$ ]]; then
    warn "World-writable directory in PATH: $DIR"
    ((WW_PATH++))
  fi
done
if [[ "$WW_PATH" -eq 0 ]]; then
  pass "No world-writable directories in PATH"
fi

fi # end integrity

###############################################################################
# Section 36: Browser Privacy
###############################################################################
check_browser_privacy() {
  should_skip "browser" && return
  header "35" "BROWSER PRIVACY"

  local found_any=false

  _bp_check_user() {
    local user="$1" uid="$2" home="$3"
    # Check all known Firefox profile locations:
    # - Standard:       ~/.mozilla/firefox  (most distros)
    # - XDG-compliant:  ~/.config/mozilla/firefox  (Fedora 33+, some others)
    # - Flatpak:        ~/.var/app/org.mozilla.firefox/.mozilla/firefox
    local ff_dirs=(
      "$home/.mozilla/firefox"
      "$home/.config/mozilla/firefox"
      "$home/.var/app/org.mozilla.firefox/.mozilla/firefox"
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
      if [[ "$val" == "2" || "$val" == "3" ]]; then
        pass "DNS-over-HTTPS active (mode $val) [$label]"
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

  local chrome_bin
  local -A chrome_seen=()
  for chrome_bin in google-chrome google-chrome-stable chromium chromium-browser; do
    if command -v "$chrome_bin" &>/dev/null; then
      local chrome_real
      chrome_real="$(realpath "$(command -v "$chrome_bin")" 2>/dev/null || echo "$chrome_bin")"
      [[ -n "${chrome_seen[$chrome_real]:-}" ]] && continue
      chrome_seen["$chrome_real"]=1
      warn "$chrome_bin installed — Google telemetry/tracking risk"
    fi
  done

  if [[ "$found_any" == false ]]; then
    info "No Firefox profiles found"
  fi
}

###############################################################################
# Section 37: Application Telemetry & Privacy
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
      age="${age//[^0-9]/}"
      if [[ -n "$age" && "$age" -le 7 && "$age" -gt 0 ]]; then
        info "Recent files kept for ${age} days [$user]"
      elif [[ "$age" == "0" ]]; then
        warn "Recent files kept forever [$user]"
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

  if systemctl is-active --quiet tracker-miner-fs-3.service 2>/dev/null || \
     systemctl is-active --quiet tracker-miner-fs.service 2>/dev/null; then
    warn "GNOME Tracker file indexer active — indexes all files"
  else
    pass "GNOME Tracker file indexer not running"
  fi

  if command -v flatpak &>/dev/null; then
    local dangerous=0
    local app
    while IFS= read -r app; do
      [[ -z "$app" ]] && continue
      local perms
      perms="$(flatpak info --show-permissions "$app" 2>/dev/null)"
      if echo "$perms" | grep -qE "filesystems=host([;,[:space:]]|$)|filesystems=host-os([;,[:space:]]|$)|talk-name=org\.freedesktop\.Flatpak"; then
        warn "Flatpak '$app' has dangerous permissions (host filesystem or Flatpak portal)"
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
    if snap get system system.telemetry.enabled 2>/dev/null | grep -qi "true"; then
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
    if [[ -f "$dnf_conf" ]] && grep -qi "^countme\s*=\s*true" "$dnf_conf" 2>/dev/null; then
      warn "Fedora countme enabled in dnf.conf"
    elif [[ -f "$dnf_conf" ]] && grep -qi "^countme\s*=\s*false" "$dnf_conf" 2>/dev/null; then
      pass "Fedora countme disabled in dnf.conf"
    else
      info "Fedora countme not set (default: enabled per-repo)"
    fi
  fi

  if [[ "$DISTRO_FAMILY" == "debian" ]]; then
    if dpkg -l popularity-contest &>/dev/null 2>&1; then
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

  local nm_conf="/etc/NetworkManager/NetworkManager.conf"
  if [[ -f "$nm_conf" ]]; then
    if grep -qi "^\[connectivity\]" "$nm_conf" 2>/dev/null; then
      local uri
      uri="$(sed -n '/^\[connectivity\]/,/^\[/{ s/^uri\s*=\s*//p; }' "$nm_conf" 2>/dev/null)"
      if [[ -z "$uri" || "$uri" == "" ]]; then
        pass "NetworkManager connectivity check disabled"
      else
        info "NetworkManager connectivity check active (pings $uri)"
      fi
    else
      info "NetworkManager connectivity check uses default (may phone home)"
    fi
  fi

  if [[ -f "/etc/NetworkManager/conf.d/20-connectivity-fedora.conf" ]]; then
    info "Fedora connectivity check config present"
  fi
}

###############################################################################
# Section 38: Network Privacy
###############################################################################
check_network_privacy() {
  should_skip "netprivacy" && return
  header "37" "NETWORK PRIVACY"

  local nm_wifi_rand=""
  local conf_file
  for conf_file in /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/conf.d/*.conf; do
    [[ -f "$conf_file" ]] || continue
    local val
    val="$(sed -n '/^\[device\]/,/^\[/{ s/^wifi\.scan-rand-mac-address\s*=\s*//p; }' "$conf_file" 2>/dev/null)"
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
    val="$(sed -n '/^\[connection\]/,/^\[/{ s/^ethernet\.cloned-mac-address\s*=\s*//p; }' "$conf_file" 2>/dev/null)"
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
      pub_host="$(sed -n '/^\[publish\]/,/^\[/{ s/^publish-hostname\s*=\s*//p; }' "$avahi_conf" 2>/dev/null)"
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
    llmnr_val="$(grep -i "^LLMNR\s*=" "$resolved_conf" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')"
  fi
  # Also check drop-in files
  for dropin in /etc/systemd/resolved.conf.d/*.conf; do
    [[ -f "$dropin" ]] || continue
    local dval
    dval="$(grep -i "^LLMNR\s*=" "$dropin" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')"
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
  while IFS=: read -r user _ uid _ gecos _ _; do
    [[ "$uid" -ge 1000 ]] || continue
    local first_name="${gecos%%,*}"
    first_name="${first_name%% *}"
    [[ -z "$first_name" ]] && first_name="$user"
    if [[ "${hostname,,}" == *"${first_name,,}"* && ${#first_name} -ge 3 ]]; then
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
  local _ipv6_nm_disabled=false
  if require_cmd nmcli; then
    while IFS= read -r _cname; do
      [[ -z "$_cname" ]] && continue
      local _ipv6method
      _ipv6method=$(nmcli -t -f ipv6.method connection show "$_cname" 2>/dev/null | grep -oP '(?<=ipv6\.method:).*' | head -1)
      if [[ "$_ipv6method" == "disabled" ]]; then
        _ipv6_nm_disabled=true
        break
      fi
    done < <(nmcli -t -f NAME connection show --active 2>/dev/null)
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
      if [[ "$_method" == "auto" || "$_method" == "link-local" ]]; then
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
    for conf_file in /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/conf.d/*.conf; do
      [[ -f "$conf_file" ]] || continue
      local val
      val="$(sed -n '/^\[ipv4\]/,/^\[/{ s/^dhcp-send-hostname\s*=\s*//p; }' "$conf_file" 2>/dev/null)"
      [[ -n "$val" ]] && dhcp_hostname="$val"
    done
    if [[ "$dhcp_hostname" == "false" || "$dhcp_hostname" == "no" ]]; then
      pass "DHCP hostname sending disabled"
    else
      warn "DHCP sends hostname to network (dhcp-send-hostname=${dhcp_hostname:-true})"
    fi
  fi

  local mdns_val=""
  if [[ -f "$resolved_conf" ]]; then
    mdns_val="$(grep -i "^MulticastDNS\s*=" "$resolved_conf" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')"
  fi
  for dropin in /etc/systemd/resolved.conf.d/*.conf; do
    [[ -f "$dropin" ]] || continue
    local dval
    dval="$(grep -i "^MulticastDNS\s*=" "$dropin" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')"
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

  if systemctl is-active --quiet cups-browsed.service 2>/dev/null; then
    fail "cups-browsed active — CVE-2024-47176 Remote Code Execution risk!"
  elif systemctl is-enabled --quiet cups-browsed.service 2>/dev/null; then
    warn "cups-browsed enabled but not running — consider disabling"
  else
    pass "cups-browsed not active"
  fi
}

###############################################################################
# Section 39: Data & Disk Privacy
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

    local histfile="$home/.bash_history"
    local bashrc="$home/.bashrc"
    if [[ -f "$histfile" ]]; then
      local lines
      lines="$(wc -l < "$histfile" 2>/dev/null || true)"
      lines=${lines:-0}
      if [[ "$lines" -gt 10000 ]]; then
        warn "Bash history has $lines lines [$user] — may contain sensitive data"
      fi
    fi
    if [[ -f "$bashrc" ]]; then
      local histsize
      histsize="$(grep -oP '^HISTSIZE=\K\d+' "$bashrc" 2>/dev/null | tail -1)"
      if [[ -n "$histsize" && "$histsize" -gt 10000 ]]; then
        warn "HISTSIZE=$histsize (very large) [$user]"
      fi
      local histfilesize
      histfilesize="$(grep -oP '^HISTFILESIZE=\K\d+' "$bashrc" 2>/dev/null | tail -1)"
      if [[ -n "$histfilesize" && "$histfilesize" -gt 10000 ]]; then
        warn "HISTFILESIZE=$histfilesize (very large) [$user]"
      fi
    fi
  }

  _for_each_user _dp_check_user

  local clip_procs=("gpaste-daemon" "klipper" "clipman" "clipit" "parcellite" "copyq" "xclip" "greenclip")
  local clip_found=false
  local proc
  for proc in "${clip_procs[@]}"; do
    if pgrep -x "$proc" &>/dev/null; then
      warn "Clipboard manager '$proc' running — may store passwords in memory"
      clip_found=true
    fi
  done
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
      pass "Core dumps disabled (systemd-coredump storage=none)"
    else
      warn "Core dumps via systemd-coredump (storage=${core_storage:-external}) — may contain secrets"
    fi
  elif [[ "$core_pattern" == "|"* ]]; then
    info "Core dumps piped to: ${core_pattern:0:60}"
  elif [[ "$core_soft" == "0" ]]; then
    pass "Core dumps disabled (soft ulimit = 0)"
  else
    warn "Core dumps enabled (pattern: ${core_pattern:-core}) — crash dumps may contain secrets"
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
# Section 40: Desktop Session Security
###############################################################################
check_desktop_session() {
  should_skip "session" && return
  header "39" "DESKTOP SESSION SECURITY"

  local found_lock_delay=0
  _gs_lock_delay_cb() {
    found_lock_delay=1
    local delay
    delay=$(echo "$3" | sed "s/uint32 //;s/'//g" | tr -d ' ')
    if [[ "$delay" == "0" ]]; then
      pass "Screen lock delay is 0 (instant) for $1"
    else
      fail "Screen lock delay is ${delay}s for $1 (should be 0)"
    fi
  }
  _gsettings_for_users "org.gnome.desktop.screensaver" "lock-delay" _gs_lock_delay_cb
  [[ "$found_lock_delay" -eq 0 ]] && info "No active GNOME sessions found for lock-delay check"

  local found_idle=0
  _gs_idle_cb() {
    found_idle=1
    local delay
    delay=$(echo "$3" | sed "s/uint32 //;s/'//g" | tr -d ' ')
    if [[ "$delay" == "0" ]]; then
      warn "Idle timeout disabled for $1 (screen never blanks)"
    elif [[ "$delay" -le 300 ]]; then
      pass "Idle timeout is ${delay}s for $1"
    else
      fail "Idle timeout is ${delay}s for $1 (should be ≤ 300)"
    fi
  }
  _gsettings_for_users "org.gnome.desktop.session" "idle-delay" _gs_idle_cb
  [[ "$found_idle" -eq 0 ]] && info "No active GNOME sessions found for idle-delay check"

  local found_lock_suspend=0
  _gs_lock_suspend_cb() {
    found_lock_suspend=1
    local val
    val=$(echo "$3" | xargs)
    if [[ "$val" == "true" ]]; then
      pass "Lock on suspend enabled for $1"
    else
      fail "Lock on suspend disabled for $1"
    fi
  }
  _gsettings_for_users "org.gnome.desktop.screensaver" "ubuntu-lock-on-suspend" _gs_lock_suspend_cb
  if [[ "$found_lock_suspend" -eq 0 ]]; then
    _gsettings_for_users "org.gnome.desktop.screensaver" "lock-enabled" _gs_lock_suspend_cb
  fi
  [[ "$found_lock_suspend" -eq 0 ]] && info "No active GNOME sessions found for lock-on-suspend check"

  local found_notif=0
  _gs_notif_cb() {
    found_notif=1
    local val
    val=$(echo "$3" | xargs)
    if [[ "$val" == "false" ]]; then
      pass "Lock screen notifications hidden for $1"
    else
      warn "Lock screen shows notification previews for $1"
    fi
  }
  _gsettings_for_users "org.gnome.desktop.notifications" "show-in-lock-screen" _gs_notif_cb
  [[ "$found_notif" -eq 0 ]] && info "No active GNOME sessions for notification check"

  local autologin_found=0
  for conf in /etc/gdm*/custom.conf /etc/gdm*/daemon.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qi '^\s*AutomaticLoginEnable\s*=\s*true' "$conf" 2>/dev/null; then
      local autouser
      autouser=$(grep -i '^\s*AutomaticLogin\s*=' "$conf" | head -1 | cut -d= -f2 | xargs)
      fail "Auto-login enabled in $conf${autouser:+ (user: $autouser)}"
      autologin_found=1
    fi
  done
  [[ "$autologin_found" -eq 0 ]] && pass "No GDM auto-login configured"

  local guest_found=0
  if [[ -d /etc/lightdm ]]; then
    if grep -rqs '^\s*allow-guest\s*=\s*true' /etc/lightdm/; then
      fail "LightDM guest account enabled"
      guest_found=1
    fi
  fi
  for conf in /etc/gdm*/custom.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qi '^\s*TimedLoginEnable\s*=\s*true' "$conf" 2>/dev/null; then
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
    local vnc_listen
    vnc_listen=$(ss -tlnp 2>/dev/null | grep -E ':590[0-9]|:3389' | head -3)
    if [[ -n "$vnc_listen" ]]; then
      warn "VNC/RDP port listening detected"
      remote_found=1
    fi
  fi
  _gs_rdp_cb() {
    remote_found=1
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
  _gs_switch_cb() {
    found_switch=1
    local val
    val=$(echo "$3" | xargs)
    if [[ "$val" == "true" ]]; then
      pass "User switching restricted for $1"
    else
      info "User switching allowed for $1"
    fi
  }
  _gsettings_for_users "org.gnome.desktop.lockdown" "disable-user-switching" _gs_switch_cb
  [[ "$found_switch" -eq 0 ]] && info "No active sessions for user-switch check"

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
      if grep -rqs 'disable-user-list\s*=\s*true' "$db/"; then
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
      warn "User list visible on login screen (attackers can enumerate users)"
    fi
  else
    info "GDM not found — skipping user-list check"
  fi
}

###############################################################################
# Section 41: Webcam & Audio Privacy
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
    if grep -rqs 'module-protocol-pulse.*tcp' /etc/pipewire/ /usr/share/pipewire/ 2>/dev/null; then
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
  if systemctl --user is-active xdg-desktop-portal.service &>/dev/null 2>&1; then
    info "Portal service active for current user"
  fi
}

###############################################################################
# Section 42: Bluetooth Privacy
###############################################################################
check_bluetooth_privacy() {
  should_skip "btprivacy" && return
  header "41" "BLUETOOTH PRIVACY"

  if ! command -v bluetoothctl &>/dev/null && ! systemctl list-unit-files bluetooth.service &>/dev/null 2>&1; then
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

  if [[ "$paired_count" -eq 0 ]]; then
    warn "Bluetooth active with no paired devices — consider disabling"
  fi
}

###############################################################################
# Section 43: Password & Keyring Security
###############################################################################
check_keyring_security() {
  should_skip "keyring" && return
  header "42" "PASSWORD & KEYRING SECURITY"

  local pm_found=0
  local pm_list=""
  for pm in keepassxc keepass2 bitwarden 1password op pass gopass; do
    if command -v "$pm" &>/dev/null; then
      pm_found=1
      pm_list="${pm_list:+$pm_list, }$pm"
    fi
  done
  if flatpak list 2>/dev/null | grep -qi 'bitwarden\|keepass\|1password'; then
    pm_found=1
    pm_list="${pm_list:+$pm_list, }(flatpak)"
  fi
  if snap list 2>/dev/null | grep -qi 'bitwarden\|keepass\|1password'; then
    pm_found=1
    pm_list="${pm_list:+$pm_list, }(snap)"
  fi
  if [[ "$pm_found" -eq 1 ]]; then
    pass "Password manager installed: $pm_list"
  else
    warn "No password manager detected (consider keepassxc, bitwarden, or pass)"
  fi

  local keyring_pam=0
  for pamfile in /etc/pam.d/gdm-password /etc/pam.d/gdm-autologin /etc/pam.d/login /etc/pam.d/lightdm; do
    [[ -f "$pamfile" ]] || continue
    if grep -qs 'pam_gnome_keyring.so' "$pamfile"; then
      keyring_pam=1
      info "GNOME Keyring auto-unlock configured in $(basename "$pamfile")"
    fi
  done
  [[ "$keyring_pam" -eq 0 ]] && info "GNOME Keyring PAM auto-unlock not found"

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

  local secrets_found=0
  local secret_patterns=(".password" ".secret" ".credentials" ".env" "passwords.txt" "secrets.txt" ".netrc")
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    [[ -d "$home" ]] || continue
    for pat in "${secret_patterns[@]}"; do
      local target="$home/$pat"
      if [[ -f "$target" && -s "$target" ]]; then
        fail "Plaintext secret file found: $target"
        secrets_found=1
      fi
    done
    if [[ -f "$home/.netrc" ]]; then
      local perms
      perms=$(stat -c '%a' "$home/.netrc" 2>/dev/null)
      if [[ "$perms" != "600" && "$perms" != "400" ]]; then
        fail ".netrc has insecure permissions ($perms) for $user"
      fi
    fi
  done < /etc/passwd
  [[ "$secrets_found" -eq 0 ]] && pass "No obvious plaintext secret files found"

  if command -v fwupdmgr &>/dev/null; then
    local fw_output
    fw_output=$(timeout 15 fwupdmgr get-updates --no-unreported-check 2>/dev/null)
    local fw_exit=$?
    if [[ $fw_exit -eq 0 && -n "$fw_output" ]]; then
      local update_count
      update_count=$(echo "$fw_output" | grep -c '│\|New version')
      if [[ "$update_count" -gt 0 ]]; then
        warn "Firmware updates available (run: fwupdmgr update)"
      else
        pass "Firmware is up to date"
      fi
    elif [[ $fw_exit -eq 2 ]] || echo "$fw_output" | grep -qi 'no upgrades\|no updates'; then
      pass "Firmware is up to date"
    else
      info "Could not check firmware updates"
    fi
  else
    info "fwupdmgr not installed — cannot check firmware updates"
  fi

  local tb_found=0
  for dev in /sys/bus/thunderbolt/devices/*/security; do
    [[ -f "$dev" ]] || continue
    tb_found=1
    local level
    level=$(cat "$dev" 2>/dev/null)
    local devname
    devname=$(basename "$(dirname "$dev")")
    case "$level" in
      none)
        fail "Thunderbolt device $devname: security level NONE (DMA attacks possible)"
        ;;
      user)
        pass "Thunderbolt device $devname: user authorization required"
        ;;
      secure)
        pass "Thunderbolt device $devname: secure connect (key verification)"
        ;;
      dponly)
        pass "Thunderbolt device $devname: DisplayPort only (no PCIe tunneling)"
        ;;
      *)
        info "Thunderbolt device $devname: security level '$level'"
        ;;
    esac
  done
  if [[ "$tb_found" -eq 0 ]]; then
    if [[ -d /sys/bus/thunderbolt ]]; then
      info "Thunderbolt bus present but no devices connected"
    else
      info "No Thunderbolt controller detected"
    fi
  fi
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
# Example: 200 PASS, 5 FAIL, 10 WARN → 200*100 / (200 + 10 + 10) = 90%
SCORE_DENOM=$((PASS + FAIL * 2 + WARN))
if [[ "$SCORE_DENOM" -gt 0 ]]; then
  SCORE=$(( (PASS * 100) / SCORE_DENOM ))
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
  printf '  ]\n'
  printf '}\n'
else
  # --- Normal Summary Output ---
  echo ""
  printf "${BOLD}${WHT}╔══════════════════════════════════════════════════════════════════════╗${RST}\n"
  printf "${BOLD}${WHT}║                          FINAL RESULTS${RST}\n"
  printf "${BOLD}${WHT}╠══════════════════════════════════════════════════════════════════════╣${RST}\n"
  printf "${BOLD}${WHT}║${RST}  Total checks:      ${BOLD}$((PASS + FAIL + WARN + INFO))${RST} ($PASS pass, $FAIL fail, $WARN warn, $INFO info)\n"
  printf "${BOLD}${WHT}║${RST}  ${GRN}✅ Passed:${RST}           ${BOLD}$PASS${RST}\n"
  printf "${BOLD}${WHT}║${RST}  ${RED}🔴 Failed:${RST}           ${BOLD}$FAIL${RST}\n"
  printf "${BOLD}${WHT}║${RST}  ${YLW}⚠️  Warnings:${RST}        ${BOLD}$WARN${RST}\n"
  printf "${BOLD}${WHT}║${RST}  ${CYN}ℹ️  Info:${RST}             ${BOLD}$INFO${RST}\n"
  printf "${BOLD}${WHT}╠══════════════════════════════════════════════════════════════════════╣${RST}\n"
  printf "${BOLD}${WHT}║${RST}  Score formula:     PASS×100 / (PASS + FAIL×2 + WARN)\n"
  printf "${BOLD}${WHT}║${RST}  ${BOLD}SECURITY & PRIVACY SCORE:${RST}    ${RATING_COLOR}${BOLD}${SCORE}%% ${RATING}${RST}\n"
  printf "${BOLD}${WHT}║${RST}  Kernel:            $KERNEL\n"
  printf "${BOLD}${WHT}║${RST}  Uptime:            $(uptime -p 2>/dev/null || echo 'N/A')\n"
  printf "${BOLD}${WHT}║${RST}  Scan duration:     ${DURATION} seconds\n"
  printf "${BOLD}${WHT}╚══════════════════════════════════════════════════════════════════════╝${RST}\n"
  echo ""
  printf "${CYN}Report generated: $NOW${RST}\n"
  printf "${CYN}by NexusOne23 & Claude 🤖 — NoID Privacy for Linux v${NOID_PRIVACY_VERSION} | https://noid-privacy.com/linux.html${RST}\n"

  # --- AI Mode Output ---
  if $AI_MODE; then
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "NoID Privacy for Linux AI ASSISTANT PROMPT"
    echo "═══════════════════════════════════════════════════"
    echo ""
    echo "Copy everything below and paste it to your AI assistant (ChatGPT, Claude, Gemini, etc.):"
    echo ""
    echo "---START---"
    echo "I ran NoID Privacy for Linux v${NOID_PRIVACY_VERSION} (Privacy & Security Audit) on my system."
    echo "Here are the findings that need attention:"
    echo ""
    echo "System: ${DISTRO_PRETTY} ${KERNEL} ${DESKTOP_ENV}"
    echo ""
    echo "FAILED:"
    if [[ ${#FAIL_MSGS[@]} -eq 0 ]]; then
      echo "- (none)"
    else
      for msg in "${FAIL_MSGS[@]}"; do
        echo "- $msg"
      done
    fi
    echo ""
    echo "WARNINGS:"
    if [[ ${#WARN_MSGS[@]} -eq 0 ]]; then
      echo "- (none)"
    else
      for msg in "${WARN_MSGS[@]}"; do
        echo "- $msg"
      done
    fi
    echo ""
    echo "Please help me fix these issues. For each one:"
    echo "1. Explain what the risk is (one sentence)"
    echo "2. Show me the exact command to fix it"
    echo "3. Tell me if the fix could break anything (Bluetooth, WiFi, GPU, etc.)"
    echo "4. Ask me before applying anything destructive"
    echo ""
    echo "Focus on FAILs first, then WARNs. Skip INFO items."
    echo "---END---"
  fi
fi

fi # end summary
