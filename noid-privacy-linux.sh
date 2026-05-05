#!/usr/bin/env bash
###############################################################################
#  NoID Privacy for Linux v3.6.1 — Hardening Posture Audit
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
#  420+ checks across 42 sections
#  Requires: root
###############################################################################
NOID_PRIVACY_VERSION="3.6.2"
set +e          # Don't exit on errors — we handle them ourselves

# F-341 (v3.6.1): bumped from 4.0 to 4.3. The script uses ${arr[-1]} (negative
# array indices, Section 1 latest-kernel detection line ~1228) which is a
# Bash 4.3+ feature — Bash 4.0-4.2 emits "bad array subscript" and the kernel
# version detection silently fails. Other 4.0-only features (associative
# arrays, mapfile, ${var^^}/${var,,}) work down to 4.0, but the negative-index
# usage is the binding minimum. Bash 4.3 was released in 2014; modern distros
# all ship 5.x — this only affects very old legacy systems.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
  echo "Error: Bash 4.3+ required (found ${BASH_VERSION})" >&2; exit 1
fi

# --- Argument Parsing ---
NO_COLOR=false
AI_MODE=false
JSON_MODE=false
VERBOSE=false
COMPLIANCE_MODE=""    # v3.9: cis-l1 / cis-l2 / stig — emits coverage report
declare -a SKIP_SECTIONS=()
declare -a FAIL_MSGS=()
declare -a WARN_MSGS=()
declare -a JSON_FINDINGS=()
CURRENT_SECTION=""
CURRENT_SECTION_ID=""

show_help() {
  cat <<EOF
Usage: noid-privacy-linux.sh [OPTIONS]

🛡️  NoID Privacy for Linux v${NOID_PRIVACY_VERSION} — Hardening Posture Audit

Options:
  --help          Show this help message
  --no-color      Disable color output (for logs/pipes)
  --ai            Generate AI assistant prompt with findings at the end
  --json          Output results as JSON only (no normal output)
  --verbose, -v   Show every individual PASS (boot params, sysctl).
                  Default: aggregate PASSes into summaries for cleaner output.
                  --json always includes full detail regardless of this flag.
  --offline       Skip all sections that make network requests
                  (equivalent to --skip vpn --skip interfaces --skip netleaks)
  --cis-l1        Append CIS RHEL 9 Level 1 coverage report at end.
                  See Docs/CIS_RHEL9_MAPPING.md for the mapping table.
  --cis-l2        Append CIS RHEL 9 Level 2 coverage report at end.
  --stig          Append DISA STIG coverage report at end.
  --skip SECTION  Skip a section (can be repeated)
                  Sections (in display order): kernel, selinux, firewall,
                  nftables, vpn, sysctl, services, ports, ssh, audit,
                  users, filesystem, crypto, updates, rootkit, processes,
                  network, containers, logs, performance, hardware,
                  interfaces, certificates, environment, systemd, desktop,
                  ntp, fail2ban, logins, hardening, modules, permissions,
                  boot, integrity, browser, telemetry, netprivacy,
                  dataprivacy, session, media, btprivacy, keyring
                  Virtual flags (sub-checks, not full sections):
                  netleaks (network-side leak tests in vpn section),
                  summary (final results block)

Environment variables (v3.7+ opt-in detection-depth features):
  NOID_AIDE_LIVE=1            Run actual aide --check (slow: up to 5min)
  NOID_RPM_BASELINE_INIT=1    Capture current rpm -V state as baseline
  NOID_RPM_BASELINE_UPDATE=1  Update existing baseline with current state

Examples:
  sudo bash noid-privacy-linux.sh
  sudo bash noid-privacy-linux.sh --no-color > report.txt
  sudo bash noid-privacy-linux.sh --skip rootkit --skip containers
  sudo bash noid-privacy-linux.sh --ai
  sudo bash noid-privacy-linux.sh --json | jq .
  sudo NOID_AIDE_LIVE=1 bash noid-privacy-linux.sh --skip rootkit
  sudo NOID_RPM_BASELINE_INIT=1 bash noid-privacy-linux.sh
  sudo bash noid-privacy-linux.sh --verbose            # full PASS detail

420+ checks. Requires root. Tested on Fedora 43, RHEL 9, Debian 12, Ubuntu 24.04.
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) show_help ;;
    --no-color) NO_COLOR=true; shift ;;
    --ai) AI_MODE=true; shift ;;
    --json) JSON_MODE=true; NO_COLOR=true; shift ;;
    --verbose|-v) VERBOSE=true; shift ;;
    --cis-l1) COMPLIANCE_MODE="cis-l1"; shift ;;
    --cis-l2) COMPLIANCE_MODE="cis-l2"; shift ;;
    --stig) COMPLIANCE_MODE="stig"; shift ;;
    --skip) [[ -z "${2:-}" ]] && { echo "Error: --skip requires a section name"; exit 1; }; SKIP_SECTIONS+=("$2"); shift 2 ;;
    --offline) SKIP_SECTIONS+=("vpn" "interfaces" "netleaks"); shift ;;
    *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
  esac
done

# --ai and --json now combine: JSON output includes ai_prompt as a field
# (eliminates the entrypoint.sh double-run problem — F-272 era integration).

should_skip() {
  local section="$1" s
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

# F-014: SECTION_KEYS is the single source of truth for the 42-section
# audit. TOTAL_SECTIONS is derived; --help (above) lists the same keys
# manually but the count is now authoritative from this array.
declare -a SECTION_KEYS=(
  kernel selinux firewall nftables vpn sysctl services ports ssh audit
  users filesystem crypto updates rootkit processes network containers
  logs performance hardware interfaces certificates environment systemd
  desktop ntp fail2ban logins hardening modules permissions boot integrity
  browser telemetry netprivacy dataprivacy session media btprivacy keyring
)
PASS=0; FAIL=0; WARN=0; INFO=0
TOTAL_START=$(date +%s)
TOTAL_SECTIONS="${#SECTION_KEYS[@]}"

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

# Severity emitters — underscore-prefix prevents name collision with CLI tools
# (e.g. `pass` from password-store, `info` from texinfo) when scanning $PATH
# via `command -v`. v3.6 refactor of pass()/fail()/warn()/info().
_emit_pass() {
  PASS=$((PASS + 1))
  if $JSON_MODE; then
    JSON_FINDINGS+=("{\"severity\":\"PASS\",\"section\":\"$(_json_escape "$CURRENT_SECTION")\",\"section_id\":\"$(_json_escape "${CURRENT_SECTION_ID:-unknown}")\",\"message\":\"$(_json_escape "$1")\"}")
  else
    printf "  ${GRN}✅ PASS${RST}  %s\n" "$1"
  fi
}
_emit_fail() {
  FAIL=$((FAIL + 1))
  FAIL_MSGS+=("$1")
  if $JSON_MODE; then
    JSON_FINDINGS+=("{\"severity\":\"FAIL\",\"section\":\"$(_json_escape "$CURRENT_SECTION")\",\"section_id\":\"$(_json_escape "${CURRENT_SECTION_ID:-unknown}")\",\"message\":\"$(_json_escape "$1")\"}")
  else
    printf "  ${RED}🔴 FAIL${RST}  %s\n" "$1"
  fi
}
_emit_warn() {
  WARN=$((WARN + 1))
  WARN_MSGS+=("$1")
  if $JSON_MODE; then
    JSON_FINDINGS+=("{\"severity\":\"WARN\",\"section\":\"$(_json_escape "$CURRENT_SECTION")\",\"section_id\":\"$(_json_escape "${CURRENT_SECTION_ID:-unknown}")\",\"message\":\"$(_json_escape "$1")\"}")
  else
    printf "  ${YLW}⚠️  WARN${RST}  %s\n" "$1"
  fi
}
_emit_info() {
  INFO=$((INFO + 1))
  if $JSON_MODE; then
    JSON_FINDINGS+=("{\"severity\":\"INFO\",\"section\":\"$(_json_escape "$CURRENT_SECTION")\",\"section_id\":\"$(_json_escape "${CURRENT_SECTION_ID:-unknown}")\",\"message\":\"$(_json_escape "$1")\"}")
  else
    printf "  ${CYN}ℹ️  INFO${RST}  %s\n" "$1"
  fi
}

# PASS-aggregation helpers — collapse N individual PASSes into one summary
# unless --verbose or --json (JSON consumers always need detail).
# Score-impact preserved: each aggregated item still increments PASS counter.
_AGG_LABEL=""
declare -a _AGG_ITEMS=()
_emit_pass_agg_start() {
  _AGG_LABEL="$1"
  _AGG_ITEMS=()
}
_emit_pass_agg() {
  if $VERBOSE || $JSON_MODE; then
    _emit_pass "$_AGG_LABEL: $1"
  else
    # `((PASS++))` returns 1 when PASS was 0 (post-increment value = old);
    # under `set -e` (used by BATS) that aborts. Use plain assignment.
    PASS=$((PASS + 1))         # increment counter, defer message until _end
    _AGG_ITEMS+=("$1")
  fi
}
_emit_pass_agg_end() {
  local _total="$1" _suffix="${2:-set}"
  if ! $VERBOSE && ! $JSON_MODE; then
    local _count="${#_AGG_ITEMS[@]}"
    if [[ "$_count" -gt 0 ]]; then
      printf "  ${GRN}✅ PASS${RST}  %s: %d/%d %s\n" \
        "$_AGG_LABEL" "$_count" "$_total" "$_suffix"
    fi
  fi
  _AGG_ITEMS=()
  _AGG_LABEL=""
}
header() {
  # F-010: Track stable section ID alongside human-readable name. The
  # section number ($1, 2-digit) maps to SECTION_KEYS array (0-indexed).
  # Sections 02 has 3 variants (SELINUX/APPARMOR/MAC) all sharing key
  # "selinux"; otherwise ${SECTION_KEYS[N-1]} = the canonical key.
  local _num="$1" _name="$2"
  local _idx=$((10#$_num - 1))
  CURRENT_SECTION="$_name"
  if [[ "$_idx" -ge 0 && "$_idx" -lt "${#SECTION_KEYS[@]}" ]]; then
    CURRENT_SECTION_ID="${SECTION_KEYS[$_idx]}"
  else
    CURRENT_SECTION_ID="unknown"
  fi
  if ! $JSON_MODE; then
    printf "\n${BOLD}${MAG}━━━ [%s/%s] %s ━━━${RST}\n" "$_num" "$TOTAL_SECTIONS" "$_name"
  fi
}
sub_header() { $JSON_MODE || printf "  ${CYN}--- %s ---${RST}\n" "$1"; }
txt() { $JSON_MODE || printf "%s\n" "$1"; }

# --- Dependency Check Helper ---
require_cmd() {
  command -v "$1" &>/dev/null
}

# --- Capability Detection Layer (v3.8) ---
# Eliminates the bug class where API-version differences across distros
# silently break checks. Section code uses _fw_*, _systemd_* helpers
# instead of raw command invocations.
#
# Detected capabilities populate $_CAPS[]. Call _detect_capabilities once
# at startup; helpers below consult the array.
declare -A _CAPS=()
_detect_capabilities() {
  # firewalld: --get-policies replaced --list-policies in 0.9+
  if command -v firewall-cmd &>/dev/null; then
    if firewall-cmd --get-policies &>/dev/null; then  # CAP-LINT-EXEMPT
      _CAPS[firewalld_policies]="--get-policies"
    elif firewall-cmd --list-policies &>/dev/null; then  # CAP-LINT-EXEMPT
      _CAPS[firewalld_policies]="--list-policies"
    else
      _CAPS[firewalld_policies]=""
    fi
    _CAPS[firewalld_version]=$(firewall-cmd --version 2>/dev/null | head -1)
  fi
  # systemctl: `is-masked` verb does NOT exist (Bug Pattern #4).
  # Always use is-enabled and parse output.
  _CAPS[systemd_masked_method]="is-enabled-output"
  if command -v systemctl &>/dev/null; then
    _CAPS[systemd_version]=$(systemctl --version 2>/dev/null \
      | head -1 | grep -oP 'systemd \K[0-9]+')
  fi
  # nftables version (informational)
  if command -v nft &>/dev/null; then
    _CAPS[nft_version]=$(nft --version 2>/dev/null \
      | grep -oP 'v\K[0-9.]+' | head -1)
  fi
}
# Helper: list firewalld policies via the detected flag (or empty if N/A)
_fw_get_policies() {
  local _flag="${_CAPS[firewalld_policies]:-}"
  [[ -z "$_flag" ]] && return 1
  firewall-cmd "$_flag" 2>/dev/null
}
# Note: a functionally identical _service_masked_any() helper already exists
# in the script body (around line 800) — kept there for backwards-compat with
# existing callers; capability layer documents the method via _CAPS.
# Run capability detection once at startup
_detect_capabilities

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

# F-004: read UID_MIN/UID_MAX from /etc/login.defs to honor distro-specific
# bounds. Defaults match RHEL/Fedora (1000-65533, excluding nobody at 65534)
# but are overridable. Cached at first read into _NOID_UID_MIN/_NOID_UID_MAX.
# All section-body UID checks use `_is_human_uid "$uid"` (consistency fix
# v3.5.x — formerly hardcoded `[[ "$uid" -ge 1000 && "$uid" -lt 65534 ]]`
# pattern in 14+ places, now centralized).
_NOID_UID_MIN=""
_NOID_UID_MAX=""
_load_uid_bounds() {
  [[ -n "$_NOID_UID_MIN" ]] && return  # already loaded
  if [[ -f /etc/login.defs ]]; then
    _NOID_UID_MIN=$(awk '$1=="UID_MIN" {print $2; exit}' /etc/login.defs 2>/dev/null)
    _NOID_UID_MAX=$(awk '$1=="UID_MAX" {print $2; exit}' /etc/login.defs 2>/dev/null)
  fi
  _NOID_UID_MIN="${_NOID_UID_MIN:-1000}"
  _NOID_UID_MAX="${_NOID_UID_MAX:-65533}"  # exclude nobody (65534) by default
}
_is_human_uid() {
  _load_uid_bounds
  local uid="$1"
  [[ "$uid" =~ ^[0-9]+$ ]] || return 1
  [[ "$uid" -ge "$_NOID_UID_MIN" && "$uid" -le "$_NOID_UID_MAX" ]]
}

# Iterate over user home directories across classic + Atomic Fedora layouts.
# Yields one path per line on stdout, deduplicated by canonical path so that
# `/home/nexus` (Silverblue symlink to `/var/home/nexus`) and `/var/home/nexus`
# are not both returned.
_iter_user_homes() {
  local seen=() resolved h s already
  shopt -s nullglob
  for h in /home/* /var/home/* /root; do
    [[ -d "$h" ]] || continue
    resolved=$(realpath -- "$h" 2>/dev/null) || resolved="$h"
    already=false
    for s in "${seen[@]}"; do
      [[ "$s" == "$resolved" ]] && { already=true; break; }
    done
    $already && continue
    seen+=("$resolved")
    printf '%s\n' "$h"
  done
  shopt -u nullglob
}

# --- Privacy Section Helpers ---
_for_each_user() {
  local callback="$1"
  while IFS=: read -r user _ uid _ _ home shell; do
    _is_human_uid "$uid" || continue
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
    _is_human_uid "$uid" || continue
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
    _is_human_uid "$uid" || continue
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
    _is_human_uid "$uid" || continue
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
# F-302: dispatch primarily checks ubuntu-lock-on-suspend (Ubuntu-specific
# key). Upstream GNOME doesn't ship this key — callers needing the fallback
# must implement it explicitly (see Section 39 _de_lock_suspend_cb). This
# generic dispatcher returns a single result; the section-side wrapper is
# responsible for deciding whether to follow up with lock-enabled.
_de_check_lock_on_suspend() {
  local cb="$1"
  case "$_DE_FAMILY" in
    gnome)
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
        _is_human_uid "$_uid" || continue
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
# F-338 (v3.6.1): switch from `-not -path` (per-file evaluation, no subdir
# pruning) to `-prune` (skips entire subdirs without descending). On btrfs
# systems with many snapshots in /home/.snapshots/, the old pattern walked
# 200+ snapshots × full home tree before filtering paths — often hitting
# the 30s timeout and returning partial/empty results non-deterministically.
# With -prune the snapshot subvolumes are skipped at directory-entry boundary,
# typical 30s → 1-2s. Same applies to /var/lib/containers/storage etc.
# Caller args ("$@") expand in the -o branch with explicit -print since
# implicit -print is suppressed once -prune is in the expression.
_safe_find_root() {
  # F-340 (v3.6.1): /var/lib/gdm exclusion moved into the helper-internal prune
  # list. Was previously passed as caller-side `-not -path '/var/lib/gdm/*'`
  # by the unowned-files check (Section 12), which is per-file evaluation —
  # not directory pruning. Same Performance bug-class as F-338 fixed for the
  # snapshot exclusions. /var/lib/gdm contains the gdm system-user's home
  # whose ownership (gdm:gdm = uid 42 typically) trips -nouser/-nogroup
  # FALSE POSITIVES on systems that haven't synced uid mapping (Atomic /
  # Silverblue layered installs, container hosts).
  timeout 30 find / -xdev \
    \( -path '*/.snapshots/*' \
       -o -path '*/.timeshift/*' \
       -o -path '*/timeshift-btrfs/*' \
       -o -path '*/.btrfs-snapshots/*' \
       -o -path '*/.snapper/*' \
       -o -path '/var/lib/containers/storage/*' \
       -o -path '/var/lib/docker/*' \
       -o -path '/var/lib/lxd/*' \
       -o -path '/var/lib/lxc/*' \
       -o -path '/var/lib/machines/*' \
       -o -path '/var/lib/gdm/*' \
       -o -path '*/ostree/repo/objects/*' \
    \) -prune -o \( "$@" \) -print 2>/dev/null
}

# Same exclusion pattern, scoped to /home and /root for secret/key scans.
# Also excludes common dev/cache directories where false-positive .key/.env
# files live (node_modules, .git/objects, .cache, .venv).
# Atomic Fedora (Silverblue/Kinoite) uses /var/home — included so user home
# scanning works on those distros even without the /home → /var/home symlink.
# `timeout 30` matches _safe_find_root: prevents indefinite hangs on huge
# home directories or stuck NFS/sshfs mounts.
_safe_find_home() {
  local _hd_args=()
  [[ -d /home ]] && _hd_args+=(/home)
  [[ -d /var/home ]] && _hd_args+=(/var/home)
  [[ -d /root ]] && _hd_args+=(/root)
  [[ "${#_hd_args[@]}" -eq 0 ]] && return 0
  timeout 30 find "${_hd_args[@]}" \
    \( -path '*/.snapshots/*' \
       -o -path '*/.timeshift/*' \
       -o -path '*/node_modules/*' \
       -o -path '*/.git/objects/*' \
       -o -path '*/.cache/*' \
       -o -path '*/.venv/*' \
       -o -path '*/__pycache__/*' \
       -o -path '*/target/*' \
    \) -prune -o \( "$@" \) -print 2>/dev/null
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
  # systemctl has no `is-masked` verb (it's only valid in unit-internal API).
  # Detect masked status by parsing `is-enabled` output, which returns the
  # literal string "masked" when the unit is masked.
  local s
  for s in "$@"; do
    [[ "$(systemctl is-enabled "$s" 2>/dev/null)" == "masked" ]] && return 0
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
    # F-343 (v3.6.2): NoID Privacy Workstation = Fedora-derivative privacy distro
    # ID=noid-privacy-workstation in /etc/os-release. Treat as RHEL-family for
    # all package-manager / systemd / SELinux checks (downstream of Fedora 44).
    noid-privacy-workstation)              DISTRO="noid-privacy"; DISTRO_FAMILY="rhel" ;;
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
# F-005: VPN-interface regex now covers Tailscale/ZeroTier/Nebula/Mullvad
# in addition to OpenVPN/WireGuard/Proton.
_VPN_IFACE_REGEX='^(tun|tap|wg|proton|pvpn|tailscale|zt|nebula|mullvad|nordlynx)'

PRIMARY_IFACE=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
if [[ -z "$PRIMARY_IFACE" ]] || echo "$PRIMARY_IFACE" | grep -qE "$_VPN_IFACE_REGEX"; then
  PRIMARY_IFACE=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
    | grep -vE "^(lo|docker|br-|veth|virbr|cni|flannel|calico|kube)|$_VPN_IFACE_REGEX" \
    | head -1)
fi
PRIMARY_IFACE="${PRIMARY_IFACE:-eth0}"

# F-070: when VPN is up, lowest-metric default gateway is the VPN gateway,
# not the physical LAN gateway. Find physical LAN gateway by filtering routes
# whose interface matches a VPN pattern. Pass $_VPN_IFACE_REGEX into awk to
# stay in sync with the global definition (Bug Pattern #5: hand-written subset).
ACTUAL_GW=$(ip route show default 2>/dev/null | grep -oP 'via \K\S+' | head -1)
LAN_GW=$(ip route show default 2>/dev/null | awk -v vpn_re="$_VPN_IFACE_REGEX" '{
  for (i=1; i<=NF; i++) if ($i=="via") via=$(i+1)
  for (i=1; i<=NF; i++) if ($i=="dev") dev=$(i+1)
  if (dev !~ vpn_re) print via
}' | head -1)
LAN_GW="${LAN_GW:-$ACTUAL_GW}"

# VPN interfaces (dynamic)
VPN_IFACES=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
  | grep -E "$_VPN_IFACE_REGEX" | tr '\n' ' ')

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
echo "║  🛡️ NoID Privacy for Linux v${NOID_PRIVACY_VERSION} — Hardening Posture Audit"
echo "║  $NOW | $HOSTNAME | $KERNEL"
echo "║  Arch: $ARCH | Distro: $DISTRO_PRETTY"
echo "║  Checks: 420+ across $TOTAL_SECTIONS sections"
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
check_kernel() {
  should_skip "kernel" && return
  header "01" "KERNEL & BOOT INTEGRITY"
###############################################################################

_emit_info "Kernel: $KERNEL"

# Secure Boot — only relevant on UEFI systems (F-018: legacy BIOS misclassified)
if [[ ! -d /sys/firmware/efi ]]; then
  _emit_info "Secure Boot: N/A (legacy BIOS, no UEFI firmware)"
elif require_cmd mokutil; then
  if mokutil --sb-state 2>/dev/null | grep -q "enabled"; then
    _emit_pass "Secure Boot: ENABLED"
  else
    _emit_fail "Secure Boot: DISABLED"
  fi
elif [[ -d /sys/firmware/efi/efivars ]]; then
  # Fallback: read EFI variable directly when mokutil missing
  _SB_VAR=$(find /sys/firmware/efi/efivars -name "SecureBoot-*" 2>/dev/null | head -1)
  if [[ -n "$_SB_VAR" ]] && [[ "$(od -An -t u1 -N1 -j4 "$_SB_VAR" 2>/dev/null | tr -d ' ')" == "1" ]]; then
    _emit_pass "Secure Boot: ENABLED (via efivars)"
  else
    _emit_info "Secure Boot: cannot determine without mokutil"
  fi
else
  _emit_info "Secure Boot: cannot determine (mokutil missing, efivars unreadable)"
fi

# Kernel Lockdown
if [[ -f /sys/kernel/security/lockdown ]]; then
  LOCKDOWN=$(grep -oP '\[\K[^\]]+' /sys/kernel/security/lockdown 2>/dev/null)
  if [[ -z "$LOCKDOWN" ]]; then
    _emit_warn "Kernel Lockdown: could not parse status"
  elif [[ "$LOCKDOWN" == "none" ]]; then
    _emit_warn "Kernel Lockdown: none (despite Secure Boot)"
  else
    _emit_pass "Kernel Lockdown: $LOCKDOWN"
  fi
else
  # F-019: not all kernels are built with CONFIG_SECURITY_LOCKDOWN_LSM —
  # absence is informational, not a hardening regression.
  _emit_info "Kernel Lockdown: not available (CONFIG_SECURITY_LOCKDOWN_LSM not built)"
fi

# Kernel Taint — F-021: decode all 19 bits per Documentation/admin-guide/tainted-kernels.rst
# Severity tier: PROPRIETARY/OOT/CRAP/AUX/LIVEPATCH/RANDSTRUCT/UNSIGNED/TEST = informational
# (legitimate use), all others (DIE/FORCED_MODULE/OVERRIDDEN/WARNING/MACHINE_CHECK/etc) = warn
TAINT=$(< /proc/sys/kernel/tainted)
if [[ "$TAINT" -eq 0 ]]; then
  _emit_pass "Kernel Taint: 0 (clean)"
else
  declare -A _TAINT_FLAGS=(
    [1]="PROPRIETARY"      [2]="FORCED_MODULE"      [4]="UNSAFE_SMP"
    [8]="FORCED_RMMOD"     [16]="MACHINE_CHECK"     [32]="BAD_PAGE"
    [64]="USER"            [128]="DIE"              [256]="OVERRIDDEN_ACPI_TABLE"
    [512]="WARNING"        [1024]="CRAP"            [2048]="FIRMWARE_WORKAROUND"
    [4096]="OOT_MODULE"    [8192]="UNSIGNED_MODULE" [16384]="SOFTLOCKUP"
    [32768]="LIVEPATCH"    [65536]="AUX"            [131072]="RANDSTRUCT"
    [262144]="TEST"
  )
  # Bits that indicate user choice rather than runtime trouble.
  # F-301: UNSIGNED_MODULE (8192) is contextually-benign: legitimate when
  # paired with NVIDIA-akmod / DKMS modules MOK-signed on the user's host
  # (RPM-signing isn't possible for locally-built kernel modules). But it's
  # a contradiction when module.sig_enforce=Y/Force: the kernel claims it
  # blocks unsigned modules, yet here's evidence one slipped through. That's
  # either a Secure-Boot bypass attempt, a stale-MOK race, or a kernel-bug
  # finding worth surfacing. Conditional removes UNSIGNED_MODULE from the
  # benign set when sig_enforce is active.
  declare -a _TAINT_BENIGN=(1 4096 1024 65536 131072 32768 8192 262144)
  declare -A _TAINT_BENIGN_MAP=()
  for _b in "${_TAINT_BENIGN[@]}"; do _TAINT_BENIGN_MAP[$_b]=1; done
  # If module signing is enforced, UNSIGNED_MODULE in taint = real anomaly
  if [[ -f /sys/module/module/parameters/sig_enforce ]] && \
     [[ "$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null)" == "Y" ]]; then
    unset '_TAINT_BENIGN_MAP[8192]'
  elif grep -qw "module.sig_enforce=1" /proc/cmdline 2>/dev/null; then
    unset '_TAINT_BENIGN_MAP[8192]'
  fi

  _decoded=""
  _all_benign=true
  for _bit in 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536 131072 262144; do
    if (( TAINT & _bit )); then
      _decoded+="${_TAINT_FLAGS[$_bit]}+"
      [[ -z "${_TAINT_BENIGN_MAP[$_bit]:-}" ]] && _all_benign=false
    fi
  done
  _decoded="${_decoded%+}"
  if $_all_benign; then
    _emit_info "Kernel Taint: $TAINT ($_decoded — known-benign flags)"
  else
    _emit_warn "Kernel Taint: $TAINT ($_decoded — review flags)"
  fi
fi

# Insecure boot parameters check
# F-023: 'nomodeset' is a troubleshooting flag (NVIDIA/early-boot graphics issues),
# not a security setting. Distinguish from actual security disablers.
CMDLINE=$(< /proc/cmdline)
for PARAM in "noapic" "acpi=off" "selinux=0" "enforcing=0" "audit=0"; do
  if echo "$CMDLINE" | grep -qw "$PARAM"; then
    _emit_fail "Insecure boot parameter: $PARAM"
  fi
done
if echo "$CMDLINE" | grep -qw "nomodeset"; then
  _emit_info "Boot parameter: nomodeset (graphics troubleshooting — not security-relevant)"
fi

# Secure boot parameters — F-024: accept stronger variants ("force" instead of "on")
# v3.6: aggregated PASSes (use --verbose for per-param detail)
_emit_pass_agg_start "Boot hardening"
for PARAM in "init_on_alloc=1" "init_on_free=1" "slab_nomerge" "pti=on" "vsyscall=none" "debugfs=off" "page_alloc.shuffle=1" "randomize_kstack_offset=on"; do
  # Match the param literally OR (for pti) accept the stronger pti=force variant
  if echo "$CMDLINE" | grep -qw "$PARAM"; then
    _emit_pass_agg "$PARAM"
  elif [[ "$PARAM" == "pti=on" ]] && echo "$CMDLINE" | grep -qw "pti=force"; then
    _emit_pass_agg "pti=force (stronger than pti=on)"
  else
    _emit_warn "Boot hardening missing: $PARAM"
  fi
done
_emit_pass_agg_end 8 "params set"

# F-026: spec_store_bypass_disable=on is only required on CPUs vulnerable to
# Spectre v4. Modern Intel (Alder Lake+) and AMD Zen3+ have hardware mitigation
# and don't need the boot param. Read CPU vuln state to decide WARN vs INFO.
PARAM="spec_store_bypass_disable=on"
_SSB_STATE=$(cat /sys/devices/system/cpu/vulnerabilities/spec_store_bypass 2>/dev/null)
if echo "$CMDLINE" | grep -qw "$PARAM"; then
  _emit_pass "Boot security param: $PARAM"
elif [[ "$_SSB_STATE" == "Not affected" ]]; then
  _emit_info "Boot security param '$PARAM' not set — CPU not affected by Spectre v4 (HW mitigation)"
elif [[ "$_SSB_STATE" =~ Mitigation ]]; then
  _emit_info "Boot security param '$PARAM' not set — CPU already mitigated ($_SSB_STATE)"
else
  _emit_warn "Boot security param missing: $PARAM (CPU state: ${_SSB_STATE:-unknown})"
fi
# Optional params (can break NVIDIA/hardware on desktop systems)
for PARAM in "iommu=force" "lockdown=confidentiality"; do
  if echo "$CMDLINE" | grep -qw "$PARAM"; then
    _emit_pass "Boot security param: $PARAM"
  else
    _emit_info "Boot security param not set: $PARAM (optional — may break NVIDIA/hardware)"
  fi
done

# LUKS
if lsblk -o TYPE 2>/dev/null | grep -q crypt; then
  _emit_pass "LUKS encryption active"
  # F-027: -r (raw) drops tree-art prefix (└─ characters from interactive lsblk)
  LUKS_DEVS=$(lsblk -rno NAME,TYPE 2>/dev/null | awk '$2=="crypt" {print $1}' | tr '\n' ' ')
  _emit_info "LUKS devices: ${LUKS_DEVS% }"
else
  _emit_fail "No LUKS encryption detected"
fi

# Boot Performance
if require_cmd systemd-analyze; then
  BOOT_TIME=$(systemd-analyze 2>/dev/null | head -1)
  _emit_info "Boot: $BOOT_TIME"

  # F-329 (v3.6.1): label says "services" but systemd-analyze blame returns
  # all unit types (.device, .mount, .target, .service, .socket, .timer).
  # Renamed to "units" for accuracy.
  sub_header "Top 5 slowest boot units"
  if ! $JSON_MODE; then
    while read -r line; do
      printf "       %s\n" "$line"
    done < <(LC_ALL=C systemd-analyze blame 2>/dev/null | head -5)
  fi
fi

# GRUB Password — F-031: cross-distro detection (Fedora/RHEL: /boot/grub2/,
# Debian/Ubuntu/Arch: /boot/grub/) plus direct grub.cfg content scan as
# authoritative fallback (catches all generation paths).
# F-031b: exclude Fedora's default /etc/grub.d/01_users template which contains
# `password_pbkdf2 root ${GRUB2_PASSWORD}` as a placeholder — the variable is
# only populated when /boot/grub2/user.cfg exists with a real GRUB2_PASSWORD=
# entry. Same exclusion for generated grub.cfg (the conditional block embeds
# the literal placeholder when user.cfg is missing).
_GRUB_CFG=$(_grub_main_cfg)
if [[ -n "$_GRUB_CFG" ]]; then
  _grub_pwd_found=false
  # 1. user.cfg with non-empty GRUB2_PASSWORD= (authoritative for Fedora/RHEL)
  for _gucfg in /boot/grub2/user.cfg /boot/grub/user.cfg; do
    if [[ -f "$_gucfg" ]] && grep -qE '^\s*GRUB2_PASSWORD=\S' "$_gucfg" 2>/dev/null; then
      _grub_pwd_found=true
    fi
  done
  # 2. grub.d snippets (Debian convention via 40_password.conf or similar)
  #    Exclude lines referencing ${GRUB2_PASSWORD} variable — those are templates.
  if ! $_grub_pwd_found; then
    if grep -rE '^\s*(password_pbkdf2|password)\s+' /etc/grub.d/ 2>/dev/null \
       | grep -vqE '\$\{?GRUB2_PASSWORD\}?'; then
      _grub_pwd_found=true
    fi
  fi
  # 3. Authoritative: scan generated grub.cfg directly — works on any distro
  #    regardless of how the password was inserted (Anaconda, debconf, manual)
  #    Same template-exclusion as pfad 2.
  if ! $_grub_pwd_found; then
    if grep -E '^\s*(password_pbkdf2|password)\s+' "$_GRUB_CFG" 2>/dev/null \
       | grep -vqE '\$\{?GRUB2_PASSWORD\}?'; then
      _grub_pwd_found=true
    fi
  fi
  if $_grub_pwd_found; then
    _emit_pass "GRUB password set"
  else
    if lsblk -o TYPE 2>/dev/null | grep -q crypt; then
      _emit_info "GRUB no password (LUKS encryption protects)"
    else
      _emit_warn "GRUB no password (physical access = root)"
    fi
  fi
fi

# Running latest installed kernel?
# SC2012-clean: shell glob with version-sort instead of `ls -v`.
# Filter rescue kernels (vmlinuz-0-rescue-*, vmlinuz-*-rescue-*): `sort -V`
# would otherwise place "rescue" lexicographically after numeric versions
# (`r` > `6`), causing a false "reboot recommended" warn on systems with
# both a rescue and a regular kernel installed.
shopt -s nullglob
_kernel_files=(/boot/vmlinuz-*)
shopt -u nullglob
LATEST_KERNEL=""
if [[ "${#_kernel_files[@]}" -gt 0 ]]; then
  mapfile -t _kernel_sorted < <(printf '%s\n' "${_kernel_files[@]}" | grep -v -- '-rescue' | sort -V)
  if [[ "${#_kernel_sorted[@]}" -gt 0 ]]; then
    LATEST_KERNEL="${_kernel_sorted[-1]##*/vmlinuz-}"
  fi
fi
if [[ -n "$LATEST_KERNEL" ]]; then
  if [[ "$KERNEL" == "$LATEST_KERNEL" ]]; then
    _emit_pass "Running latest installed kernel ($KERNEL)"
  else
    _emit_warn "Running kernel $KERNEL but $LATEST_KERNEL is installed — reboot recommended"
  fi
fi

}

###############################################################################
# Initialize MAC detection variables (used in AI output even if section is skipped)
HAS_SELINUX=false
HAS_APPARMOR=false
if require_cmd getenforce; then
  _se_mode=$(getenforce 2>/dev/null)
  [[ "$_se_mode" == "Enforcing" || "$_se_mode" == "Permissive" ]] && HAS_SELINUX=true
fi
require_cmd aa-status && HAS_APPARMOR=true

check_selinux() {
  should_skip "selinux" && return

if $HAS_SELINUX; then
header "02" "SELINUX & MAC"
###############################################################################

SE_STATUS=$(getenforce)
if [[ "$SE_STATUS" == "Enforcing" ]]; then
  _emit_pass "SELinux: Enforcing"
elif [[ "$SE_STATUS" == "Permissive" ]]; then
  _emit_fail "SELinux: Permissive (logging only, not blocking!)"
else
  _emit_fail "SELinux: Disabled"
fi

# SELinux Booleans (dangerous ones)
if require_cmd getsebool; then
  # F-038: SELinux booleans audit. Two tiers:
  # 1. Universal-dangerous (warn always when on): execheap/execmod/execstack
  #    bypass memory-protection; httpd_can_network_connect / httpd_execmem
  #    are exploit vectors when active without specific need.
  # 2. Service-conditional (warn only if the corresponding service is active):
  #    nfs_export_all_*, samba_enable_home_dirs — these only have effect when
  #    the actual server (nfsd/smbd) runs; ON-without-service is a no-op.
  # NOT included: cron_userdomain_transition and allow_user_exec_content are
  # default-ON on Fedora and required for normal user-script/cron behavior;
  # flagging them WARNs every desktop user without security benefit.
  # cron_allow_writes (default OFF): when ON, cron-domain can write to
  # arbitrary paths — privilege-escalation vector via crontab editing.
  # NOT to be confused with cron_userdomain_transition (default ON, required
  # for user crontabs to work).
  DANGEROUS_BOOLS_UNIVERSAL="httpd_can_network_connect httpd_execmem allow_execheap allow_execmod allow_execstack cron_allow_writes"
  for BOOL in $DANGEROUS_BOOLS_UNIVERSAL; do
    VAL=$(getsebool "$BOOL" 2>/dev/null | awk '{print $3}' || echo "n/a")
    if [[ "$VAL" == "on" ]]; then
      if [[ "$BOOL" == "allow_execmod" || "$BOOL" == "allow_execstack" ]] && lsmod | grep -q nvidia; then
        _emit_info "SELinux bool active: $BOOL = on (NVIDIA dependency)"
      else
        _emit_warn "SELinux bool active: $BOOL = on"
      fi
    fi
  done
  # Service-conditional bools — warn only if matching service is active
  if _service_active_any nfs-server nfsd nfs-kernel-server; then
    for BOOL in nfs_export_all_rw nfs_export_all_ro; do
      VAL=$(getsebool "$BOOL" 2>/dev/null | awk '{print $3}' || echo "n/a")
      [[ "$VAL" == "on" ]] && _emit_warn "SELinux bool active: $BOOL = on (NFS server running)"
    done
  fi
  if _service_active_any smb smbd samba; then
    VAL=$(getsebool samba_enable_home_dirs 2>/dev/null | awk '{print $3}' || echo "n/a")
    [[ "$VAL" == "on" ]] && _emit_warn "SELinux bool active: samba_enable_home_dirs = on (Samba shares /home)"
  fi
fi

# SELinux Denials
# Known-benign processes that routinely generate AVC denials as part of their normal operation:
#   aide              — file integrity checks access many restricted paths
#   usbguard-daemon   — USB access control interacts with udev/systemd
#   systemd-logind    — session management, normal boot-time interactions
#   rpm/fwupd         — package + firmware update hooks touch restricted paths
#   gdm/gdm-x-session — display-manager startup quirks
#   systemd-update    — update-engine probes restricted FS regions
#   snapperd (F-289)  — Btrfs snapshot daemon: when iterating snapshot contents
#                       containing podman/docker overlay storage, snapperd_t
#                       hits container_ro_file_t with class=chr_file (Btrfs
#                       snapshot mode-bit quirk for container-storage files).
#                       Common after dnf transactions because Snapper's
#                       pre/post DNF plugin creates fresh snapshots that
#                       snapper-cleanup.timer scans next. SELinux correctly
#                       blocks the cross-domain access; snapperd functions
#                       fine without the getattr — the denials are noise.
# Only warn if AVC denials come from OTHER (unexpected) processes.
if require_cmd ausearch; then
  # F-293: include USER_AVC denials (DBus / PolicyKit / userspace AVC).
  # Previously `-m avc` matched only kernel AVC entries, silently dropping
  # USER_AVC events that surface DBus method-call denials and PolicyKit
  # authorization denials — both are real MAC-blocked actions worth seeing.
  _SE_AVC_RAW=$(ausearch -m avc -m user_avc --start recent 2>/dev/null)
  SE_DENIALS=$(echo "$_SE_AVC_RAW" | grep -cE "type=(AVC|USER_AVC)" || true)
  SE_DENIALS=${SE_DENIALS//[^0-9]/}
  SE_DENIALS=${SE_DENIALS:-0}
  if [[ "$SE_DENIALS" -gt 0 ]]; then
    _SE_UNEXPECTED=$(echo "$_SE_AVC_RAW" \
      | grep -oP 'comm="\K[^"]+' \
      | grep -cvE "^(aide|usbguard-daemon|usbguard|systemd-logind|rpm|gdm|gdm-x-session|fwupd|systemd-update|snapperd)$" || true)
    _SE_UNEXPECTED=${_SE_UNEXPECTED//[^0-9]/}
    _SE_UNEXPECTED=${_SE_UNEXPECTED:-0}
    # F-335 (v3.6.1): when classified as known-benign, append top-3 source
    # breakdown so unusual volume from a single benign source (e.g. snapperd
    # iterating container-storage in snapshots → 1000+ denials) becomes
    # visible without forcing the user to dig through ausearch manually.
    _SE_TOP_SOURCES=$(echo "$_SE_AVC_RAW" \
      | grep -oP 'comm="\K[^"]+' \
      | sort | uniq -c | sort -rn | head -3 \
      | awk '{printf "%s:%s ", $2, $1}' | sed 's/ $//')
    if [[ "$_SE_UNEXPECTED" -eq 0 ]]; then
      _emit_info "SELinux: $SE_DENIALS AVC denials (recent) — known-benign sources only (top: ${_SE_TOP_SOURCES:-none} — MAC working correctly)"
    else
      _emit_warn "SELinux: $SE_DENIALS AVC denials ($_SE_UNEXPECTED from unexpected processes — top: ${_SE_TOP_SOURCES:-none})"
    fi
  else
    _emit_pass "SELinux: 0 AVC denials (recent)"
  fi
fi

elif $HAS_APPARMOR; then
  header "02" "APPARMOR & MAC"

  # F-042/043: report enforcing/complain/unconfined counts (unconfined =
  # processes running with AA loaded but no profile attached — privilege gap).
  AA_STATUS_OUT=$(aa-status 2>/dev/null)
  AA_ENFORCED=$(echo "$AA_STATUS_OUT" | grep -oP '^\s*\K\d+(?=\s+profiles? are in enforce mode)' | head -1 || echo "0")
  AA_ENFORCED=${AA_ENFORCED:-0}
  AA_COMPLAIN=$(echo "$AA_STATUS_OUT" | grep -oP '^\s*\K\d+(?=\s+profiles? are in complain mode)' | head -1 || echo "0")
  AA_COMPLAIN=${AA_COMPLAIN:-0}
  AA_UNCONFINED=$(echo "$AA_STATUS_OUT" | grep -oP '^\s*\K\d+(?=\s+processes are unconfined)' | head -1 || echo "0")
  AA_UNCONFINED=${AA_UNCONFINED:-0}
  if [[ "$AA_ENFORCED" -gt 0 ]]; then
    _emit_pass "AppArmor: $AA_ENFORCED profiles enforcing, $AA_COMPLAIN complaining"
  else
    _emit_warn "AppArmor: no enforcing profiles"
  fi
  if [[ "$AA_UNCONFINED" -gt 0 ]]; then
    _emit_info "AppArmor: $AA_UNCONFINED unconfined processes (no profile attached)"
  fi

else
  header "02" "MANDATORY ACCESS CONTROL"
  if require_cmd getenforce && [[ "$(getenforce 2>/dev/null)" == "Disabled" ]]; then
    _emit_fail "SELinux: Disabled (getenforce present but SELinux is off)"
  else
    _emit_warn "No MAC system (SELinux/AppArmor) detected"
  fi
fi
}

###############################################################################
check_firewall() {
  should_skip "firewall" && return
  header "03" "FIREWALL"
###############################################################################

if require_cmd firewall-cmd && systemctl is-active firewalld &>/dev/null; then
  _emit_pass "firewalld: active"

  # Check zones — F-046b: combine permanent AND runtime interface assignments.
  # NM/libvirt assign interfaces dynamically at runtime, so permanent-only
  # iteration misses live attached zones (libvirt→virbr0, NM-managed VPN, etc.)
  _DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "")
  for ZONE in $(firewall-cmd --get-zones 2>/dev/null); do
    TARGET=$(firewall-cmd --zone="$ZONE" --get-target --permanent 2>/dev/null || echo "")
    [[ -z "$TARGET" ]] && continue  # zone doesn't exist
    SERVICES=$(firewall-cmd --zone="$ZONE" --list-services --permanent 2>/dev/null || echo "")
    PORTS=$(firewall-cmd --zone="$ZONE" --list-ports --permanent 2>/dev/null || echo "")
    _IFACES_PERM=$(firewall-cmd --zone="$ZONE" --list-interfaces --permanent 2>/dev/null || echo "")
    _IFACES_RUN=$(firewall-cmd --zone="$ZONE" --list-interfaces 2>/dev/null || echo "")
    IFACES=$(echo "$_IFACES_PERM $_IFACES_RUN" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')
    IFACES="${IFACES% }"

    # Only evaluate zones that are actively in use:
    # - Zones with interfaces explicitly assigned, OR
    # - The default zone (applies to any interface not in another zone)
    # Zones with no interfaces and not the default zone are inactive — skip them.
    _ZONE_IS_DEFAULT=false
    [[ "$ZONE" == "$_DEFAULT_ZONE" ]] && _ZONE_IS_DEFAULT=true

    if [[ -n "$IFACES" ]] || $_ZONE_IS_DEFAULT; then
      # Check if all assigned interfaces are VPN/virtual (not physical internet-facing)
      # F-046d: use the global $_VPN_IFACE_REGEX (covers all VPN families) instead
      # of the original 4-name subset — Tailscale/ZeroTier/Mullvad zones were
      # incorrectly classified as physical-exposed.
      _ALL_VPN=true
      for _iface in $IFACES; do
        if [[ "$_iface" != "lo" ]] && ! echo "$_iface" | grep -qE "$_VPN_IFACE_REGEX"; then
          _ALL_VPN=false
          break
        fi
      done
      # VPN-only zones or empty default zones with VPN traffic are not directly internet-facing
      if [[ -z "$IFACES" ]] && $_ZONE_IS_DEFAULT; then
        # Default zone applies to all unassigned interfaces — evaluate as exposed
        if [[ "$TARGET" == "DROP" || "$TARGET" == "REJECT" || "$TARGET" == "%%REJECT%%" ]]; then
          _emit_pass "Zone $ZONE (default): target=$TARGET"
        else
          _emit_warn "Zone $ZONE (default): target=$TARGET (not DROP/REJECT — applies to unassigned interfaces)"
        fi
        if [[ -n "$SERVICES" ]]; then
          _emit_warn "Zone $ZONE (default) open services: $SERVICES"
        fi
        if [[ -n "$PORTS" ]]; then
          _emit_warn "Zone $ZONE (default) open ports: $PORTS"
        fi
      elif $_ALL_VPN && [[ -n "$IFACES" ]]; then
        _emit_info "Zone $ZONE: target=$TARGET (VPN-only interfaces: $IFACES)"
      elif [[ "$TARGET" == "DROP" || "$TARGET" == "REJECT" || "$TARGET" == "%%REJECT%%" ]]; then
        _emit_pass "Zone $ZONE: target=$TARGET"
      else
        _emit_warn "Zone $ZONE: target=$TARGET (not DROP/REJECT)"
      fi
      if [[ -n "$SERVICES" ]] && ! $_ALL_VPN && [[ -n "$IFACES" ]]; then
        _emit_warn "Zone $ZONE open services: $SERVICES"
      elif [[ -n "$SERVICES" ]] && [[ -n "$IFACES" ]]; then
        _emit_info "Zone $ZONE services: $SERVICES (VPN-only)"
      fi
      if [[ -n "$PORTS" ]] && ! $_ALL_VPN && [[ -n "$IFACES" ]]; then
        _emit_warn "Zone $ZONE open ports: $PORTS"
      fi
      if [[ -n "$IFACES" ]]; then
        _emit_info "Zone $ZONE interfaces: $IFACES"
      fi
    fi
  done

  # Default Zone
  DEF_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
  _emit_info "Default zone: $DEF_ZONE"

  # Active Zones
  ACTIVE_ZONES=$(firewall-cmd --get-active-zones 2>/dev/null)
  _emit_info "Active zones:"
  if ! $JSON_MODE; then
    while IFS= read -r zline; do
      [[ -n "$zline" ]] && printf "  %s\n" "$zline"
    done <<< "$ACTIVE_ZONES"
  fi

  # Rich Rules
  RICH_RULES=$(firewall-cmd --list-rich-rules 2>/dev/null || echo "")
  if [[ -n "$RICH_RULES" ]]; then
    RICH_COUNT=$(echo "$RICH_RULES" | wc -l)
    _emit_info "Rich rules: $RICH_COUNT"
    if ! $JSON_MODE; then
      while read -r rule; do
        printf "       %s\n" "$rule"
      done < <(echo "$RICH_RULES" | head -5)
    fi
  fi

  # Forward Ports
  FWD=$(firewall-cmd --list-forward-ports 2>/dev/null || echo "")
  if [[ -n "$FWD" ]]; then
    _emit_warn "Forward ports active: $FWD"
  fi

  # Masquerading
  if firewall-cmd --query-masquerade &>/dev/null; then
    _emit_warn "Masquerading active"
  fi

  # Firewall Policies (firewalld 0.9+: inter-zone traffic control)
  # v3.8: query via capability layer — automatically uses --get-policies
  # (0.9+) or falls back to --list-policies (0.8-) based on _CAPS detection.
  FWD_POLICIES=$(_fw_get_policies || true)
  # Normalize: --get-policies returns single line space-separated, normalize to
  # newline-separated so the existing while-read loop works unchanged.
  FWD_POLICIES=$(echo "$FWD_POLICIES" | tr ' ' '\n' | grep -v '^$' || true)
  if [[ -n "$FWD_POLICIES" ]]; then
    sub_header "Firewall Policies"
    while IFS= read -r policy; do
      [[ -z "$policy" ]] && continue
      PTARGET=$(firewall-cmd --policy="$policy" --get-target --permanent 2>/dev/null || echo "unknown")
      if [[ "$PTARGET" == "DROP" || "$PTARGET" == "REJECT" ]]; then
        _emit_pass "Policy '$policy': target=$PTARGET (blocks inter-zone traffic)"
      elif [[ "$PTARGET" == "CONTINUE" || "$PTARGET" == "ACCEPT" ]]; then
        _emit_info "Policy '$policy': target=$PTARGET"
      else
        _emit_info "Policy '$policy': target=$PTARGET"
      fi
    done <<< "$FWD_POLICIES"
  fi
elif require_cmd ufw; then
  # F-047: also check default policies and rule count (not just active/inactive)
  UFW_STATUS_VERB=$(ufw status verbose 2>/dev/null)
  if echo "$UFW_STATUS_VERB" | head -1 | grep -qi "active"; then
    _emit_pass "ufw: active"
    UFW_DEFAULT_IN=$(echo "$UFW_STATUS_VERB" | grep -oP 'Default: \K\S+' | head -1)
    case "$UFW_DEFAULT_IN" in
      deny|reject)
        _emit_pass "ufw: default-incoming policy '$UFW_DEFAULT_IN' (secure)"
        ;;
      allow)
        _emit_fail "ufw: default-incoming policy 'allow' — blocks nothing"
        ;;
    esac
    # F-bug: previous regex `^[0-9.]+:` matched IP:PORT format which UFW
    # never emits — ufw rules look like `22/tcp ALLOW IN Anywhere`. Count
    # action keywords (ALLOW/DENY/REJECT/LIMIT) instead, which appear once
    # per rule line in `ufw status verbose` output.
    UFW_RULES=$(echo "$UFW_STATUS_VERB" | grep -cE '\b(ALLOW|DENY|REJECT|LIMIT)\b')
    UFW_RULES=${UFW_RULES:-0}
    _emit_info "ufw: $UFW_RULES configured rules"
  else
    _emit_fail "ufw: inactive"
  fi
  _emit_info "Firewall: ufw (firewalld not available)"
elif require_cmd iptables; then
  # F-048: check default policies in addition to rule count.
  IPTABLES_RULES=$(iptables -L -n 2>/dev/null | grep -cvE "^Chain |^target |^$" || true)
  IPTABLES_RULES=${IPTABLES_RULES:-0}
  IPT_INPUT_POLICY=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+')
  IPT_FWD_POLICY=$(iptables -L FORWARD -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+')
  if [[ "$IPT_INPUT_POLICY" == "DROP" || "$IPT_INPUT_POLICY" == "REJECT" ]]; then
    _emit_pass "iptables: INPUT policy '$IPT_INPUT_POLICY' (default-deny)"
  elif [[ -n "$IPT_INPUT_POLICY" ]]; then
    if [[ "$IPTABLES_RULES" -gt 0 ]]; then
      _emit_info "iptables: INPUT policy '$IPT_INPUT_POLICY' with $IPTABLES_RULES rules (rule-based filter)"
    else
      _emit_fail "iptables: INPUT policy '$IPT_INPUT_POLICY' and no rules — wide open"
    fi
  fi
  if [[ "$IPT_FWD_POLICY" == "DROP" || "$IPT_FWD_POLICY" == "REJECT" ]]; then
    _emit_pass "iptables: FORWARD policy '$IPT_FWD_POLICY' (default-deny)"
  elif [[ -n "$IPT_FWD_POLICY" ]]; then
    _emit_info "iptables: FORWARD policy '$IPT_FWD_POLICY'"
  fi
  _emit_info "Firewall: iptables (firewalld not available; $IPTABLES_RULES rules)"
else
  _emit_fail "No firewall detected (firewalld/ufw/iptables)"
fi

# Firewall Logging
sub_header "Firewall Logging"
if require_cmd firewall-cmd && systemctl is-active firewalld &>/dev/null; then
  _FW_LOG_DENIED=$(firewall-cmd --get-log-denied 2>/dev/null || echo "off")
  if [[ "$_FW_LOG_DENIED" == "off" ]]; then
    # F-282 (v3.6.1): privacy-design override. Some hardened distros (NoID,
    # Tails) intentionally disable LogDenied because every LAN-scan,
    # NAT-probe, and stray broadcast otherwise lands in journal with
    # src/dst IPs — continuous IP-tracking data on hostile networks.
    # If the firewalld.conf comment documents this rationale, emit INFO
    # instead of WARN. Marker phrases checked: "Privacy rationale",
    # "privacy by design", "stray broadcast", "IP-tracking".
    if [[ -f /etc/firewalld/firewalld.conf ]] && \
       grep -qiE "privacy[ -]?(rationale|by[ -]design)|stray broadcast|IP[ -]tracking" /etc/firewalld/firewalld.conf 2>/dev/null; then
      _emit_info "Firewall logging: denied packets NOT logged (privacy-by-design — toggle on demand via firewall-cmd --set-log-denied=all)"
    else
      _emit_warn "Firewall logging: denied packets NOT logged (firewall-cmd --get-log-denied=off)"
    fi
  else
    _emit_pass "Firewall logging: denied packets logged (mode: $_FW_LOG_DENIED)"
  fi
elif require_cmd ufw; then
  _UFW_LOG=$(ufw status verbose 2>/dev/null | grep -i "^Logging:" | awk '{print $2}')
  if [[ "${_UFW_LOG,,}" == "off" || -z "$_UFW_LOG" ]]; then
    _emit_warn "UFW logging disabled"
  else
    _emit_pass "UFW logging: $_UFW_LOG"
  fi
elif require_cmd iptables; then
  _IPT_LOG=$(iptables -L -n 2>/dev/null | grep -c "LOG" || true)
  if [[ "${_IPT_LOG:-0}" -gt 0 ]]; then
    _emit_pass "iptables: $_IPT_LOG LOG rules"
  else
    _emit_info "iptables: no LOG rules detected"
  fi
fi

}

###############################################################################
check_nftables() {
  should_skip "nftables" && return
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
    _emit_pass "nftables: active (standalone)"
  elif $_NFTABLES_BACKEND; then
    _emit_pass "nftables: active via firewalld backend"
  else
    _emit_warn "nftables: inactive"
  fi

  if systemctl is-enabled nftables &>/dev/null; then
    _emit_pass "nftables: boot-persistent (standalone)"
  elif $_NFTABLES_BACKEND; then
    _emit_pass "nftables: boot-persistent via firewalld"
  else
    _emit_warn "nftables: not boot-persistent"
  fi

  # Kill-Switch detection
  KS_TABLES=$(get_killswitch_tables)
  if [[ -n "$KS_TABLES" ]]; then
    KS_COUNT=$(echo "$KS_TABLES" | wc -l)
    _emit_pass "VPN kill-switch detected ($KS_COUNT table(s) dropping on $PRIMARY_IFACE)"

    if has_nft_drop_on_phys; then
      _emit_pass "Kill-switch: $PRIMARY_IFACE drop active"
    else
      _emit_fail "Kill-switch: $PRIMARY_IFACE drop MISSING"
    fi

    # Duplicate rule check
    ALL_RULES=""
    while read -r ks_family ks_table; do
      # F-054: only count drop rules — accept rules are not kill-switch material
      ALL_RULES+=$(nft list table "$ks_family" "$ks_table" 2>/dev/null | grep -E "oifname.*\<drop\>")
      ALL_RULES+=$'\n'
    done <<< "$KS_TABLES"
    RULE_COUNT=$(echo "$ALL_RULES" | grep -c "oifname" || true)
    RULE_COUNT=${RULE_COUNT:-0}
    UNIQUE_RULES=$(echo "$ALL_RULES" | grep "oifname" | sort -u | wc -l)
    if [[ "$RULE_COUNT" -ne "$UNIQUE_RULES" ]]; then
      _emit_info "Kill-switch: $RULE_COUNT rules ($UNIQUE_RULES unique) — duplicates from VPN management"
    else
      _emit_pass "Kill-switch: $RULE_COUNT rules (no duplicates)"
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
      _emit_pass "VPN kill-switch detected via ip routing rules (WireGuard/policy routing)"
    else
      _emit_warn "No VPN kill-switch found (no nftables drop on $PRIMARY_IFACE, no ip rule killswitch)"
    fi
  fi
else
  _emit_info "nftables not installed — skipped"
fi

}

###############################################################################
check_vpn() {
  should_skip "vpn" && return
  header "05" "VPN & NETWORK"
###############################################################################

# NOTE: This section makes network requests (ping, dig).
# Use --skip vpn to avoid network traffic from this section.

# Internet Connectivity Test — F-057: prefer ICMP-only (no HTTP tracking)
# Try ping first (no third-party logs); fall back to Cloudflare's
# generate_204 endpoint (less identifiable than detectportal.firefox.com).
if ping -c1 -W2 1.1.1.1 &>/dev/null; then
  _emit_pass "Internet connectivity: OK (ICMP)"
elif ping -c1 -W2 9.9.9.9 &>/dev/null; then
  _emit_pass "Internet connectivity: OK (ICMP fallback)"
elif curl -fsS --max-time 5 http://cp.cloudflare.com/generate_204 &>/dev/null; then
  _emit_pass "Internet connectivity: OK (HTTP)"
else
  _emit_warn "Internet connectivity: FAIL (ICMP + HTTP timeout)"
fi

# VPN Interface — F-061b: use the global $_VPN_IFACE_REGEX so Tailscale,
# ZeroTier, Mullvad, Nebula, and Nordlynx tunnels are detected like Proton.
VPN_UP=false
for IFACE in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E "$_VPN_IFACE_REGEX"); do
  STATE=$(ip link show "$IFACE" 2>/dev/null | grep -oP 'state \K\w+')
  # WireGuard/tun interfaces report UNKNOWN state — that's normal (they have no carrier detection)
  _emit_pass "VPN interface $IFACE: active${STATE:+ (state: $STATE)}"
  VPN_UP=true
done
$VPN_UP || _emit_warn "No VPN interface active"

# Default Route — F-061b: extract iface and check against full VPN regex
# (anchored), not unanchored substring match which could false-positive on
# unrelated text containing "tun" or "wg".
DEF_ROUTE=$(ip route show default 2>/dev/null | head -1)
_DEF_IFACE=$(echo "$DEF_ROUTE" | grep -oP 'dev \K\S+' | head -1)
if [[ -n "$_DEF_IFACE" ]] && echo "$_DEF_IFACE" | grep -qE "$_VPN_IFACE_REGEX"; then
  _emit_pass "Default route via VPN: $DEF_ROUTE"
elif $VPN_UP; then
  _emit_fail "Default route NOT via VPN: $DEF_ROUTE"
else
  _emit_info "Default route: $DEF_ROUTE (no VPN active)"
fi

# DNS
DNS_SERVERS=$(grep -E '^[[:space:]]*nameserver[[:space:]]' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
_emit_info "DNS servers: $DNS_SERVERS"

# DNS over VPN check
VPN_DNS=false
STUB_DNS=false
while read -r DNS; do
  [[ -z "$DNS" ]] && continue
  if [[ "$DNS" =~ ^10\. || "$DNS" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. || "$DNS" =~ ^192\.168\. || "$DNS" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]]; then
    VPN_DNS=true
  elif [[ "$DNS" == "127.0.0.53" || "$DNS" == "127.0.0.54" ]]; then
    STUB_DNS=true
  fi
done < <(grep -E '^[[:space:]]*nameserver[[:space:]]' /etc/resolv.conf 2>/dev/null | awk '{print $2}')
if $VPN_DNS; then
  _emit_pass "DNS via VPN (private/CGNAT range)"
elif $STUB_DNS && $VPN_UP; then
  # F-062: stub resolver alone doesn't prove VPN routing — query upstream via
  # resolvectl to verify the actual DNS server falls into a VPN range.
  # F-062b: also accept global IPv6 DNS servers (e.g. ProtonVPN's
  # 2a07:b944::2:1) when resolvectl reports them on a VPN interface.
  if require_cmd resolvectl; then
    _UPSTREAM_DNS=$(LC_ALL=C resolvectl status 2>/dev/null | awk '/Current DNS Server/ {print $4; exit}')
    if [[ -z "$_UPSTREAM_DNS" ]]; then
      _UPSTREAM_DNS=$(LC_ALL=C resolvectl status 2>/dev/null | grep -A1 "DNS Servers" | tail -1 | awk '{print $1}')
    fi
    _DNS_VIA_VPN=false
    # 1. IPv4 private/CGNAT ranges (covers OpenVPN/WireGuard internal nets)
    if [[ "$_UPSTREAM_DNS" =~ ^10\. || \
          "$_UPSTREAM_DNS" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. || \
          "$_UPSTREAM_DNS" =~ ^192\.168\. || \
          "$_UPSTREAM_DNS" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]]; then
      _DNS_VIA_VPN=true
    fi
    # 2. Any address family: check which link owns this DNS — covers global
    #    IPv6 addresses that are still tunnel-routed (Proton 2a07:b944::2:1)
    if ! $_DNS_VIA_VPN && [[ -n "$_UPSTREAM_DNS" ]]; then
      _DNS_LINK=$(LC_ALL=C resolvectl status 2>/dev/null | awk -v dns="$_UPSTREAM_DNS" '
        /^Link [0-9]+ \(/ { iface=$3; gsub(/[()]/, "", iface) }
        ($0 ~ "Current DNS Server: " dns "$") || ($0 ~ "DNS Servers:.*" dns) { print iface; exit }
      ')
      if echo "$_DNS_LINK" | grep -qE "$_VPN_IFACE_REGEX"; then
        _DNS_VIA_VPN=true
      fi
    fi
    if $_DNS_VIA_VPN; then
      _emit_pass "DNS via systemd-resolved (upstream $_UPSTREAM_DNS — VPN-routed)"
    elif [[ -n "$_UPSTREAM_DNS" ]]; then
      _emit_info "DNS via systemd-resolved (upstream: $_UPSTREAM_DNS — verify it routes via VPN)"
    else
      _emit_pass "DNS via systemd-resolved (stub resolver — VPN routes DNS)"
    fi
  else
    _emit_pass "DNS via systemd-resolved (stub resolver — VPN routes DNS)"
  fi
else
  if $VPN_UP; then
    _emit_warn "DNS servers not on VPN network (potential DNS leak)"
  else
    _emit_info "DNS not via VPN (no VPN active)"
  fi
fi

# DNSSEC validation status — systemd-resolved + unbound + dnscrypt-proxy
# (F-065: extend beyond resolvectl-only).
_DNSSEC_FOUND=false
if require_cmd resolvectl; then
  _DNSSEC_STATUS=$(LC_ALL=C resolvectl status 2>/dev/null | grep -oP 'DNSSEC\s*[=:]\s*\K\S+' | head -1)
  if [[ "$_DNSSEC_STATUS" == "yes" ]]; then
    _emit_pass "DNSSEC validation: enabled (systemd-resolved)"
    _DNSSEC_FOUND=true
  elif [[ -n "$_DNSSEC_STATUS" ]]; then
    _emit_info "DNSSEC validation: $_DNSSEC_STATUS (systemd-resolved)"
    _DNSSEC_FOUND=true
  fi
fi
if ! $_DNSSEC_FOUND && systemctl is-active unbound &>/dev/null; then
  if grep -rqE "^\s*module-config:.*validator" /etc/unbound/ 2>/dev/null; then
    _emit_pass "DNSSEC validation: enabled (unbound with validator module)"
    _DNSSEC_FOUND=true
  else
    _emit_info "DNSSEC validation: unbound active but validator module not configured"
    _DNSSEC_FOUND=true
  fi
fi
if ! $_DNSSEC_FOUND && systemctl is-active dnscrypt-proxy &>/dev/null; then
  if grep -qE "^\s*require_dnssec\s*=\s*true" /etc/dnscrypt-proxy/dnscrypt-proxy.toml 2>/dev/null; then
    _emit_pass "DNSSEC validation: enabled (dnscrypt-proxy require_dnssec)"
    _DNSSEC_FOUND=true
  fi
fi
$_DNSSEC_FOUND || _emit_info "DNSSEC validation: could not determine (no resolvectl/unbound/dnscrypt-proxy)"

# DNS Leak Test & External IP (makes network requests — skippable with --skip netleaks)
if ! should_skip "netleaks"; then
  if require_cmd dig; then
    RESOLVED_IP=$(dig +short +time=5 whoami.akamai.net @ns1-1.akamaitech.net 2>/dev/null || echo "timeout")
    if [[ "$RESOLVED_IP" != "timeout" && -n "$RESOLVED_IP" ]]; then
      _emit_info "DNS leak test (public IP via DNS): $RESOLVED_IP"
    fi
  fi

  if require_cmd curl; then
    EXT_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "timeout")
    if [[ "$EXT_IP" != "timeout" ]]; then
      _emit_info "Public IP (HTTP): $EXT_IP"
      if [[ "$EXT_IP" =~ ^192\.168\. ]] || [[ "$EXT_IP" =~ ^10\. ]] || [[ "$EXT_IP" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        _emit_fail "Public IP is private — VPN leak?"
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
    # F-067/068: tighter regex — match prefix exactly via length-aware patterns.
    # if_inet6 format is 32-hex-char address. Link-local fe80, multicast ff*,
    # ULA fc/fd, loopback all-zero. Old regex `^(fe80|ff|fd|0000000000000000)`
    # could match "fe80abc..." (any address starting with fe80) which is
    # technically correct (fe80::/10), but stricter form anchors the
    # 16-character first half so we don't accidentally match a global address
    # that happens to start with "fd" but isn't ULA (very edge but possible).
    [[ "$_v6addr" =~ ^(fe[89ab][0-9a-f]|f[cd][0-9a-f]{2}|ff[0-9a-f]{2}|0{16}) ]] && continue
    # Skip VPN interfaces — their IPv6 is tunnel-internal, not a leak.
    # Use the global $_VPN_IFACE_REGEX so new families auto-propagate here.
    echo "$_v6iface" | grep -qE "$_VPN_IFACE_REGEX" && continue
    IPV6_GLOBAL=$((IPV6_GLOBAL + 1))
  done < /proc/net/if_inet6
  IPV6_TOTAL=$(wc -l < /proc/net/if_inet6)
  if [[ "$IPV6_GLOBAL" -gt 0 ]]; then
    _emit_warn "IPv6 active ($IPV6_GLOBAL global addresses on physical interfaces, $IPV6_TOTAL total) — leak risk"
  else
    # Remaining addresses may be link-local (fe80), ULA (fd), or loopback (::1)
    IPV6_ULA=$(grep -c '^fd' /proc/net/if_inet6 2>/dev/null || true)
    IPV6_ULA=${IPV6_ULA:-0}
    if [[ "$IPV6_ULA" -gt 0 ]]; then
      _emit_pass "IPv6: disabled/minimal ($IPV6_TOTAL addresses: link-local + $IPV6_ULA ULA)"
    else
      _emit_pass "IPv6: disabled/minimal ($IPV6_TOTAL link-local only)"
    fi
  fi
else
  _emit_pass "IPv6: completely disabled"
fi

# LAN Isolation — F-069: extend gateway list with common defaults beyond
# the original 3 (Fritz!Box DE, Speedport DE, corporate, Asus, USG).
# Plus dynamically learned LAN_GW (F-070, picks physical iface gateway not VPN).
LAN_GW_LIST="192.168.1.1 192.168.0.1 192.168.2.1 192.168.50.1 192.168.178.1 \
             10.0.0.1 10.0.0.138 10.0.1.1 172.16.0.1"
[[ -n "$LAN_GW" ]] && LAN_GW_LIST="$LAN_GW $LAN_GW_LIST"
[[ -n "$ACTUAL_GW" && "$ACTUAL_GW" != "$LAN_GW" ]] && LAN_GW_LIST="$ACTUAL_GW $LAN_GW_LIST"
# Plus any reachable neighbors from ARP table (already-known L2 peers)
if require_cmd ip; then
  while read -r _arp; do
    [[ -z "$_arp" ]] && continue
    LAN_GW_LIST="$_arp $LAN_GW_LIST"
  done < <(ip neigh show 2>/dev/null | awk '/REACHABLE|STALE/ && $1 ~ /^(10\.|172\.|192\.168\.|169\.254\.)/ {print $1}' | head -5)
fi
TESTED_GWS=""
for GW in $LAN_GW_LIST; do
  echo "$TESTED_GWS" | grep -qwF "$GW" && continue
  TESTED_GWS="$TESTED_GWS $GW"
  if ! ping -c1 -W1 "$GW" &>/dev/null; then
    _emit_pass "LAN blocked: $GW"
  else
    # Check if this gateway belongs to a VPN interface (e.g. WireGuard killswitch dummy)
    # These are intentionally reachable — they are the VPN's own internal addresses
    # F-071b: use $_VPN_IFACE_REGEX (covers Tailscale/ZeroTier/Mullvad/etc)
    # — old 4-name regex misclassified non-Proton VPN gateways as physical LAN.
    _GW_IS_VPN=false
    if require_cmd ip; then
      _GW_IFACE=$(ip route get "$GW" 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
      if echo "$_GW_IFACE" | grep -qE "$_VPN_IFACE_REGEX"; then
        _GW_IS_VPN=true
      fi
      # Also check if the GW IP is assigned to a VPN interface itself
      if ip addr show 2>/dev/null | grep -qP "inet\s+${GW//./\\.}/"; then
        _VPN_IFACE_OF_IP=$(ip addr show 2>/dev/null | grep -B3 "inet ${GW//./\\.}/" | grep -oP "^\d+:\s*\K\S+" | head -1)
        echo "$_VPN_IFACE_OF_IP" | grep -qE "$_VPN_IFACE_REGEX" && _GW_IS_VPN=true
      fi
    fi
    if $_GW_IS_VPN; then
      _emit_pass "LAN gateway $GW: VPN internal address (expected — WireGuard/killswitch interface)"
    elif [[ "$GW" == "$ACTUAL_GW" ]]; then
      _emit_warn "LAN gateway reachable: $GW (kill-switch?)"
    else
      _emit_warn "LAN reachable: $GW (kill-switch?)"
    fi
  fi
done

# Promiscuous Mode — F-072: filter known virtualization bridges/veth pairs
# (libvirt virbr*, docker docker0/br-*, lxc lxcbr*, podman cni-*) that
# legitimately enable promisc when slaves are attached.
PROMISC=$(ip -o link show | grep -i promisc | \
  grep -vE '^[0-9]+: (virbr|docker[0-9]|br-|veth|lxcbr|cni-|podman[0-9]+|tap)' || true)
if [[ -z "$PROMISC" ]]; then
  _emit_pass "No promiscuous mode (virt bridges excluded)"
else
  _emit_fail "Promiscuous mode active: $PROMISC"
fi

# ARP Table
# F-073: ARP state breakdown — REACHABLE entries are real peers, FAILED
# entries indicate hosts that don't respond (could be probing/scan attempts),
# STALE/DELAY/PROBE are transitional. Helps diagnose unusual LAN activity.
ARP_COUNT=$(ip neigh show 2>/dev/null | wc -l)
ARP_REACHABLE=$(ip neigh show nud reachable 2>/dev/null | wc -l)
ARP_FAILED=$(ip neigh show nud failed 2>/dev/null | wc -l)
ARP_STALE=$(ip neigh show nud stale 2>/dev/null | wc -l)
# F-308 (v3.6.1): account for PERMANENT/NOARP/NONE/INCOMPLETE/PROBE/DELAY entries
# in the math so total = sum of breakdown. Previously total could be > sum
# (e.g. 1 total / 0 reachable + 0 stale + 0 failed) when a PERMANENT or NOARP
# entry existed, leaving users to wonder where the missing entry went.
ARP_OTHER=$(( ARP_COUNT - ARP_REACHABLE - ARP_STALE - ARP_FAILED ))
[[ "$ARP_OTHER" -lt 0 ]] && ARP_OTHER=0
_emit_info "ARP entries: $ARP_COUNT total ($ARP_REACHABLE reachable, $ARP_STALE stale, $ARP_FAILED failed, $ARP_OTHER other)"
[[ "$ARP_FAILED" -gt 5 ]] && _emit_warn "ARP: $ARP_FAILED failed entries (possible LAN scanning attempts)"

# Network Namespaces
NS_COUNT=$(ip netns list 2>/dev/null | wc -l)
if [[ "$NS_COUNT" -gt 0 ]]; then
  _emit_info "Network namespaces: $NS_COUNT"
else
  _emit_info "Network namespaces: 0"
fi

}

###############################################################################
check_sysctl() {
  should_skip "sysctl" && return
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
  ["kernel.yama.ptrace_scope"]=2
  ["kernel.unprivileged_bpf_disabled"]=1
  ["net.ipv4.conf.all.rp_filter"]=1
  ["net.ipv4.conf.default.rp_filter"]=1
)

# F-074: bash assoc-array iteration is non-deterministic. Sort the keys
# so output is diff-friendly across runs and consistent in CI logs.
# v3.6: aggregated PASSes (use --verbose for per-key detail)
mapfile -t _SYSCTL_CHECKS_KEYS < <(printf '%s\n' "${!SYSCTL_CHECKS[@]}" | sort)
_emit_pass_agg_start "Sysctl basic"
for KEY in "${_SYSCTL_CHECKS_KEYS[@]}"; do
  EXPECTED="${SYSCTL_CHECKS[$KEY]}"
  ACTUAL=$(sysctl -n "$KEY" 2>/dev/null || echo "N/A")
  if [[ "$ACTUAL" == "N/A" ]]; then
    _emit_warn "sysctl $KEY: not available"
  elif [[ "$ACTUAL" -eq "$EXPECTED" ]]; then
    _emit_pass_agg "$KEY = $ACTUAL"
  elif [[ -n "${SYSCTL_MIN_OK[$KEY]+x}" ]] && [[ "$ACTUAL" -ge "${SYSCTL_MIN_OK[$KEY]}" ]]; then
    _emit_pass_agg "$KEY = $ACTUAL (>=${SYSCTL_MIN_OK[$KEY]} — hardened)"
  else
    _emit_fail "sysctl $KEY = $ACTUAL (expected: $EXPECTED)"
  fi
done
_emit_pass_agg_end "${#_SYSCTL_CHECKS_KEYS[@]}" "hardened"

sub_header "Strict/Optional"
mapfile -t _SYSCTL_STRICT_KEYS < <(printf '%s\n' "${!SYSCTL_STRICT[@]}" | sort)
_emit_pass_agg_start "Sysctl strict"
for KEY in "${_SYSCTL_STRICT_KEYS[@]}"; do
  EXPECTED="${SYSCTL_STRICT[$KEY]}"
  ACTUAL=$(sysctl -n "$KEY" 2>/dev/null || echo "N/A")
  if [[ "$ACTUAL" == "N/A" ]]; then
    _emit_info "sysctl $KEY: not available"
  elif [[ "$ACTUAL" -eq "$EXPECTED" ]]; then
    _emit_pass_agg "$KEY = $ACTUAL"
  else
    _emit_info "sysctl $KEY = $ACTUAL (strict would be: $EXPECTED)"
  fi
done
_emit_pass_agg_end "${#_SYSCTL_STRICT_KEYS[@]}" "strict-hardened"

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
    _emit_info "Magic SysRq: ALL functions enabled (value=1)"
  else
    _emit_info "Magic SysRq: value=$SYSRQ_VAL bits: $SYSRQ_BITS"
  fi
fi

# ip_forward (VPN exception)
IP_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
if [[ "${IP_FWD:-0}" -eq 1 ]]; then
  if [[ -n "$VPN_IFACES" ]]; then
    _emit_pass "ip_forward=1 (VPN active — expected)"
  else
    _emit_fail "ip_forward=1 WITHOUT active VPN!"
  fi
else
  _emit_pass "ip_forward=0"
fi

}

###############################################################################
check_services() {
  should_skip "services" && return
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
# F-309 (v3.6.1): bluetooth.service + bluetooth.socket grouped — they're the
# same logical entity (socket activates service). Reporting separately leads
# to "service masked, socket off" inconsistencies that confuse users about
# whether bluetooth is fully disabled.
_SVC_GROUPS_DESKTOP=(
  "cups:printing"
  "avahi-daemon:Bonjour/mDNS discovery"
  "bluetooth.service bluetooth.socket:Bluetooth"
  # F-336 (v3.6.1): switcheroo-control surfaces only when laptop has hybrid
  # graphics (NVIDIA Optimus / AMD APU + dGPU / Intel iGPU + dGPU). On
  # single-GPU workstations or systems where the iGPU has no outputs it is
  # pure attack surface — gets enabled by default in Fedora Workstation but
  # can safely be masked. Surfacing it in this group means "masked" emits PASS
  # (visible) and "running" emits INFO (desktop default — context-aware).
  "switcheroo-control:GPU power switching (hybrid graphics laptops)"
)

for _grp in "${_SVC_GROUPS_OFF[@]}"; do
  # First name in group is the canonical display name
  _canonical="${_grp%% *}"
  # shellcheck disable=SC2086  # intentional word-split on space-separated group
  if _service_active_any $_grp; then
    _emit_fail "Service running: $_canonical"
  elif _service_masked_any $_grp; then
    _emit_pass "Service masked: $_canonical"
  elif _service_enabled_any $_grp; then
    _emit_warn "Service enabled but inactive: $_canonical"
  else
    _emit_pass "Service off: $_canonical"
  fi
done

# Desktop-relevant services with context-aware severity
# F-309: support space-separated unit aliases per entry (everything before the
# LAST colon is the unit-list, after the last colon is context). ANY-active /
# ANY-masked semantics — the strictest state of any alias drives the report.
for _entry in "${_SVC_GROUPS_DESKTOP[@]}"; do
  _svc_list="${_entry%:*}"
  _ctx="${_entry##*:}"
  _svc_canonical="${_svc_list%% *}"
  # shellcheck disable=SC2086  # intentional word-split on space-separated aliases
  if _service_active_any $_svc_list; then
    if $_IS_DESKTOP; then
      _emit_info "Service running: $_svc_canonical (desktop default — $_ctx)"
    else
      _emit_warn "Service running: $_svc_canonical (consider disabling on server — $_ctx)"
    fi
  elif _service_masked_any $_svc_list; then
    _emit_pass "Service masked: $_svc_canonical"
  else
    _emit_pass "Service off: $_svc_canonical"
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
  _emit_warn "wsdd.service active — WS-Discovery broadcasts hostname on local network"
elif $_WSDD_STANDALONE_PROC; then
  _emit_warn "wsdd process running (not via systemd service)"
else
  _emit_pass "wsdd (standalone): not running"
fi

# gvfsd-wsdd is part of GNOME's gvfs — started on-demand for network browsing.
# It is firewall-protected on hardened systems. Warn only if firewall is absent.
# F-317 (v3.6.1): include the count of wsdd listener processes that gvfsd
# spawned, so users understand the UDP listeners they see in Section 8 ports
# come from this gvfsd subsystem (running with --no-host, won't broadcast
# the hostname). Without this counter, Section 8's many wsdd UDP entries
# look contradictory to Section 7's "wsdd standalone: not running".
if pgrep -x gvfsd-wsdd &>/dev/null; then
  _GVFSD_WSDD_PROCS=$(pgrep -x wsdd 2>/dev/null | wc -l)
  if systemctl is-active firewalld &>/dev/null || systemctl is-active ufw &>/dev/null; then
    _emit_info "gvfsd-wsdd (GNOME network browsing): running — firewall-protected (spawned $_GVFSD_WSDD_PROCS wsdd listener process(es), see Section 8)"
  else
    _emit_warn "gvfsd-wsdd running without active firewall — WS-Discovery exposed on LAN ($_GVFSD_WSDD_PROCS wsdd listener process(es) spawned)"
  fi
fi

# Critical services that should be ON
SHOULD_BE_ON="firewalld auditd fail2ban"
for SVC in $SHOULD_BE_ON; do
  if systemctl is-active "$SVC" &>/dev/null; then
    _emit_pass "Service active: $SVC"
  elif ! require_cmd "$SVC" && ! systemctl cat "$SVC" &>/dev/null; then
    _emit_info "Service $SVC: not installed — skipped"
  else
    _emit_fail "Service INACTIVE: $SVC"
  fi
done

# Failed Services
# F-085: extended whitelist for known-FP failed-services on bootc/Silverblue/
# minimal systems. binfmt_misc and update-utmp are environment-specific; the
# tracked-pids-too-old line appears in fresh container boots transiently.
FAILED_SVCS=$(systemctl --failed --no-legend 2>/dev/null | grep -vE 'proc-sys-fs-binfmt_misc\.(mount|automount)|systemd-update-utmp\.service|tracked-pids-too-old')
FAILED=$(echo "$FAILED_SVCS" | grep -c '\S' || true)
if [[ "$FAILED" -eq 0 ]]; then
  _emit_pass "0 failed services"
else
  svc_names=$(echo "$FAILED_SVCS" | awk '{print ($1 == "●" || $1 == "×") ? $2 : $1}' | tr '\n' ', ' | sed 's/,$//')
  _emit_fail "$FAILED failed services: $svc_names"
  if ! $JSON_MODE; then
    while read -r line; do
      printf "       %s\n" "$line"
    done <<< "$FAILED_SVCS"
  fi
fi

# Timer Units
TIMER_COUNT=$(systemctl list-timers --all --no-legend 2>/dev/null | wc -l)
_emit_info "Active timers: $TIMER_COUNT"

}

###############################################################################
check_ports() {
  should_skip "ports" && return
  header "08" "OPEN PORTS & LISTENERS"
###############################################################################

# F-088b: pre-compute address sets bound to VM/container bridges and VPN
# tunnels. A listener on these is not "internet-exposed" — virbr0/docker0/
# podman bridges are intra-host VM/container traffic; tun/wg/proton tunnels
# are encrypted point-to-point links. Reduces FP noise on virtualization +
# VPN hosts (e.g., wsdd announcing on tunnel addresses).
_VM_BRIDGE_ADDRS=$(ip -o addr show 2>/dev/null | awk '
  $2 ~ /^(virbr|docker|podman|cni-|lxcbr|br-)/ {
    split($4, a, "/"); print a[1]
  }' | tr '\n' '|' | sed 's/|$//')
_VPN_TUNNEL_ADDRS=$(ip -o addr show 2>/dev/null | awk -v vpn_re="$_VPN_IFACE_REGEX" '
  $2 ~ vpn_re {
    split($4, a, "/"); print a[1]
  }' | tr '\n' '|' | sed 's/|$//')

# Helper: extract IP portion (no port, no [] brackets, no %iface scope) from
# an ss `Local Address:Port` field. ss output forms:
#   192.168.122.1:53           → 192.168.122.1
#   [::1]:53                   → ::1
#   0.0.0.0%virbr0:67          → 0.0.0.0
#   [fe80::xx]%proton0:3702    → fe80::xx
_extract_ip() {
  local addr="$1"
  # Strip %iface scope first (between IP and port, can confuse port-strip)
  addr="${addr%%\%*}"
  # Strip trailing :port
  if [[ "$addr" =~ ^\[(.+)\]:[0-9]+$ ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    echo "${addr%:*}"
  fi
}

_classify_listener() {
  local addr_field="$1"
  local ip
  ip=$(_extract_ip "$addr_field")
  # Localhost/loopback
  if [[ "$ip" == "127.0.0.1" ]] || [[ "$ip" =~ ^127\. ]] || \
     [[ "$ip" == "::1" ]] || [[ "$ip" =~ ^::ffff:127\. ]]; then
    echo "loopback"
    return
  fi
  # VM/container bridge
  if [[ -n "$_VM_BRIDGE_ADDRS" ]] && echo "$ip" | grep -qE "^($_VM_BRIDGE_ADDRS)$"; then
    echo "bridge"
    return
  fi
  # VPN tunnel
  if [[ -n "$_VPN_TUNNEL_ADDRS" ]] && echo "$ip" | grep -qE "^($_VPN_TUNNEL_ADDRS)$"; then
    echo "vpn"
    return
  fi
  echo "external"
}

sub_header "TCP"
while read -r line; do
  [[ -z "$line" ]] && continue
  ADDR=$(echo "$line" | awk '{print $4}')
  PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
  case "$(_classify_listener "$ADDR")" in
    loopback)
      _emit_pass "TCP $ADDR ($PROC) — localhost only" ;;
    bridge)
      _emit_info "TCP $ADDR ($PROC) — VM/container bridge (intra-host)" ;;
    vpn)
      _emit_info "TCP $ADDR ($PROC) — VPN tunnel address" ;;
    *)
      if has_firewall_block_on_phys; then
        _emit_warn "TCP $ADDR ($PROC) — externally bound, but firewall/kill-switch blocks"
      else
        _emit_fail "TCP $ADDR ($PROC) — EXTERNALLY REACHABLE"
      fi
      ;;
  esac
done < <(ss -tlnp 2>/dev/null | tail -n+2)

sub_header "UDP"
# F-322 (v3.6.1): dedupe identical (address, port, process) bindings into a
# single line with "[×N multi-interface]" suffix. wsdd binds the same multicast
# group (239.255.255.250:3702 / [ff02::c]:3702) per-interface, producing 3-6
# visually identical entries that clutter the report. Each unique listener now
# emits exactly one finding regardless of how many interfaces it's bound on —
# duplicates are not additional security findings, just per-interface socket
# instances of the same logical service.
declare -A _UDP_KEY_COUNT=()
declare -A _UDP_KEY_LINE=()
declare -a _UDP_KEY_ORDER=()
# F-328 (v3.6.1): per-PROC accumulator for collapsed firewall-blocked summary.
# Repeating "externally bound, but firewall/kill-switch blocks" on every wsdd
# listener (often 10+ on multi-interface systems) clutters the output. Detail
# lines now keep the address but drop the long annotation; a single per-PROC
# summary line at the section end states the firewall-blocked verdict once.
declare -A _UDP_EXT_BLOCKED_PROCS=()
while read -r line; do
  [[ -z "$line" ]] && continue
  ADDR=$(echo "$line" | awk '{print $4}')
  PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "kernel")
  key="${ADDR}|${PROC}"
  if [[ -z "${_UDP_KEY_LINE[$key]+x}" ]]; then
    _UDP_KEY_ORDER+=("$key")
    _UDP_KEY_LINE[$key]="$line"
    _UDP_KEY_COUNT[$key]=1
  else
    _UDP_KEY_COUNT[$key]=$((${_UDP_KEY_COUNT[$key]} + 1))
  fi
done < <(ss -ulnp 2>/dev/null | tail -n+2)
for key in "${_UDP_KEY_ORDER[@]}"; do
  line="${_UDP_KEY_LINE[$key]}"
  count="${_UDP_KEY_COUNT[$key]}"
  ADDR=$(echo "$line" | awk '{print $4}')
  PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "kernel")
  _multi_suffix=""
  [[ "$count" -gt 1 ]] && _multi_suffix=" [×${count} multi-interface]"
  case "$(_classify_listener "$ADDR")" in
    loopback)
      _emit_pass "UDP $ADDR ($PROC) — localhost only${_multi_suffix}" ;;
    bridge)
      _emit_info "UDP $ADDR ($PROC) — VM/container bridge (intra-host)${_multi_suffix}" ;;
    vpn)
      _emit_info "UDP $ADDR ($PROC) — VPN tunnel address${_multi_suffix}" ;;
    *)
      if echo "$PROC" | grep -qiE "wireguard|wg|vpn"; then
        _emit_pass "UDP $ADDR (VPN/WireGuard)${_multi_suffix}"
      elif [[ "$PROC" == "kernel" ]]; then
        # Kernel-owned UDP sockets can be WireGuard, IPVS, conntrack, etc.
        if ip link show type wireguard 2>/dev/null | grep -q .; then
          _emit_info "UDP $ADDR (kernel — likely WireGuard)${_multi_suffix}"
        else
          _emit_info "UDP $ADDR (kernel — no WireGuard interfaces found)${_multi_suffix}"
        fi
      elif has_firewall_block_on_phys; then
        _emit_info "UDP $ADDR ($PROC) — externally bound${_multi_suffix}"
        _UDP_EXT_BLOCKED_PROCS[$PROC]=$((${_UDP_EXT_BLOCKED_PROCS[$PROC]:-0} + 1))
      else
        _emit_warn "UDP $ADDR ($PROC) — external${_multi_suffix}"
      fi
      ;;
  esac
done
# F-328: per-PROC summary instead of repeating annotation on every listener
for _ext_proc in "${!_UDP_EXT_BLOCKED_PROCS[@]}"; do
  _ext_n="${_UDP_EXT_BLOCKED_PROCS[$_ext_proc]}"
  [[ "$_ext_n" -eq 1 ]] && _ext_word="listener" || _ext_word="listeners"
  _emit_info "  └─ ${_ext_proc}: ${_ext_n} ${_ext_word} above are firewall/kill-switch blocked"
done

# Connections to unusual ports
sub_header "Unusual destination ports"
UNUSUAL_PORTS=$(while read -r port; do
  # F-090: extended whitelist covers HTTPS/HTTP, mail (IMAP/IMAPS/POP3/POP3S/
  # SMTP/Submission/SMTPS), DNS, XMPP/XMPP-S, SSH, alt-HTTPS (8080/8443/4443/
  # 7443), STUN (3478/3479), TURN-S (5349), SIP/SIPS (5060/5061), MQTT-S
  # (8883), WebRTC default port range, and IRC-over-TLS (6697).
  case "$port" in
    80|443|53|993|465|8443|22|587|143|995|5222|5223|\
    8080|4443|7443|3478|3479|5349|5060|5061|8883|6697) ;;
    *) echo "$port" ;;
  esac
done < <(ss -tnp state established 2>/dev/null | awk '{print $4}' | grep -oP ':\K\d+$' | sort -n | uniq))
if [[ -n "$UNUSUAL_PORTS" ]]; then
  # F-324 (v3.6.1): annotate well-known app-internal ports so users don't
  # treat them as suspicious. Map common privacy-tooling ports to their owner;
  # everything else is shown as bare port number.
  _annotated_ports=""
  while read -r _p; do
    [[ -z "$_p" ]] && continue
    case "$_p" in
      65432) _annotated_ports+="$_p (protonvpn-app control) " ;;
      11434) _annotated_ports+="$_p (Ollama LLM) " ;;
      9090)  _annotated_ports+="$_p (Cockpit web UI) " ;;
      9443)  _annotated_ports+="$_p (Portainer / NetBox) " ;;
      8000)  _annotated_ports+="$_p (Python http.server / Django dev) " ;;
      *)     _annotated_ports+="$_p " ;;
    esac
  done <<< "$UNUSUAL_PORTS"
  _emit_info "Connections to non-standard ports: ${_annotated_ports% }"
else
  _emit_pass "All connections on standard ports"
fi

# Raw Sockets
RAW=$(ss -wnp 2>/dev/null | tail -n+2 | wc -l)
if [[ "$RAW" -gt 0 ]]; then
  _emit_warn "Raw sockets: $RAW"
else
  _emit_pass "No raw sockets"
fi

}

###############################################################################
check_ssh() {
  should_skip "ssh" && return
  header "09" "SSH HARDENING"
###############################################################################

# F-093: SSH off when masked OR disabled+inactive — both states deliver
# "SSH not reachable", so accept either as maximum security. Previous logic
# only matched masked, false-flagging users who keep sshd installed but
# disabled (Fedora default).
_SSH_OFF=true
for _ssh_unit in sshd ssh ssh.socket sshd.socket; do
  if systemctl is-active "$_ssh_unit" &>/dev/null; then
    _SSH_OFF=false
    break
  fi
  _ssh_state=$(systemctl is-enabled "$_ssh_unit" 2>/dev/null || echo "missing")
  if [[ "$_ssh_state" == "enabled" ]]; then
    _SSH_OFF=false
    break
  fi
done

if $_SSH_OFF; then
  _emit_pass "SSH: inactive (no enabled or running unit) — maximum security"
else
  SSHD_CONFIG="/etc/ssh/sshd_config"
  if [[ -f "$SSHD_CONFIG" ]]; then
    # PermitRootLogin
    VAL=$(sshd_cfg_val PermitRootLogin)
    if [[ "$VAL" == "no" ]]; then
      _emit_pass "SSH: PermitRootLogin no"
    else
      _emit_fail "SSH: PermitRootLogin ${VAL:-not set} (should be 'no')"
    fi

    # PasswordAuthentication
    VAL=$(sshd_cfg_val PasswordAuthentication)
    if [[ "$VAL" == "no" ]]; then
      _emit_pass "SSH: PasswordAuthentication no"
    else
      _emit_warn "SSH: PasswordAuthentication ${VAL:-not explicitly 'no'}"
    fi

    # PubkeyAuthentication (default is 'yes' in OpenSSH — only warn if explicitly disabled)
    VAL=$(sshd_cfg_val PubkeyAuthentication)
    if [[ "$VAL" == "yes" ]]; then
      _emit_pass "SSH: PubkeyAuthentication yes"
    elif [[ "$VAL" == "no" ]]; then
      _emit_warn "SSH: PubkeyAuthentication no (should be 'yes')"
    else
      # Not explicitly set — OpenSSH default is 'yes', which is correct
      _emit_pass "SSH: PubkeyAuthentication yes (default)"
    fi

    # X11Forwarding
    VAL=$(sshd_cfg_val X11Forwarding)
    if [[ "$VAL" == "no" ]]; then
      _emit_pass "SSH: X11Forwarding no"
    else
      _emit_warn "SSH: X11Forwarding ${VAL:-not set to 'no'}"
    fi

    # MaxAuthTries
    MAX_AUTH=$(sshd_cfg_val MaxAuthTries)
    MAX_AUTH=${MAX_AUTH:-6}
    if [[ "$MAX_AUTH" -le 3 ]]; then
      _emit_pass "SSH: MaxAuthTries $MAX_AUTH"
    else
      _emit_warn "SSH: MaxAuthTries $MAX_AUTH (recommended: <=3)"
    fi

    # AllowUsers/AllowGroups
    if grep -qhiE "^\s*(AllowUsers|AllowGroups)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
      _emit_pass "SSH: user/group whitelist active"
    else
      _emit_warn "SSH: no user/group whitelist"
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
        _emit_pass "SSH: LoginGraceTime $LGT (${LGT_SEC}s)"
      else
        _emit_warn "SSH: LoginGraceTime $LGT (${LGT_SEC}s, recommended: <=60s)"
      fi
    else
      _emit_warn "SSH: LoginGraceTime not set (default 120s — too long)"
    fi

    # SSH Key Strength
    sub_header "SSH Key Strength"
    while read -r USER_HOME; do
      [[ -d "$USER_HOME" ]] || continue
      for KEY in "$USER_HOME"/.ssh/*.pub; do
        [[ -f "$KEY" ]] || continue
        _KEY_INFO=$(ssh-keygen -l -f "$KEY" 2>/dev/null) || continue
        BITS=$(echo "$_KEY_INFO" | awk '{print $1}')
        TYPE=$(echo "$_KEY_INFO" | awk '{print $NF}' | tr -d '()')
        # RSA thresholds: <2048 = insecure (NIST deprecated), <4096 = acceptable but 4096 recommended
        # F-097: ECDSA must be >=256 (P-256/P-384/P-521). P-192 is broken.
        # F-098: DSA is deprecated since OpenSSH 7.0 — explicit fail.
        if [[ "$TYPE" == "DSA" ]]; then
          _emit_fail "Insecure SSH key: $KEY ($BITS bit DSA — deprecated since OpenSSH 7.0)"
        elif [[ "$TYPE" == "RSA" ]] && [[ "${BITS:-0}" -lt 2048 ]]; then
          _emit_fail "Weak SSH key: $KEY ($BITS bit $TYPE — minimum 2048)"
        elif [[ "$TYPE" == "RSA" ]] && [[ "${BITS:-0}" -lt 4096 ]]; then
          _emit_warn "SSH key: $KEY ($BITS bit $TYPE — 4096 recommended)"
        elif [[ "$TYPE" == "ECDSA" ]] && [[ "${BITS:-0}" -lt 256 ]]; then
          _emit_fail "Weak SSH key: $KEY ($BITS bit $TYPE — minimum P-256)"
        elif [[ -n "$TYPE" ]]; then
          _emit_pass "SSH key: $KEY ($BITS bit $TYPE)"
        fi
      done
    done < <(_iter_user_homes)
  fi
fi

}

###############################################################################
check_audit() {
  should_skip "audit" && return
  header "10" "AUDIT SYSTEM"
###############################################################################

if systemctl is-active auditd &>/dev/null; then
  _emit_pass "auditd: active"
elif ! require_cmd auditctl; then
  _emit_info "auditd not installed — skipped"
else
  _emit_fail "auditd: INACTIVE"
fi

if require_cmd auditctl; then
  AUDIT_RULES=$(auditctl -l 2>/dev/null | grep -cv "^No rules" || true)
  # F-100: CIS Level 2 + STIG expect 38+ rules; 20 is a soft minimum.
  if [[ "$AUDIT_RULES" -ge 38 ]]; then
    _emit_pass "Audit rules: $AUDIT_RULES (meets CIS Level 2 / STIG ≥38)"
  elif [[ "$AUDIT_RULES" -ge 20 ]]; then
    _emit_pass "Audit rules: $AUDIT_RULES (consider ≥38 for CIS Level 2)"
  elif [[ "$AUDIT_RULES" -gt 0 ]]; then
    _emit_warn "Audit rules: only $AUDIT_RULES (recommended ≥20; CIS L2 ≥38)"
  else
    _emit_fail "Audit rules: 0"
  fi

  AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep -oP '(?:^enabled\s+|enabled=)\K[0-9]+' | head -1)
  if [[ "$AUDIT_ENABLED" == "2" ]]; then
    _emit_pass "Audit: immutable (enabled=2)"
  elif [[ "$AUDIT_ENABLED" == "1" ]]; then
    _emit_warn "Audit: enabled=1 (not immutable)"
  else
    _emit_fail "Audit: enabled=$AUDIT_ENABLED"
  fi

  CRITICAL_WATCHES="/etc/passwd /etc/shadow /etc/sudoers /etc/ssh /etc/pam.d"
  _AUDIT_RULES_CACHE=$(auditctl -l 2>/dev/null)
  for WATCH in $CRITICAL_WATCHES; do
    # F-101: escape regex metacharacters in paths (`.` in pam.d, etc) so the
    # regex doesn't match unintended substrings like "pamXd".
    _watch_re="${WATCH//./\\.}"
    # Match both short form (-w /path) and long form (-F path=/path, -F dir=/path),
    # including sub-path matches (e.g. -F path=/etc/ssh/sshd_config covers /etc/ssh)
    if echo "$_AUDIT_RULES_CACHE" | grep -qE -- "(-w ${_watch_re}( |$)|-F (path|dir)=${_watch_re}(/|\s|$))"; then
      _emit_pass "Audit watch: $WATCH"
    else
      _emit_warn "Audit watch missing: $WATCH"
    fi
  done
fi

if [[ -f /var/log/audit/audit.log ]]; then
  # F-102: warn if audit log is huge (>1GiB) — usually means rules are
  # generating excessive events and rotation isn't keeping up.
  AUDIT_SIZE_BYTES=$(stat -c%s /var/log/audit/audit.log 2>/dev/null || echo 0)
  AUDIT_SIZE=$(_human_size "$AUDIT_SIZE_BYTES")
  if [[ "$AUDIT_SIZE_BYTES" -gt 1073741824 ]]; then
    _emit_warn "Audit log: $AUDIT_SIZE (>1GiB — rules may be too verbose; check rotation)"
  else
    _emit_info "Audit log: $AUDIT_SIZE"
  fi
fi

}

###############################################################################
check_users() {
  should_skip "users" && return
  header "11" "USERS & AUTHENTICATION"
###############################################################################

# UID-0 Accounts
UID0_COUNT=$(awk -F: '$3==0' /etc/passwd | wc -l)
if [[ "$UID0_COUNT" -eq 1 ]]; then
  _emit_pass "Only 1 UID-0 account (root)"
else
  _emit_fail "$UID0_COUNT UID-0 accounts!"
  $JSON_MODE || awk -F: '$3==0 {print "       " $1}' /etc/passwd
fi

# Empty Passwords — F-273: severity coupled with PAM nullok presence.
# An empty $2 field in /etc/shadow has two distinct meanings:
#   (a) "No password set" (NP-state) — PAM rejects login when nullok absent.
#       Common on Anaconda Live-ISOs (root + liveuser ship NP) and freshly
#       provisioned systems where install-time setup is pending.
#   (b) "Truly empty password" — exploitable iff PAM nullok is enabled.
# Pre-scan PAM nullok first so the empty-PW finding can pick correct severity
# AND the dedicated nullok finding below reuses the same scan (avoid double-grep).
declare -A _NULLOK_FOUND_IN=()
for PAM_FILE in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
  [[ -f "$PAM_FILE" ]] || continue
  _nullok_line=$(grep -E '^[[:space:]]*[^#[:space:]].*nullok' "$PAM_FILE" 2>/dev/null | head -1)
  [[ -n "$_nullok_line" ]] && _NULLOK_FOUND_IN["$(basename "$PAM_FILE")"]="$_nullok_line"
done

EMPTY_PW_USERS=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null)
EMPTY_PW=$(printf '%s' "$EMPTY_PW_USERS" | grep -c . 2>/dev/null || true)
EMPTY_PW=${EMPTY_PW:-0}

if [[ "$EMPTY_PW" -eq 0 ]]; then
  _emit_pass "No accounts with empty password"
elif [[ "${#_NULLOK_FOUND_IN[@]}" -gt 0 ]]; then
  # Worst case — empty $2 AND PAM nullok lets it authenticate
  _emit_fail "$EMPTY_PW account(s) with empty password AND PAM nullok present — passwordless login enabled"
  if ! $JSON_MODE; then
    printf '%s\n' "$EMPTY_PW_USERS" | head -5 | while read -r _u; do
      [[ -n "$_u" ]] && printf "       %s\n" "$_u"
    done
  fi
else
  # Empty $2 but PAM blocks — NP-state. Live-ISO convention or pending setup.
  _emit_info "$EMPTY_PW account(s) with no password set (NP-status, PAM blocks login — common on Live-ISOs / install-pending systems)"
  if ! $JSON_MODE; then
    printf '%s\n' "$EMPTY_PW_USERS" | head -5 | while read -r _u; do
      [[ -n "$_u" ]] && printf "       %s\n" "$_u"
    done
  fi
fi

# PAM nullok — dedicated reporting per file (uses _NULLOK_FOUND_IN scanned above)
for PAM_FILE in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
  [[ -f "$PAM_FILE" ]] || continue
  _pam_basename=$(basename "$PAM_FILE")
  if [[ -n "${_NULLOK_FOUND_IN[$_pam_basename]:-}" ]]; then
    _emit_fail "PAM nullok in $_pam_basename — empty passwords allowed"
    $JSON_MODE || printf "       %s\n" "${_NULLOK_FOUND_IN[$_pam_basename]:0:100}"
  else
    _emit_pass "PAM nullok removed: $_pam_basename"
  fi
done

# securetty — empty or missing file blocks root on all TTYs (hardened),
# but only if pam_securetty.so is in the PAM stack.
if [[ -f /etc/securetty ]]; then
  if [[ ! -s /etc/securetty ]]; then
    _emit_pass "securetty present and empty (root TTY login blocked)"
  else
    _emit_pass "securetty present"
  fi
else
  _emit_info "securetty absent (root TTY restriction depends on PAM config)"
fi

# Sudo group
WHEEL_MEMBERS=$(grep "^wheel:" /etc/group 2>/dev/null | cut -d: -f4)
if [[ -z "$WHEEL_MEMBERS" ]]; then
  WHEEL_MEMBERS=$(grep "^sudo:" /etc/group 2>/dev/null | cut -d: -f4)
fi
_emit_info "Wheel/sudo members: $WHEEL_MEMBERS"

# Shell users
SHELL_USERS=$(grep -cvE '/nologin|/false|/sync|/shutdown|/halt' /etc/passwd)
_emit_info "Users with login shell: $SHELL_USERS"
if ! $JSON_MODE; then
  while IFS=: read -r user _ uid _ _ _ shell; do
    printf "       %s (UID=%s, Shell=%s)\n" "$user" "$uid" "$shell"
  done < <(grep -vE '/nologin|/false|/sync|/shutdown|/halt' /etc/passwd)
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
  _emit_pass "Password hashing: YESCRYPT (strongest)"
elif [[ "${_EFFECTIVE_HASH^^}" == "SHA512" ]]; then
  _emit_pass "Password hashing: SHA512 (strong)"
elif [[ "${_EFFECTIVE_HASH^^}" == "SHA256" ]]; then
  _emit_warn "Password hashing: SHA256 (consider SHA512 or YESCRYPT)"
elif [[ -n "$_EFFECTIVE_HASH" ]]; then
  _emit_fail "Password hashing: $_EFFECTIVE_HASH (weak — migrate to SHA512 or YESCRYPT)"
else
  _emit_info "Password hashing method: could not determine"
fi

# Password Hashing Rounds
_PW_ROUNDS=$(grep -iE "^SHA_CRYPT_MAX_ROUNDS|^YESCRYPT_COST_FACTOR" /etc/login.defs 2>/dev/null | tail -1 | awk '{print $2}')
if [[ -n "$_PW_ROUNDS" ]]; then
  _emit_info "Password hashing rounds/cost: $_PW_ROUNDS"
fi

# PAM password quality (pwquality/cracklib)
# F-104b: Fedora's authselect ships /etc/pam.d/system-auth and password-auth as
# symlinks into /etc/authselect/. `grep -r` does NOT dereference symlinks
# encountered during traversal; only `grep -R` (capital R) does. Without this
# fix, pam_pwquality/cracklib detection silently false-negatives on Fedora.
_PW_QUALITY=false
if grep -RqsE "pam_pwquality|pam_cracklib" /etc/pam.d/ 2>/dev/null; then
  _PW_QUALITY=true
  _emit_pass "Password quality enforcement: pam_pwquality/pam_cracklib active"
else
  _emit_warn "No password quality enforcement (pam_pwquality/pam_cracklib not in PAM stack)"
fi

# Accounts without password expiry — F-106: skip on systems using LDAP/SSSD
# central auth (chage queries the local shadow file which doesn't have the
# expiry policy when authentication is centralized).
sub_header "Password Expiry"
_NO_EXPIRE=0
_CENTRAL_AUTH=false
if [[ -f /etc/nsswitch.conf ]] && grep -qE '^passwd:.*\b(sss|ldap|winbind)\b' /etc/nsswitch.conf 2>/dev/null; then
  _CENTRAL_AUTH=true
  _emit_info "Password expiry: skipped (central auth detected via nsswitch — chage queries local shadow only)"
fi
if ! $_CENTRAL_AUTH; then
  # F-106b: chage(1) outputs are LOCALIZED — on a German/French/etc. system,
  # the labels "Maximum number of days..." and "Password expires" become
  # "Maximale Anzahl..." and "Passwort läuft ab", and the English-only greps
  # silently return zero matches → false PASS for password-expiry checks.
  # Force LC_ALL=C (POSIX/English) for chage so labels are stable.
  while IFS=: read -r _user _ _uid _ _ _ _; do
    _is_human_uid "$_uid" || continue
    # Extract the value-side after the colon — handles "99999", "-1", and
    # the literal "never" string equivalently (a negative number caught by
    # the previous \d+$ regex was returned as the unsigned digits, masking
    # the no-expiry condition).
    _max_val=$(LC_ALL=C chage -l "$_user" 2>/dev/null \
      | awk -F: '/Maximum/{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2; exit}')
    case "$_max_val" in
      never|-1|99999) _NO_EXPIRE=$((_NO_EXPIRE + 1)) ;;
    esac
    # Check for expired passwords
    _pw_expired=$(LC_ALL=C chage -l "$_user" 2>/dev/null | grep "Password expires" | grep -ciE "password must be changed|expired" || true)
    if [[ "${_pw_expired:-0}" -gt 0 ]]; then
      _emit_warn "Password expired for user: $_user"
    fi
  done < /etc/passwd
fi
if ! $_CENTRAL_AUTH; then
  if [[ "$_NO_EXPIRE" -gt 0 ]]; then
    _emit_info "$_NO_EXPIRE user account(s) with no password expiry (perpetual passwords)"
  else
    _emit_pass "All user accounts have password expiry configured"
  fi
fi

# Duplicate accounts
_DUP_UIDS=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
if [[ -n "$_DUP_UIDS" ]]; then
  _emit_fail "Duplicate UIDs found: $_DUP_UIDS"
else
  _emit_pass "No duplicate UIDs"
fi

# Duplicate group IDs
_DUP_GIDS=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
if [[ -n "$_DUP_GIDS" ]]; then
  _emit_warn "Duplicate GIDs found: $_DUP_GIDS"
else
  _emit_pass "No duplicate GIDs"
fi

# Password file consistency (pwck)
if require_cmd pwck; then
  _PWCK_OUT=$(pwck -rq 2>&1 || true)
  _PWCK_ERRORS=$(echo "$_PWCK_OUT" | grep -cvE "^$|^pwck:" || true)
  _PWCK_ERRORS=${_PWCK_ERRORS:-0}
  if [[ "$_PWCK_ERRORS" -eq 0 ]]; then
    _emit_pass "Password file consistency: OK (pwck)"
  else
    _emit_warn "Password file inconsistencies: $_PWCK_ERRORS (run 'pwck' to review)"
  fi
fi

# Locked user accounts + NP (no-password) accounts.
# F-275: passwd -S returns five status tokens — distinguish them all:
#   L / LK : locked (passwd -l)
#   NP     : no password set (Anaconda Live-ISO convention; PAM blocks login
#            when nullok absent — see Empty-PW finding above for severity)
#   P      : password set (regular account)
#   NP and locked are reported as INFO; NP-state is also auditable so it
#   surfaces in JSON output for downstream tooling.
# LC_ALL=C: passwd -S output is locale-translatable; force C for parsing.
sub_header "Account Status"
_LOCKED_ACCOUNTS=0
_NP_ACCOUNTS=0
declare -a _NP_USERS=()
while IFS=: read -r _lu_user _ _lu_uid _ _ _ _; do
  _is_human_uid "$_lu_uid" || continue
  _lu_status=$(LC_ALL=C passwd -S "$_lu_user" 2>/dev/null | awk '{print $2}')
  case "$_lu_status" in
    L|LK)
      _emit_info "Account locked: $_lu_user"
      _LOCKED_ACCOUNTS=$((_LOCKED_ACCOUNTS + 1))
      ;;
    NP)
      _NP_USERS+=("$_lu_user")
      _NP_ACCOUNTS=$((_NP_ACCOUNTS + 1))
      ;;
  esac
done < /etc/passwd

if [[ "$_LOCKED_ACCOUNTS" -gt 0 ]]; then
  _emit_info "$_LOCKED_ACCOUNTS user account(s) locked"
else
  _emit_pass "No locked user accounts"
fi

if [[ "$_NP_ACCOUNTS" -gt 0 ]]; then
  _emit_info "$_NP_ACCOUNTS account(s) with no password set (NP-status, PAM-blocked: ${_NP_USERS[*]})"
fi

# Sudoers security
sub_header "Sudoers Security"
if [[ -f /etc/sudoers ]]; then
  # Check sudoers file permissions (should be 440)
  _SUDOERS_PERMS=$(stat -c %a /etc/sudoers 2>/dev/null)
  if [[ "$_SUDOERS_PERMS" == "440" ]]; then
    _emit_pass "sudoers permissions: $_SUDOERS_PERMS"
  else
    _emit_warn "sudoers permissions: $_SUDOERS_PERMS (should be 440)"
  fi
  # Check sudoers.d drop-in permissions
  if [[ -d /etc/sudoers.d ]]; then
    _SUDOERSD_BAD=0
    for _sf in /etc/sudoers.d/*; do
      [[ -f "$_sf" ]] || continue
      _sf_perms=$(stat -c %a "$_sf" 2>/dev/null)
      if [[ "$_sf_perms" != "440" && "$_sf_perms" != "400" ]]; then
        _emit_warn "sudoers.d/$(basename "$_sf"): permissions $_sf_perms (should be 440)"
        _SUDOERSD_BAD=$((_SUDOERSD_BAD + 1))
      fi
    done
    [[ "$_SUDOERSD_BAD" -eq 0 ]] && _emit_pass "sudoers.d drop-ins: all permissions correct"
  fi
  # Check for NOPASSWD — F-107: properly skip commented lines including
  # tab-indented comments. Use anchored regex on file contents (not grep
  # output prefix-based filter which fails on tab-prefixed comments).
  _NOPASSWD=$(grep -rE -- '^[[:space:]]*[^#[:space:]].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)
  if [[ -n "$_NOPASSWD" ]]; then
    _emit_warn "NOPASSWD found in sudoers (passwordless sudo enabled)"
    if ! $JSON_MODE; then
      echo "$_NOPASSWD" | while read -r _np_line; do
        printf "       %s\n" "$_np_line"
      done
    fi
  else
    _emit_pass "No NOPASSWD in sudoers (all sudo requires password)"
  fi
  # Syntax check
  if require_cmd visudo; then
    if visudo -c &>/dev/null; then
      _emit_pass "sudoers syntax: valid (visudo -c)"
    else
      _emit_fail "sudoers syntax errors detected (run 'visudo -c')"
    fi
  fi
fi

# Password Aging
PASS_MAX=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
PASS_MIN=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
PASS_WARN=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
_emit_info "Password policy: MAX=$PASS_MAX, MIN=$PASS_MIN, WARN=$PASS_WARN"

# Umask Check — F-105: scan all sources individually, report mismatches.
# tail -1 across multi-file glob picks last match in alphabetic order which
# != runtime precedence (login.defs is for login shells via PAM; /etc/profile
# applies to interactive shells; profile.d/*.sh apply in alphabetic order).
sub_header "Default umask"
declare -A _UMASK_BY_FILE=()
_UMASK_BY_FILE["/etc/login.defs"]=$(grep -iE '^\s*UMASK\s+' /etc/login.defs 2>/dev/null | tail -1 | awk '{print $2}')
for _umf in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/zsh/zshenv /etc/zsh/zshrc; do
  [[ -f "$_umf" ]] || continue
  _val=$(grep -hiE '^\s*umask\s+' "$_umf" 2>/dev/null | tail -1 | awk '{print $2}')
  [[ -n "$_val" ]] && _UMASK_BY_FILE["$_umf"]="$_val"
done
for _umf in /etc/profile.d/*.sh /etc/profile.d/*.zsh; do
  [[ -f "$_umf" ]] || continue
  _val=$(grep -hiE '^\s*umask\s+' "$_umf" 2>/dev/null | tail -1 | awk '{print $2}')
  [[ -n "$_val" ]] && _UMASK_BY_FILE["$_umf"]="$_val"
done

# Count distinct values; if multiple, list them all (potential conflict)
declare -A _UMASK_DISTINCT=()
for _file in "${!_UMASK_BY_FILE[@]}"; do
  _v="${_UMASK_BY_FILE[$_file]}"
  [[ -n "$_v" ]] && _UMASK_DISTINCT["$_v"]=1
done
if [[ "${#_UMASK_DISTINCT[@]}" -eq 0 ]]; then
  _emit_warn "Default umask not explicitly set in any /etc/ source"
elif [[ "${#_UMASK_DISTINCT[@]}" -eq 1 ]]; then
  UMASK_VAL="${!_UMASK_DISTINCT[*]}"
  if [[ "$UMASK_VAL" =~ ^0*(27|77)$ ]]; then
    _emit_pass "Default umask: $UMASK_VAL (restrictive, consistent across /etc/)"
  else
    _emit_warn "Default umask: $UMASK_VAL (recommended: 027 or 077)"
  fi
else
  # F-274: distinguish intentional defense-in-depth split from runtime conflict.
  # login.defs UMASK applies to non-interactive system processes (PAM-spawned
  # sessions, dnf/rpm, systemd services); /etc/profile and profile.d/*.sh apply
  # to interactive shells. A common hardened-but-compatible pattern is system=022
  # (avoids dnf5 #1908 file-perm breakage on F41+) combined with interactive=027
  # (user-data privacy on terminal-created files). When the interactive value
  # is at-least-as-restrictive as login.defs AND interactive is in the
  # recommended range (027/077), this is treated as intentional split (PASS).
  _LOGIN_DEFS_UMASK="${_UMASK_BY_FILE[/etc/login.defs]:-}"
  _INTERACTIVE_MAX_UMASK=""   # most-restrictive non-login.defs value (highest octal)
  # F-294: octal-decode helper — strip leading zeros safely. The naive form
  # `8#${_v#0}` errors with "8#: invalid arithmetic" when _v="0" (strip leaves
  # empty string). Defaulting to 0 keeps the comparison sane.
  _umask_to_dec() { local v="${1#0}"; echo "$((8#${v:-0}))"; }
  for _file in "${!_UMASK_BY_FILE[@]}"; do
    [[ "$_file" == "/etc/login.defs" ]] && continue
    _v="${_UMASK_BY_FILE[$_file]}"
    [[ -z "$_v" ]] && continue
    if [[ -z "$_INTERACTIVE_MAX_UMASK" ]]; then
      _INTERACTIVE_MAX_UMASK="$_v"
    else
      _val_dec=$(_umask_to_dec "$_v")
      _max_dec=$(_umask_to_dec "$_INTERACTIVE_MAX_UMASK")
      [[ "$_val_dec" -gt "$_max_dec" ]] && _INTERACTIVE_MAX_UMASK="$_v"
    fi
  done
  _INTENTIONAL_SPLIT=0
  if [[ -n "$_LOGIN_DEFS_UMASK" && -n "$_INTERACTIVE_MAX_UMASK" ]]; then
    _ldef_dec=$(_umask_to_dec "$_LOGIN_DEFS_UMASK")
    _imax_dec=$(_umask_to_dec "$_INTERACTIVE_MAX_UMASK")
    if [[ "$_imax_dec" -ge "$_ldef_dec" ]] && \
       [[ "$_INTERACTIVE_MAX_UMASK" =~ ^0*(27|77)$ ]]; then
      _INTENTIONAL_SPLIT=1
    fi
  fi

  if [[ "$_INTENTIONAL_SPLIT" -eq 1 ]]; then
    _emit_pass "Default umask: system=$_LOGIN_DEFS_UMASK / interactive=$_INTERACTIVE_MAX_UMASK (intentional split — interactive shells stricter than system processes)"
  else
    # Genuine conflict — report all values
    _conflict_summary=""
    for _file in "${!_UMASK_BY_FILE[@]}"; do
      [[ -n "${_UMASK_BY_FILE[$_file]}" ]] && \
        _conflict_summary+="${_file##*/}=${_UMASK_BY_FILE[$_file]}, "
    done
    _emit_warn "Default umask has CONFLICTING values across files: ${_conflict_summary%, } (last shell-init wins at runtime)"
  fi
fi

# Faillock
# faillock output format per user: "username:\nWhen  Type  Source  Valid\n2026-04-09 ... RHOST  V\n"
# Count only actual failure entries (lines starting with a date YYYY-MM-DD), not headers.
if require_cmd faillock; then
  _FAILLOCK_OUT=$(faillock --dir /var/run/faillock 2>/dev/null)
  LOCKED=$(echo "$_FAILLOCK_OUT" | grep -cE "^[0-9]{4}-[0-9]{2}-[0-9]{2}" || true)
  LOCKED=${LOCKED:-0}
  if [[ "$LOCKED" -gt 0 ]]; then
    # F-297: count unique usernames with failures via state-machine awk.
    # Previous form `grep -B50 "^[0-9]\{4\}-"` was arbitrary — on heavy-failure
    # systems with >50 entries per user, the user header scrolled out of the
    # B-context window and was undercounted. State-machine tracks current user
    # header and counts users that have ≥1 dated entry under them.
    _LOCKED_USERS=$(echo "$_FAILLOCK_OUT" | awk '
      /^[a-zA-Z][a-zA-Z0-9._-]*:$/ { user=$0; has_failure=0; next }
      /^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
        if (user != "" && !has_failure) { count++; has_failure=1 }
      }
      END { print count+0 }
    ')
    _LOCKED_USERS=${_LOCKED_USERS:-0}
    _emit_warn "Faillock: $LOCKED failed attempt(s) across $_LOCKED_USERS account(s)"
  else
    _emit_pass "Faillock: no recorded failed login attempts"
  fi
fi

# History File Permissions — F-109: extended coverage beyond bash/zsh.
# Severity tier: shell histories (bash/zsh/fish) = warn on 077-loose perms;
# app histories (Python/DB/etc) often contain tokens too — warn at higher
# threshold (only world-readable group is fine for non-shell as those
# typically don't store passwords typed inline).
sub_header "History File Permissions"
declare -a _SHELL_HISTS=(".bash_history" ".zsh_history" ".fish_history" ".local/share/fish/fish_history")
declare -a _APP_HISTS=(".python_history" ".psql_history" ".mysql_history" ".sqlite_history"
                       ".node_repl_history" ".lua_history" ".gdb_history" ".irb_history"
                       ".lesshst" ".viminfo"
                       ".local/share/nano/search_history"
                       ".config/nvim/shada/main.shada")
while read -r USER_HOME; do
  [[ -d "$USER_HOME" ]] || continue
  # Shell histories: strict 077 check (passwords typed inline land here)
  for HIST in "${_SHELL_HISTS[@]}"; do
    [[ -f "$USER_HOME/$HIST" ]] || continue
    PERMS=$(stat -c %a "$USER_HOME/$HIST" 2>/dev/null)
    if (( (8#${PERMS:-777} & 8#077) != 0 )); then
      _emit_warn "Shell history too open: $USER_HOME/$HIST ($PERMS, should be 600 or stricter)"
    else
      _emit_pass "Shell history: $USER_HOME/$HIST ($PERMS)"
    fi
  done
  # App histories: world-readable (007) bit is the danger; group access acceptable
  for HIST in "${_APP_HISTS[@]}"; do
    [[ -f "$USER_HOME/$HIST" ]] || continue
    PERMS=$(stat -c %a "$USER_HOME/$HIST" 2>/dev/null)
    if (( (8#${PERMS:-777} & 8#007) != 0 )); then
      _emit_warn "App history world-readable: $USER_HOME/$HIST ($PERMS — may contain tokens/credentials)"
    fi
    # No PASS for app histories — too noisy at scale; user gets implicit pass via no-warn
  done
done < <(_iter_user_homes)

}

###############################################################################
check_filesystem() {
  should_skip "filesystem" && return
  header "12" "FILESYSTEM SECURITY"
###############################################################################

# SUID/SGID baseline thresholds (excludes container-storage SUID layers
# via _safe_find_root). Values calibrated against:
#   - hardened Fedora desktop with Flatpak: ~22-32 SUID typical
#   - vanilla Ubuntu desktop: ~28-38 SUID typical
#   - server-minimal install: ~12-18 SUID typical
# Adjust here (single source of truth) if your baseline differs.
_SUID_PASS_MAX=30
_SUID_WARN_MAX=45
_SGID_PASS_MAX=10
_SGID_WARN_MAX=20

SUID_COUNT=$(_safe_find_root -perm -4000 -type f | wc -l)
if [[ "$SUID_COUNT" -le "$_SUID_PASS_MAX" ]]; then
  _emit_pass "SUID files: $SUID_COUNT (≤${_SUID_PASS_MAX})"
elif [[ "$SUID_COUNT" -le "$_SUID_WARN_MAX" ]]; then
  _emit_warn "SUID files: $SUID_COUNT (>${_SUID_PASS_MAX}, investigate)"
else
  _emit_fail "SUID files: $SUID_COUNT (>${_SUID_WARN_MAX})"
fi

# SGID Files
SGID_COUNT=$(_safe_find_root -perm -2000 -type f | wc -l)
if [[ "$SGID_COUNT" -le "$_SGID_PASS_MAX" ]]; then
  _emit_pass "SGID files: $SGID_COUNT (≤${_SGID_PASS_MAX})"
elif [[ "$SGID_COUNT" -le "$_SGID_WARN_MAX" ]]; then
  _emit_warn "SGID files: $SGID_COUNT (>${_SGID_PASS_MAX})"
else
  _emit_fail "SGID files: $SGID_COUNT (>${_SGID_WARN_MAX})"
fi

# World-Writable — F-110: cache find result so we don't run the same scan
# twice (counter + display). On big filesystems this halves the time.
# Empty-string handling without grep-c trap: count via [[ -n ]] guard.
_WW_FIND_ARGS=(-perm -0002 -type f
  ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*")
_WW_RESULT=$(_safe_find_root "${_WW_FIND_ARGS[@]}")
if [[ -z "$_WW_RESULT" ]]; then
  WW_COUNT=0
else
  WW_COUNT=$(echo "$_WW_RESULT" | wc -l)
fi
WW_COUNT=${WW_COUNT:-0}
if [[ "$WW_COUNT" -eq 0 ]]; then
  _emit_pass "World-writable files: 0"
else
  _emit_fail "World-writable files: $WW_COUNT"
  if ! $JSON_MODE; then
    while read -r f; do
      printf "       %s\n" "$f"
    done < <(echo "$_WW_RESULT" | head -5)
  fi
fi
unset _WW_RESULT

# Unowned Files
# F-340 (v3.6.1): /var/lib/gdm exclusion is now in _safe_find_root's internal
# prune list (per-directory skip, not per-file evaluation). Caller no longer
# needs to pass -not -path here.
UNOWNED=$(_safe_find_root \( -nouser -o -nogroup \) | wc -l)
if [[ "$UNOWNED" -eq 0 ]]; then
  _emit_pass "Unowned files: 0"
elif [[ "$UNOWNED" -le 5 ]]; then
  _emit_warn "Unowned files: $UNOWNED (investigate)"
else
  _emit_fail "Unowned files: $UNOWNED (>5)"
fi

# Swappiness
# F-330 (v3.6.1): detect ZRAM-only swap so the annotation reflects in-memory
# compression vs disk I/O semantics — high swappiness with ZRAM-only swap is
# RAM compression, NOT "more data written to disk", so no recovery risk.
_SWAPPINESS=$(sysctl -n vm.swappiness 2>/dev/null || echo "N/A")
if [[ "$_SWAPPINESS" != "N/A" ]]; then
  _swap_zram_only=false
  if command -v swapon &>/dev/null; then
    _swap_devs=$(swapon --noheadings --show=NAME 2>/dev/null || true)
    if [[ -n "$_swap_devs" ]] && ! echo "$_swap_devs" | grep -qv '^/dev/zram'; then
      _swap_zram_only=true
    fi
  fi
  if [[ "$_swap_zram_only" == "true" ]]; then
    _zram_note=" — ZRAM-only (in-memory compression, no disk I/O)"
  else
    _zram_note=""
  fi
  if [[ "$_SWAPPINESS" -le 10 ]]; then
    _emit_pass "Swappiness: $_SWAPPINESS (low — minimal swap usage)${_zram_note}"
  elif [[ "$_SWAPPINESS" -le 60 ]]; then
    _emit_info "Swappiness: $_SWAPPINESS (default range)${_zram_note}"
  elif [[ "$_swap_zram_only" == "true" ]]; then
    _emit_info "Swappiness: $_SWAPPINESS (high — aggressive RAM compression via ZRAM, no disk I/O)"
  else
    _emit_warn "Swappiness: $_SWAPPINESS (high — more data written to disk, recovery risk)"
  fi
fi

# ACL support on root filesystem
if require_cmd getfacl; then
  if mount | grep " / " | grep -qE "acl|posixacl"; then
    _emit_pass "ACL support: enabled on root filesystem"
  else
    # Most modern filesystems (ext4, xfs, btrfs) have ACL enabled by default.
    # Use findmnt instead of `df -T` — df can wrap on long device names
    # (LUKS-LVM dm-X paths) and break the awk NR==2 column extraction.
    if require_cmd findmnt; then
      _ROOT_FS_TYPE=$(findmnt -no FSTYPE / 2>/dev/null)
    else
      _ROOT_FS_TYPE=$(df -PT / 2>/dev/null | tail -1 | awk '{print $2}')
    fi
    if [[ "$_ROOT_FS_TYPE" =~ ^(ext4|xfs|btrfs)$ ]]; then
      _emit_pass "ACL support: $_ROOT_FS_TYPE has ACL enabled by default"
    else
      _emit_info "ACL support: could not verify on $_ROOT_FS_TYPE"
    fi
  fi
fi

# /tmp Permissions
TMP_MOUNT=$(mount | grep " /tmp " || echo "")
if [[ -n "$TMP_MOUNT" ]]; then
  if echo "$TMP_MOUNT" | grep -q "nosuid"; then
    _emit_pass "/tmp: nosuid"
  else
    _emit_warn "/tmp: no nosuid"
  fi
  if echo "$TMP_MOUNT" | grep -q "noexec"; then
    _emit_pass "/tmp: noexec"
  else
    _emit_info "/tmp: no noexec (may break programs)"
  fi
else
  _emit_info "/tmp: not separately mounted"
fi

# Core Dumps — F-115b: accept any pipe-to-noop pattern as "disabled".
# Common hardening choices: |/dev/null, |/bin/false, |/bin/true, |/usr/bin/false.
# All discard the core dump just as effectively as ulimit=0.
CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
CORE_ULIMIT=$(ulimit -c 2>/dev/null)
CORE_STORAGE=$(_systemd_conf_val /etc/systemd/coredump.conf Storage 2>/dev/null)
if [[ "$CORE_ULIMIT" == "0" ]] || \
   echo "$CORE_PATTERN" | grep -qE '^\|(/usr)?/(s)?bin/(false|true)$|^\|/dev/null$' || \
   [[ "$CORE_STORAGE" == "none" ]]; then
  _emit_pass "Core dumps: disabled"
else
  _emit_warn "Core dumps: possible (pattern: $CORE_PATTERN)"
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
      # to avoid users panicking at "Permissions /etc/shadow: 0" output (F-115).
      # F-295: explicit octal compare via $((8#…)). The bash [[ -lt ]] form
      # was actually treating these as decimal (so 0640 < 0644 worked by
      # accident), making the intent unclear. Octal-explicit is unambiguous.
      if [[ $((8#${ACTUAL:-777})) -lt $((8#$EXPECTED)) ]]; then
        _emit_pass "Permissions $FILE: $ACTUAL (stricter than recommended $EXPECTED)"
      else
        _emit_pass "Permissions $FILE: $ACTUAL"
      fi
    else
      _emit_warn "Permissions $FILE: $ACTUAL (expected: <=$EXPECTED)"
    fi
  fi
done

# Banner Check (new)
sub_header "Login Banners"
for BANNER_FILE in /etc/issue /etc/issue.net /etc/motd; do
  if [[ -f "$BANNER_FILE" ]] && [[ -s "$BANNER_FILE" ]]; then
    # F-117: extend regex to cover Arch, openSUSE, Manjaro, Mint, Pop!_OS,
    # Rocky, AlmaLinux, EndeavourOS — the typical default-banner strings.
    if grep -qiE "(Linux kernel [0-9]|Fedora release|Ubuntu [0-9]|CentOS|Debian GNU|RHEL|Red Hat|Arch Linux|openSUSE|Manjaro Linux|Linux Mint|Pop!_OS|Rocky Linux|AlmaLinux|EndeavourOS)" "$BANNER_FILE" 2>/dev/null; then
      _emit_warn "$BANNER_FILE leaks system info"
    else
      _emit_pass "$BANNER_FILE: no system info leaked"
    fi
  fi
done

}

###############################################################################
check_crypto() {
  should_skip "crypto" && return
  header "13" "ENCRYPTION & CRYPTO"
###############################################################################

if require_cmd cryptsetup; then
  # F-118: while-read avoids word-splitting on device names with rare special chars
  while read -r DEV; do
    [[ -z "$DEV" ]] && continue
    CIPHER=$(cryptsetup status "$DEV" 2>/dev/null | grep "cipher:" | awk '{print $2}')
    KEYSIZE=$(cryptsetup status "$DEV" 2>/dev/null | grep "keysize:" | awk '{print $2}')
    _emit_info "LUKS $DEV: cipher=$CIPHER keysize=$KEYSIZE"
    if echo "$CIPHER" | grep -qE "aes-xts"; then
      _emit_pass "LUKS cipher: $CIPHER (strong)"
    elif echo "$CIPHER" | grep -qE "aes-cbc"; then
      _emit_warn "LUKS cipher: $CIPHER (aes-cbc has known weaknesses — consider migrating to aes-xts)"
    elif [[ -n "$CIPHER" ]]; then
      _emit_warn "LUKS cipher: $CIPHER (unusual)"
    fi
  done < <(lsblk -rno NAME,TYPE 2>/dev/null | awk '$2=="crypt" {print $1}')
else
  _emit_info "cryptsetup not installed — LUKS details skipped"
fi

# SSL/TLS Libraries
if require_cmd openssl; then
  OPENSSL_VER=$(openssl version 2>/dev/null)
  _emit_info "OpenSSL: $OPENSSL_VER"
fi

# GPG Keys
if require_cmd gpg; then
  GPG_KEYS=$(gpg --list-keys 2>/dev/null | grep -c "^pub" | ccount)
  _emit_info "GPG keys: $GPG_KEYS"
fi

# Entropy Check (new)
if [[ -f /proc/sys/kernel/random/entropy_avail ]]; then
  ENTROPY=$(< /proc/sys/kernel/random/entropy_avail)
  if [[ "$ENTROPY" -ge 256 ]]; then
    _emit_pass "Entropy: $ENTROPY (sufficient)"
  else
    _emit_warn "Entropy: $ENTROPY (low — minimum 256)"
  fi
fi

# Hardware Random Number Generator
if [[ -c /dev/hwrng ]]; then
  _emit_pass "Hardware RNG: /dev/hwrng present"
elif [[ -d /sys/class/misc/hw_random ]]; then
  _emit_pass "Hardware RNG: hw_random device available"
elif grep -qE "rdrand|rdseed" /proc/cpuinfo 2>/dev/null; then
  _emit_pass "Hardware RNG: CPU supports RDRAND/RDSEED"
else
  _emit_info "No hardware RNG detected (software entropy only)"
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
  # F-314 (v3.6.1): collect ZRAM device names for a SINGLE summary line at
  # the end. Previously each ZRAM device emitted its own INFO inside the
  # loop AND a PASS message after — duplicate display for the same fact.
  SWAP_ZRAM_DEVS=""
  while read -r swapdev; do
    [[ -z "$swapdev" ]] && continue
    # ZRAM is in-memory compression — not persistent storage, no encryption needed
    if [[ "$swapdev" =~ ^/dev/zram ]]; then
      SWAP_ZRAM_DEVS+="$swapdev "
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
  if ! $SWAP_HAS_REAL && [[ -n "$SWAP_ZRAM_DEVS" ]]; then
    _emit_pass "Swap: ZRAM only (${SWAP_ZRAM_DEVS% } — in-memory compression, no disk persistence)"
  elif ! $SWAP_HAS_REAL; then
    _emit_pass "Swap: ZRAM only (in-memory — no disk persistence risk)"
  elif $SWAP_ENCRYPTED; then
    [[ -n "$SWAP_ZRAM_DEVS" ]] && _emit_info "Swap: ZRAM ${SWAP_ZRAM_DEVS% } (in-memory) + encrypted disk swap"
    _emit_pass "Swap: encrypted"
  else
    [[ -n "$SWAP_ZRAM_DEVS" ]] && _emit_info "Swap: ZRAM ${SWAP_ZRAM_DEVS% } (in-memory) + UNENCRYPTED disk swap"
    _emit_warn "Swap: NOT encrypted (memory contents at risk)"
  fi
else
  _emit_info "No swap configured"
fi

}

###############################################################################
check_updates() {
  should_skip "updates" && return
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
  _emit_pass "System up to date (0 updates)"
elif [[ "$UPDATES" == "?" ]]; then
  _emit_info "Could not check for updates"
elif [[ "$UPDATES" -le 10 ]]; then
  # F-304: tier the WARN — small backlog (1-10) is normal for daily maintenance,
  # 11-50 is "noticeable backlog", >50 starts looking like maintenance neglect.
  # Same severity (WARN) but the message differentiates so users get an honest
  # signal of how far behind they actually are.
  _emit_warn "$UPDATES updates available (small backlog — apply when convenient)"
elif [[ "$UPDATES" -le 50 ]]; then
  _emit_warn "$UPDATES updates available (noticeable backlog — schedule update soon)"
else
  _emit_warn "$UPDATES updates available (heavy backlog — system maintenance overdue)"
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
    _emit_fail "Security updates: $SEC_UPDATES"
  else
    _emit_pass "No pending security updates"
  fi
else
  _emit_info "Security updates: could not check (unsupported package manager)"
fi

# Package count
if require_cmd rpm; then
  PKG_COUNT=$(rpm -qa 2>/dev/null | wc -l)
  _emit_info "Installed packages: $PKG_COUNT"
elif require_cmd dpkg; then
  PKG_COUNT=$(dpkg -l 2>/dev/null | grep -c "^ii")
  _emit_info "Installed packages: $PKG_COUNT"
elif require_cmd pacman; then
  PKG_COUNT=$(pacman -Q 2>/dev/null | wc -l)
  _emit_info "Installed packages: $PKG_COUNT"
else
  _emit_info "Package count: unsupported package manager"
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
    | grep "RSA:(none) PGP:(none) GPG:(none)" | grep -cvE "^gpg-pubkey-|^kmod-" | ccount)
  RPM_NOSIG_KMOD_ONLY=$(( RPM_NOSIG - RPM_NOSIG_KMOD ))
  if [[ "$RPM_NOSIG" -eq 0 ]]; then
    _emit_pass "All RPM packages signed"
  elif [[ "$RPM_NOSIG_KMOD" -eq 0 && "$RPM_NOSIG_KMOD_ONLY" -gt 0 ]]; then
    _emit_info "$RPM_NOSIG unsigned RPM packages (all kmod — locally built, expected)"
  elif [[ "$RPM_NOSIG_KMOD" -gt 0 && "$RPM_NOSIG_KMOD_ONLY" -gt 0 ]]; then
    _emit_warn "$RPM_NOSIG_KMOD unsigned RPM packages (+ $RPM_NOSIG_KMOD_ONLY locally-built kmod)"
  else
    _emit_warn "$RPM_NOSIG unsigned RPM packages"
  fi

  # RPM GPG Key Count (new)
  GPG_KEY_COUNT=$(rpm -qa gpg-pubkey 2>/dev/null | wc -l)
  _emit_info "RPM GPG keys imported: $GPG_KEY_COUNT"
elif require_cmd dpkg; then
  # Debian/Ubuntu: check for unauthenticated packages and GPG key count
  APT_NOAUTH=$(apt list --installed 2>/dev/null | grep -c "\[.*local\]" || true)
  APT_NOAUTH=${APT_NOAUTH:-0}
  if [[ "$APT_NOAUTH" -eq 0 ]]; then
    _emit_pass "All APT packages from authenticated sources"
  else
    _emit_warn "$APT_NOAUTH APT packages from unauthenticated/local sources"
  fi

  # APT trusted key count
  APT_KEYS=$(apt-key list 2>/dev/null | grep -c "^pub" || true)
  if [[ "${APT_KEYS:-0}" -gt 0 ]]; then
    _emit_info "APT trusted keys: $APT_KEYS"
  else
    # Newer systems use /etc/apt/trusted.gpg.d/
    APT_KEYS=$(find /etc/apt/trusted.gpg.d/ /usr/share/keyrings/ -name "*.gpg" -o -name "*.asc" 2>/dev/null | wc -l || true)
    _emit_info "APT trusted keyrings: ${APT_KEYS:-0}"
  fi
elif require_cmd pacman; then
  # Arch: check pacman signature enforcement
  if grep -qE "^SigLevel\s*=.*Required" /etc/pacman.conf 2>/dev/null; then
    _emit_pass "Pacman: package signature verification required"
  elif grep -qE "^SigLevel\s*=.*Never" /etc/pacman.conf 2>/dev/null; then
    _emit_fail "Pacman: package signature verification DISABLED"
  else
    _emit_info "Pacman: default signature level (Optional)"
  fi
else
  _emit_info "Package signature verification: not available for this package manager"
fi

# Automated Security Updates
# dnf5-automatic (Fedora 41+) and legacy dnf-automatic (Fedora ≤40, RHEL)
if systemctl is-active dnf5-automatic.timer &>/dev/null || systemctl is-enabled dnf5-automatic.timer &>/dev/null; then
  # Check if configured for security-only updates
  _DNF5_AUTO_CONF="/etc/dnf/dnf5-plugins/automatic.conf"
  # F-128: sed-based extraction preserves any '=' in value (defensive)
  _DNF5_UPGRADE_TYPE=$(grep -i "^upgrade_type" "$_DNF5_AUTO_CONF" 2>/dev/null | sed -E 's/^[^=]+=[[:space:]]*//;s/[[:space:]]+$//' | tail -1)
  if [[ "${_DNF5_UPGRADE_TYPE,,}" == "security" ]]; then
    _emit_pass "Automated updates: dnf5-automatic enabled (security-only)"
  else
    _emit_pass "Automated updates: dnf5-automatic enabled (upgrade_type=${_DNF5_UPGRADE_TYPE:-default})"
  fi
elif systemctl is-active dnf-automatic.timer &>/dev/null || systemctl is-enabled dnf-automatic.timer &>/dev/null; then
  _emit_pass "Automated updates: dnf-automatic enabled"
elif systemctl is-active unattended-upgrades &>/dev/null || [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
  _emit_pass "Automated updates: unattended-upgrades active"
elif require_cmd pacman; then
  if systemctl is-active pacman-filesdb-refresh.timer &>/dev/null; then
    _emit_info "Automated updates: pacman-filesdb-refresh timer active (partial)"
  else
    _emit_info "Automated updates: Arch uses rolling updates — manual 'pacman -Syu' recommended"
  fi
elif require_cmd zypper; then
  if systemctl is-active packagekit.service &>/dev/null; then
    _emit_pass "Automated updates: PackageKit service active"
  else
    _emit_warn "No automated security update mechanism detected"
  fi
# F-344 (v3.6.2): NoID Privacy weekly update reminder (privacy-by-design)
# Privacy distros deliberately avoid auto-updates (bandwidth fingerprinting,
# MITM exposure, surprise behavior changes). NoID ships a weekly user-systemd
# REMINDER timer instead — the user runs `noid-update-all.sh` themselves.
# Detection: timer file at /etc/systemd/user/noid-update-reminder.timer
# (system-wide enabled, activates per-user when GNOME session starts).
elif [[ -f /etc/systemd/user/noid-update-reminder.timer ]]; then
  _emit_pass "Automated updates: noid-update-reminder weekly (privacy-by-design — manual user upgrade)"
else
  _emit_warn "No automated security update mechanism detected"
fi

# Flatpaks
if require_cmd flatpak; then
  # F-129: --columns=application gives one line per app, no header — exact count
  FLATPAK_COUNT=$(flatpak list --app --columns=application 2>/dev/null | wc -l)
  _emit_info "Flatpaks: $FLATPAK_COUNT"
fi

}

###############################################################################
check_rootkit() {
  should_skip "rootkit" && return
  header "15" "ROOTKIT & MALWARE SCAN"
###############################################################################

# rkhunter (deprecated — last release 2018-02-24, signatures don't cover
# post-2018 rootkits like XZ Backdoor, Bootkitty, Kovid, BPFDoor).
# Recommend chkrootkit (last release 2025-05-12) which knows modern threats.
if require_cmd rkhunter; then
  _emit_info "rkhunter installed but UNMAINTAINED since 2018-02 — signatures miss XZ Backdoor, Bootkitty, BPFDoor; use chkrootkit instead"
else
  _emit_info "rkhunter not installed (chkrootkit + AIDE + IMA preferred for modern rootkit detection)"
fi

# chkrootkit with false-positive filter (timeout 120s prevents hangs).
# F-132: filtered FPs are surfaced as INFO so user can audit nothing's hidden.
if require_cmd chkrootkit; then
  $JSON_MODE || printf "  ${CYN}Running chkrootkit (max 120s)...${RST}\n"
  CHKRK_OUT=$(timeout 120 chkrootkit 2>/dev/null || echo "TIMEOUT")
  if [[ "$CHKRK_OUT" == "TIMEOUT" ]]; then
    _emit_warn "chkrootkit: timed out after 120s"
  else
    CHKRK_FP_PATTERN="bindshell|sniffer|chkutmp|w55808|slapper|scalper|wted|Xor\.DDoS|linux_ldiscs|suckit"
    CHKRK_INFECTED=$(echo "$CHKRK_OUT" | grep "INFECTED" | grep -cviE "$CHKRK_FP_PATTERN" | ccount)
    CHKRK_FP=$(echo "$CHKRK_OUT" | grep "INFECTED" | grep -ciE "$CHKRK_FP_PATTERN" | ccount)
    if [[ "$CHKRK_INFECTED" -eq 0 ]]; then
      _emit_pass "chkrootkit: clean (0 real INFECTED, $CHKRK_FP known false positives filtered)"
      # F-132: show filtered FPs as INFO so user can verify nothing legit was hidden
      if [[ "$CHKRK_FP" -gt 0 ]] && ! $JSON_MODE; then
        echo "$CHKRK_OUT" | grep "INFECTED" | grep -iE "$CHKRK_FP_PATTERN" | head -3 | while read -r fp; do
          printf "       (filtered FP) %s\n" "${fp:0:80}"
        done
      fi
    else
      _emit_fail "chkrootkit: $CHKRK_INFECTED INFECTED (after filtering $CHKRK_FP known FPs)"
      if ! $JSON_MODE; then
        while read -r i; do
          printf "       %s\n" "$i"
        done < <(echo "$CHKRK_OUT" | grep "INFECTED" | grep -viE "$CHKRK_FP_PATTERN" | head -5)
      fi
    fi
  fi
else
  # F-334 (v3.6.1): conditional recommendation strength based on whether the
  # system already has modern integrity coverage. AIDE (file FIM) + IMA
  # (kernel-runtime measurements) cover most rootkit-relevant surface; in that
  # case chkrootkit is supplemental, not critical.
  _ima_active=false
  _aide_ready=false
  [[ -e /sys/kernel/security/integrity/ima/runtime_measurements_count ]] && _ima_active=true
  if [[ -s /var/lib/aide/aide.db.gz ]] || [[ -s /var/lib/aide/aide.db ]]; then
    _aide_ready=true
  fi
  if $_ima_active && $_aide_ready; then
    _emit_info "chkrootkit not installed — supplemental only (AIDE + IMA already provide integrity coverage)"
  else
    _emit_info "chkrootkit not installed — recommended (modern alternative to unmaintained rkhunter)"
  fi
fi

# Suspect Cron Jobs — F-133: when cron.deny restricts users, `crontab -l -u`
# silently fails. Read /var/spool/cron/<user> directly as authoritative source.
sub_header "Cron jobs (all users)"
while read -r USER_HOME; do
  [[ -d "$USER_HOME" ]] || continue
  _cron_user=$(basename "$USER_HOME")
  # Direct file read survives cron.deny restrictions
  _crontab_file=""
  for _cf in "/var/spool/cron/$_cron_user" "/var/spool/cron/crontabs/$_cron_user"; do
    [[ -f "$_cf" ]] && _crontab_file="$_cf" && break
  done
  if [[ -n "$_crontab_file" ]]; then
    CRONTAB=$(grep -v "^#" "$_crontab_file" 2>/dev/null | grep -v "^$" || true)
  else
    CRONTAB=$(crontab -l -u "$_cron_user" 2>/dev/null | grep -v "^#" | grep -v "^$" || true)
  fi
  if [[ -n "$CRONTAB" ]]; then
    _emit_info "Crontab $_cron_user:"
    while read -r line; do
      $JSON_MODE || printf "       %s\n" "$line"
      if echo "$line" | grep -qiE "curl|wget|nc |ncat|python.*http|bash.*http|/dev/tcp"; then
        _emit_warn "Suspicious cron entry: $line"
      fi
    done <<< "$CRONTAB"
  fi
done < <(_iter_user_homes)
for CRONDIR in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  if [[ -d "$CRONDIR" ]]; then
    # SC2012-clean: count via shell glob with nullglob
    shopt -s nullglob
    _cron_files=("$CRONDIR"/*)
    shopt -u nullglob
    COUNT="${#_cron_files[@]}"
    [[ "$COUNT" -eq 1 ]] && _ent="entry" || _ent="entries"
    _emit_info "$CRONDIR: $COUNT $_ent"
  fi
done

}

###############################################################################
check_processes() {
  should_skip "processes" && return
  header "16" "PROCESS SECURITY"
###############################################################################

# Suspicious processes
# F-136: Name-pattern matching is heuristic only — real attackers rename
# binaries. PASS gives false reassurance unless annotated.
# shellcheck disable=SC2009  # pgrep can't match multi-pattern regex with word boundaries
SUSPECT_PROCS=$(ps aux 2>/dev/null | grep -iE "\bnc\s+-[a-z]*l|\bncat\s+-[a-z]*l|\bsocat\s+.*EXEC|\bsocat\s+.*TCP-LISTEN|\bmeterpreter\b|\breverse[_.-]shell\b|\bcobalt\s*strike\b|\bmimikatz\b|\blazagne\b|\bkeylog\b" | grep -v grep || true)
if [[ -z "$SUSPECT_PROCS" ]]; then
  _emit_pass "No obvious-named suspicious processes (real malware renames — see AIDE/IMA/chkrootkit for actual integrity)"
else
  _emit_fail "Suspicious processes found:"
  if ! $JSON_MODE; then
    while read -r p; do printf "       %s\n" "$p"; done <<< "$SUSPECT_PROCS"
  fi
fi

# Processes running as root
ROOT_PROCS=$(ps aux | awk '$1=="root" {print $11}' | sort -u | wc -l)
_emit_info "Root processes (unique): $ROOT_PROCS"

# Hidden Processes
PS_PIDS=$(ps -eo pid --no-headers | sed 's/ //g' | sort -u)
PROC_PIDS=$(printf '%s\n' /proc/[0-9]*/ 2>/dev/null | sed 's|^/proc/||;s|/$||' | sort -u)
HIDDEN=$(comm -23 <(echo "$PROC_PIDS") <(echo "$PS_PIDS") | wc -l)
HIDDEN=${HIDDEN//[^0-9]/}
HIDDEN=${HIDDEN:-0}
if [[ "$HIDDEN" -le 10 ]]; then
  _emit_pass "Hidden processes: $HIDDEN (normal: race condition)"
else
  _emit_warn "Hidden processes: $HIDDEN"
fi

# Zombie / Dead Processes
_ZOMBIE_COUNT=$(ps aux 2>/dev/null | awk '$8 ~ /^Z/ {count++} END {print count+0}')
if [[ "$_ZOMBIE_COUNT" -eq 0 ]]; then
  _emit_pass "Zombie processes: 0"
elif [[ "$_ZOMBIE_COUNT" -le 5 ]]; then
  _emit_warn "Zombie processes: $_ZOMBIE_COUNT (investigate with: ps aux | grep ' Z ')"
else
  _emit_fail "Zombie processes: $_ZOMBIE_COUNT (resource leak or crashed processes)"
fi

# Deleted Binaries still running
# shellcheck disable=SC2010,SC2012  # /proc/*/exe requires ls -l to show symlink targets
DELETED_BINS=$(ls -l /proc/*/exe 2>/dev/null | grep -c "(deleted)")
if [[ "$DELETED_BINS" -eq 0 ]]; then
  _emit_pass "No deleted binaries running"
else
  _emit_warn "Deleted binaries running: $DELETED_BINS"
  if ! $JSON_MODE; then
    # shellcheck disable=SC2010
    while read -r d; do
      printf "       %s\n" "$d"
    done < <(ls -l /proc/*/exe 2>/dev/null | grep "(deleted)" | head -5)
  fi
fi

}

###############################################################################
check_network() {
  should_skip "network" && return
  header "17" "NETWORK SECURITY (Advanced)"
###############################################################################

# Established Connections
ESTAB=$(ss -tnp state established 2>/dev/null | tail -n+2)
ESTAB_COUNT=$(echo "$ESTAB" | grep -c . || true)
ESTAB_COUNT=${ESTAB_COUNT:-0}
_emit_info "Established TCP connections: $ESTAB_COUNT"
if [[ "$ESTAB_COUNT" -gt 0 ]] && ! $JSON_MODE; then
  while read -r line; do
    printf "       %s\n" "$line"
  done < <(echo "$ESTAB" | head -10)
fi

# ICMP Redirect
ICMP_REDIR_ALL=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
ICMP_REDIR_DEF=$(sysctl -n net.ipv4.conf.default.accept_redirects 2>/dev/null)
if [[ "${ICMP_REDIR_ALL:-1}" -eq 0 ]] && [[ "${ICMP_REDIR_DEF:-1}" -eq 0 ]]; then
  _emit_pass "ICMP redirects: blocked (all+default)"
elif [[ "${ICMP_REDIR_ALL:-1}" -eq 0 ]]; then
  _emit_warn "ICMP redirects: conf.all=0, but conf.default=${ICMP_REDIR_DEF} (new interfaces may accept)"
else
  _emit_fail "ICMP redirects: accepted"
fi

# TCP Wrappers (new)
sub_header "TCP Wrappers"
if [[ -f /etc/hosts.allow ]]; then
  ALLOW_RULES=$(grep -cvE '^#|^$' /etc/hosts.allow 2>/dev/null)
  ALLOW_RULES="${ALLOW_RULES:-0}"
  DENY_RULES=$(grep -cvE '^#|^$' /etc/hosts.deny 2>/dev/null)
  DENY_RULES="${DENY_RULES:-0}"
  _emit_info "TCP wrappers: $ALLOW_RULES allow, $DENY_RULES deny rules"
  if [[ "$DENY_RULES" -eq 0 ]]; then
    _emit_info "hosts.deny: no deny rules (TCP wrappers deprecated on modern systems)"
  else
    _emit_pass "hosts.deny: $DENY_RULES deny rules"
  fi
else
  _emit_info "TCP wrappers: not configured (hosts.allow missing)"
fi

# Connections in WAIT state
sub_header "Connection States"
_WAIT_COUNT=$(ss -tn state time-wait 2>/dev/null | tail -n+2 | wc -l)
_WAIT_COUNT=${_WAIT_COUNT:-0}
if [[ "$_WAIT_COUNT" -gt 100 ]]; then
  _emit_warn "TCP TIME_WAIT connections: $_WAIT_COUNT (possible resource exhaustion)"
elif [[ "$_WAIT_COUNT" -gt 50 ]]; then
  _emit_info "TCP TIME_WAIT connections: $_WAIT_COUNT"
else
  _emit_pass "TCP TIME_WAIT connections: $_WAIT_COUNT"
fi

# ARP monitoring
sub_header "ARP Monitoring"
_ARP_MON_FOUND=false
for _arp_tool in arpwatch arpon addrwatch; do
  if require_cmd "$_arp_tool" || systemctl is-active "${_arp_tool}" &>/dev/null; then
    _emit_pass "ARP monitoring: $_arp_tool available"
    _ARP_MON_FOUND=true
    break
  fi
done
if ! $_ARP_MON_FOUND; then
  _emit_info "No ARP monitoring software detected (consider arpwatch)"
fi

}

###############################################################################
check_containers() {
  should_skip "containers" && return
  header "18" "CONTAINERS & VIRTUALIZATION"
###############################################################################

if require_cmd docker; then
  if systemctl is-active docker &>/dev/null; then
    # F-145: distinguish rootless (safe) from rootful (privileged daemon)
    if docker info 2>/dev/null | grep -qi "rootless"; then
      _emit_info "Docker rootless mode — minimal daemon attack surface"
    else
      _emit_warn "Docker daemon running (rootful) — consider rootless mode"
    fi
    CONTAINERS=$(docker ps -q 2>/dev/null | wc -l)
    _emit_info "Running containers: $CONTAINERS"
  else
    _emit_info "Docker installed, not active"
  fi
fi

if require_cmd podman; then
  PODMAN_ROOT=$(podman ps -q 2>/dev/null | wc -l)
  if [[ "$PODMAN_ROOT" -gt 0 ]]; then
    _emit_warn "Podman root containers: $PODMAN_ROOT"
  else
    _emit_pass "Podman containers (root): 0"
  fi
fi

# F-287 (v3.6.1): split VM detection into libvirt-managed vs standalone qemu.
# `virsh list` only sees libvirt-managed VMs — standalone qemu invocations
# (livemedia-creator during ISO builds, direct `qemu-system-*` calls, CI
# runners) are invisible to virsh. Counting them via pgrep complements the
# libvirt path and surfaces unmanaged VM activity that previously appeared
# as "Running VMs: 0" while a qemu process consumed 100%+ CPU.
_VM_LIBVIRT=0
if require_cmd virsh; then
  _VM_LIBVIRT=$(LC_ALL=C virsh list --all 2>/dev/null | grep -cE "running|paused" | ccount)
  _emit_info "Running VMs (libvirt-managed): $_VM_LIBVIRT"
fi
_QEMU_TOTAL=0
if require_cmd pgrep; then
  _QEMU_TOTAL=$(pgrep -c -f '^qemu-system-' 2>/dev/null || true)
  _QEMU_TOTAL=${_QEMU_TOTAL:-0}
fi
if [[ "$_QEMU_TOTAL" -gt "$_VM_LIBVIRT" ]]; then
  _VM_STANDALONE=$(( _QEMU_TOTAL - _VM_LIBVIRT ))
  _emit_info "Standalone qemu-system processes: $_VM_STANDALONE (not libvirt-managed — e.g. livemedia-creator, direct qemu)"
else
  # F-332 (v3.6.1): emit symmetric zero-line so the user can see both checks ran
  # (libvirt + standalone). Previously skip-when-zero hid the standalone-qemu
  # check entirely, leaving readers unsure whether "Running VMs: 0" covered all
  # qemu invocations or just libvirt-managed ones.
  _emit_pass "Standalone qemu-system processes: 0 (no unmanaged qemu detected)"
fi

# F-148: severity-tiered classification of user.max_user_namespaces
USER_NS=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "N/A")
if [[ "$USER_NS" == "N/A" ]]; then
  _emit_info "Max user namespaces: N/A (kernel does not expose this sysctl)"
elif [[ "$USER_NS" == "0" ]]; then
  _emit_pass "Max user namespaces: 0 (hardened — userns disabled)"
elif [[ "$USER_NS" -lt 1000 ]]; then
  _emit_pass "Max user namespaces: $USER_NS (restricted)"
elif [[ "$USER_NS" -lt 10000 ]]; then
  _emit_info "Max user namespaces: $USER_NS (Fedora/RHEL default range)"
else
  _emit_info "Max user namespaces: $USER_NS (high — typical for Ubuntu/container hosts)"
fi

}

###############################################################################
check_logs() {
  should_skip "logs" && return
  header "19" "LOGS & MONITORING"
###############################################################################

# Journal errors — separate "host security signal" from "dev workload noise".
# We filter two classes:
#   1. Authentication chatter (sudo PAM, pam_unix retries, systemd-coredump
#      handler) — already non-critical and noisy on busy admin systems.
#   2. Containerized / VM / dev-server processes whose err-level messages
#      bubble into the host journal but are local to the guest userspace
#      (qemu/libvirt/virtlogd/virtnetworkd/conmon/virtqemud, plus Docker/
#      Podman auto-generated names like xenodochial_khayyam[PID] which
#      follow the adjective_noun pattern, plus common dev runtimes:
#      phpsite, php-fpm, nodejs, gunicorn, uwsgi).
# Threshold: <=15 pass, <=100 warn, >100 fail. When FAIL fires, the
# message includes the top 3 offending source units so the user can
# investigate rather than guess.
# Journal format: "MMM DD HH:MM:SS hostname unit[PID]: message"
# Match unit name as token preceded by space (the host→unit separator).
# Previous version anchored to ^MMM DD HH:MM:SS but only stripped 2 fields
# instead of 3 — `27 02:30:17` were fields 2 and 3 but `fedora` (hostname)
# was field 4 and got eaten by `(phpsite|...)` which then never matched.
_journal_filter='sudo|password is required|auth could not identify|systemd-coredump'
_journal_filter+='| (qemu|libvirt|virtlogd|virtnetworkd|conmon|systemd-machined|virtqemud|virt-pki-validate)\['
_journal_filter+='| [a-z]+_[a-z]+\[[0-9]+\]'  # Docker/Podman auto-names: adjective_noun[PID]
_journal_filter+='| (phpsite|php-fpm|nodejs|gunicorn|uwsgi|wsgi)\['
# F-290: known-benign host-noise patterns that are not security signals.
#   - binfmt_misc.mount: F43+ kernel quirk where systemd retries the
#     mount every few minutes and fails. The Section 30 binfmt_misc
#     check separately verifies that no non-native formats are
#     registered, so the missing mount-point is purely cosmetic.
#   - dbus-broker "Ignoring duplicate name": triggered when a DBus
#     service is shipped twice (e.g. our GOA hard-mask leaves the
#     original *.service file alongside the masked override). Broker
#     does the right thing — keeps the first, discards the second.
#   - dracut "No /dev/log or logger included for syslog logging":
#     warning emitted during initramfs *assembly* (not runtime). The
#     resulting initramfs boots fine; this is a packaging-time hint
#     for embedded-target builds, not a host issue.
# Pattern includes word-boundary on the source unit to avoid false
# matches in unrelated message bodies.
_journal_filter+='|Failed to mount proc-sys-fs-binfmt_misc'
_journal_filter+='|dbus-broker-launch\[[0-9]+\]: Ignoring duplicate name'
_journal_filter+='|dracut\[[0-9]+\]: No .[^[:space:]]+/dev/log'
# F-346 (v3.6.2): activation-request failures for SPECIFIC privacy-masked
# services. When NoID/Tails/Kicksecure/secureblue masks GNOME-default services
# for privacy hardening, dbus-broker logs an error each time a still-installed
# app pokes the masked bus name. The mask IS the security guarantee.
#
# IMPORTANT: this is an EXPLICIT allow-list, NOT a wildcard. Adding a new
# masked service to NoID requires extending this list — that is intentional,
# so unexpected activation failures (e.g. crashed NetworkManager helper,
# corrupted bus-name registration) still surface as real WARN findings.
#
# Service-name → masking rationale:
#   ColorManager     — colord (color profile mgmt) masked: privacy
#   nm_dispatcher    — NM-dispatcher masked: per-state-change script attack-surface
#   home1            — systemd-homed masked: NoID uses static /home/<user>
#   Avahi            — avahi-daemon masked: zero-conf network discovery off
#   ModemManager1    — ModemManager masked: no cellular support needed
#   GeoClue2         — geoclue2 service masked: location services off
#   UPower           — defensive: NoID may mask in future for laptop-only privacy
_journal_filter+="|dbus-broker-launch\[[0-9]+\]: Activation request for 'org\.freedesktop\.(ColorManager|nm_dispatcher|home1|Avahi|ModemManager1|GeoClue2|UPower)' failed"
# F-347 (v3.6.2): gnome-keyring init noise — gkr-pam logs an error before
# the daemon is ready (race during PAM init). Harmless: keyring functions
# correctly post-init. Upstream gnome-keyring issue, not deployment-specific.
_journal_filter+='|gkr-pam: unable to locate daemon control file'
_journal_raw=$(journalctl -p err --since "1 hour ago" --no-pager -q 2>/dev/null \
  | grep -E "^[A-Z][a-z]{2} ")
JOURNAL_ERR=$(echo "$_journal_raw" | grep -cvE "$_journal_filter" || true)
JOURNAL_ERR=${JOURNAL_ERR:-0}
if [[ "$JOURNAL_ERR" -le 15 ]]; then
  _emit_pass "Journal errors (1h): $JOURNAL_ERR"
elif [[ "$JOURNAL_ERR" -le 100 ]]; then
  _emit_warn "Journal errors (1h): $JOURNAL_ERR (review with: journalctl -p err --since '1 hour ago')"
else
  _emit_fail "Journal errors (1h): $JOURNAL_ERR — top offending sources:"
  if ! $JSON_MODE; then
    echo "$_journal_raw" | grep -vE "$_journal_filter" | awk '{print $5}' \
      | sort | uniq -c | sort -rn | head -3 | while read -r line; do
        printf "       %s\n" "$line"
      done
  fi
fi

# journalctl short format: each actual entry starts with a 3-letter month (e.g. "Feb 26 ...").
# Multi-line entries (coredump stack traces + module lists) produce many continuation lines
# that are indented with spaces — these are NOT separate events and must not be counted.
# Filter to timestamp-prefixed lines only, then exclude known-benign sources.
_JCRIT_LINES=$(journalctl -p crit --since "24 hours ago" --no-pager -q 2>/dev/null)
# Filter known-benign critical messages (F-156: extend to AMD/SP5100 watchdog
# variants in addition to Intel iTCO):
#   sudo/auth                          — normal sudo operations without TTY
#   systemd-coredump                   — stack traces inflate count (filtered since v3.2.1)
#   watchdog.*did not stop             — Intel iTCO watchdog harmless shutdown log
#   sp5100-tco|amd_(pci_pm|nb)         — AMD TCO/NB watchdog variants
#   pcieport.*AER.*(Corrected|RxErr)   — transient PCIe link noise
JOURNAL_CRIT=$(echo "$_JCRIT_LINES" \
  | grep -E "^[A-Z][a-z]{2} " \
  | grep -cvE "sudo|password is required|auth could not identify|systemd-coredump|watchdog.*did not stop|sp5100-tco|amd_pci_pm|amd_nb|pcieport.*AER.*(Corrected|RxErr)" || true)
JOURNAL_CRIT=${JOURNAL_CRIT:-0}
if [[ "$JOURNAL_CRIT" -eq 0 ]]; then
  _emit_pass "Journal critical (24h): 0"
elif [[ "$JOURNAL_CRIT" -le 20 ]]; then
  _emit_warn "Journal critical (24h): $JOURNAL_CRIT"
else
  _emit_fail "Journal critical (24h): $JOURNAL_CRIT"
fi

# F-151: limit to recent (1h) — kernel ring buffer accumulates boot-time
# errors over months on long-uptime servers, inflating count
DMESG_ERR=$(dmesg --level=err,crit,alert,emerg --since "1 hour ago" 2>/dev/null | wc -l)
if [[ "$DMESG_ERR" -le 5 ]]; then
  _emit_pass "dmesg errors (1h): $DMESG_ERR"
else
  _emit_warn "dmesg errors (1h): $DMESG_ERR"
fi

OOM_KILLS=$(dmesg 2>/dev/null | grep -c "Out of memory" | ccount)
if [[ "$OOM_KILLS" -eq 0 ]]; then
  _emit_pass "OOM kills: 0"
else
  _emit_fail "OOM kills: $OOM_KILLS"
fi

SEGFAULTS=$(dmesg 2>/dev/null | grep -c "segfault" | ccount)
if [[ "$SEGFAULTS" -eq 0 ]]; then
  _emit_pass "Segfaults: 0"
else
  _emit_warn "Segfaults: $SEGFAULTS"
fi

if [[ -f /etc/logrotate.conf ]]; then
  _emit_pass "logrotate configured"
else
  _emit_warn "logrotate not configured"
fi

# LC_ALL=C — journalctl translates the size suffix and may emit comma decimals
# on de_DE/fr_FR (e.g. "280,0M") which the dot-only regex below cannot parse.
# F-286 (v3.6.1): label the measurement source. `journalctl --disk-usage`
# reports the size systemd accounts for (active + archived journal files,
# excluding fragmentation). Section 38 separately reports the raw filesystem
# size of /var/log/journal via `du -sb` which can differ noticeably (du
# includes filesystem-level overhead). Two different measurements, both valid
# — the labels now make the source explicit so users don't think the script
# is contradicting itself.
JOURNAL_STORAGE=$(LC_ALL=C journalctl --disk-usage 2>/dev/null | grep -oP '\d+\.?\d*[GMKT]' | head -1)
# F-316 (v3.6.1): cross-reference Section 38 — both reports describe journal
# storage but from different sources (journald-accounted vs filesystem du -sb).
# Without explicit cross-reference, users see two different sizes and assume
# the script contradicts itself.
_emit_info "Journal storage (journalctl --disk-usage): ${JOURNAL_STORAGE:-unknown} — see Section 38 for filesystem-size view"

# Systemd Journal Forwarding (new)
JOURNAL_FWD=$(grep -i "ForwardToSyslog" /etc/systemd/journald.conf 2>/dev/null | grep -v "^#" | head -1)
if [[ -n "$JOURNAL_FWD" ]]; then
  _emit_info "Journal forwarding: $JOURNAL_FWD"
else
  _emit_info "Journal forwarding: default (not explicitly configured)"
fi

# Deleted log files still in use (file handle open but file deleted — logs lost on restart)
# shellcheck disable=SC2012  # ls -la inside -exec is the canonical way to surface (deleted) marker
_DELETED_LOGS=$(find /proc/*/fd -lname '*/log/*' -exec ls -la {} \; 2>/dev/null | grep -c "(deleted)")
_DELETED_LOGS=${_DELETED_LOGS:-0}
if [[ "$_DELETED_LOGS" -eq 0 ]]; then
  _emit_pass "No deleted log files in use"
elif [[ "$_DELETED_LOGS" -le 3 ]]; then
  _emit_info "Deleted log files still open: $_DELETED_LOGS (logrotate pending restart)"
else
  _emit_warn "Deleted log files still open: $_DELETED_LOGS (services holding stale file handles)"
fi

# F-155: only check empty syslog files if rsyslog/syslog-ng is actually
# active. On systemd-only systems (Fedora 40+, Arch, modern minimal installs)
# these files don't exist by design and shouldn't trigger warnings.
if systemctl is-active rsyslog syslog-ng &>/dev/null; then
  _EMPTY_LOGS=0
  for _logf in /var/log/messages /var/log/syslog /var/log/auth.log /var/log/secure /var/log/kern.log; do
    if [[ -f "$_logf" && ! -s "$_logf" ]]; then
      _EMPTY_LOGS=$((_EMPTY_LOGS + 1))
      _emit_warn "Empty log file: $_logf (logging may be broken)"
    fi
  done
  [[ "$_EMPTY_LOGS" -eq 0 ]] && _emit_pass "No empty log files detected"
else
  _emit_info "Syslog implementation not active — using systemd-journald only (modern default)"
fi

}

###############################################################################
check_performance() {
  should_skip "performance" && return
  header "20" "PERFORMANCE & RESOURCES"
###############################################################################

UPTIME=$(uptime -p)
LOAD=$(awk '{print $1, $2, $3}' /proc/loadavg)
CPU_COUNT=$(nproc)
LOAD_1=$(echo "$LOAD" | awk '{print $1}')
_emit_info "Uptime: $UPTIME"
_emit_info "Load: $LOAD (CPUs: $CPU_COUNT)"

# F-157: replace bc dependency with awk (POSIX-portable, always available)
if [[ -n "$LOAD_1" ]]; then
  if awk -v l="$LOAD_1" -v c="$CPU_COUNT" 'BEGIN { exit !(l > c) }'; then
    _emit_warn "Load ($LOAD_1) > CPU count ($CPU_COUNT)"
  else
    _emit_pass "Load OK: $LOAD_1 / $CPU_COUNT CPUs"
  fi
fi

MEM_TOTAL=$(LC_ALL=C free -h | awk '/^Mem:/ {print $2}')
MEM_USED=$(LC_ALL=C free -h | awk '/^Mem:/ {print $3}')
MEM_AVAIL=$(LC_ALL=C free -h | awk '/^Mem:/ {print $7}')
# F-158: use 'available' (column 7) instead of 'used' — Linux aggressively
# caches files which inflates 'used'. 'available' is what apps can claim
# without paging.
MEM_AVAIL_PCT=$(LC_ALL=C free | awk '/^Mem:/ {printf "%.0f", ($7/$2)*100}')
_emit_info "RAM: $MEM_USED / $MEM_TOTAL (${MEM_AVAIL_PCT}% available, $MEM_AVAIL free)"
if [[ "$MEM_AVAIL_PCT" -lt 5 ]]; then
  _emit_fail "RAM: only ${MEM_AVAIL_PCT}% available (critical)"
elif [[ "$MEM_AVAIL_PCT" -lt 15 ]]; then
  _emit_warn "RAM: ${MEM_AVAIL_PCT}% available"
else
  _emit_pass "RAM: ${MEM_AVAIL_PCT}% available"
fi

SWAP_TOTAL=$(LC_ALL=C free -h | awk '/^Swap:/ {print $2}')
SWAP_USED=$(LC_ALL=C free -h | awk '/^Swap:/ {print $3}')
if [[ "$SWAP_TOTAL" != "0B" ]] && [[ "$SWAP_TOTAL" != "0" ]]; then
  _emit_info "Swap: $SWAP_USED / $SWAP_TOTAL"
else
  _emit_info "No swap configured"
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
      _emit_info "Disk $MOUNT: read-only $FSTYPE image (always 100% — skipped)"
      continue
      ;;
  esac
  # Skip explicitly read-only mounts (loopback ISOs etc.)
  if mount | grep -qE "on $MOUNT type [^ ]+ \(ro,"; then
    _emit_info "Disk $MOUNT: read-only mount (skipped)"
    continue
  fi
  if [[ "$PCT" -gt 90 ]]; then
    _emit_fail "Disk $MOUNT: ${PCT}% full!"
  elif [[ "$PCT" -gt 80 ]]; then
    if [[ "$MOUNT" == */efi* || "$MOUNT" == */firmware* ]]; then
      _emit_info "Disk $MOUNT: ${PCT}% (EFI/firmware — normal)"
    else
      _emit_warn "Disk $MOUNT: ${PCT}% full"
    fi
  else
    _emit_pass "Disk $MOUNT: ${PCT}% used"
  fi
done < <(df -h -T -x tmpfs -x devtmpfs -x squashfs -x iso9660 -x erofs -x overlay 2>/dev/null | tail -n+2)

# F-160: Inode check — detect FS type to label dynamic-inode systems
# correctly. Btrfs/ZFS/F2FS/Bcachefs all return "-" or 0% — dynamic
# allocation, not a measurement. Add 80% WARN tier for fixed-inode FS.
# Use findmnt for fs-type — `df -T` can wrap on long device names.
if require_cmd findmnt; then
  ROOT_FS_TYPE=$(findmnt -no FSTYPE / 2>/dev/null)
else
  ROOT_FS_TYPE=$(df -PT / 2>/dev/null | tail -1 | awk '{print $2}')
fi
INODE_PCT=$(df -Pi / 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
case "$ROOT_FS_TYPE" in
  btrfs|zfs|f2fs|bcachefs)
    _emit_pass "Inodes /: N/A ($ROOT_FS_TYPE — dynamic allocation)"
    ;;
  *)
    if [[ "$INODE_PCT" == "-" ]] || [[ -z "$INODE_PCT" ]]; then
      _emit_info "Inodes /: not reportable ($ROOT_FS_TYPE)"
    elif [[ "$INODE_PCT" -gt 90 ]]; then
      _emit_fail "Inodes /: ${INODE_PCT}% ($ROOT_FS_TYPE — critical)"
    elif [[ "$INODE_PCT" -gt 80 ]]; then
      _emit_warn "Inodes /: ${INODE_PCT}% ($ROOT_FS_TYPE — approaching limit)"
    else
      _emit_pass "Inodes /: ${INODE_PCT}% ($ROOT_FS_TYPE)"
    fi
    ;;
esac

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
  _emit_warn "I/O wait: ${IOWAIT}%"
else
  _emit_pass "I/O wait: ${IOWAIT:-0}%"
fi

sub_header "Top 5 CPU"
if ! $JSON_MODE; then
  # shellcheck disable=SC2009  # ps -eo + grep filters the sort header line — pgrep can't replace this
  # Lowercase loop vars so we don't shadow the $USER environment variable.
  while read -r _user _cpu _mem _cmd; do
    printf "       %s %s%% %s\n" "$_user" "$_cpu" "$(echo "$_cmd" | cut -c1-60)"
  done < <(ps -eo user,pcpu,pmem,args --sort=-pcpu 2>/dev/null | grep -v 'sort=-pcpu' | head -6 | tail -5)
fi

sub_header "Top 5 Memory"
if ! $JSON_MODE; then
  # shellcheck disable=SC2009
  while read -r _user _cpu _mem _cmd; do
    printf "       %s %s%% %s\n" "$_user" "$_mem" "$(echo "$_cmd" | cut -c1-60)"
  done < <(ps -eo user,pcpu,pmem,args --sort=-pmem 2>/dev/null | grep -v 'sort=-pmem' | head -6 | tail -5)
fi

}

###############################################################################
check_hardware() {
  should_skip "hardware" && return
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
      _emit_fail "CPU vuln $NAME: $STATUS"
    elif echo "$STATUS" | grep -qi "mitigation"; then
      _emit_pass "CPU vuln $NAME: mitigated"
    elif echo "$STATUS" | grep -qi "not affected"; then
      _emit_pass "CPU vuln $NAME: Not affected"
    else
      _emit_warn "CPU vuln $NAME: $STATUS"
    fi
  done
fi

# SMART Health — F-164: USB/eSATA disks may need -d sat or -d usbjmicron to
# pass SMART through the bridge chip. Skip virtual/in-memory block devices
# entirely (zram=RAM-backed swap, loop=file-backed, dm-=device-mapper has
# its own underlying device, md=RAID member device check, ram=ramdisk, nbd=
# network block device, sr=optical) — none of these expose SMART data.
if require_cmd smartctl; then
  while read -r DISK; do
    [[ -z "$DISK" ]] && continue
    # Skip non-physical block devices
    case "$DISK" in
      /dev/zram*|/dev/loop*|/dev/dm-*|/dev/md*|/dev/ram*|/dev/nbd*|/dev/sr*)
        continue
        ;;
    esac
    SMART=$(smartctl -H "$DISK" 2>/dev/null | grep -iE "health|result" | tail -1)
    if [[ -z "$SMART" ]]; then
      # Empty output often means USB/eSATA bridge — retry with -d sat
      SMART=$(smartctl -H -d sat "$DISK" 2>/dev/null | grep -iE "health|result" | tail -1)
    fi
    if [[ -z "$SMART" ]]; then
      # Some USB bridges need the JMicron passthrough
      SMART=$(smartctl -H -d usbjmicron "$DISK" 2>/dev/null | grep -iE "health|result" | tail -1)
    fi
    if echo "$SMART" | grep -qiE "passed|ok"; then
      _emit_pass "SMART $DISK: OK"
    elif [[ -n "$SMART" ]]; then
      _emit_fail "SMART $DISK: $SMART"
    else
      _emit_info "SMART $DISK: not reportable (USB bridge without SMART passthrough?)"
    fi
  done < <(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2=="disk"{print "/dev/"$1}')
else
  _emit_info "smartctl not installed — SMART checks skipped"
fi

# Temperature (F-165: distinguish "not installed" from "installed but
# unconfigured" — silent skip on misconfigured sensors hides actual issue)
if require_cmd sensors; then
  _SENSORS_OUT=$(sensors 2>/dev/null)
  if [[ -z "$_SENSORS_OUT" ]] || ! echo "$_SENSORS_OUT" | grep -q "°C"; then
    _emit_info "lm_sensors installed but no readings — run 'sudo sensors-detect' to configure"
  else
    MAX_TEMP=$(echo "$_SENSORS_OUT" | grep -oP ':\s+\+\K\d+\.\d+(?=°C)' | sort -rn | head -1)
    if [[ -n "$MAX_TEMP" ]]; then
      TEMP_NUM=$(echo "$MAX_TEMP" | grep -oP '^\d+')
      if [[ "$TEMP_NUM" -gt 85 ]]; then
        _emit_fail "Max temperature: ${MAX_TEMP}°C (CRITICAL)"
      elif [[ "$TEMP_NUM" -gt 70 ]]; then
        _emit_warn "Max temperature: ${MAX_TEMP}°C (elevated)"
      else
        _emit_pass "Max temperature: ${MAX_TEMP}°C"
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
  _emit_info "lm_sensors not installed — temperature checks skipped"
fi

# USB Devices
# F-166: filter root-hub controllers from USB device count. lsusb shows
# `Bus NNN Device NNN: ID 1d6b:NNNN Linux Foundation X.X root hub` for each
# host controller — those are not real devices, just the bus endpoints.
USB_COUNT=$(lsusb 2>/dev/null | grep -cv "Linux Foundation.*root hub")
USB_COUNT=${USB_COUNT:-0}
_emit_info "USB devices: $USB_COUNT (excluding host root hubs)"

}

###############################################################################
check_interfaces() {
  should_skip "interfaces" && return
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
# F-323 (v3.6.1): use 2-space prefix matching the network interfaces listing
# directly above. Previous 7-space prefix was visually orphaned — this section
# has its own sub_header but the per-line indentation should still match the
# raw-data style used for interfaces (`  lo (UNKNOWN): ...`).
if ! $JSON_MODE; then
  while read -r route; do
    printf "  %s\n" "$route"
  done < <(ip route show 2>/dev/null)
fi

if require_cmd dig; then
  # F-167: query DNS root nameservers (no third-party tracked)
  DNS_TEST=$(dig +short . NS +time=3 2>/dev/null | head -1 || echo "FAIL")
  if [[ "$DNS_TEST" != "FAIL" ]] && [[ -n "$DNS_TEST" ]]; then
    _emit_pass "DNS resolution: working"
  else
    _emit_warn "DNS resolution: failed"
  fi
fi

}

###############################################################################
check_certificates() {
  should_skip "certificates" && return
  header "23" "CRYPTO & CERTIFICATES"
###############################################################################

# F-168: Cross-distro CA certificate count (trust is Fedora/RHEL-only).
# `grep -c` returns rc=1 with stdout="0" on no-match; the legacy `|| echo "?"`
# pattern would APPEND "?" to "0", producing multi-line "0\n?" in info output.
# Use ${var:-0} default instead so empty/zero captures cleanly.
if require_cmd trust; then
  CA_COUNT=$(trust list 2>/dev/null | grep -c "type: certificate")
  CA_COUNT=${CA_COUNT:-0}
  _emit_info "System CA certificates: $CA_COUNT"
elif [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
  CA_COUNT=$(grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt 2>/dev/null)
  CA_COUNT=${CA_COUNT:-0}
  _emit_info "System CA certificates: $CA_COUNT (from ca-certificates.crt)"
elif [[ -d /etc/ssl/certs ]]; then
  CA_COUNT=$(find /etc/ssl/certs -maxdepth 1 \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | wc -l)
  _emit_info "System CA certificates: $CA_COUNT (from /etc/ssl/certs/)"
fi

if require_cmd openssl; then
  for _CERT_DIR in /etc/pki/tls/certs /etc/ssl/certs; do
    [[ -d "$_CERT_DIR" ]] || continue
    while read -r cert; do
      if ! openssl x509 -checkend 0 -in "$cert" -noout &>/dev/null; then
        _emit_warn "Expired certificate: $cert"
      fi
    done < <(find "$_CERT_DIR" -maxdepth 1 \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | grep -v "ca-bundle" | head -20)
  done
fi

sub_header "SSH Keys"
while read -r USER_HOME; do
  _ssh_user=$(basename "$USER_HOME")
  if [[ -d "$USER_HOME/.ssh" ]]; then
    # SC2012-clean: count via shell glob with nullglob
    shopt -s nullglob
    _ssh_pubkeys=("$USER_HOME/.ssh/"*.pub)
    shopt -u nullglob
    KEY_COUNT="${#_ssh_pubkeys[@]}"
    AUTH_KEYS=$(wc -l "$USER_HOME/.ssh/authorized_keys" 2>/dev/null | awk '{print $1}' || true)
    AUTH_KEYS=${AUTH_KEYS:-0}
    if [[ "$KEY_COUNT" -gt 0 ]] || [[ "$AUTH_KEYS" -gt 0 ]]; then
      [[ "$KEY_COUNT" -eq 1 ]] && _kw="key" || _kw="keys"
      [[ "$AUTH_KEYS" -eq 1 ]] && _aw="authorized key" || _aw="authorized"
      _emit_info "SSH keys for $_ssh_user: $KEY_COUNT $_kw, $AUTH_KEYS $_aw"
    fi
  fi
done < <(_iter_user_homes)

}

###############################################################################
check_environment() {
  should_skip "environment" && return
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
  _emit_pass "No exposed private keys"
else
  _emit_fail "Exposed private keys:"
  if ! $JSON_MODE; then
    while read -r k; do printf "       %s\n" "$k"; done <<< "$EXPOSED_KEYS"
  fi
fi

# .env files (uses _safe_find_home — same snapshot/cache excludes)
ENV_FILES=$(_safe_find_home \( -name ".env" -o -name ".env.local" -o -name ".env.production" \) -readable -size +0c | wc -l)
if [[ "$ENV_FILES" -gt 0 ]]; then
  _emit_info ".env files found: $ENV_FILES"
fi

# Credentials in configs
CRED_PATTERNS="password|passwd|secret|api_key|token|credential"
# F-173: `find -exec grep` per-file forks once each. `grep -rli` on /etc is
# faster (single grep process scans recursively).
CRED_FOUND=$(grep -rliE "$CRED_PATTERNS" /etc --include='*.conf' 2>/dev/null | wc -l)
_emit_info "Config files with credential patterns: $CRED_FOUND"

}

###############################################################################
check_systemd() {
  should_skip "systemd" && return
  header "25" "SYSTEMD SECURITY"
###############################################################################

if require_cmd systemd-analyze; then
  sub_header "systemd-analyze security"
  # F-333 (v3.6.1): explicit classification note up-front so readers understand
  # why services with similar scores are reported differently — security/hardware
  # services with high scores are infrastructure-required (cannot be sandboxed
  # without breaking core function); user-facing services with high scores are
  # actual hardening regressions because they CAN be sandboxed.
  _emit_info "Score tiers: <5.0=PASS, 5.0-7.0=INFO, ≥7.0=WARN (per systemd src). Security/hardware services bypass tier check — high scores expected (root/HW access required)"
  # Security services (need root — high score expected and acceptable)
  _SECURITY_SVCS="sshd firewalld fail2ban auditd usbguard chronyd"
  # Hardware/display services (inherently need broad access — high score expected)
  _HARDWARE_SVCS="gdm gdm3 thermald"
  # User-facing services (should be sandboxed — high score = problem)
  _USER_SVCS="NetworkManager ModemManager colord fwupd power-profiles-daemon switcheroo-control"
  # F-310 (v3.6.1): annotate inactive units. systemd-analyze security parses
  # the unit FILE regardless of runtime state — inactive units still get a
  # score, which misleads users into thinking the score is a current concern.
  # For _USER_SVCS the score-tier (PASS/INFO/WARN) is also short-circuited
  # to INFO when inactive, since an inactive unit can't be exploited.
  for SVC in $_SECURITY_SVCS; do
    SCORE=$(LC_ALL=C systemd-analyze security "$SVC" 2>/dev/null | tail -1 | grep -oP '\d+\.\d+' || echo "N/A")
    if [[ "$SCORE" != "N/A" ]]; then
      if systemctl is-active "$SVC" &>/dev/null; then
        _emit_info "systemd-security $SVC: $SCORE (security service, needs root)"
      else
        _emit_info "systemd-security $SVC: $SCORE (unit inactive — score irrelevant)"
      fi
    fi
  done
  for SVC in $_HARDWARE_SVCS; do
    SCORE=$(LC_ALL=C systemd-analyze security "$SVC" 2>/dev/null | tail -1 | grep -oP '\d+\.\d+' || echo "N/A")
    if [[ "$SCORE" != "N/A" ]]; then
      if systemctl is-active "$SVC" &>/dev/null; then
        _emit_info "systemd-security $SVC: $SCORE (system service, needs hardware access)"
      else
        _emit_info "systemd-security $SVC: $SCORE (unit inactive — score irrelevant)"
      fi
    fi
  done
  # F-320 + F-321 (v3.6.1): float-compare via awk with systemd-analyze's actual
  # tier boundaries (from src/analyze/analyze-security.c):
  #   exposure ≥ 90 (score ≥ 9.0) = DANGEROUS  → WARN
  #   exposure ≥ 70 (score ≥ 7.0) = UNSAFE     → WARN
  #   exposure ≥ 50 (score ≥ 5.0) = MEDIUM     → INFO
  #   exposure ≥ 10 (score ≥ 1.0) = OK         → PASS
  #   exposure < 10 (score < 1.0) = SAFE       → PASS
  # F-320 fixed cut -d. -f1 integer-truncation (e.g. 7.8→"7" misclassified)
  # but used wrong PASS boundary 4.0; F-321 corrects to 5.0 to match systemd's
  # own "OK" tier — fwupd 4.5 is "OK"-tier per systemd, was incorrectly flagged
  # as INFO under F-320. Final mapping: <5.0 → PASS, 5.0-7.0 → INFO, ≥7.0 → WARN.
  _HIGH_EXPOSURE=0
  for SVC in $_USER_SVCS; do
    SCORE=$(LC_ALL=C systemd-analyze security "$SVC" 2>/dev/null | tail -1 | grep -oP '\d+\.\d+' || echo "N/A")
    [[ "$SCORE" == "N/A" ]] && continue
    if ! systemctl is-active "$SVC" &>/dev/null; then
      _emit_info "systemd-security $SVC: $SCORE (unit inactive — score irrelevant)"
      continue
    fi
    if awk -v s="$SCORE" 'BEGIN { exit !(s < 5.0) }'; then
      _emit_pass "systemd-security $SVC: $SCORE (well-sandboxed)"
    elif awk -v s="$SCORE" 'BEGIN { exit !(s < 7.0) }'; then
      _emit_info "systemd-security $SVC: $SCORE"
    else
      _emit_warn "systemd-security $SVC: $SCORE (high exposure — poor sandboxing)"
      _HIGH_EXPOSURE=$((_HIGH_EXPOSURE + 1))
    fi
  done
  if [[ "$_HIGH_EXPOSURE" -eq 0 ]]; then
    _emit_pass "No user-facing services with critical exposure scores"
  fi
fi

}

###############################################################################
check_desktop() {
  should_skip "desktop" && return
  header "26" "DESKTOP & GUI SECURITY"
###############################################################################

# Wayland vs X11
if require_cmd loginctl; then
  SESSION_ID=$(loginctl list-sessions --no-legend 2>/dev/null | grep -E "seat[0-9]" | awk '{print $1}' | head -1)
  [[ -z "$SESSION_ID" ]] && SESSION_ID=$(loginctl list-sessions --no-legend 2>/dev/null | awk 'NR==1{print $1}')
  if [[ -n "$SESSION_ID" ]]; then
    SESSION_TYPE=$(loginctl show-session "$SESSION_ID" -p Type --value 2>/dev/null || echo "unknown")
    if [[ "$SESSION_TYPE" == "wayland" ]]; then
      _emit_pass "Display server: Wayland (more secure than X11)"
    elif [[ "$SESSION_TYPE" == "x11" ]]; then
      _emit_warn "Display server: X11 (keylogger risk — consider Wayland)"
    else
      _emit_info "Display server: $SESSION_TYPE"
    fi
  fi
fi

# Screen Lock (per-user, DE-aware: GNOME / KDE Plasma / XFCE / MATE / Cinnamon)
_de_lock_check_cb() {
  local user="$1" val
  val=$(echo "$3" | xargs | tr '[:upper:]' '[:lower:]')
  _DE_LOCK_FOUND=1
  case "$val" in
    true|1) _emit_pass "Screen lock: enabled [$user, $_DE_FAMILY]" ;;
    false|0) _emit_warn "Screen lock: disabled [$user, $_DE_FAMILY]" ;;
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
  _emit_info "Screen lock: no active $_DE_FAMILY session found for check"

# Auto-Login — detailed check in Section 39 (Desktop Session Security)
if [[ -f /etc/gdm/custom.conf ]] || [[ -f /etc/gdm3/custom.conf ]]; then
  if grep -qi '^\s*AutomaticLoginEnable[[:space:]]*=[[:space:]]*true' /etc/gdm*/custom.conf /etc/gdm*/daemon.conf 2>/dev/null; then
    _emit_fail "GDM auto-login enabled!"
  else
    _emit_pass "GDM: no auto-login"
  fi
fi

}

###############################################################################
check_ntp() {
  should_skip "ntp" && return
  header "27" "TIME SYNC & NTP"
###############################################################################

if require_cmd timedatectl; then
  NTP_SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  if [[ "$NTP_SYNC" == "yes" ]]; then
    _emit_pass "NTP synchronized"
  else
    _emit_warn "NTP not synchronized"
  fi
  TZ=$(timedatectl show -p Timezone --value 2>/dev/null)
  _emit_info "Timezone: $TZ"
fi

if systemctl is-active chronyd &>/dev/null || systemctl is-active chrony &>/dev/null; then
  _emit_pass "chrony: active"
  if require_cmd chronyc; then
    CHRONY_SOURCES=$(chronyc sources 2>/dev/null | grep -c "^\^" || true)
    CHRONY_SOURCES=${CHRONY_SOURCES:-0}
    _emit_info "Chrony sources: $CHRONY_SOURCES"

    # Network Time Security (NTS) check — F-180: detect chrony version first
    # since `authdata` is chrony 4.0+ only. RHEL 8 ships chrony 3.x; on those,
    # skip authdata path and go straight to config-grep fallback.
    CHRONY_VER=$(chronyd -v 2>&1 | grep -oE 'version [0-9]+\.[0-9]+' | head -1 | awk '{print $2}')
    CHRONY_MAJOR="${CHRONY_VER%%.*}"
    NTS_SOURCES=0
    if [[ "${CHRONY_MAJOR:-0}" -ge 4 ]]; then
      NTS_SOURCES=$(chronyc -n authdata 2>/dev/null | awk '$3 == "NTS" {c++} END {print c+0}')
    fi
    if [[ "$NTS_SOURCES" -gt 0 ]]; then
      _emit_pass "NTS (Network Time Security): $NTS_SOURCES active source(s) using NTS"
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
        _emit_pass "NTS (Network Time Security) configured in chrony.conf"
      else
        _emit_info "NTS (Network Time Security) not configured — consider adding 'nts' to chrony server lines"
      fi
    fi
  fi
  # NTP source quality (stratum 16 = unreachable, falsetickers)
  if require_cmd chronyc; then
    _BAD_SOURCES=0
    while read -r _cs_line; do
      # chronyc sources: field 3 is stratum, lines starting with ? or x are problematic
      if echo "$_cs_line" | grep -qE "^\?|^x"; then
        _BAD_SOURCES=$((_BAD_SOURCES + 1))
      fi
    done < <(chronyc sources 2>/dev/null | tail -n+3)
    if [[ "$_BAD_SOURCES" -gt 0 ]]; then
      _emit_warn "NTP: $_BAD_SOURCES unreachable/falseticker source(s) (check 'chronyc sources')"
    else
      _emit_pass "NTP: all sources reachable and valid"
    fi
  fi
elif systemctl is-active systemd-timesyncd &>/dev/null; then
  _emit_pass "timesyncd: active"
else
  _emit_warn "No NTP service active"
fi

}

###############################################################################
check_fail2ban() {
  should_skip "fail2ban" && return
  header "28" "FAIL2BAN"
###############################################################################

if systemctl is-active fail2ban &>/dev/null; then
  _emit_pass "fail2ban: active"

  if require_cmd fail2ban-client; then
    JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' | xargs)
    _emit_info "Active jails: $JAILS"

    for JAIL in $JAILS; do
      BANNED=$(fail2ban-client status "$JAIL" 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
      TOTAL_BANNED=$(fail2ban-client status "$JAIL" 2>/dev/null | grep "Total banned" | awk '{print $NF}')
      _emit_info "Jail $JAIL: $BANNED current, $TOTAL_BANNED total banned"
    done
  fi
elif ! require_cmd fail2ban-client; then
  _emit_info "fail2ban not installed — skipped"
else
  _emit_fail "fail2ban: INACTIVE"
fi

}

###############################################################################
check_logins() {
  should_skip "logins" && return
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
    # shellcheck disable=SC2001  # bash ${//} can't do \b word boundaries; sed is appropriate
    line_redacted=$(echo "$line" | sed 's/\b[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\b/X.X.X.X/g')
    printf "       %s\n" "$line_redacted"
  done < <(lastb -n 5 2>/dev/null | head -5)
fi

# F-312 (v3.6.1): `who` reports SESSIONS not USERS. One user with 3 ttys
# shows as 3 lines. Distinguish session count from unique-user count.
# F-325 (v3.6.1): when unique-user count exceeds the number of human users
# in /etc/passwd (typically 1 on personal desktops), the extra "user" is
# almost always a display-manager pseudo-user (gdm/sddm/lightdm). Annotate
# so users don't think a real second account is signed in.
SESSIONS_LOGGED=$(who | wc -l)
USERS_UNIQUE=$(who | awk '{print $1}' | sort -u | wc -l)
_HUMAN_USER_COUNT=$(awk -F: -v min="$_NOID_UID_MIN" -v max="$_NOID_UID_MAX" '
  $3 >= min && $3 <= max && $7 !~ /\/(nologin|false)$/ {c++} END {print c+0}
' /etc/passwd)
if [[ "$USERS_UNIQUE" -gt "$_HUMAN_USER_COUNT" ]]; then
  _emit_info "Currently logged in: $SESSIONS_LOGGED session(s) across $USERS_UNIQUE unique user(s) — extra over $_HUMAN_USER_COUNT human user(s) is likely a display-manager session (gdm/sddm/lightdm)"
else
  _emit_info "Currently logged in: $SESSIONS_LOGGED session(s) across $USERS_UNIQUE unique user(s)"
fi

# F-186: sudo usage count exposes admin-activity rhythm. On multi-user systems
# this leaks behavioral metadata when audit output is shared. Bucketize by
# magnitude rather than exact count.
SUDO_USAGE=$(journalctl _COMM=sudo --since "1 hour ago" --no-pager 2>/dev/null | grep -c "COMMAND" || true)
SUDO_USAGE=${SUDO_USAGE:-0}
if [[ "$SUDO_USAGE" -eq 0 ]]; then
  _emit_info "Sudo activity (1h): no sudo commands logged"
elif [[ "$SUDO_USAGE" -lt 10 ]]; then
  _emit_info "Sudo activity (1h): low (<10 commands — typical admin)"
elif [[ "$SUDO_USAGE" -lt 100 ]]; then
  _emit_info "Sudo activity (1h): moderate (10-99 commands — active admin/automation)"
else
  _emit_info "Sudo activity (1h): high (100+ commands — heavy automation or scripted use)"
fi

}

###############################################################################
check_hardening() {
  should_skip "hardening" && return
  header "30" "ADVANCED HARDENING"
###############################################################################

# Coredump Service Check
# F-bug: socket-active alone is not a hardening regression — modern Fedora
# enables systemd-coredump.socket by default for socket-activation. What
# matters is whether dumps actually persist (Storage= setting). Check
# storage first, then qualify socket state by storage outcome.
sub_header "Core Dump Service"
COREDUMP_STORAGE=$(_systemd_conf_val /etc/systemd/coredump.conf Storage)
_coredump_socket_active=false
systemctl is-active systemd-coredump.socket &>/dev/null && _coredump_socket_active=true

if [[ "${COREDUMP_STORAGE,,}" == "none" ]]; then
  _emit_pass "Coredump storage: none (disabled)"
  if $_coredump_socket_active; then
    _emit_info "systemd-coredump socket: active (no persistence — storage=none)"
  else
    _emit_pass "systemd-coredump socket: inactive (fully disabled)"
  fi
elif [[ -n "$COREDUMP_STORAGE" ]]; then
  _emit_warn "Coredump storage: $COREDUMP_STORAGE (should be 'none')"
  if $_coredump_socket_active; then
    _emit_warn "systemd-coredump socket: active with storage=$COREDUMP_STORAGE"
  fi
else
  _emit_info "Coredump storage: default/external (not explicitly disabled)"
  if $_coredump_socket_active; then
    _emit_info "systemd-coredump socket: active (default behavior — set Storage=none to suppress)"
  fi
fi

# USB Guard (new)
sub_header "USB Guard"
if require_cmd usbguard; then
  if systemctl is-active usbguard &>/dev/null; then
    _emit_pass "USBGuard: active"
    # F-188: filter empty trailing line (off-by-one)
    POLICY_COUNT=$(usbguard list-rules 2>/dev/null | grep -cE '^[0-9]+:')
    POLICY_COUNT=${POLICY_COUNT:-0}
    _emit_info "USBGuard rules: $POLICY_COUNT"
  else
    _emit_warn "USBGuard installed but inactive"
  fi
else
  _emit_info "USBGuard not installed — USB devices unrestricted"
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
  # F-189: Distinguish desktop / CI build host / production server.
  # Desktop with DE → normal. CI/build host signature → expected. Anything else
  # = production server where compilers are an unnecessary attack surface.
  _IS_BUILD_HOST=false
  for _bh_indicator in /var/lib/jenkins /home/buildbot /home/gitlab-runner /var/lib/buildbot \
                       /etc/buildbot /var/lib/gitlab-runner; do
    [[ -d "$_bh_indicator" ]] && _IS_BUILD_HOST=true && break
  done
  if ! $_IS_BUILD_HOST; then
    for _bh_svc in jenkins gitlab-runner buildbot-master buildbot-worker drone-server gitea-runner; do
      systemctl is-active "$_bh_svc" &>/dev/null && _IS_BUILD_HOST=true && break
    done
  fi
  if $_IS_DESKTOP; then
    _emit_info "Compilers/build tools present: $COMPILERS_FOUND(normal for development desktop)"
  elif $_IS_BUILD_HOST; then
    _emit_info "Compilers/build tools present: $COMPILERS_FOUND(expected on CI/build host)"
  else
    _emit_warn "Compilers/build tools present: $COMPILERS_FOUND(risk on production systems)"
  fi
else
  _emit_pass "No compilers/build tools found"
fi

# Prelink Check (new)
if require_cmd prelink; then
  _emit_warn "prelink is installed (can interfere with AIDE/security)"
else
  _emit_pass "prelink not installed"
fi

# AIDE/Tripwire — File Integrity Monitoring (new)
sub_header "File Integrity Monitoring"
FIM_FOUND=false
if require_cmd aide; then
  _emit_pass "AIDE installed (file integrity monitoring)"
  FIM_FOUND=true
fi
if require_cmd tripwire; then
  _emit_pass "Tripwire installed (file integrity monitoring)"
  FIM_FOUND=true
fi
if ! $FIM_FOUND; then
  _emit_warn "No file integrity monitoring (AIDE/Tripwire) installed"
fi

# Cron Permission Check (new)
sub_header "Cron/At Permissions"
if [[ -f /etc/cron.allow ]]; then
  _emit_pass "cron.allow exists (whitelist approach)"
elif [[ -f /etc/cron.deny ]]; then
  _emit_info "cron.deny exists (blacklist approach — cron.allow preferred)"
else
  _emit_warn "Neither cron.allow nor cron.deny exists"
fi

# At Permission Check (new)
if require_cmd at; then
  if [[ -f /etc/at.allow ]]; then
    _emit_pass "at.allow exists (whitelist approach)"
  elif [[ -f /etc/at.deny ]]; then
    _emit_info "at.deny exists (blacklist approach — at.allow preferred)"
  else
    _emit_warn "Neither at.allow nor at.deny exists"
  fi
fi

# IMA/EVM (Integrity Measurement Architecture / Extended Verification Module)
sub_header "Kernel Integrity (IMA/EVM)"
_IMA_ACTIVE=false
if [[ -d /sys/kernel/security/ima ]]; then
  _IMA_ACTIVE=true
  _IMA_POLICY=$(cat /sys/kernel/security/ima/policy_name 2>/dev/null || echo "custom")
  _emit_pass "IMA: active (policy: $_IMA_POLICY)"
  _IMA_VIOLATIONS=$(cat /sys/kernel/security/ima/violations 2>/dev/null || echo "0")
  if [[ "${_IMA_VIOLATIONS:-0}" -gt 0 ]]; then
    _emit_warn "IMA violations: $_IMA_VIOLATIONS"
  else
    _emit_pass "IMA violations: 0"
  fi
  # v3.7: actively-measuring signal (count > 0 means policy is hitting files)
  _IMA_COUNT_FILE=/sys/kernel/security/integrity/ima/runtime_measurements_count
  if [[ -r "$_IMA_COUNT_FILE" ]]; then
    _IMA_COUNT=$(< "$_IMA_COUNT_FILE")
    if [[ "${_IMA_COUNT:-0}" -gt 100 ]]; then
      _emit_pass "IMA: $_IMA_COUNT runtime measurements (actively measuring)"
    elif [[ "${_IMA_COUNT:-0}" -gt 0 ]]; then
      _emit_info "IMA: only $_IMA_COUNT measurements (policy may be too narrow)"
    else
      _emit_warn "IMA: 0 runtime measurements (active but not measuring — check policy)"
    fi
  fi
else
  if grep -q "ima" /proc/cmdline 2>/dev/null; then
    _emit_info "IMA: configured in cmdline but /sys/kernel/security/ima not found"
  else
    _emit_info "IMA: not active (consider adding ima_policy=appraise_tcb to kernel cmdline)"
  fi
fi
# EVM
if [[ -f /sys/kernel/security/evm ]]; then
  _EVM_STATUS=$(cat /sys/kernel/security/evm 2>/dev/null)
  if [[ "$_EVM_STATUS" -ge 1 ]]; then
    _emit_pass "EVM: active (status=$_EVM_STATUS)"
  else
    _emit_info "EVM: present but not initialized (status=$_EVM_STATUS)"
  fi
else
  _emit_info "EVM: not available"
fi

# binfmt_misc (non-native binary execution)
sub_header "Binary Format Registration"
if [[ -d /proc/sys/fs/binfmt_misc ]]; then
  _BINFMT_COUNT=0
  for _bf_entry in /proc/sys/fs/binfmt_misc/*; do
    [[ -e "$_bf_entry" ]] || continue
    case "$(basename "$_bf_entry")" in register|status) continue ;; esac
    _BINFMT_COUNT=$((_BINFMT_COUNT + 1))
  done
  _BINFMT_COUNT=${_BINFMT_COUNT:-0}
  if [[ "$_BINFMT_COUNT" -eq 0 ]]; then
    _emit_pass "binfmt_misc: no non-native binary formats registered"
  else
    _emit_info "binfmt_misc: $_BINFMT_COUNT registered format(s)"
    if ! $JSON_MODE; then
      for _bf in /proc/sys/fs/binfmt_misc/*; do
        [[ "$(basename "$_bf")" =~ ^(register|status)$ ]] && continue
        [[ -f "$_bf" ]] || continue
        printf "       %s\n" "$(basename "$_bf")"
      done
    fi
  fi
else
  _emit_pass "binfmt_misc: not mounted"
fi

# FireWire (IEEE 1394) DMA attack surface
sub_header "FireWire / IEEE 1394"
if lsmod 2>/dev/null | grep -qE "^firewire_core|^ohci1394|^sbp2"; then
  _emit_fail "FireWire module loaded — DMA attack risk"
elif grep -rqsE "install\s+(firewire[-_]core|ohci1394|sbp2)\s+/(usr/)?s?bin/(false|true)|blacklist\s+(firewire[-_]core|ohci1394|sbp2)" /etc/modprobe.d/ 2>/dev/null; then
  _emit_pass "FireWire modules: blacklisted"
else
  _emit_pass "FireWire modules: not loaded"
fi

# Home directory permissions
sub_header "Home Directory Security"
while IFS=: read -r _huser _ _huid _ _ _hhome _; do
  _is_human_uid "$_huid" || continue
  [[ -d "$_hhome" ]] || continue
  _HPERMS=$(stat -c %a "$_hhome" 2>/dev/null)
  [[ -z "$_HPERMS" ]] && continue
  # Severity tiering: 0xx (no o/g) = pass, 0x5 (group-only) = pass, 755 (Linux
  # default, group+other read) = INFO with note, anything writable = warn.
  # 755 is the install default on Fedora/Ubuntu — flagging it as WARN creates
  # systematic alarm fatigue (F-196).
  if (( (8#${_HPERMS} & 8#022) != 0 )); then
    _emit_warn "Home directory $_hhome: $_HPERMS (group/other writable — fix with chmod 750)"
  elif (( (8#${_HPERMS} & 8#005) != 0 )); then
    _emit_info "Home directory $_hhome: $_HPERMS (Linux default — chmod 750 for stricter privacy)"
  else
    _emit_pass "Home directory $_hhome: $_HPERMS (private)"
  fi
  # Check ownership
  _HOWNER=$(stat -c %U "$_hhome" 2>/dev/null)
  if [[ "$_HOWNER" != "$_huser" ]]; then
    _emit_fail "Home directory $_hhome owned by $_HOWNER (should be $_huser)"
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
        _emit_pass "Shell TMOUT=${_TMOUT_VAL}s (in $(basename "$_tmout_file"))"
      else
        _emit_warn "Shell TMOUT=${_TMOUT_VAL}s (recommended: ≤900s)"
      fi
      break
    fi
  fi
done
if ! $_TMOUT_SET; then
  _emit_info "Shell TMOUT not set (idle sessions never timeout)"
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
      _emit_pass "AIDE database: $_AIDE_DB ($(_human_size "$_AIDE_DB_SIZE"))"
    else
      _emit_warn "AIDE database exists but is empty: $_AIDE_DB"
    fi
  else
    _emit_warn "AIDE installed but no database found (run: sudo aide --init)"
  fi
fi

# v3.7: AIDE actual integrity-check status (not just existence)
# Reads last scheduled run from journal + offers opt-in fresh check via
# NOID_AIDE_LIVE=1. Without this, "AIDE installed" was a placebo signal.
sub_header "AIDE Integrity Status"
if require_cmd aide; then
  # F-337 (v3.6.1): switch from 7-day journal-grep to authoritative systemctl
  # show ExecMainStatus (AIDE's actual exit code from the LAST run). Previous
  # logic used `journalctl -u <unit> --since '7 days ago' -n 10` and grepped
  # for drift markers — but old drift-detected entries from prior runs would
  # match the regex even after a fresh clean run, leaving the WARN sticky
  # for 7 days. systemctl show only exposes the LAST run's exit code, so a
  # clean re-run flips PASS/WARN immediately.
  # AIDE exit-code semantics: 0=clean, bitmask 1=added | 2=removed | 4=changed
  # (exit 7 = all three categories), 14=warning, etc. Any non-zero = drift.
  _AIDE_LAST_STATUS=""
  _AIDE_LAST_TIME=""
  # F-337: iterate units and probe ExecMainStartTimestamp directly. Don't use
  # `systemctl cat` as guard — it requires the unit to be currently loaded
  # (LoadState=loaded), which fails silently for on-demand timer-spawned
  # services like aide-check.service. systemctl show returns the cached
  # last-run state regardless of current load state.
  for _aide_unit in aide-check.service aide.service aidecheck.service; do
    _candidate_time=$(systemctl show "$_aide_unit" -p ExecMainStartTimestamp --value 2>/dev/null)
    if [[ -n "$_candidate_time" && "$_candidate_time" != "n/a" && "$_candidate_time" != "0" ]]; then
      _AIDE_LAST_TIME="$_candidate_time"
      _AIDE_LAST_STATUS=$(systemctl show "$_aide_unit" -p ExecMainStatus --value 2>/dev/null)
      break
    fi
  done
  if [[ -n "$_AIDE_LAST_TIME" && "$_AIDE_LAST_TIME" != "n/a" && "$_AIDE_LAST_TIME" != "0" ]]; then
    if [[ "$_AIDE_LAST_STATUS" == "0" ]]; then
      _emit_pass "AIDE: last scheduled check clean (no changes)"
    elif [[ -n "$_AIDE_LAST_STATUS" && "$_AIDE_LAST_STATUS" != "0" ]]; then
      _emit_warn "AIDE: last scheduled check found changes (AIDE exit=$_AIDE_LAST_STATUS) — review journalctl -u aide-check"
      # F-339 (v3.6.1): show top drift paths inline so user can immediately see
      # if drift is benign (transient lockfiles, intentional config changes) or
      # genuine integrity concern. Avoids forcing manual `journalctl -u aide-check`
      # for every WARN. AIDE diff symbols: f+++=added, f---=removed, f...i...=changed.
      if ! $JSON_MODE; then
        while IFS= read -r _drift_line; do
          [[ -z "$_drift_line" ]] && continue
          _drift_marker="${_drift_line%%:*}"
          _drift_path="${_drift_line##*: }"
          case "$_drift_marker" in
            *"+++"*) _drift_label="Added  " ;;
            *"---"*) _drift_label="Removed" ;;
            *)       _drift_label="Changed" ;;
          esac
          printf "       %s: %s\n" "$_drift_label" "$_drift_path"
        done < <(journalctl -u "$_aide_unit" --since "$_AIDE_LAST_TIME" --no-pager 2>/dev/null \
          | grep -oP 'aide\[\d+\]: \K[fd][+\-. ]{15,}: /\S+' \
          | head -5)
      fi
    else
      _emit_info "AIDE: last scheduled check ran (status unclear — review journal)"
    fi
  else
    _emit_info "AIDE: no scheduled check yet — schedule via systemd timer"
  fi

  # 2. Optional fresh check via NOID_AIDE_LIVE=1 (slow: can take minutes)
  if [[ "${NOID_AIDE_LIVE:-0}" == "1" ]]; then
    $JSON_MODE || printf "  ${CYN}Running aide --check (max 5min)...${RST}\n"
    _AIDE_OUT=$(mktemp -t noid-aide-XXXXXX.log)
    timeout 300 aide --check &>"$_AIDE_OUT"
    _AIDE_RC=$?
    # AIDE exit codes are a bitmask:
    #   0 = no differences
    #   1 = new files
    #   2 = removed files
    #   4 = changed files
    #   7 = combination of the above
    #   14+ = errors during scan
    if [[ "$_AIDE_RC" -eq 0 ]]; then
      _emit_pass "AIDE on-demand check: 0 changes detected"
      # Clean up — log only contains the "0 differences" header on success.
      rm -f "$_AIDE_OUT"
    elif [[ "$_AIDE_RC" -ge 14 ]]; then
      _emit_warn "AIDE on-demand check: scan errors (rc=$_AIDE_RC) — see $_AIDE_OUT"
    else
      # Keep log on drift detection — user needs the per-file detail to act.
      _bits=""
      [[ $((_AIDE_RC & 1)) -ne 0 ]] && _bits+="new "
      [[ $((_AIDE_RC & 2)) -ne 0 ]] && _bits+="removed "
      [[ $((_AIDE_RC & 4)) -ne 0 ]] && _bits+="changed "
      _emit_warn "AIDE on-demand check: ${_bits}files (rc=$_AIDE_RC) — see $_AIDE_OUT"
    fi
  else
    _emit_info "AIDE fresh check: skipped (set NOID_AIDE_LIVE=1 to run on-demand)"
  fi
fi

# Suspicious shell history entries
sub_header "Shell History Analysis"
_SUSPICIOUS_HIST=0
while IFS=: read -r _huser _ _huid _ _ _hhome _; do
  _is_human_uid "$_huid" || continue
  for _histf in "$_hhome/.bash_history" "$_hhome/.zsh_history"; do
    [[ -f "$_histf" ]] || continue
    _SH_PATTERN="curl.*\|.*bash|wget.*\|.*sh|curl.*-o.*/tmp|wget.*/tmp|chmod\s+\+x.*/tmp|/dev/tcp|nc\s+-e|ncat\s+-e"
    _SH_SUSP=$(grep -ciE "$_SH_PATTERN" "$_histf" 2>/dev/null || true)
    _SH_SUSP=${_SH_SUSP:-0}
    if [[ "$_SH_SUSP" -gt 0 ]]; then
      _emit_warn "$_SH_SUSP suspicious entries in $_histf (curl|bash, wget, /dev/tcp patterns)"
      # F-200: show first 3 examples (truncated) so user can audit instead of guess
      if ! $JSON_MODE; then
        grep -nE "$_SH_PATTERN" "$_histf" 2>/dev/null | head -3 | while read -r line; do
          printf "       %s\n" "${line:0:90}"
        done
      fi
      _SUSPICIOUS_HIST=$((_SUSPICIOUS_HIST + _SH_SUSP))
    fi
  done
done < /etc/passwd
if [[ "$_SUSPICIOUS_HIST" -eq 0 ]]; then
  _emit_pass "No suspicious shell history entries found"
fi

}

###############################################################################
check_modules() {
  should_skip "modules" && return
  header "31" "KERNEL MODULES & INTEGRITY"
###############################################################################

# Suspicious kernel modules (basic heuristic — real rootkits use innocuous names)
sub_header "Suspicious Module Check"
# F-201: Same anti-pattern as F-136 — real rootkits don't advertise themselves
# with obvious names. AIDE/IMA file-integrity checks are the reliable signal.
SUSPICIOUS_MODS=$(lsmod 2>/dev/null | awk '{print $1}' | grep -iE "backdoor|rootkit|hide|keylog|sniff|inject" || true)
if [[ -z "$SUSPICIOUS_MODS" ]]; then
  _emit_pass "No obvious-named suspicious modules (real rootkits hide — rely on IMA/AIDE for integrity)"
else
  _emit_fail "Suspicious kernel modules: $SUSPICIOUS_MODS"
fi

# Unnecessary filesystem modules (new)
sub_header "Disabled Filesystem Modules"
for FS_MOD in cramfs freevxfs jffs2 hfs hfsplus squashfs udf affs befs sysv qnx4 qnx6; do
  if grep -rqsE "install\s+$FS_MOD\s+/(usr/)?s?bin/(false|true)|blacklist\s+$FS_MOD" /etc/modprobe.d/ 2>/dev/null; then
    _emit_pass "Module $FS_MOD: disabled"
  elif [[ "$FS_MOD" == "squashfs" ]] && command -v flatpak &>/dev/null; then
    if lsmod 2>/dev/null | grep -q "^squashfs\s"; then
      _emit_info "Module squashfs: loaded (required by Flatpak)"
    else
      _emit_info "Module squashfs: not disabled but not loaded (Flatpak installed)"
    fi
  else
    if lsmod 2>/dev/null | grep -q "^${FS_MOD}\s"; then
      _emit_warn "Module $FS_MOD: loaded (should be disabled)"
    else
      _emit_info "Module $FS_MOD: not explicitly disabled (not loaded)"
    fi
  fi
done

# USB storage module — F-203b: USBGuard is an alternative defense-in-depth
# layer that policy-controls USB devices at runtime. When USBGuard is active,
# blacklisting usb-storage is redundant rather than mandatory; downgrade WARN
# to INFO to avoid alarm fatigue on users who chose USBGuard instead.
if grep -rqsE "install\s+usb[-_]storage\s+/(usr/)?s?bin/(false|true)|blacklist\s+usb[-_]storage" /etc/modprobe.d/ 2>/dev/null; then
  _emit_pass "USB storage module: disabled"
elif systemctl is-active usbguard &>/dev/null; then
  _emit_info "USB storage module: not blacklisted (USBGuard active — runtime policy enforced)"
else
  _emit_warn "USB storage module: not disabled"
fi

# Module loading status
if [[ -f /proc/sys/kernel/modules_disabled ]]; then
  MOD_DISABLED=$(< /proc/sys/kernel/modules_disabled)
  if [[ "$MOD_DISABLED" -eq 1 ]]; then
    _emit_pass "Kernel module loading: disabled (locked down)"
  else
    _emit_info "Kernel module loading: enabled (modules_disabled=0)"
  fi
fi

}

###############################################################################
check_permissions() {
  should_skip "permissions" && return
  header "32" "PERMISSIONS & ACCESS CONTROL"
###############################################################################

# Cron permissions
for CRONDIR in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  if [[ -e "$CRONDIR" ]]; then
    OWNER=$(stat -c '%U' "$CRONDIR" 2>/dev/null)
    PERMS=$(stat -c '%a' "$CRONDIR" 2>/dev/null)
    if [[ "$OWNER" != "root" ]]; then
      _emit_fail "$CRONDIR owner: $OWNER (should be root)"
    elif [[ -d "$CRONDIR" ]]; then
      if (( (8#${PERMS:-777} & ~8#755) == 0 )); then
        _emit_pass "$CRONDIR: owner=$OWNER, perms=$PERMS"
      else
        _emit_warn "$CRONDIR permissions: $PERMS (too open for directory)"
      fi
    elif [[ -f "$CRONDIR" ]]; then
      # Allow read for group/other (644), warn on write/execute for group/other
      if (( (8#${PERMS:-777} & 8#033) != 0 )); then
        _emit_warn "$CRONDIR permissions: $PERMS (write/execute for group/other)"
      elif (( (8#${PERMS:-777} & ~8#644) != 0 )); then
        _emit_warn "$CRONDIR permissions: $PERMS (expected: <=644)"
      else
        _emit_pass "$CRONDIR: owner=$OWNER, perms=$PERMS"
      fi
    fi
  fi
done

# /etc/securetty
if [[ -f /etc/securetty ]]; then
  # F-bash-grep-c-trap: `|| echo 0` produces "0\n0" multi-line when grep -c
  # legitimately returns 0 (file exists, zero matches). Use ${var:-0} default.
  TTY_COUNT=$(grep -cvE '^#|^$' /etc/securetty 2>/dev/null)
  TTY_COUNT="${TTY_COUNT:-0}"
  _emit_info "securetty: $TTY_COUNT TTYs allowed"
fi

# /etc/security/limits.conf + drop-ins — core dump limits (F-206: scan
# /etc/security/limits.d/*.conf as well, modern systems put hardening rules
# in drop-ins instead of editing the main file)
if grep -qrhE "^\s*\*\s+hard\s+core\s+0" /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null; then
  _emit_pass "limits.conf: hard core 0 (core dumps disabled)"
else
  _emit_warn "limits.conf: core dumps not disabled via limits"
fi

}

###############################################################################
check_boot() {
  should_skip "boot" && return
  header "33" "BOOT SECURITY & INTEGRITY"
###############################################################################

# UEFI vs BIOS
if [[ -d /sys/firmware/efi ]]; then
  _emit_pass "Boot mode: UEFI"
else
  _emit_info "Boot mode: Legacy BIOS"
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
    _SIG_REASON="runtime — likely Secure Boot"
  elif grep -qw "module.sig_enforce=1" /proc/cmdline 2>/dev/null; then
    _SIG_ENFORCED=true
    _SIG_REASON="runtime — kernel cmdline"
  fi
  if $_SIG_ENFORCED; then
    _emit_pass "Kernel module signing: enforced ($_SIG_REASON)"
  else
    _emit_info "Kernel module signing: not enforced"
  fi
fi

# Check for multiple kernels — SC2012-clean: shell glob count
shopt -s nullglob
_boot_kernels=(/boot/vmlinuz-*)
shopt -u nullglob
KERNEL_COUNT="${#_boot_kernels[@]}"
_emit_info "Installed kernels: $KERNEL_COUNT"

# Boot Security Analysis — rescue/emergency shell sulogin check.
# F-285 (v3.6.1): emit a positive PASS when no risky rescue shells are found,
# so the sub-header always has at least one finding underneath. Previously
# the for-loop was silent on hardened systems (sulogin protected) → empty
# sub-header in the report. Sub-header is now also conditional on systemd
# being present.
if require_cmd systemd-analyze; then
  sub_header "Boot Security Analysis"
  _rescue_risk=0
  for _rescue_unit in rescue.service emergency.service; do
    _rescue_exec=$(systemctl show -p ExecStart "$_rescue_unit" 2>/dev/null | grep -oP 'path=\K[^;]+' || true)
    if [[ -n "$_rescue_exec" && "$_rescue_exec" != *sulogin* ]]; then
      _emit_info "${_rescue_unit%.service} shell: no password required (physical access risk)"
      _rescue_risk=$((_rescue_risk + 1))
    fi
  done
  [[ "$_rescue_risk" -eq 0 ]] && _emit_pass "Rescue/emergency shells: password-protected (sulogin)"
fi

}

###############################################################################
check_integrity() {
  should_skip "integrity" && return
  header "34" "SYSTEM INTEGRITY CHECKS"
###############################################################################

# File Integrity — key system binaries
sub_header "Critical Binary Integrity"
if require_cmd rpm; then
  $JSON_MODE || printf "  ${CYN}Running rpm -Va (full package verify, max 90s)...${RST}\n"
  # Timeout prevents 5+ minute hangs on large package sets (F-211)
  RPM_VA_OUTPUT=$(timeout 90 rpm -Va 2>/dev/null || echo "TIMEOUT")
  if [[ "$RPM_VA_OUTPUT" == "TIMEOUT" ]]; then
    _emit_warn "RPM verify: timed out after 90s (large package set or DB locked)"
  else
    RPM_VERIFY_ALL=$(echo "$RPM_VA_OUTPUT" | grep -cE "^..5" || true)
    RPM_VERIFY_ALL=${RPM_VERIFY_ALL:-0}
    # F-281 (v3.6.1): exclude OS-image branding/identity overrides — these are
    # legitimately modified by hardened-distro builds (NoID, Qubes, secureblue,
    # Kicksecure, Tails) for branding/cosmetic reasons, not malicious tampering.
    # Files: /usr/lib/os-release (distro identity), /usr/lib/issue & issue.net
    # (login banner), /usr/share/anaconda/pixmaps/* (installer artwork),
    # /usr/share/icons/*/apps/anaconda.png (installer icon),
    # /usr/share/pixmaps/{fedora,system}-logo*.png (desktop branding).
    # F-315 (v3.6.1): also exclude GNOME Online Accounts D-Bus service files —
    # /usr/share/dbus-1/services/org.gnome.{Identity,OnlineAccounts}.service
    # are routinely overridden by privacy-hardening playbooks (NoID hard-block,
    # GrapheneOS-style desktop) to prevent dormant GOA D-Bus activation. The
    # files are NOT executable code — they're activation manifests with Exec=
    # pointing to /bin/false or similar. Same exclusion-class as os-release.
    # F-345 (v3.6.2): extended exclusion-list for NoID Privacy Workstation
    # legitimately-modified RPM-owned files. Each one originates in a kickstart
    # snippet (M16 Anaconda branding, M17 GNOME hardening, M32 Plymouth+desktop
    # branding, M99 Anaconda transaction-progress patch). All are identifier /
    # branding / privacy-disable manifests, NOT executable code. Equivalent
    # exclusion-class as os-release / fedora-logo (F-281 / F-315).
    RPM_VERIFY_BIN=$(echo "$RPM_VA_OUTPUT" | grep -E "^..5" | grep -v " c " \
      | grep -cvE "\.pyc\b|/__pycache__/|/usr/lib/(issue|os-release)|/etc/system-release|/usr/share/(anaconda/pixmaps|icons/.*/apps/anaconda\.png|pixmaps/(fedora|system)-logo)|/usr/share/dbus-1/services/org\.gnome\.(Identity|OnlineAccounts)\.service|/usr/share/anaconda/(gnome/(fedora-welcome|org\.fedoraproject\.welcome-screen\.desktop)|interactive-defaults\.ks)|/usr/share/applications/(liveinst|org\.mozilla\.firefox)\.desktop|/usr/share/gnome-initial-setup/vendor\.conf|/usr/share/dbus-1/services/.*(Tracker3.*|portal\.Tracker)\.service|/etc/xdg/autostart/(geoclue-demo-agent|org\.gnome\.Evolution-alarm-notify)\.desktop|/usr/share/gvfs/mounts/(dns-sd|wsdd)\.mount|/usr/share/plymouth/themes/bgrt/bgrt\.plymouth|/usr/lib64/firefox/distribution/distribution\.ini|/usr/lib64/python.*/site-packages/pyanaconda/modules/payloads/payload/dnf/transaction_progress\.py" || true)
    RPM_VERIFY_BIN=${RPM_VERIFY_BIN:-0}
    if [[ "$RPM_VERIFY_ALL" -eq 0 ]]; then
      _emit_pass "RPM verify: all package files intact"
    elif [[ "$RPM_VERIFY_BIN" -eq 0 ]]; then
      _emit_pass "RPM verify: $RPM_VERIFY_ALL config files changed (no binaries — normal after hardening)"
    elif [[ "$RPM_VERIFY_BIN" -le 5 ]]; then
      _emit_warn "RPM verify: $RPM_VERIFY_BIN binaries + $((RPM_VERIFY_ALL - RPM_VERIFY_BIN)) configs changed"
    else
      _emit_fail "RPM verify: $RPM_VERIFY_BIN binaries with changed checksums!"
    fi

    # v3.7: RPM drift-detection via baseline diff
    # First run: NOID_RPM_BASELINE_INIT=1 captures current state
    # Subsequent runs: diff against baseline, alert on NEW modifications
    # Catches XZ-Backdoor-class changes (modified binary, valid signature,
    # drift between runs). Snapshot count alone misses this.
    _RPM_BASELINE=/var/lib/noid-privacy/rpm-baseline.txt
    _RPM_MODIFIED_NOW=$(echo "$RPM_VA_OUTPUT" | awk '/^..5/ {print $NF}' | sort -u)
    if [[ -f "$_RPM_BASELINE" ]]; then
      _RPM_NEW=$(comm -13 <(sort -u "$_RPM_BASELINE") <(echo "$_RPM_MODIFIED_NOW") | grep -v '^$')
      if [[ -z "$_RPM_NEW" ]]; then
        _emit_pass "RPM drift: no new modifications since baseline"
      else
        _RPM_NEW_COUNT=$(echo "$_RPM_NEW" | wc -l)
        _emit_warn "RPM drift: $_RPM_NEW_COUNT new modification(s) since baseline"
        if ! $JSON_MODE && [[ "$_RPM_NEW_COUNT" -le 10 ]]; then
          echo "$_RPM_NEW" | while read -r _line; do
            printf "       %s\n" "$_line"
          done
        fi
      fi
    else
      _emit_info "RPM baseline: not initialized (run with NOID_RPM_BASELINE_INIT=1)"
    fi
    # Optional: capture/update baseline
    if [[ "${NOID_RPM_BASELINE_INIT:-0}" == "1" ]] || [[ "${NOID_RPM_BASELINE_UPDATE:-0}" == "1" ]]; then
      install -d -m 755 /var/lib/noid-privacy 2>/dev/null
      echo "$_RPM_MODIFIED_NOW" > "$_RPM_BASELINE" 2>/dev/null
      chmod 644 "$_RPM_BASELINE" 2>/dev/null
      _RPM_BASELINE_COUNT=$(echo "$_RPM_MODIFIED_NOW" | wc -l)
      _emit_info "RPM baseline: captured $_RPM_BASELINE_COUNT modified files to $_RPM_BASELINE"
    fi
  fi
elif require_cmd debsums; then
  # F-212: tier debsums output similar to RPM verify — config changes are
  # routine after hardening, only binary changes warrant escalation.
  DEB_OUTPUT=$(timeout 90 debsums -c 2>/dev/null || echo "TIMEOUT")
  if [[ "$DEB_OUTPUT" == "TIMEOUT" ]]; then
    _emit_warn "debsums: timed out after 90s"
  else
    DEB_VERIFY_TOTAL=$(echo "$DEB_OUTPUT" | grep -c '\S' || echo 0)
    DEB_VERIFY_TOTAL=${DEB_VERIFY_TOTAL:-0}
    DEB_VERIFY_BIN=$(echo "$DEB_OUTPUT" | grep -cE '/(s?bin|libexec)/' || echo 0)
    DEB_VERIFY_BIN=${DEB_VERIFY_BIN:-0}
    if [[ "$DEB_VERIFY_TOTAL" -eq 0 ]]; then
      _emit_pass "debsums: all package files intact"
    elif [[ "$DEB_VERIFY_BIN" -eq 0 ]]; then
      _emit_pass "debsums: $DEB_VERIFY_TOTAL config files changed (no binaries — normal after hardening)"
    elif [[ "$DEB_VERIFY_BIN" -le 5 ]]; then
      _emit_warn "debsums: $DEB_VERIFY_BIN binaries + $((DEB_VERIFY_TOTAL - DEB_VERIFY_BIN)) configs changed"
    else
      _emit_fail "debsums: $DEB_VERIFY_BIN binaries with changed checksums!"
    fi
  fi
elif [[ "$DISTRO_FAMILY" == "debian" ]]; then
  _emit_info "Package integrity: install 'debsums' for Debian file verification (apt install debsums)"
elif require_cmd pacman; then
  # Arch: verify installed package files
  PAC_VERIFY=$(pacman -Qkk 2>/dev/null | grep -c "MODIFIED" || true)
  PAC_VERIFY=${PAC_VERIFY:-0}
  if [[ "$PAC_VERIFY" -eq 0 ]]; then
    _emit_pass "Pacman verify: all package files intact"
  elif [[ "$PAC_VERIFY" -le 10 ]]; then
    _emit_warn "Pacman verify: $PAC_VERIFY modified files"
  else
    _emit_fail "Pacman verify: $PAC_VERIFY modified files!"
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
    _emit_fail "PATH contains empty entry (equivalent to '.' — privilege escalation risk)"
    PATH_ISSUES=$((PATH_ISSUES + 1))
    continue
  fi
  if [[ "$DIR" == "." ]]; then
    _emit_fail "PATH contains '.' (current directory — privilege escalation risk)"
    PATH_ISSUES=$((PATH_ISSUES + 1))
    continue
  fi
  if [[ "$DIR" != /* ]]; then
    _emit_fail "PATH contains relative entry: $DIR (privilege escalation risk)"
    PATH_ISSUES=$((PATH_ISSUES + 1))
    continue
  fi
  # Skip symlinks (e.g. /sbin -> /usr/sbin on Fedora)
  [[ -L "$DIR" ]] && continue
  if [[ -d "$DIR" ]] && [[ "$(stat -c %a "$DIR" 2>/dev/null)" =~ [2367]$ ]]; then
    _emit_warn "World-writable directory in PATH: $DIR"
    PATH_ISSUES=$((PATH_ISSUES + 1))
  fi
done
if [[ "$PATH_ISSUES" -eq 0 ]]; then
  _emit_pass "PATH security: no world-writable, '.', or relative entries"
fi

# Duplicate lines in /etc/hosts
sub_header "/etc/hosts Integrity"
if [[ -f /etc/hosts ]]; then
  _HOSTS_DUPS=$(grep -vE '^#|^$' /etc/hosts 2>/dev/null | sort | uniq -d | wc -l)
  _HOSTS_DUPS=${_HOSTS_DUPS:-0}
  if [[ "$_HOSTS_DUPS" -eq 0 ]]; then
    _emit_pass "/etc/hosts: no duplicate entries"
  else
    _emit_warn "/etc/hosts: $_HOSTS_DUPS duplicate entries"
  fi
  # Verify localhost entry
  if grep -qE "^127\.0\.0\.1\s+localhost" /etc/hosts 2>/dev/null; then
    _emit_pass "/etc/hosts: localhost entry present"
  else
    _emit_warn "/etc/hosts: missing 127.0.0.1 localhost entry"
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
      _emit_pass "AIDE checksum: $_AIDE_HASH (strong)"
    elif grep -qE "md5" "$_AIDE_CONF" 2>/dev/null; then
      _emit_fail "AIDE checksum: MD5 (weak — switch to sha512)"
    else
      _emit_info "AIDE checksum algorithm: could not determine from $_AIDE_CONF"
    fi
  fi
fi

# Available valid shells
sub_header "Valid Shells"
if [[ -f /etc/shells ]]; then
  _SHELL_COUNT=$(grep -cvE "^#|^$" /etc/shells 2>/dev/null || true)
  _emit_info "Valid shells in /etc/shells: ${_SHELL_COUNT:-0}"
  # Check for insecure shells
  # F-217: legacy-shell list includes csh/tcsh and bare dash.
  # F-311 (v3.6.1): /bin/sh removed from list — it's the universal POSIX
  # symlink (sh→bash on RHEL/Fedora/Ubuntu, sh→dash on Debian). Required
  # by countless scripts via #!/bin/sh shebang, not "legacy" in any sense.
  for _ishell in /bin/csh /bin/tcsh /bin/dash; do
    if grep -q "^${_ishell}$" /etc/shells 2>/dev/null; then
      _emit_info "Legacy shell available: $_ishell"
    fi
  done
fi

}

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
        _emit_fail "Firefox telemetry explicitly enabled [$label]"
      elif [[ "$val" == "false" ]]; then
        _emit_pass "Firefox telemetry disabled [$label]"
      else
        _emit_info "Firefox telemetry not explicitly set (default: disabled on most distros) [$label]"
      fi

      val="$(_ff_pref "$pf" "datareporting.healthreport.uploadEnabled")"
      if [[ "$val" == "false" ]]; then
        _emit_pass "Firefox health report disabled [$label]"
      elif [[ "$val" == "true" ]]; then
        _emit_fail "Firefox health report upload enabled [$label]"
      else
        _emit_warn "Firefox health report not explicitly disabled [$label]"
      fi

      val="$(_ff_pref "$pf" "media.peerconnection.enabled")"
      if [[ "$val" == "false" ]]; then
        _emit_pass "WebRTC disabled — no IP leak [$label]"
      else
        _emit_warn "WebRTC enabled — may leak real IP behind VPN [$label]"
      fi

      val="$(_ff_pref "$pf" "network.trr.mode")"
      if [[ "$val" == "2" ]]; then
        _emit_pass "DNS-over-HTTPS enabled (mode 2 — DoH first, fallback to native DNS) [$label]"
      elif [[ "$val" == "3" ]]; then
        _emit_pass "DNS-over-HTTPS strict (mode 3 — DoH only, no fallback) [$label]"
      elif [[ -z "$val" || "$val" == "0" ]]; then
        _emit_warn "DNS-over-HTTPS not configured [$label]"
      else
        _emit_info "DNS-over-HTTPS mode $val [$label]"
      fi

      val="$(_ff_pref "$pf" "browser.contentblocking.category")"
      if [[ "$val" == "strict" ]]; then
        _emit_pass "Tracking protection set to strict [$label]"
      elif [[ "$val" == "custom" ]]; then
        _emit_info "Tracking protection custom [$label]"
      else
        _emit_warn "Tracking protection not strict (${val:-standard}) [$label]"
      fi

      val="$(_ff_pref "$pf" "network.cookie.cookieBehavior")"
      if [[ "$val" == "5" ]]; then
        _emit_pass "Third-party cookies blocked (Total Cookie Protection) [$label]"
      elif [[ "$val" == "4" ]]; then
        _emit_pass "Third-party cookies blocked [$label]"
      elif [[ "$val" == "1" ]]; then
        _emit_info "Third-party cookies blocked (legacy) [$label]"
      elif [[ -z "$val" ]]; then
        _emit_info "Cookie behavior not set (default: Total Cookie Protection with ETP) [$label]"
      else
        _emit_warn "Third-party cookies allowed (behavior=${val}) [$label]"
      fi

      local ext_json="$profile_dir/extensions.json"
      if [[ -f "$ext_json" ]]; then
        # F-221: check uBlock state. extensions.json is single-line JSON with
        # nested objects (sourceURI, dependencies, etc) — PCRE [^{}]* doesn't
        # cross nesting cleanly. Use jq when available for reliable parsing;
        # fall back to existence-only when jq missing.
        local _ublock_status=""
        if command -v jq &>/dev/null; then
          _ublock_status=$(jq -r '.addons[] | select(.id=="uBlock0@raymondhill.net") | "\(.active)|\(.userDisabled)"' "$ext_json" 2>/dev/null | head -1)
        fi
        if [[ -n "$_ublock_status" ]]; then
          # parse "active|userDisabled"
          local _ub_active="${_ublock_status%|*}"
          local _ub_userdis="${_ublock_status#*|}"
          if [[ "$_ub_active" == "true" && "$_ub_userdis" == "false" ]]; then
            _emit_pass "uBlock Origin installed and enabled [$label]"
          else
            _emit_warn "uBlock Origin installed but DISABLED (active=$_ub_active userDisabled=$_ub_userdis) [$label]"
          fi
        elif grep -q "uBlock0@raymondhill.net" "$ext_json" 2>/dev/null; then
          # Without jq, just confirm presence (assume active if listed)
          _emit_pass "uBlock Origin installed [$label]"
        elif grep -qE "uBOLite@raymondhill.net|@ublock-origin-lite" "$ext_json" 2>/dev/null; then
          _emit_pass "uBlock Origin Lite installed [$label]"
        else
          _emit_warn "uBlock Origin not found [$label]"
        fi
      else
        _emit_info "No extensions data found [$label]"
      fi

      val="$(_ff_pref "$pf" "app.shield.optoutstudies.enabled")"
      if [[ "$val" == "false" ]]; then
        _emit_pass "Shield Studies disabled [$label]"
      elif [[ "$val" == "true" ]]; then
        _emit_warn "Shield Studies enabled [$label]"
      else
        _emit_info "Shield Studies not explicitly configured [$label]"
      fi

      # F-222: differentiate "no password saving" (good), "saving with master
      # password" (acceptable — Firefox's own manager IS a password manager
      # if encrypted), and "saving without master password" (warn — bad).
      val="$(_ff_pref "$pf" "signon.rememberSignons")"
      if [[ "$val" == "false" ]]; then
        _emit_pass "Browser password saving disabled [$label]"
      else
        # Check for Firefox primary password (formerly "master password")
        local _has_pp=false
        if [[ -f "$profile_dir/key4.db" ]] || [[ -f "$profile_dir/key3.db" ]]; then
          # Heuristic: if logins exist and key4/key3 has metadata, primary password may be set.
          # Firefox 75+ uses key4.db; older used key3.db. We can't decrypt but we can check
          # security.default_personal_token_name — set when primary password configured.
          local _pp_token
          _pp_token="$(_ff_pref "$pf" "security.default_personal_token_name")"
          [[ -n "$_pp_token" && "$_pp_token" != "NSS Internal PKCS #11 Module" ]] && _has_pp=true
        fi
        if $_has_pp; then
          _emit_info "Browser password saving enabled with primary password [$label]"
        elif [[ -z "$val" ]]; then
          _emit_info "Browser password saving not explicitly disabled (default: enabled) [$label]"
        else
          _emit_warn "Browser password saving enabled WITHOUT primary password [$label] — set one in Settings → Privacy"
        fi
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
      _emit_warn "$chrome_bin installed — vendor telemetry/tracking risk"
    fi
  done
  for chrome_bin in chromium chromium-browser; do
    if command -v "$chrome_bin" &>/dev/null; then
      local chrome_real
      chrome_real="$(realpath "$(command -v "$chrome_bin")" 2>/dev/null || echo "$chrome_bin")"
      [[ -n "${chrome_seen[$chrome_real]:-}" ]] && continue
      chrome_seen["$chrome_real"]=1
      _emit_info "$chrome_bin installed (Chromium upstream — no Google services by default)"
    fi
  done
  for chrome_bin in brave-browser brave; do
    if command -v "$chrome_bin" &>/dev/null; then
      local chrome_real
      chrome_real="$(realpath "$(command -v "$chrome_bin")" 2>/dev/null || echo "$chrome_bin")"
      [[ -n "${chrome_seen[$chrome_real]:-}" ]] && continue
      chrome_seen["$chrome_real"]=1
      _emit_info "$chrome_bin installed (privacy-focused Chromium fork)"
    fi
  done
  # Flatpak Brave/Edge/Opera presence
  if command -v flatpak &>/dev/null; then
    if flatpak list --app --columns=application 2>/dev/null | grep -qE '^com\.brave\.Browser$'; then
      _emit_info "Brave Browser installed (flatpak)"
    fi
    if flatpak list --app --columns=application 2>/dev/null | grep -qE '^com\.microsoft\.Edge$'; then
      _emit_warn "Microsoft Edge installed (flatpak) — vendor telemetry"
    fi
  fi

  if [[ "$found_any" == false ]]; then
    _emit_info "No Firefox-family browser profiles found"
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
      _emit_warn "GNOME Location Services enabled [$user]"
    elif [[ "$val" == "false" ]]; then
      _emit_pass "GNOME Location Services disabled [$user]"
    fi

    val="$(_gsettings_user "$user" "$uid" "org.gnome.desktop.privacy" "report-technical-problems" 2>/dev/null)"
    if [[ "$val" == "true" ]]; then
      _emit_warn "GNOME problem reporting enabled [$user]"
    elif [[ "$val" == "false" ]]; then
      _emit_pass "GNOME problem reporting disabled [$user]"
    fi

    val="$(_gsettings_user "$user" "$uid" "org.gnome.desktop.privacy" "remember-recent-files" 2>/dev/null)"
    if [[ "$val" == "true" ]]; then
      local age
      age="$(_gsettings_user "$user" "$uid" "org.gnome.desktop.privacy" "recent-files-max-age" 2>/dev/null)"
      age="${age##*uint32 }"    # Strip GVariant type prefix (e.g. "uint32 30" → "30")
      age="${age//[^0-9]/}"
      if [[ "$age" == "0" ]]; then
        _emit_pass "Recent files: max-age=0 (list always empty) [$user]"
      elif [[ -n "$age" && "$age" -le 7 && "$age" -gt 0 ]]; then
        _emit_pass "Recent files kept for ${age} days [$user]"
      elif [[ -n "$age" && "$age" -le 30 ]]; then
        _emit_info "Recent files kept for ${age} days [$user]"
      else
        _emit_warn "Recent files enabled (max age: ${age:-unlimited} days) [$user]"
      fi
    elif [[ "$val" == "false" ]]; then
      _emit_pass "Recent files tracking disabled [$user]"
    fi

    val="$(_gsettings_user "$user" "$uid" "org.gnome.desktop.privacy" "send-software-usage-stats" 2>/dev/null)"
    if [[ "$val" == "true" ]]; then
      _emit_warn "GNOME software usage stats enabled [$user]"
    elif [[ "$val" == "false" ]]; then
      _emit_pass "GNOME software usage stats disabled [$user]"
    fi
  }

  _for_each_user _at_check_user

  # File indexer detection — DE-aware (GNOME Tracker, KDE Baloo, Recoll, ...)
  local _idx_name _idx_rc
  _idx_name=$(_de_check_file_indexer)
  _idx_rc=$?
  if [[ "$_idx_rc" -eq 0 ]]; then
    _emit_warn "$_idx_name file indexer active — indexes file contents (privacy: stores in user DB)"
  else
    _emit_pass "$_idx_name file indexer not running"
  fi

  if command -v flatpak &>/dev/null; then
    # F-225 (revised): only flag GENUINELY high-risk permissions. The
    # original Phase 12.5 attempt was too aggressive — it matched
    # `sockets=.*x11` which fires on EVERY Flatpak GUI app via fallback-x11
    # support (sockets=x11;wayland;fallback-x11 is standard), and
    # `--share=network` doesn't even match the actual `flatpak info` output
    # syntax (`shared=network;...`).
    #
    # Genuinely high-risk:
    #   filesystems=host[-os]   — unrestricted FS access
    #   filesystems=home        — home dir access (defeats sandbox purpose)
    #   org.freedesktop.Flatpak=talk — sandbox-escape permission
    #
    # Medium-risk (info-tier — legitimate for some apps but worth noting):
    #   devices=all             — raw hardware (legitimate for Signal w/ webcam,
    #                             OBS, virt-manager; problematic for unknown apps)
    local dangerous=0
    local app
    while IFS= read -r app; do
      [[ -z "$app" ]] && continue
      local perms
      perms="$(flatpak info --show-permissions "$app" 2>/dev/null)"
      # High-risk patterns
      if echo "$perms" | grep -qE "filesystems=(host([;,[:space:]]|$)|.*[;,]host([;,[:space:]]|$))|filesystems=(host-os([;,[:space:]]|$)|.*[;,]host-os([;,[:space:]]|$))|filesystems=(home([;,[:space:]]|$)|.*[;,]home([;,[:space:]]|$))|org\.freedesktop\.Flatpak=talk"; then
        _emit_warn "Flatpak '$app' has high-risk permissions (host/home filesystem or Flatpak portal)"
        dangerous=$((dangerous + 1))
      fi
      # Medium-risk: raw device access (info, not warn)
      if echo "$perms" | grep -qE "devices=(all([;,[:space:]]|$)|.*[;,]all([;,[:space:]]|$))"; then
        _emit_info "Flatpak '$app' has devices=all (raw hardware — legitimate for webcam/audio apps)"
      fi
    done < <(flatpak list --app --columns=application 2>/dev/null)
    if [[ "$dangerous" -eq 0 ]]; then
      _emit_pass "No Flatpak apps with high-risk permissions"
    fi
  else
    _emit_info "Flatpak not installed"
  fi

  if command -v snap &>/dev/null; then
    if snap get system experimental.telemetry 2>/dev/null | grep -qi "true"; then
      _emit_warn "Snap telemetry enabled"
    else
      _emit_pass "Snap telemetry not enabled"
    fi
  fi

  local abrt_active
  abrt_active="$(systemctl list-units --state=active --no-legend 'abrt-*' 2>/dev/null | wc -l | ccount)"
  if [[ "$abrt_active" -gt 0 ]]; then
    _emit_warn "ABRT crash reporter active ($abrt_active services) — sends crash data"
  else
    _emit_pass "ABRT crash reporter not active"
  fi

  if [[ "$DISTRO_FAMILY" == "rhel" ]]; then
    local dnf_conf="/etc/dnf/dnf.conf"
    if [[ -f "$dnf_conf" ]] && grep -qi "^countme[[:space:]]*=[[:space:]]*true" "$dnf_conf" 2>/dev/null; then
      _emit_warn "Fedora countme enabled in dnf.conf"
    elif [[ -f "$dnf_conf" ]] && grep -qi "^countme[[:space:]]*=[[:space:]]*false" "$dnf_conf" 2>/dev/null; then
      _emit_pass "Fedora countme disabled in dnf.conf"
    else
      _emit_info "Fedora countme not explicitly set in dnf.conf (default: disabled since Fedora 36)"
    fi
  fi

  if [[ "$DISTRO_FAMILY" == "debian" ]]; then
    if dpkg -l popularity-contest 2>/dev/null | grep -q "^ii"; then
      local popcon_conf="/etc/popularity-contest.conf"
      if [[ -f "$popcon_conf" ]] && grep -q 'PARTICIPATE="yes"' "$popcon_conf" 2>/dev/null; then
        _emit_warn "Ubuntu popularity-contest active — reports installed packages"
      else
        _emit_info "popularity-contest installed but not participating"
      fi
    else
      _emit_pass "popularity-contest not installed"
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
        _emit_pass "NetworkManager connectivity check disabled (in $(basename "$_nmf"))"
        break
      fi
      # Check uri setting
      local _nm_uri
      _nm_uri="$(sed -n '/^\[connectivity\]/,/^\[/{ s/^uri[[:space:]]*=[[:space:]]*//p; }' "$_nmf" 2>/dev/null | tail -1)"
      if [[ -n "$_nm_uri" ]]; then
        _emit_info "NetworkManager connectivity check active (pings $_nm_uri, in $(basename "$_nmf"))"
        break
      fi
    fi
  done

  if $_nm_connectivity_disabled; then
    : # already reported pass above
  elif $_nm_connectivity_found; then
    _emit_info "NetworkManager [connectivity] section found but no explicit disable — connectivity check likely active"
  else
    _emit_info "NetworkManager connectivity check uses default (may phone home)"
  fi
}

###############################################################################
# Section 37: Network Privacy
###############################################################################
check_network_privacy() {
  should_skip "netprivacy" && return
  header "37" "NETWORK PRIVACY"

  # F-331 (v3.6.1): skip WiFi MAC randomization check when no WiFi adapter
  # is present (ethernet-only or WiFi disabled in firmware). Reporting "not
  # configured" on a system that has no WiFi hardware is misleading noise.
  local _has_wifi=false
  if command -v nmcli &>/dev/null && nmcli -t -f TYPE device 2>/dev/null | grep -q '^wifi$'; then
    _has_wifi=true
  fi
  if ! $_has_wifi; then
    for _netif in /sys/class/net/*/wireless; do
      [[ -e "$_netif" ]] && _has_wifi=true && break
    done
  fi
  if ! $_has_wifi; then
    _emit_pass "WiFi scan MAC randomization: N/A (no WiFi adapter present)"
  else
    local nm_wifi_rand=""
    local conf_file
    for conf_file in /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/conf.d/*.conf; do
      [[ -f "$conf_file" ]] || continue
      local val
      val="$(sed -n '/^\[device\]/,/^\[/{ s/^wifi\.scan-rand-mac-address[[:space:]]*=[[:space:]]*//p; }' "$conf_file" 2>/dev/null)"
      [[ -n "$val" ]] && nm_wifi_rand="$val"
    done
    if [[ "$nm_wifi_rand" == "yes" || "$nm_wifi_rand" == "true" ]]; then
      _emit_pass "WiFi scan MAC randomization enabled"
    elif [[ "$nm_wifi_rand" == "no" || "$nm_wifi_rand" == "false" ]]; then
      _emit_fail "WiFi scan MAC randomization disabled"
    else
      _emit_info "WiFi scan MAC randomization not configured (default: yes since NM 1.4)"
    fi
  fi

  # F-232b: cloned-mac-address can live in three places:
  # 1. NetworkManager.conf [connection] section: ethernet.cloned-mac-address=...
  # 2. conf.d drop-ins:                          ethernet.cloned-mac-address=...
  # 3. system-connections/*.nmconnection [ethernet] section: cloned-mac-address=...
  # Per-connection profiles (3) are the common case on Fedora — config-section
  # form (1+2) is for global defaults. Scan all three.
  local eth_clone=""
  for conf_file in /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/conf.d/*.conf; do
    [[ -f "$conf_file" ]] || continue
    local val
    val="$(sed -n '/^\[connection\]/,/^\[/{ s/^ethernet\.cloned-mac-address[[:space:]]*=[[:space:]]*//p; }' "$conf_file" 2>/dev/null)"
    [[ -n "$val" ]] && eth_clone="$val"
  done
  # Per-connection profile scan (most common on Fedora desktop)
  # Script enforces root mode at line 720, so files are readable without sudo.
  if [[ -z "$eth_clone" ]]; then
    for conf_file in /etc/NetworkManager/system-connections/*.nmconnection; do
      [[ -f "$conf_file" ]] || continue
      local val
      val=$(sed -n '/^\[ethernet\]/,/^\[/{ s/^cloned-mac-address[[:space:]]*=[[:space:]]*//p; }' "$conf_file" 2>/dev/null | head -1)
      [[ -n "$val" ]] && eth_clone="$val" && break
    done
  fi
  # F-232: 'stable' is a deliberate privacy choice — derives consistent MAC
  # per connection-UUID. Better than no randomization (no permanent hardware
  # MAC exposure) and acceptable on static-IP setups where the IP is anyway
  # the stable identifier. Promote from INFO to PASS-with-note.
  if [[ "$eth_clone" == "random" ]]; then
    _emit_pass "Ethernet MAC randomization: random (new MAC on each connection)"
  elif [[ "$eth_clone" == "stable" ]]; then
    _emit_pass "Ethernet MAC: stable (per-connection consistent — privacy without disruption)"
  elif [[ -n "$eth_clone" ]]; then
    _emit_info "Ethernet cloned-mac-address=$eth_clone"
  else
    _emit_info "Ethernet MAC randomization not configured (uses permanent hardware MAC)"
  fi

  if systemctl is-active --quiet avahi-daemon.service 2>/dev/null; then
    _emit_warn "Avahi (mDNS) active — broadcasts hostname on local network"
  else
    _emit_pass "Avahi (mDNS) not running"
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
      _emit_info "Avahi is $avahi_enabled — config check skipped"
    else
      local pub_host
      pub_host="$(sed -n '/^\[publish\]/,/^\[/{ s/^publish-hostname[[:space:]]*=[[:space:]]*//p; }' "$avahi_conf" 2>/dev/null)"
      if [[ "$pub_host" == "no" ]]; then
        _emit_pass "Avahi hostname publishing disabled"
      else
        _emit_warn "Avahi publishes hostname (publish-hostname=${pub_host:-yes})"
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
    _emit_pass "LLMNR disabled in resolved.conf"
  elif [[ -z "$llmnr_val" ]]; then
    if [[ -f "$resolved_conf" ]]; then
      _emit_warn "LLMNR not configured (default: enabled — leaks hostname)"
    else
      _emit_warn "resolved.conf not found — LLMNR status unknown (likely enabled by default)"
    fi
  else
    _emit_info "LLMNR set to '$llmnr_val'"
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
  # F-233b: use _is_human_uid (honors /etc/login.defs UID_MIN/UID_MAX) instead
  # of hardcoded 1000 — distros with non-default UID_MIN (Ubuntu Server's 500
  # in legacy installs, custom enterprise builds) need this consistency.
  while IFS=: read -r user _ uid _ gecos _ _; do
    _is_human_uid "$uid" || continue
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
    _emit_warn "Hostname '$hostname' may contain real name — reveals identity on networks"
  else
    _emit_pass "Hostname '$hostname' does not appear to contain real names"
  fi

  # IPv6 privacy posture — three layered checks (kernel global, kernel
  # per-iface, NM config) so that systems with per-interface disable_ipv6=1
  # on physical NICs but VPN-internal IPv6 don't get a false "stable address
  # reveals identity" warning.
  local ipv6_disabled_all
  ipv6_disabled_all="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)"

  # Per-interface kernel state: if ALL non-VPN, non-loopback interfaces have
  # disable_ipv6=1, IPv6 is effectively off for the threat surface this check
  # cares about (LAN/WAN exposure). VPN-internal IPv6 is intentional.
  local _all_phys_v6_off=true
  local _has_phys_iface=false
  for _ifpath in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ -f "$_ifpath" ]] || continue
    local _if
    _if="${_ifpath#/proc/sys/net/ipv6/conf/}"
    _if="${_if%/disable_ipv6}"
    [[ "$_if" == "all" || "$_if" == "default" || "$_if" == "lo" ]] && continue
    # Skip VPN tunnels — their IPv6 is internal, not LAN-exposed
    echo "$_if" | grep -qE "$_VPN_IFACE_REGEX" && continue
    _has_phys_iface=true
    local _v
    _v="$(< "$_ifpath")"
    [[ "$_v" != "1" ]] && _all_phys_v6_off=false
  done
  $_has_phys_iface || _all_phys_v6_off=false

  # NM-config check (legacy path — kept for systems without sysctl visibility)
  local _ipv6_nm_disabled=true
  if require_cmd nmcli; then
    local _has_active=false
    while IFS= read -r _cname; do
      [[ -z "$_cname" ]] && continue
      local _conn_iface
      _conn_iface=$(nmcli -t -f GENERAL.DEVICES connection show "$_cname" 2>/dev/null | grep -oP '(?<=GENERAL\.DEVICES:).*' | head -1)
      if echo "$_conn_iface" | grep -qE "$_VPN_IFACE_REGEX"; then
        continue
      fi
      _has_active=true
      local _ipv6method
      _ipv6method=$(nmcli -t -f ipv6.method connection show "$_cname" 2>/dev/null | grep -oP '(?<=ipv6\.method:).*' | head -1)
      if [[ "$_ipv6method" == "disabled" ]]; then
        continue
      elif [[ "$_ipv6method" == "manual" || "$_ipv6method" == "link-local" ]]; then
        local _v6addrs
        _v6addrs=$(nmcli -t -f ipv6.addresses connection show "$_cname" 2>/dev/null | grep -oP '(?<=ipv6\.addresses:).*' | head -1)
        [[ -z "$_v6addrs" ]] && continue
      fi
      _ipv6_nm_disabled=false
      break
    done < <(nmcli -t -f NAME connection show --active 2>/dev/null | grep -v '^lo$')
    # If no active non-VPN connections found, NM says nothing definitive — fall
    # through to kernel state instead of forcing _ipv6_nm_disabled=false.
    $_has_active || _ipv6_nm_disabled=true
  else
    _ipv6_nm_disabled=false
  fi

  if [[ "$ipv6_disabled_all" == "1" ]] || $_all_phys_v6_off || $_ipv6_nm_disabled; then
    _emit_pass "IPv6 disabled on physical interfaces — privacy extensions not needed (VPN-internal IPv6 by design)"
  else
    local tempaddr
    tempaddr="$(sysctl -n net.ipv6.conf.default.use_tempaddr 2>/dev/null)"
    if [[ "$tempaddr" == "2" ]]; then
      _emit_pass "IPv6 privacy extensions enabled (prefer temporary addresses)"
    elif [[ "$tempaddr" == "1" ]]; then
      _emit_info "IPv6 privacy extensions enabled but not preferred"
    else
      _emit_warn "IPv6 privacy extensions disabled — stable address reveals identity"
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
    _emit_pass "DHCP hostname: N/A (all connections use static IP — no DHCP sent)"
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
      _emit_pass "DHCP hostname sending disabled"
    else
      _emit_warn "DHCP sends hostname to network (dhcp-send-hostname=${dhcp_hostname:-true})"
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
    _emit_pass "Multicast DNS disabled in resolved.conf"
  elif [[ -z "$mdns_val" ]]; then
    if [[ -f "$resolved_conf" ]]; then
      _emit_info "Multicast DNS not configured in resolved.conf"
    else
      _emit_info "resolved.conf not found — Multicast DNS status unknown"
    fi
  else
    _emit_info "Multicast DNS set to '$mdns_val'"
  fi

  # Conservative: flags any active cups-browsed regardless of patch level.
  # Patched builds (cups-filters >= 2.0.1) are not vulnerable to CVE-2024-47176.
  if systemctl is-active --quiet cups-browsed.service 2>/dev/null; then
    _emit_warn "cups-browsed active — check if patched for CVE-2024-47176 (cups-filters >= 2.0.1)"
  elif systemctl is-enabled --quiet cups-browsed.service 2>/dev/null; then
    _emit_warn "cups-browsed enabled but not running — consider disabling"
  else
    _emit_pass "cups-browsed not active"
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
        _emit_warn "recently-used.xbel is $(_human_size "$size") [$user] — consider clearing"
      elif [[ "$size" -gt 102400 ]]; then
        _emit_info "recently-used.xbel is $(_human_size "$size") [$user]"
      else
        _emit_pass "recently-used.xbel small ($(_human_size "$size")) [$user]"
      fi
    fi

    local thumb_dir="$home/.cache/thumbnails"
    if [[ -d "$thumb_dir" ]]; then
      local size
      # F-241: 5-second timeout in case thumb dir has runaway expansion.
      size="$(timeout 5 du -sb "$thumb_dir" 2>/dev/null | cut -f1)"
      size="${size:-0}"
      if [[ "$size" -gt 104857600 ]]; then
        _emit_warn "Thumbnail cache $(_human_size "$size") [$user] — reveals viewed images"
      elif [[ "$size" -gt 10485760 ]]; then
        _emit_info "Thumbnail cache $(_human_size "$size") [$user]"
      fi
    fi

    local trash_dir="$home/.local/share/Trash"
    if [[ -d "$trash_dir" ]]; then
      local size
      size="$(du -sb "$trash_dir" 2>/dev/null | cut -f1)"
      size="${size:-0}"
      if [[ "$size" -gt 104857600 ]]; then
        _emit_warn "Trash is $(_human_size "$size") [$user] — deleted files still on disk"
      elif [[ "$size" -gt 1048576 ]]; then
        _emit_info "Trash is $(_human_size "$size") [$user]"
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
        _emit_warn "$sensitive potential secrets in $hf [$user]"
      fi
    done
    local bashrc="$home/.bashrc"
    if [[ -f "$bashrc" ]]; then
      local histsize
      histsize="$(grep -oP '^(export\s+)?HISTSIZE=\K\d+' "$bashrc" 2>/dev/null | tail -1)"
      if [[ -n "$histsize" && "$histsize" -gt 10000 ]]; then
        _emit_info "HISTSIZE=$histsize (large — consider scrubbing periodically) [$user]"
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
      _emit_warn "Clipboard manager '$proc' running — may store passwords in memory"
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
          false|0) _emit_pass "Klipper running with history disabled [$1, KDE]" ;;
          true|1)  _emit_info "Klipper running with history (KDE default — disable in System Settings → Clipboard) [$1]" ;;
        esac
      }
      _kreadconfig_for_users "klipperrc" "General" "KeepClipboardContents" _kde_klipper_history_check
    else
      _emit_warn "Klipper running outside KDE — may store passwords in memory"
    fi
    clip_found=true
  fi
  if [[ "$clip_found" == false ]]; then
    _emit_pass "No clipboard manager daemon detected"
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
      _emit_info "Core dumps: systemd-coredump storage=none (checked in filesystem section)"
    else
      _emit_info "Core dumps: systemd-coredump storage=${core_storage:-external} (checked in filesystem section)"
    fi
  elif [[ "$core_pattern" == "|"* ]]; then
    _emit_info "Core dumps piped to: ${core_pattern:0:60}"
  elif [[ "$core_soft" == "0" ]]; then
    _emit_info "Core dumps: ulimit=0 (checked in filesystem section)"
  else
    _emit_info "Core dumps: enabled (checked in filesystem section)"
  fi

  local journal_dir="/var/log/journal"
  if [[ -d "$journal_dir" ]]; then
    local jsize
    jsize="$(du -sb "$journal_dir" 2>/dev/null | cut -f1)"
    jsize="${jsize:-0}"
    # F-316 (v3.6.1): cross-reference Section 19 — du -sb reports raw bytes
    # incl. fs-overhead; journalctl --disk-usage reports what journald accounts
    # for. Both numbers are correct, just different measurements.
    # F-326 (v3.6.1): explain typical reasons for the S19↔S38 size discrepancy
    # (often 30-50%): journald excludes orphaned/uncatalogued .journal files,
    # while du counts them; Btrfs CoW + snapshots inflate du for
    # /var/log/journal subvolumes; xfs/ext4 fs-block alignment adds slack;
    # uncompressed user.persistent.journal files vs journald's compressed
    # accounting. None of these differences indicate a bug.
    if [[ "$jsize" -gt 536870912 ]]; then
      _emit_warn "Persistent journal /var/log/journal is $(_human_size "$jsize") on disk (filesystem du-sb view; differs from journalctl --disk-usage in S19 — typical fs-overhead/CoW/orphan-file delta) — may contain sensitive data"
    else
      _emit_info "Persistent journal /var/log/journal is $(_human_size "$jsize") on disk (filesystem du-sb view; differs from journalctl --disk-usage in S19 — typical fs-overhead/CoW/orphan-file delta)"
    fi
  else
    _emit_pass "No persistent journal (logs in volatile memory only)"
  fi

  local tmp_fs
  if require_cmd findmnt; then
    tmp_fs="$(findmnt -no FSTYPE /tmp 2>/dev/null)"
  else
    tmp_fs="$(df -PT /tmp 2>/dev/null | tail -1 | awk '{print $2}')"
  fi
  if [[ "$tmp_fs" == "tmpfs" ]]; then
    _emit_pass "/tmp is tmpfs (cleared on reboot)"
  else
    _emit_warn "/tmp is $tmp_fs — temporary files survive reboot"
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
      _emit_pass "Screen lock delay is 0 (instant) for $1 [$_DE_FAMILY]"
    else
      _emit_fail "Screen lock delay is ${delay}s for $1 (should be 0) [$_DE_FAMILY]"
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
    _emit_info "No active $_DE_FAMILY sessions found for lock-delay check"

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
      _emit_warn "Idle timeout disabled for $1 (screen never blanks) [$_DE_FAMILY]"
    elif [[ "$delay" -le 300 ]]; then
      _emit_pass "Idle timeout is ${delay}s for $1 [$_DE_FAMILY]"
    else
      _emit_fail "Idle timeout is ${delay}s for $1 (should be ≤ 300) [$_DE_FAMILY]"
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
    _emit_info "No active $_DE_FAMILY sessions found for idle-delay check"

  local found_lock_suspend=0
  _de_lock_suspend_cb() {
    found_lock_suspend=1
    local val
    val=$(echo "$3" | xargs | tr '[:upper:]' '[:lower:]')
    case "$val" in
      true|1)  _emit_pass "Lock on suspend enabled for $1 [$_DE_FAMILY]" ;;
      false|0) _emit_fail "Lock on suspend disabled for $1 [$_DE_FAMILY]" ;;
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
    _emit_info "No active $_DE_FAMILY sessions found for lock-on-suspend check"

  local found_notif=0
  _de_notif_cb() {
    found_notif=1
    local val
    val=$(echo "$3" | xargs | tr '[:upper:]' '[:lower:]')
    case "$_DE_FAMILY" in
      gnome|cinnamon)
        # show-in-lock-screen=false → notifications hidden (good)
        case "$val" in
          false|0) _emit_pass "Lock screen notifications hidden for $1 [$_DE_FAMILY]" ;;
          true|1)  _emit_warn "Lock screen shows notification previews for $1 [$_DE_FAMILY]" ;;
        esac
        ;;
      kde)
        # plasmanotifyrc DoNotDisturb/WhenScreenLocked=true → notifications hidden (good)
        case "$val" in
          true|1)  _emit_pass "Lock screen notifications hidden for $1 [KDE DND]" ;;
          false|0) _emit_warn "Lock screen shows notifications for $1 [KDE DND]" ;;
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
    _emit_info "Lock screen notification check not available for $_DE_FAMILY"

  local autologin_found=0
  for conf in /etc/gdm*/custom.conf /etc/gdm*/daemon.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qi '^\s*AutomaticLoginEnable[[:space:]]*=[[:space:]]*true' "$conf" 2>/dev/null; then
      local autouser
      autouser=$(grep -iP '^\s*AutomaticLogin\s*=(?!Enable)' "$conf" | head -1 | cut -d= -f2 | xargs)
      _emit_fail "Auto-login enabled in $conf${autouser:+ (user: $autouser)}"
      autologin_found=1
    fi
  done
  [[ "$autologin_found" -eq 0 ]] && _emit_pass "No GDM auto-login configured"

  local guest_found=0
  if [[ -d /etc/lightdm ]]; then
    if grep -rqs '^\s*allow-guest[[:space:]]*=[[:space:]]*true' /etc/lightdm/; then
      _emit_fail "LightDM guest account enabled"
      guest_found=1
    fi
  fi
  for conf in /etc/gdm*/custom.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qi '^\s*TimedLoginEnable[[:space:]]*=[[:space:]]*true' "$conf" 2>/dev/null; then
      _emit_warn "GDM timed login enabled in $conf"
      guest_found=1
    fi
  done
  [[ "$guest_found" -eq 0 ]] && _emit_pass "No guest/timed login enabled"

  local remote_found=0
  if systemctl is-active --quiet gnome-remote-desktop.service 2>/dev/null; then
    _emit_warn "gnome-remote-desktop service is active"
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
      _emit_warn "VNC/RDP port listening EXTERNALLY"
      remote_found=1
    elif [[ -n "$vnc_local" ]]; then
      _emit_info "VNC/RDP port listening on localhost only (likely qemu SPICE/VNC console)"
    fi
  fi
  _gs_rdp_cb() {
    local val
    val=$(echo "$3" | xargs)
    if [[ "$val" == "true" ]]; then
      _emit_warn "GNOME RDP sharing enabled for $1"
      remote_found=1
    fi
  }
  _gsettings_for_users "org.gnome.desktop.remote-desktop.rdp" "enable" _gs_rdp_cb
  [[ "$remote_found" -eq 0 ]] && _emit_pass "No remote desktop services detected"

  local total_autostart=0 user_autostart=0
  local sys_count=0
  sys_count=$(find /etc/xdg/autostart/ -name '*.desktop' 2>/dev/null | wc -l)
  total_autostart=$((total_autostart + sys_count))

  while IFS=: read -r user _ uid _ _ home _; do
    _is_human_uid "$uid" || continue
    local ucount=0
    ucount=$(find "$home/.config/autostart/" -name '*.desktop' 2>/dev/null | wc -l)
    if [[ "$ucount" -gt 0 ]]; then
      user_autostart=$((user_autostart + ucount))
      total_autostart=$((total_autostart + ucount))
      [[ "$ucount" -gt 10 ]] && _emit_warn "$user has $ucount autostart programs"
    fi
  done < /etc/passwd

  if [[ "$total_autostart" -gt 20 ]]; then
    _emit_warn "$total_autostart total autostart entries (${sys_count} system, ${user_autostart} user)"
  else
    _emit_info "$total_autostart autostart entries (${sys_count} system, ${user_autostart} user)"
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
          true|1)  _emit_pass "User switching restricted for $1 [$_DE_FAMILY]" ;;
          false|0) _emit_info "User switching allowed for $1 [$_DE_FAMILY]" ;;
        esac
        ;;
      kde)
        # KDE Action Restrictions/action/start_new_session: false=restricted (good)
        case "$val" in
          false|0) _emit_pass "User switching restricted for $1 [KDE]" ;;
          true|1)  _emit_info "User switching allowed for $1 [KDE]" ;;
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
    _emit_info "No user-switching policy found for $_DE_FAMILY sessions"

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
    if [[ -S "/run/user/$(id -u gdm 2>/dev/null)/bus" ]]; then
      local gdm_uid
      gdm_uid=$(id -u gdm 2>/dev/null)
      local val
      val=$(sudo -u gdm DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$gdm_uid/bus" \
        gsettings get org.gnome.login-screen disable-user-list 2>/dev/null | xargs)
      [[ "$val" == "true" ]] && userlist_disabled=1
    fi
    if [[ "$userlist_disabled" -eq 1 ]]; then
      _emit_pass "User list hidden on login screen"
    else
      if lsblk -o TYPE 2>/dev/null | grep -q crypt; then
        _emit_info "User list visible on login screen (LUKS encryption limits physical access risk)"
      else
        _emit_warn "User list visible on login screen (attackers can enumerate users)"
      fi
    fi
  else
    _emit_info "GDM not found — skipping user-list check"
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
    _emit_info "$cam_count webcam device(s) found${cam_names:+ ($cam_names)}"
    if lsmod 2>/dev/null | grep -q uvcvideo; then
      _emit_info "uvcvideo kernel module loaded"
    fi
  else
    _emit_pass "No webcam devices found"
  fi

  # F-313 (v3.6.1): PipeWire/PulseAudio client need DBUS_SESSION_BUS_ADDRESS
  # in addition to XDG_RUNTIME_DIR — pure XDG_RUNTIME_DIR was insufficient on
  # F43+ where wpctl returns empty silently. Adding the bus addr matches what
  # other check sections (gsettings, kreadconfig) already do via the same
  # `unix:path=/run/user/$uid/bus` pattern.
  # F-319 (v3.6.1): capture STDERR (2>&1 instead of 2>/dev/null) so we can
  # detect "no default audio source" / "Translate ID error" messages that
  # wpctl emits on stderr when there's no mic hardware. Previously these
  # silent-stderr returns produced empty $vol → mic_checked=0 → confusing
  # "Could not check microphone status" on systems that simply have no mic.
  local mic_checked=0
  if command -v wpctl &>/dev/null; then
    while IFS=: read -r user _ uid _ _ _ shell; do
      _is_human_uid "$uid" || continue
      [[ "$shell" == */nologin || "$shell" == */false ]] && continue
      [[ -S "/run/user/$uid/bus" ]] || continue
      local vol
      vol=$(sudo -u "$user" \
        XDG_RUNTIME_DIR="/run/user/$uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
        wpctl get-volume @DEFAULT_AUDIO_SOURCE@ 2>&1)
      if echo "$vol" | grep -qE '^Volume:'; then
        mic_checked=1
        if echo "$vol" | grep -qi 'muted'; then
          _emit_pass "Microphone muted for $user"
        else
          _emit_info "Microphone active for $user: $vol"
        fi
      elif echo "$vol" | grep -qiE 'invalid id|Translate ID error|node not found|No such object'; then
        mic_checked=1
        _emit_pass "No default audio source for $user (no microphone hardware)"
      fi
    done < /etc/passwd
  elif command -v pactl &>/dev/null; then
    while IFS=: read -r user _ uid _ _ _ shell; do
      _is_human_uid "$uid" || continue
      [[ "$shell" == */nologin || "$shell" == */false ]] && continue
      [[ -S "/run/user/$uid/bus" ]] || continue
      local muted_raw
      muted_raw=$(sudo -u "$user" \
        XDG_RUNTIME_DIR="/run/user/$uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
        pactl get-source-mute @DEFAULT_SOURCE@ 2>&1)
      local muted
      muted=$(echo "$muted_raw" | awk '/^Mute:/ {print $2; exit}')
      if [[ -n "$muted" ]]; then
        mic_checked=1
        if [[ "$muted" == "yes" ]]; then
          _emit_pass "Microphone muted for $user"
        else
          _emit_info "Microphone not muted for $user"
        fi
      elif echo "$muted_raw" | grep -qiE 'no such|not found|failure|invalid'; then
        mic_checked=1
        _emit_pass "No default audio source for $user (no microphone hardware)"
      fi
    done < /etc/passwd
  fi
  [[ "$mic_checked" -eq 0 ]] && _emit_info "Could not check microphone status (no wpctl/pactl or no active sessions)"

  local net_audio=0
  if pgrep -x pulseaudio &>/dev/null; then
    # F-258b: stock /etc/pulse/default.pa ships with `#load-module
    # module-native-protocol-tcp` as a COMMENTED template — the previous loose
    # grep matched commented lines and FAILed every default Fedora/Ubuntu
    # install that still had pulseaudio. Anchor on first-non-whitespace ≠ '#'.
    if grep -rqsE '^[[:space:]]*[^#[:space:]].*module-native-protocol-tcp' /etc/pulse/ /etc/pulseaudio/ 2>/dev/null; then
      _emit_fail "PulseAudio network audio (module-native-protocol-tcp) enabled in config"
      net_audio=1
    fi
    while IFS=: read -r user _ uid _ _ _ shell; do
      _is_human_uid "$uid" || continue
      [[ "$shell" == */nologin || "$shell" == */false ]] && continue
      [[ -S "/run/user/$uid/bus" ]] || continue
      if sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$uid" \
        pactl list modules short 2>/dev/null | grep -q 'module-native-protocol-tcp'; then
        _emit_fail "PulseAudio TCP module loaded for $user"
        net_audio=1
      fi
    done < /etc/passwd
  fi
  if pgrep -x pipewire &>/dev/null; then
    if grep -rhE 'tcp:[0-9]|module-native-protocol-tcp' /etc/pipewire/ /usr/share/pipewire/ 2>/dev/null | grep -vE '^\s*#' | grep -qE 'tcp:[0-9]|module-native-protocol-tcp'; then
      _emit_fail "PipeWire network audio protocol enabled in config"
      net_audio=1
    fi
  fi
  [[ "$net_audio" -eq 0 ]] && _emit_pass "No network audio modules detected"

  # F-259: PipeWire remote-access detection.
  # The previous file-grep heuristic produced false positives on multi-line
  # configs, and the pw-dump JSON pattern was unreliable too (props nesting
  # varies, "args" appears in many module entries unrelated to socket scope).
  # Reduced to two unambiguous signals: (1) explicit TCP listener via ss,
  # (2) explicit "tcp:" socket spec in config file (not just protocol-native).
  local pw_remote=0
  for confdir in /etc/pipewire /usr/share/pipewire; do
    [[ -d "$confdir" ]] || continue
    if grep -rqs '"access.allowed"' "$confdir/" 2>/dev/null; then
      _emit_info "PipeWire access control rules found in $confdir"
    fi
    # Explicit TCP socket in config = remote exposure intent.
    # Stricter regex: first non-whitespace MUST NOT be '#' (commented examples
    # in stock PipeWire configs use whitespace+# prefix, the previous loose
    # regex with `[^#]` could match a leading space too via backtracking).
    if grep -rhsE '^[[:space:]]*[^#[:space:]].*tcp:[0-9]+' "$confdir/" 2>/dev/null | grep -q .; then
      _emit_warn "PipeWire config in $confdir declares a TCP socket — remote access enabled"
      pw_remote=1
    fi
  done
  # Authoritative: TCP listener owned by pipewire process
  if ss -tlnp 2>/dev/null | grep -q 'pipewire'; then
    _emit_warn "PipeWire listening on TCP"
    pw_remote=1
  fi
  [[ "$pw_remote" -eq 0 ]] && _emit_pass "No PipeWire remote access detected"

  if pgrep -f xdg-desktop-portal &>/dev/null; then
    _emit_info "xdg-desktop-portal is running (screen sharing available when requested)"
  else
    _emit_info "xdg-desktop-portal not running"
  fi
}

###############################################################################
# Section 41: Bluetooth Privacy
###############################################################################
check_bluetooth_privacy() {
  should_skip "btprivacy" && return
  header "41" "BLUETOOTH PRIVACY"

  # F-318 (v3.6.1): split bluetoothctl-presence and unit-file-existence into
  # separate checks. `systemctl list-unit-files bluetooth.service` returns
  # rc=1 in some transient post-mask states even though the unit is loaded
  # (bluetoothctl is on PATH, unit IS masked + enabled per `systemctl show`).
  # `systemctl show -p UnitFileState` is the authoritative API: returns the
  # unit's persistent state (enabled/disabled/masked/static/not-found) without
  # depending on list-unit-files's edge cases. Differentiated INFO messages
  # also tell users WHICH part is missing.
  if ! command -v bluetoothctl &>/dev/null; then
    _emit_info "Bluetooth not available — bluetoothctl not installed"
    return
  fi
  local _bt_unit_state
  _bt_unit_state=$(systemctl show bluetooth.service -p UnitFileState --value 2>/dev/null)
  if [[ -z "$_bt_unit_state" || "$_bt_unit_state" == "not-found" ]]; then
    _emit_info "Bluetooth not available — bluetooth.service unit not present"
    return
  fi
  if [[ "$_bt_unit_state" == "masked" ]]; then
    _emit_pass "Bluetooth service masked (cannot start)"
    return
  fi

  local bt_active=0
  if systemctl is-active --quiet bluetooth.service 2>/dev/null; then
    bt_active=1
    _emit_info "Bluetooth service is active"
  else
    _emit_pass "Bluetooth service is not running"
  fi

  if [[ "$bt_active" -eq 0 ]]; then
    return
  fi

  local bt_info
  # Force LC_ALL=C — bluetoothctl labels (Discoverable/Pairable) can be
  # locale-translated on some BlueZ builds; the English-anchored greps below
  # silently fail then. Defensive against the same locale-bug class as chage.
  bt_info=$(LC_ALL=C timeout 3 bluetoothctl show 2>/dev/null)
  if [[ -z "$bt_info" ]]; then
    _emit_warn "Could not query bluetooth controller (timeout or no adapter)"
    return
  fi

  local discoverable
  discoverable=$(echo "$bt_info" | grep -i 'Discoverable:' | awk '{print $2}')
  if [[ "$discoverable" == "yes" ]]; then
    _emit_fail "Bluetooth is discoverable (visible to nearby devices)"
  elif [[ "$discoverable" == "no" ]]; then
    _emit_pass "Bluetooth is not discoverable"
  else
    _emit_info "Could not determine discoverable status"
  fi

  local pairable
  pairable=$(echo "$bt_info" | grep -i 'Pairable:' | awk '{print $2}')

  local paired_count=0
  local paired_devices
  paired_devices=$(LC_ALL=C timeout 3 bluetoothctl devices Paired 2>/dev/null || LC_ALL=C timeout 3 bluetoothctl paired-devices 2>/dev/null)
  if [[ -n "$paired_devices" ]]; then
    paired_count=$(echo "$paired_devices" | grep -c 'Device')
  fi
  _emit_info "$paired_count paired Bluetooth device(s)"

  if [[ "$pairable" == "yes" ]]; then
    if [[ "$paired_count" -eq 0 ]]; then
      # F-262: pairable + 0 paired could be temporary setup mode (legitimate)
      # if discoverable is off. Tighten message to suggest review rather than
      # warn unconditionally.
      _emit_info "Bluetooth pairable but 0 paired devices (active setup mode? — disable pairable when done)"
    else
      _emit_info "Bluetooth pairable with $paired_count paired device(s)"
    fi
  elif [[ "$pairable" == "no" ]]; then
    _emit_pass "Bluetooth pairing disabled"
  fi

  if [[ "$paired_count" -eq 0 && "$pairable" != "yes" ]]; then
    _emit_warn "Bluetooth active with no paired devices — consider disabling"
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
  # F-263b: use `type -P` (path-only) instead of `command -v`. `command -v`
  # also matches shell functions/aliases — and this script defines a function
  # named `pass()` for output formatting, which shadows the `pass` CLI tool.
  # `type -P` only resolves through PATH and never matches functions.
  local pm_found=0
  local pm_list=""
  for pm in keepassxc keepass2 keepass keeweb bitwarden bitwarden-cli rbw \
            1password op pass gopass passmenu lesspass nordpass \
            buttercup qtpass enpass; do
    if [[ -n "$(type -P "$pm" 2>/dev/null)" ]]; then
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
    _emit_pass "Password manager installed: $pm_list"
  else
    _emit_warn "No password manager detected (consider keepassxc, bitwarden, or pass)"
  fi

  # F-264: Cross-DE keyring PAM detection — GNOME Keyring + KDE KWallet (pam_kwallet5)
  # F-288 (v3.6.1): suppress *autologin* PAM entries when auto-login is not
  # actually enabled. The gdm-autologin and sddm-autologin PAM files ship by
  # default on most distros but the configured auto-unlock is only effective
  # during an active auto-login session. Reporting them when auto-login is
  # disabled was misleading ("you have auto-unlock + autologin — sounds like
  # a leak" — when in fact auto-login is off and the file is dormant).
  local _autologin_active=0
  for conf in /etc/gdm*/custom.conf /etc/gdm*/daemon.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qiE '^\s*AutomaticLoginEnable\s*=\s*true' "$conf" 2>/dev/null; then
      _autologin_active=1
      break
    fi
  done
  if [[ "$_autologin_active" -eq 0 ]] && [[ -d /etc/sddm.conf.d || -f /etc/sddm.conf ]]; then
    for conf in /etc/sddm.conf /etc/sddm.conf.d/*.conf; do
      [[ -f "$conf" ]] || continue
      # SDDM autologin marker: User= under [Autologin] section
      if awk '/^\[Autologin\]/{f=1; next} /^\[/{f=0} f && /^[[:space:]]*User[[:space:]]*=/{print; exit}' \
           "$conf" 2>/dev/null | grep -qE '=[[:space:]]*[^[:space:]]'; then
        _autologin_active=1
        break
      fi
    done
  fi

  local keyring_pam=0
  for pamfile in /etc/pam.d/gdm-password /etc/pam.d/gdm-autologin /etc/pam.d/login \
                 /etc/pam.d/lightdm /etc/pam.d/sddm /etc/pam.d/sddm-autologin \
                 /etc/pam.d/kde /etc/pam.d/kdm; do
    [[ -f "$pamfile" ]] || continue
    # Skip *autologin* PAM files when auto-login is not actually enabled —
    # config exists but is dormant (default Fedora/Ubuntu state).
    if [[ "$pamfile" == *autologin* && "$_autologin_active" -eq 0 ]]; then
      continue
    fi
    if grep -qs 'pam_gnome_keyring.so' "$pamfile"; then
      keyring_pam=1
      _emit_info "GNOME Keyring auto-unlock configured in $(basename "$pamfile")"
    fi
    if grep -qs -E 'pam_kwallet5?\.so' "$pamfile"; then
      keyring_pam=1
      _emit_info "KDE KWallet auto-unlock configured in $(basename "$pamfile")"
    fi
  done
  [[ "$keyring_pam" -eq 0 ]] && _emit_info "No keyring PAM auto-unlock found (GNOME Keyring/KWallet)"

  local ssh_checked=0
  while IFS=: read -r user _ uid _ _ home shell; do
    _is_human_uid "$uid" || continue
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
      if echo "$effective" | grep -qiE 'confirm|[0-9]'; then
        _emit_pass "SSH AddKeysToAgent has timeout/confirm for $user"
      elif echo "$effective" | grep -qi 'yes'; then
        _emit_warn "SSH AddKeysToAgent=yes for $user (keys persist until agent dies)"
      fi
    fi
  done < /etc/passwd
  [[ "$ssh_checked" -eq 0 ]] && _emit_info "No AddKeysToAgent config found (keys persist by default when added)"

  local gpg_checked=0
  while IFS=: read -r user _ uid _ _ home shell; do
    _is_human_uid "$uid" || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    local gpg_conf="$home/.gnupg/gpg-agent.conf"
    [[ -f "$gpg_conf" ]] || continue
    gpg_checked=1
    local ttl
    ttl=$(grep -i 'default-cache-ttl' "$gpg_conf" 2>/dev/null | awk '{print $2}' | head -1)
    if [[ -n "$ttl" ]]; then
      if [[ "$ttl" -le 600 ]]; then
        _emit_pass "GPG cache TTL is ${ttl}s for $user"
      else
        _emit_warn "GPG cache TTL is ${ttl}s for $user (consider ≤ 600)"
      fi
    else
      _emit_info "No GPG cache TTL set for $user (default: 600s)"
    fi
  done < /etc/passwd
  [[ "$gpg_checked" -eq 0 ]] && _emit_info "No gpg-agent.conf found for any user"

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
      _emit_fail "Plaintext secret file (world-accessible $fperms): $f"
      secrets_found=1
    elif (( (8#${fperms:-777} & 8#070) != 0 )); then
      _emit_warn "Plaintext secret file (group-accessible $fperms): $f"
      secrets_warn=$((secrets_warn + 1))
    else
      _emit_info "Plaintext secret file (private $fperms — consider encrypting): $f"
      secrets_info=$((secrets_info + 1))
    fi
  done < <(_safe_find_home -maxdepth 6 -type f -size +0c \
    \( -name ".env" -o -name ".env.local" -o -name ".env.production" \
       -o -name ".env.development" -o -name ".password" -o -name ".secret" \
       -o -name ".credentials" -o -name "passwords.txt" -o -name "secrets.txt" \
       -o -name "credentials.json" \))
  while IFS=: read -r user _ uid _ _ home shell; do
    _is_human_uid "$uid" || continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    [[ -d "$home" ]] || continue
    if [[ -f "$home/.netrc" ]]; then
      local perms
      perms=$(stat -c '%a' "$home/.netrc" 2>/dev/null)
      if [[ "$perms" != "600" && "$perms" != "400" ]]; then
        _emit_fail ".netrc has insecure permissions ($perms) for $user"
      fi
    fi
  done < /etc/passwd
  [[ "$secrets_found" -eq 0 ]] && _emit_pass "No obvious plaintext secret files found"
}

# --- Run Security Sections (01-34) ---
# F-013: section bodies are now functions for consistency with privacy
# sections 35-42 (which were always functions). Each function gates on
# `should_skip "X" && return` and prints its own header.
check_kernel
check_selinux
check_firewall
check_nftables
check_vpn
check_sysctl
check_services
check_ports
check_ssh
check_audit
check_users
check_filesystem
check_crypto
check_updates
check_rootkit
check_processes
check_network
check_containers
check_logs
check_performance
check_hardware
check_interfaces
check_certificates
check_environment
check_systemd
check_desktop
check_ntp
check_fail2ban
check_logins
check_hardening
check_modules
check_permissions
check_boot
check_integrity

# --- Run Privacy & Desktop Sections (35-42) ---
check_browser_privacy
check_app_telemetry
check_network_privacy
check_data_privacy
check_desktop_session
check_media_privacy
check_bluetooth_privacy
check_keyring_security

# --- Firmware & Thunderbolt (independent of --skip keyring) ---
# F-269: keep section_id stable for JSON consumers — these sub-checks
# logically belong to "keyring" (last canonical section) rather than
# inheriting whatever section_id was set last. Without this, the JSON
# field ended up with mismatched section + section_id pairs.
CURRENT_SECTION="FIRMWARE & THUNDERBOLT"
CURRENT_SECTION_ID="keyring"
if command -v fwupdmgr &>/dev/null; then
  # LC_ALL=C — fwupdmgr translates "New version", "No upgrades" labels.
  fw_output=$(LC_ALL=C timeout 15 fwupdmgr get-updates --no-unreported-check 2>/dev/null)
  fw_exit=$?
  if [[ $fw_exit -eq 0 && -n "$fw_output" ]]; then
    update_count=$(echo "$fw_output" | grep -cE '│|New version')
    if [[ "$update_count" -gt 0 ]]; then
      _emit_warn "Firmware updates available (run: fwupdmgr update)"
    else
      _emit_pass "Firmware is up to date"
    fi
  elif [[ $fw_exit -eq 2 ]]; then
    _emit_pass "Firmware is up to date"
  elif echo "$fw_output" | grep -qiE 'no upgrades|no updates'; then
    _emit_pass "Firmware is up to date"
  else
    _emit_info "Could not check firmware updates"
  fi

  # v3.7: HSI (Host Security ID) — concrete firmware trust tier signal,
  # not just "fwupd installed?". HSI:2+ = typical secure baseline,
  # HSI:0 = fundamental issues. Adds real hardware-trust dimension.
  # `fwupdmgr security` has no --no-history-check flag (that one belongs to
  # `get-updates`). LC_ALL=C is mostly cosmetic here — the body labels remain
  # locale-translated by fwupd's own translation domain, but the "HSI:N"
  # prefix is English-stable so extraction works either way.
  _HSI_OUTPUT=$(LC_ALL=C timeout 10 fwupdmgr security 2>&1)
  _HSI_LEVEL=$(echo "$_HSI_OUTPUT" | grep -oE 'HSI:[0-9]' | head -1)
  if [[ -n "$_HSI_LEVEL" ]]; then
    case "$_HSI_LEVEL" in
      "HSI:0") _emit_fail "Firmware Trust: $_HSI_LEVEL (fundamental issues — see fwupdmgr security)" ;;
      "HSI:1") _emit_warn "Firmware Trust: $_HSI_LEVEL (basic protections only)" ;;
      "HSI:2") _emit_pass "Firmware Trust: $_HSI_LEVEL (system-protected — secure baseline)" ;;
      "HSI:3") _emit_pass "Firmware Trust: $_HSI_LEVEL (system-heavily-hardened)" ;;
      "HSI:4"|"HSI:5") _emit_pass "Firmware Trust: $_HSI_LEVEL (maximum hardening)" ;;
    esac
    # Count attestation failures via the cross marker only — `FAIL` as a
    # substring also occurs in benign body text (e.g. "FAIL-SAFE") and would
    # over-count.
    _HSI_FAILED=$(echo "$_HSI_OUTPUT" | grep -c '✘' || true)
    _HSI_FAILED="${_HSI_FAILED:-0}"
    if [[ "$_HSI_FAILED" -gt 0 ]]; then
      _emit_info "Firmware: $_HSI_FAILED HSI attestations not passing (run: fwupdmgr security)"
    fi
  else
    _emit_info "Firmware Trust: HSI level not reported (fwupd version too old?)"
  fi
else
  _emit_info "fwupdmgr not installed — cannot check firmware updates or HSI level"
fi

tb_found=0
for dev in /sys/bus/thunderbolt/devices/*/security; do
  [[ -f "$dev" ]] || continue
  tb_found=1
  level=$(cat "$dev" 2>/dev/null)
  devname=$(basename "$(dirname "$dev")")
  case "$level" in
    none)  _emit_fail "Thunderbolt device $devname: security level NONE (DMA attacks possible)" ;;
    user)  _emit_pass "Thunderbolt device $devname: user authorization required" ;;
    secure) _emit_pass "Thunderbolt device $devname: secure connect (key verification)" ;;
    dponly) _emit_pass "Thunderbolt device $devname: DisplayPort only (no PCIe tunneling)" ;;
    *)     _emit_info "Thunderbolt device $devname: security level '$level'" ;;
  esac
done
if [[ "$tb_found" -eq 0 ]]; then
  if [[ -d /sys/bus/thunderbolt ]]; then
    _emit_info "Thunderbolt bus present but no devices connected"
  else
    _emit_info "No Thunderbolt controller detected"
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
  RATING="🏰 FULLY HARDENED"
  RATING_COLOR="$GRN"
elif [[ "$SCORE" -ge 90 ]]; then
  RATING="🛡️ WELL-HARDENED"
  RATING_COLOR="$GRN"
elif [[ "$SCORE" -ge 80 ]]; then
  RATING="🛡️ MOSTLY-HARDENED"
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
  _AI_TEXT="I ran NoID Privacy for Linux v${NOID_PRIVACY_VERSION} — a 420+ check hardening posture audit.
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

NOTE: this prompt lists only FAIL/WARN findings. INFO-level entries
(VPN status, kernel taint flags, package counts, etc) provide context
but rarely require action — see the full audit output for those.

For each finding: explain the risk, show the exact fix command,
warn if it could break anything, and ask before applying.
Verify each command against current system state before suggesting.
If you cannot verify a fact, say so."
fi

if $JSON_MODE; then
  # --- JSON Output ---
  TOTAL=$((PASS + FAIL + WARN + INFO))
  # F-303: include timezone offset (RFC 3339 / ISO 8601 full form). Without
  # %z the timestamp was ambiguous between UTC and local time, breaking
  # downstream JSON consumers that need to compare audit runs across hosts.
  JSON_TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S%z')
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
  # Embed ai_prompt as JSON field when --ai was set (F-272 era integration —
  # eliminates the entrypoint.sh double-run for action wrapper).
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
  printf "${BOLD}${WHT}║${RST}  Hardening posture is your defense foundation — the layer\n"
  printf "${BOLD}${WHT}║${RST}  attackers must defeat first. Complement with:\n"
  printf "${BOLD}${WHT}║${RST}    ${GRN}✓${RST} AIDE / IMA   — file & kernel integrity\n"
  printf "${BOLD}${WHT}║${RST}    ${GRN}✓${RST} auditd       — behavioral monitoring\n"
  printf "${BOLD}${WHT}║${RST}    ${GRN}✓${RST} chkrootkit   — known-malware scanner\n"
  printf "${BOLD}${WHT}╠══════════════════════════════════════════════════════════════════════╣${RST}\n"
  printf "${BOLD}${WHT}║${RST}  Score formula:     PASS×100 / (PASS + FAIL×2 + WARN)\n"
  printf "${BOLD}${WHT}║${RST}  ${BOLD}HARDENING POSTURE SCORE:${RST}     ${RATING_COLOR}${BOLD}${SCORE}%% ${RATING}${RST}\n"
  printf "${BOLD}${WHT}║${RST}  Kernel:            %s\n" "$KERNEL"
  printf "${BOLD}${WHT}║${RST}  Uptime:            %s\n" "$(uptime -p 2>/dev/null || echo 'N/A')"
  printf "${BOLD}${WHT}║${RST}  Scan duration:     %s seconds\n" "$DURATION"
  printf "${BOLD}${WHT}╚══════════════════════════════════════════════════════════════════════╝${RST}\n"
  echo ""
  printf "${CYN}Report generated: $NOW${RST}\n"
  printf "${CYN}by NexusOne23 — NoID Privacy for Linux v${NOID_PRIVACY_VERSION} | https://noid-privacy.com/linux.html${RST}\n"

  # --- v3.9: Compliance coverage report (if --cis-l1 / --cis-l2 / --stig set) ---
  if [[ -n "$COMPLIANCE_MODE" ]]; then
    _NOID_DIR="$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")"
    _COVERAGE_SCRIPT="$_NOID_DIR/scripts/coverage-report.sh"
    if [[ -x "$_COVERAGE_SCRIPT" ]]; then
      echo ""
      printf "${BOLD}${MAG}━━━ COMPLIANCE COVERAGE (%s) ━━━${RST}\n" "$COMPLIANCE_MODE"
      bash "$_COVERAGE_SCRIPT" "$COMPLIANCE_MODE" 2>/dev/null || \
        printf "${YLW}⚠️  Coverage report unavailable — see Docs/CIS_RHEL9_MAPPING.md${RST}\n"
      echo ""
      printf "${CYN}Detail: Docs/CIS_RHEL9_MAPPING.md (mapping table)${RST}\n"
      printf "${CYN}Note:   Run-time per-check coverage requires per-finding tagging${RST}\n"
      printf "${CYN}        (planned for v3.10 — current is static doc-based summary).${RST}\n"
    else
      printf "${YLW}⚠️  Compliance flag set but scripts/coverage-report.sh not found${RST}\n"
    fi
  fi

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
