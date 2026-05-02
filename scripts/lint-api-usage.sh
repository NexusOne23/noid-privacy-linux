#!/usr/bin/env bash
#
# Lint: forbid direct API calls that bypass the v3.8 capability layer
# or repeat any of the 5 bug-pattern classes from the 2026-04 audit.
#
# Run as part of CI to catch regressions where someone adds a new section
# using firewall-cmd --get-policies directly instead of _fw_get_policies(),
# the systemctl is-masked anti-pattern, or grep -r on symlinked dirs.
#
# Exit 0 = clean, 1 = violations found.

set -euo pipefail

SCRIPT="${1:-noid-privacy-linux.sh}"

if [[ ! -f "$SCRIPT" ]]; then
  echo "::error::Script not found: $SCRIPT"
  exit 1
fi

EXIT_CODE=0

# --- Pattern 1: firewall-cmd policy API outside capability layer ---
# Direct calls to --get-policies or --list-policies must go through
# _fw_get_policies(). Exception: the capability-detection helper itself.
echo "[1/11] Checking for direct firewalld policy API calls..."
violations=$(grep -nE 'firewall-cmd[[:space:]]+--(get|list)-policies' "$SCRIPT" \
  | grep -vE '_detect_capabilities|_fw_get_policies|_CAPS\[firewalld|CAP-LINT-EXEMPT' \
  | grep -vE '^[[:space:]]*[0-9]+:[[:space:]]*#' \
  || true)
if [[ -n "$violations" ]]; then
  echo "::error::Direct firewall-cmd policy API call — use _fw_get_policies():"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 2: systemctl is-masked (verb does not exist) ---
echo "[2/11] Checking for systemctl is-masked anti-pattern..."
violations=$(grep -nE 'systemctl[[:space:]]+is-masked' "$SCRIPT" || true)
if [[ -n "$violations" ]]; then
  echo "::error::systemctl is-masked is not a valid verb — use _service_masked_any():"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 3: grep -r on /etc/pam.d (Fedora authselect symlinks) ---
# Fedora ships /etc/pam.d/system-auth as a symlink into /etc/authselect/.
# `grep -r` does NOT follow symlinks during traversal — must use `-R`.
echo "[3/11] Checking for grep -r on /etc/pam.d (must be -R)..."
violations=$(grep -nE 'grep[[:space:]]+-[^[:space:]]*r[^[:space:]R]*[[:space:]][^|]*/etc/pam\.d' "$SCRIPT" \
  || true)
if [[ -n "$violations" ]]; then
  echo "::error::grep -r on /etc/pam.d misses authselect symlinks — use grep -R:"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 4: command -v for names that shadow internal functions ---
# After v3.6 the only internal functions that match CLI tool names are
# things like sub_header, txt, header — all of which don't shadow real
# tools. But `pass`, `fail`, `warn`, `info` were the original culprits.
# We added _emit_* prefix; bare names should never come back.
echo "[4/11] Checking for re-introduction of bare emit function names..."
violations=$(grep -nE '^(pass|fail|warn|info)\(\)' "$SCRIPT" || true)
if [[ -n "$violations" ]]; then
  echo "::error::Bare emit function names re-introduced — use _emit_* prefix:"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 5: locale-dependent grep on chage output without LC_ALL=C ---
# `chage -l` output is translated. grep "Maximum" silently misses German
# "Maximale Anzahl..." → silent FALSE PASS on non-English systems.
echo "[5/11] Checking for chage parsing without LC_ALL=C..."
violations=$(grep -nE 'chage[[:space:]]+-l' "$SCRIPT" \
  | grep -vE 'LC_ALL=C[[:space:]]+chage' \
  | grep -vE '^[[:space:]]*[0-9]+:[[:space:]]*#' \
  || true)
if [[ -n "$violations" ]]; then
  echo "::error::chage -l without LC_ALL=C — locale-dependent grep will fail on non-English systems:"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 6: hardcoded VPN-iface regex bypassing _VPN_IFACE_REGEX ---
# Bug Pattern #5: hand-written subsets of the VPN families list silently
# misclassify Tailscale/ZeroTier/Mullvad/etc. when only Proton/WireGuard are
# matched. Regression magnet — re-spotted in the v3.10 audit. Use the global.
echo "[6/11] Checking for hardcoded VPN-iface regex (must use \$_VPN_IFACE_REGEX)..."
violations=$(grep -nE '\(tun\|tap\|wg\|proton\|pvpn\|tailscale\|zt\|nebula\|mullvad\|nordlynx\)' "$SCRIPT" \
  | grep -vE '_VPN_IFACE_REGEX=' \
  | grep -vE '^[[:space:]]*[0-9]+:[[:space:]]*#' \
  || true)
if [[ -n "$violations" ]]; then
  echo "::error::Hardcoded VPN-iface regex — use \$_VPN_IFACE_REGEX (or pass via awk -v):"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 7: df -T with NR==2 awk extraction (wrap risk) ---
# `df -T <path>` can wrap output when device names are long (LUKS-LVM dm-X).
# `awk 'NR==2{print $2}'` then reads from the wrapped continuation line and
# returns garbage. Use findmnt or `df -PT | tail -1`.
echo "[7/11] Checking for df -T NR==2 patterns (wrap-vulnerable)..."
violations=$(grep -nE 'df -T[^|]*\|[[:space:]]*awk .NR==2' "$SCRIPT" \
  | grep -vE '^[[:space:]]*[0-9]+:[[:space:]]*#' \
  || true)
if [[ -n "$violations" ]]; then
  echo "::error::df -T with awk NR==2 wraps on long device names — use findmnt -no FSTYPE or df -PT | tail -1:"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 8: locale-aware tools without LC_ALL=C (defensive) ---
# fwupdmgr/bluetoothctl/free emit translated labels on non-English locales.
# Audit data extraction must force LC_ALL=C so labels stay parseable.
echo "[8/11] Checking for fwupdmgr/bluetoothctl without LC_ALL=C..."
violations=$(grep -nE '\$\([^)]*\b(fwupdmgr|bluetoothctl)[[:space:]]+[a-z]' "$SCRIPT" \
  | grep -vE 'LC_ALL=C' \
  | grep -vE '_detect_capabilities|CAP-LINT-EXEMPT' \
  | grep -vE '^[[:space:]]*[0-9]+:[[:space:]]*#' \
  || true)
if [[ -n "$violations" ]]; then
  echo "::error::fwupdmgr/bluetoothctl invocation without LC_ALL=C — locale-dependent labels will fail on non-English systems:"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 9: ((var <op>)) arithmetic returning value — bombs under set -e ---
# Bash arithmetic-command returns rc=1 when result == 0:
#   ((var++))   — post-increment, returns OLD value (false when OLD was 0)
#   ((var--))   — post-decrement, returns OLD value (false when OLD was 0)
#   ((var+=N))  — compound-assign, returns NEW value (false when NEW becomes 0)
#   ((var-=N))  — same risk; ((var*=N))/((var/=N))/((var%=N)) too
# Under set -e (BATS default, many CI scripts) this aborts the calling shell.
# Use plain `var=$((var + N))` / `var=$((var - N))` form instead.
# F-306 (v3.6.1): pattern extended from ++ only to all dangerous forms after
# self-audit found `((_SUSPICIOUS_HIST += _SH_SUSP))` slipped through.
# See: feedback_bash_double_paren_increment.md (memory pattern doc).
echo "[9/11] Checking for ((var<op>)) arithmetic-command counters..."
violations=$(grep -nE '\(\([A-Za-z_][A-Za-z0-9_]*[[:space:]]*(\+\+|--|[-+*/%]=)' "$SCRIPT" \
  | grep -vE '^[[:space:]]*[0-9]+:[[:space:]]*#' \
  || true)
if [[ -n "$violations" ]]; then
  echo "::error::((var<op>)) arithmetic-command found — use 'var=\$((var + N))' form (rc=1 when result=0 bombs under set -e):"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 10: missing LC_ALL=C on systemd-analyze / virsh / resolvectl / free ---
# Same locale-translation class as Pattern 8, separate tool list.
# systemd-analyze score outputs / virsh status / resolvectl labels / free
# columns are all locale-translatable on de_DE/fr_FR/etc systems.
# F-307 (v3.6.1): the `free` sub-pattern previously required pipe directly
# after `free<space>` and missed `free -h | awk` / `free -h -m | awk` forms.
# Self-audit found 5 such sites parsing `^Mem:`/`^Swap:` headers that German
# locale translates to `Speicher:`/`Auslag.:` — silently empty MEM_TOTAL etc.
# Now matches free with any number of `-flag` args before the pipe.
echo "[10/11] Checking for systemd-analyze / virsh / resolvectl / free without LC_ALL=C..."
violations=$(grep -nE '\$\([^)]*\b(systemd-analyze[[:space:]]+(blame|security)|virsh[[:space:]]+list|resolvectl[[:space:]]+status|free([[:space:]]+-[a-zA-Z]+)*[[:space:]]*\|)' "$SCRIPT" \
  | grep -vE 'LC_ALL=C' \
  | grep -vE '^[[:space:]]*[0-9]+:[[:space:]]*#' \
  || true)
if [[ -n "$violations" ]]; then
  echo "::error::systemd-analyze/virsh/resolvectl/free invocation without LC_ALL=C — locale labels will fail parsing on non-English systems:"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

# --- Pattern 11: grep nameserver without ^ anchor on resolv.conf ---
# Unanchored `grep nameserver /etc/resolv.conf` matches commented entries
# (e.g. `# nameserver 1.2.3.4`) and reports them as active DNS servers.
# Must anchor: `^[[:space:]]*nameserver[[:space:]]`.
echo "[11/11] Checking for unanchored 'grep nameserver' on /etc/resolv.conf..."
violations=$(grep -nE 'grep[[:space:]]+nameserver[[:space:]]+/etc/resolv\.conf' "$SCRIPT" \
  | grep -vE '^[[:space:]]*[0-9]+:[[:space:]]*#' \
  || true)
if [[ -n "$violations" ]]; then
  echo "::error::Unanchored 'grep nameserver' matches commented entries — use 'grep -E ^[[:space:]]*nameserver[[:space:]]':"
  echo "$violations" | sed 's/^/  /'
  EXIT_CODE=1
fi

if [[ "$EXIT_CODE" -eq 0 ]]; then
  echo ""
  echo "✅ Lint passed — no API-layer or bug-pattern violations"
else
  echo ""
  echo "❌ Lint failed — see violations above"
  echo "   Reference: feedback_noid_audit_bug_patterns.md"
fi
exit $EXIT_CODE
