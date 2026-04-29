#!/usr/bin/env bash
###############################################################################
#  NoID Privacy for Linux — GitHub Action Entrypoint
#  Runs the audit, parses JSON output, generates summary, sets outputs
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_SCRIPT="${SCRIPT_DIR}/noid-privacy-linux.sh"

if [[ ! -f "$AUDIT_SCRIPT" ]]; then
  echo "::error::noid-privacy-linux.sh not found at ${AUDIT_SCRIPT}"
  exit 1
fi

# --- Build command ---
CMD=(sudo bash "$AUDIT_SCRIPT" --json --no-color)

# --ai flag: now combines with --json (single run, embedded ai_prompt field)
if [[ "${INPUT_AI:-false}" == "true" ]]; then
  CMD+=(--ai)
fi

# --skip sections
if [[ -n "${INPUT_SKIP:-}" ]]; then
  IFS=',' read -ra SECTIONS <<< "$INPUT_SKIP"
  for section in "${SECTIONS[@]}"; do
    section="${section// /}"  # trim whitespace via parameter expansion
    [[ -n "$section" ]] && CMD+=(--skip "$section")
  done
fi

# Additional args
if [[ -n "${INPUT_ARGS:-}" ]]; then
  read -ra EXTRA_ARGS <<< "$INPUT_ARGS"
  CMD+=("${EXTRA_ARGS[@]}")
fi

# F-272: min-score is canonical (semantic-correct name); fail-threshold
# is the deprecated v3.x alias. Either one accepted — new takes priority.
MIN_SCORE_THRESHOLD="${INPUT_MIN_SCORE:-${INPUT_FAIL_THRESHOLD:-0}}"

# --- Run audit (single JSON run with optional ai_prompt embedded) ---
echo "::group::Running NoID Privacy Audit"
echo "Command: ${CMD[*]}"

# F-271 wired to F-007: capture audit exit code so we can distinguish
# clean (0) / FAIL-present (1) / WARN-only (2) / interrupted (130/143)
# from JSON-parse failures further down. `set -euo pipefail` would kill
# us on rc>0 from the audit, so wrap explicitly.
set +e
JSON_OUTPUT=$("${CMD[@]}" 2>/dev/null)
AUDIT_EXIT=$?
set -e
echo "::endgroup::"
echo "Audit exit code: ${AUDIT_EXIT}"

# --- Parse JSON ---
if ! echo "$JSON_OUTPUT" | jq -e '.summary' >/dev/null 2>&1; then
  echo "::error::Failed to parse audit JSON output"
  echo "Raw output (first 50 lines):"
  echo "$JSON_OUTPUT" | head -50
  exit 1
fi

SCORE=$(echo "$JSON_OUTPUT" | jq -r '.summary.score')
TOTAL=$(echo "$JSON_OUTPUT" | jq -r '.summary.total')
PASS=$(echo "$JSON_OUTPUT" | jq -r '.summary.pass')
FAIL_COUNT=$(echo "$JSON_OUTPUT" | jq -r '.summary.fail')
WARN=$(echo "$JSON_OUTPUT" | jq -r '.summary.warn')
INFO=$(echo "$JSON_OUTPUT" | jq -r '.summary.info')
DISTRO=$(echo "$JSON_OUTPUT" | jq -r '.system.distro // "unknown"')
KERNEL=$(echo "$JSON_OUTPUT" | jq -r '.system.kernel // "unknown"')
VERSION=$(echo "$JSON_OUTPUT" | jq -r '.version // "unknown"')

# --- Score rating + Shields.io badge color ---
# Strings must match noid-privacy-linux.sh ratings (v3.6+: Hardening Posture wording)
if [[ "$SCORE" -ge 95 ]]; then
  RATING="🏰 FULLY HARDENED"
  BADGE_COLOR="brightgreen"
elif [[ "$SCORE" -ge 90 ]]; then
  RATING="🛡️ WELL-HARDENED"
  BADGE_COLOR="green"
elif [[ "$SCORE" -ge 80 ]]; then
  RATING="🛡️ MOSTLY-HARDENED"
  BADGE_COLOR="yellowgreen"
elif [[ "$SCORE" -ge 70 ]]; then
  RATING="⚠️ NEEDS WORK"
  BADGE_COLOR="orange"
else
  RATING="🔴 CRITICAL"
  BADGE_COLOR="red"
fi

# --- Set outputs (grouped redirect — SC2129 clean) ---
{
  echo "score=${SCORE}"
  echo "total=${TOTAL}"
  echo "pass=${PASS}"
  echo "fail=${FAIL_COUNT}"
  echo "warn=${WARN}"
  echo "info=${INFO}"
  echo "rating=${RATING}"
  echo "badge_color=${BADGE_COLOR}"
  echo "badge_url=https://img.shields.io/badge/Score-${SCORE}%25-${BADGE_COLOR}"
  # Full JSON in heredoc (multiline-safe)
  echo "json<<NOID_JSON_EOF"
  echo "$JSON_OUTPUT"
  echo "NOID_JSON_EOF"
} >> "$GITHUB_OUTPUT"

# --- Generate GitHub Summary ---
{
  echo "# 🛡️ NoID Privacy for Linux — Audit Results"
  echo ""
  echo "| | |"
  echo "|---|---|"
  echo "| **Score** | **${SCORE}%** ${RATING} |"
  echo "| **Version** | ${VERSION} |"
  echo "| **Distro** | ${DISTRO} |"
  echo "| **Kernel** | ${KERNEL} |"
  echo "| **Min-Score Threshold** | ${MIN_SCORE_THRESHOLD}% |"
  echo ""
  echo "## 📊 Summary"
  echo ""
  echo "| Check | Count |"
  echo "|-------|------:|"
  echo "| ✅ Pass | ${PASS} |"
  echo "| ❌ Fail | ${FAIL_COUNT} |"
  echo "| ⚠️ Warn | ${WARN} |"
  echo "| ℹ️ Info | ${INFO} |"
  echo "| **Total** | **${TOTAL}** |"
  echo ""

  # --- Failures ---
  FAIL_FINDINGS=$(echo "$JSON_OUTPUT" | jq -r '.findings[] | select(.severity == "FAIL") | "| `\(.section)` | \(.message) |"' 2>/dev/null || true)
  if [[ -n "$FAIL_FINDINGS" ]]; then
    echo "## ❌ Failures"
    echo ""
    echo "| Section | Finding |"
    echo "|---------|---------|"
    echo "$FAIL_FINDINGS"
    echo ""
  fi

  # --- Warnings ---
  WARN_FINDINGS=$(echo "$JSON_OUTPUT" | jq -r '.findings[] | select(.severity == "WARN") | "| `\(.section)` | \(.message) |"' 2>/dev/null || true)
  if [[ -n "$WARN_FINDINGS" ]]; then
    echo "<details>"
    echo "<summary>⚠️ Warnings (${WARN})</summary>"
    echo ""
    echo "| Section | Finding |"
    echo "|---------|---------|"
    echo "$WARN_FINDINGS"
    echo ""
    echo "</details>"
    echo ""
  fi

  # --- AI Prompt (now embedded in JSON when --ai was set) ---
  AI_PROMPT=$(echo "$JSON_OUTPUT" | jq -r '.ai_prompt // empty' 2>/dev/null)
  if [[ -n "$AI_PROMPT" ]]; then
    echo "## 🤖 AI Remediation Prompt"
    echo ""
    echo "<details>"
    echo "<summary>Click to expand AI prompt</summary>"
    echo ""
    echo '```'
    echo "$AI_PROMPT"
    echo '```'
    echo ""
    echo "</details>"
    echo ""
  fi

  echo "---"
  echo ""
  echo "*Generated by [NoID Privacy for Linux](https://github.com/NexusOne23/noid-privacy-linux) v${VERSION}*"
} >> "$GITHUB_STEP_SUMMARY"

echo "✅ Audit complete: Score ${SCORE}% (${TOTAL} checks: ${PASS} pass, ${FAIL_COUNT} fail, ${WARN} warn, ${INFO} info)"

# --- Threshold check ---
if [[ "$MIN_SCORE_THRESHOLD" -gt 0 ]] && [[ "$SCORE" -lt "$MIN_SCORE_THRESHOLD" ]]; then
  echo "::error::Hardening posture score ${SCORE}% is below minimum threshold ${MIN_SCORE_THRESHOLD}%"
  exit 1
fi

# Note: the audit script itself returns:
#   0 = clean (no FAIL)
#   1 = FAIL present (the score-threshold check above already handled this case)
#   2 = WARN-only
# We deliberately do NOT propagate rc=2 as a job failure — it's informational
# and would make every cosmetic warning fail the workflow. Users who want
# strict mode can use a higher fail-threshold input or check `outputs.warn`.
if [[ "$AUDIT_EXIT" -eq 130 || "$AUDIT_EXIT" -eq 143 ]]; then
  echo "::warning::Audit was interrupted (signal-induced exit ${AUDIT_EXIT})"
fi
exit 0
