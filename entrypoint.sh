#!/usr/bin/env bash
###############################################################################
#  NoID Privacy for Linux — GitHub Action Entrypoint
#  Runs the audit, parses JSON output, generates summary, sets outputs
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_SCRIPT="${SCRIPT_DIR}/noid-privacy-linux.sh"

# Findings can contain hostile filenames or configuration values. JSON escaping
# is not sufficient when those strings are later rendered as GitHub Markdown;
# encode HTML and table/code delimiters before writing the job summary.
_markdown_escape() {
  local s="$1" out="" char code escaped i
  local LC_ALL=C
  for ((i=0; i<${#s}; i++)); do
    char="${s:i:1}"
    printf -v code '%d' "'$char"
    if [[ "$code" -lt 32 || "$code" -eq 127 ]]; then
      printf -v escaped '\\u%04x' "$code"
      out+="$escaped"
    else
      out+="$char"
    fi
  done
  s="$out"
  s="${s//&/\&amp;}"
  s="${s//</\&lt;}"
  s="${s//>/\&gt;}"
  s="${s//|/\&#124;}"
  s="${s//\`/\&#96;}"
  printf '%s' "$s"
}

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
# is the deprecated alias. Either one accepted — min-score takes priority.
# action.yml defaults min-score to '0' (= never fail), so the variable is
# always non-empty — a plain ${A:-${B}} fallback would never consult the
# alias. Treat the '0' default as "unset" and fall back to fail-threshold
# explicitly so workflows still using the deprecated alias keep working.
MIN_SCORE_THRESHOLD="${INPUT_MIN_SCORE:-0}"
if [[ "$MIN_SCORE_THRESHOLD" == "0" && -n "${INPUT_FAIL_THRESHOLD:-}" ]]; then
  MIN_SCORE_THRESHOLD="$INPUT_FAIL_THRESHOLD"
fi
if [[ ! "$MIN_SCORE_THRESHOLD" =~ ^([0-9]|[1-9][0-9]|100)$ ]]; then
  echo "::error::min-score must be an integer from 0 to 100 (got: $(_markdown_escape "$MIN_SCORE_THRESHOLD"))"
  exit 1
fi
# Convert only after strict lexical validation so arithmetic cannot interpret
# user-controlled expressions or overflow-sized digit strings.
MIN_SCORE_THRESHOLD=$((10#$MIN_SCORE_THRESHOLD))

MIN_COVERAGE_THRESHOLD="${INPUT_MIN_COVERAGE:-0}"
if [[ ! "$MIN_COVERAGE_THRESHOLD" =~ ^([0-9]|[1-9][0-9]|100)$ ]]; then
  echo "::error::min-coverage must be an integer from 0 to 100 (got: $(_markdown_escape "$MIN_COVERAGE_THRESHOLD"))"
  exit 1
fi
MIN_COVERAGE_THRESHOLD=$((10#$MIN_COVERAGE_THRESHOLD))

# --- Run audit (single JSON run with optional ai_prompt embedded) ---
echo "::group::Running NoID Privacy Audit"
echo "Command: $(_markdown_escape "${CMD[*]}")"

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

case "$AUDIT_EXIT" in
  0|1|2) ;;
  130|143)
    echo "::error::Audit was interrupted (exit ${AUDIT_EXIT}); results are incomplete"
    exit 1
    ;;
  *)
    echo "::error::Audit failed with unexpected exit code ${AUDIT_EXIT}; results are not trustworthy"
    exit 1
    ;;
esac

# --- Parse and validate JSON ---
# A syntactically valid object is not enough: reject missing findings,
# impossible counters, unknown severities, a broken score model, or a summary
# that does not match the actual finding array.
if ! printf '%s\n' "$JSON_OUTPUT" | jq -e '
  (type == "object") and
  (.version | type == "string") and
  (.timestamp | type == "string") and
  (.system | type == "object") and
  ([.system.distro, .system.kernel, .system.hostname, .system.desktop]
    | all(type == "string")) and
  (.summary | type == "object") and
  (.scoring | type == "object") and
  (.scoring.model == "section-risk-v1") and
  (.scoring.sections | type == "array" and length == 42) and
  (.findings | type == "array") and
  ([.summary.total, .summary.pass, .summary.fail, .summary.warn, .summary.info]
    | all(type == "number" and . >= 0 and floor == .)) and
  (.summary.score | type == "number" and floor == . and . >= 0 and . <= 100) and
  (.summary.score_coverage | type == "number" and floor == . and . >= 0 and . <= 100) and
  (.summary.assessed_weight | type == "number" and floor == . and . >= 0) and
  (.summary.total_weight == 100) and
  (.summary.rating | type == "string" and length > 0) and
  (.scoring.sections | all(
    (.id | type == "string" and length > 0) and
    (.weight | type == "number" and floor == . and . >= 0) and
    ((.status == "pass") or (.status == "warn") or
     (.status == "fail") or (.status == "unassessed")) and
    ((.grade == null) or (.grade == 0) or (.grade == 50) or (.grade == 100)) and
    ([.pass, .fail, .warn, .info]
      | all(type == "number" and floor == . and . >= 0)) and
    (if .fail > 0 then .status == "fail" and .grade == 0
     elif .warn > 0 then .status == "warn" and .grade == 50
     elif .status == "pass" then .pass > 0 and .grade == 100
     else .status == "unassessed" and .grade == null end)
  )) and
  (([.scoring.sections[].id] | unique | length) == 42) and
  (([.scoring.sections[].weight] | add) == .summary.total_weight) and
  (([.scoring.sections[].pass] | add) == .summary.pass) and
  (([.scoring.sections[].fail] | add) == .summary.fail) and
  (([.scoring.sections[].warn] | add) == .summary.warn) and
  (([.scoring.sections[].info] | add) == .summary.info) and
  (.findings | all(
    ((.severity == "PASS") or (.severity == "FAIL") or
     (.severity == "WARN") or (.severity == "INFO")) and
    (.section | type == "string") and
    (.section_id | type == "string" and length > 0 and . != "unknown") and
    (.message | type == "string")
  )) and
  (.summary.total == (.findings | length)) and
  (.summary.pass == ([.findings[] | select(.severity == "PASS")] | length)) and
  (.summary.fail == ([.findings[] | select(.severity == "FAIL")] | length)) and
  (.summary.warn == ([.findings[] | select(.severity == "WARN")] | length)) and
  (.summary.info == ([.findings[] | select(.severity == "INFO")] | length)) and
  (([.scoring.sections[] | select(.grade != null and .weight > 0) | .weight] | add // 0)
    == .summary.assessed_weight) and
  (.summary.score_coverage ==
    (if .summary.total_weight > 0 then
       (((.summary.assessed_weight * 100) +
         ((.summary.total_weight / 2) | floor)) /
        .summary.total_weight | floor)
     else 0 end)) and
  (.summary.score ==
    (if .summary.assessed_weight > 0 then
       ((([.scoring.sections[] | select(.grade != null and .weight > 0) |
            (.weight * .grade)] | add // 0) +
         ((.summary.assessed_weight / 2) | floor)) /
        .summary.assessed_weight | floor)
     else 0 end)) and
  ((has("ai_prompt") | not) or (.ai_prompt | type == "string"))
' >/dev/null 2>&1; then
  echo "::error::Audit JSON is malformed or internally inconsistent"
  echo "Raw output (first 50 lines):"
  while IFS= read -r _raw_line; do
    printf '%s\n' "$(_markdown_escape "$_raw_line")"
  done < <(printf '%s\n' "$JSON_OUTPUT" | head -50)
  exit 1
fi

SCORE=$(echo "$JSON_OUTPUT" | jq -r '.summary.score')
SCORE_COVERAGE=$(echo "$JSON_OUTPUT" | jq -r '.summary.score_coverage')
TOTAL=$(echo "$JSON_OUTPUT" | jq -r '.summary.total')
PASS=$(echo "$JSON_OUTPUT" | jq -r '.summary.pass')
FAIL_COUNT=$(echo "$JSON_OUTPUT" | jq -r '.summary.fail')
WARN=$(echo "$JSON_OUTPUT" | jq -r '.summary.warn')
INFO=$(echo "$JSON_OUTPUT" | jq -r '.summary.info')
DISTRO=$(echo "$JSON_OUTPUT" | jq -r '.system.distro // "unknown"')
KERNEL=$(echo "$JSON_OUTPUT" | jq -r '.system.kernel // "unknown"')
VERSION=$(echo "$JSON_OUTPUT" | jq -r '.version // "unknown"')

# The script's exit status is part of the report contract. Fail closed if a
# truncated/buggy run returns a status that contradicts its own counters.
case "$AUDIT_EXIT" in
  0) [[ "$FAIL_COUNT" -eq 0 && "$WARN" -eq 0 ]] || {
       echo "::error::Audit exit 0 contradicts FAIL/WARN counters"; exit 1; } ;;
  1) [[ "$FAIL_COUNT" -gt 0 ]] || {
       echo "::error::Audit exit 1 without FAIL findings"; exit 1; } ;;
  2) [[ "$FAIL_COUNT" -eq 0 && "$WARN" -gt 0 ]] || {
       echo "::error::Audit exit 2 contradicts FAIL/WARN counters"; exit 1; } ;;
esac

# --- Score rating + Shields.io badge color ---
# Strings and thresholds must match noid-privacy-linux.sh. Coverage takes
# precedence so selective skipping cannot produce an overconfident badge.
if [[ "$SCORE_COVERAGE" -lt 50 ]]; then
  RATING="⚪ LIMITED EVIDENCE"
  BADGE_COLOR="lightgrey"
elif [[ "$SCORE" -ge 90 ]]; then
  RATING="🟢 STRONG POSTURE"
  BADGE_COLOR="green"
elif [[ "$SCORE" -ge 75 ]]; then
  RATING="🟡 MODERATE POSTURE"
  BADGE_COLOR="yellow"
elif [[ "$SCORE" -ge 50 ]]; then
  RATING="🟠 WEAK POSTURE"
  BADGE_COLOR="orange"
else
  RATING="🔴 HIGH EXPOSURE"
  BADGE_COLOR="red"
fi
[[ "$RATING" == "$(echo "$JSON_OUTPUT" | jq -r '.summary.rating')" ]] || {
  echo "::error::Audit rating contradicts its score/coverage"; exit 1; }

# --- Set outputs (grouped redirect — SC2129 clean) ---
{
  echo "score=${SCORE}"
  echo "score_coverage=${SCORE_COVERAGE}"
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
  echo "| **Assessed risk-weight coverage** | **${SCORE_COVERAGE}%** |"
  echo "| **Version** | $(_markdown_escape "$VERSION") |"
  echo "| **Distro** | $(_markdown_escape "$DISTRO") |"
  echo "| **Kernel** | $(_markdown_escape "$KERNEL") |"
  echo "| **Min-Score Threshold** | ${MIN_SCORE_THRESHOLD}% |"
  echo "| **Min-Coverage Threshold** | ${MIN_COVERAGE_THRESHOLD}% |"
  echo ""
  echo "## 📊 Summary"
  echo ""
  echo "| Finding severity | Count |"
  echo "|-------|------:|"
  echo "| ✅ Pass | ${PASS} |"
  echo "| ❌ Fail | ${FAIL_COUNT} |"
  echo "| ⚠️ Warn | ${WARN} |"
  echo "| ℹ️ Info | ${INFO} |"
  echo "| **Total** | **${TOTAL}** |"
  echo ""

  # --- Failures ---
  if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "## ❌ Failures"
    echo ""
    echo "| Section | Finding |"
    echo "|---------|---------|"
    while IFS=$'\t' read -r _section _message; do
      printf "| \`%s\` | %s |\n" "$(_markdown_escape "$_section")" "$(_markdown_escape "$_message")"
    done < <(echo "$JSON_OUTPUT" | jq -r '.findings[] | select(.severity == "FAIL") | [.section, .message] | @tsv')
    echo ""
  fi

  # --- Warnings ---
  if [[ "$WARN" -gt 0 ]]; then
    echo "<details>"
    echo "<summary>⚠️ Warnings (${WARN})</summary>"
    echo ""
    echo "| Section | Finding |"
    echo "|---------|---------|"
    while IFS=$'\t' read -r _section _message; do
      printf "| \`%s\` | %s |\n" "$(_markdown_escape "$_section")" "$(_markdown_escape "$_message")"
    done < <(echo "$JSON_OUTPUT" | jq -r '.findings[] | select(.severity == "WARN") | [.section, .message] | @tsv')
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
    printf '<pre>%s</pre>\n' "$(_markdown_escape "$AI_PROMPT")"
    echo ""
    echo "</details>"
    echo ""
  fi

  echo "---"
  echo ""
  echo "*Generated by [NoID Privacy for Linux](https://github.com/NexusOne23/noid-privacy-linux) v$(_markdown_escape "$VERSION")*"
} >> "$GITHUB_STEP_SUMMARY"

echo "✅ Audit complete: Score ${SCORE}% with ${SCORE_COVERAGE}% assessed risk-weight coverage (${TOTAL} findings: ${PASS} pass, ${FAIL_COUNT} fail, ${WARN} warn, ${INFO} info)"

# --- Threshold checks ---
if [[ "$MIN_COVERAGE_THRESHOLD" -gt 0 ]] \
   && [[ "$SCORE_COVERAGE" -lt "$MIN_COVERAGE_THRESHOLD" ]]; then
  echo "::error::Assessed risk-weight coverage ${SCORE_COVERAGE}% is below minimum threshold ${MIN_COVERAGE_THRESHOLD}%"
  exit 1
fi
if [[ "$MIN_SCORE_THRESHOLD" -gt 0 ]] && [[ "$SCORE" -lt "$MIN_SCORE_THRESHOLD" ]]; then
  echo "::error::Desktop posture score ${SCORE}% is below minimum threshold ${MIN_SCORE_THRESHOLD}%"
  exit 1
fi

# Note: the audit script itself returns:
#   0 = no FAIL or WARN findings
#   1 = one or more FAIL findings
#   2 = WARN-only
# Finding severities are exposed as outputs; the Action deliberately gates only
# on the explicit score/coverage inputs. Workflows that require zero FAIL or
# WARN findings can inspect `outputs.fail` / `outputs.warn` separately.
exit 0
