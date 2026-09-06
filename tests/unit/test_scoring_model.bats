#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"

  # These globals are consumed by the sourced production score-model block.
  # shellcheck disable=SC2034
  SECTION_KEYS=(security privacy performance)
  # shellcheck disable=SC2034
  declare -gA SECTION_WEIGHTS=(
    [security]=6
    [privacy]=4
    [performance]=0
  )
  declare -gA SECTION_PASS_COUNTS=()
  # shellcheck disable=SC2034
  declare -gA SECTION_FAIL_COUNTS=()
  # shellcheck disable=SC2034
  declare -gA SECTION_WARN_COUNTS=()
  # shellcheck disable=SC2034
  declare -gA SECTION_INFO_COUNTS=()
  # shellcheck disable=SC2034  # consumed by the sourced production score block
  declare -gA SECTION_INCOMPLETE_COUNTS=()
  declare -gA SECTION_SCORE_STATUS=()
  declare -gA SECTION_SCORE_GRADE=()
  _SECTION_WEIGHT_TOTAL=10

  # Source the production implementation without executing the audit.
  # shellcheck source=/dev/null
  source <(sed -n \
    '/^# BEGIN NOID SCORE MODEL$/,/^# END NOID SCORE MODEL$/p' "$SCRIPT")
}

@test "production section weights cover every canonical section and total 100" {
  run bash -c '
    script="$1"
    block=$(sed -n "/^declare -a SECTION_KEYS=(/,/^)/p" "$script")
    weights=$(sed -n "/^declare -A SECTION_WEIGHTS=(/,/^)/p" "$script")
    eval "$block"
    eval "$weights"
    total=0
    for section in "${SECTION_KEYS[@]}"; do
      [[ "${SECTION_WEIGHTS[$section]+set}" ]] || exit 10
      total=$((total + SECTION_WEIGHTS[$section]))
    done
    [[ "${#SECTION_KEYS[@]}" -eq "${#SECTION_WEIGHTS[@]}" ]] || exit 11
    [[ "$total" -eq 100 ]]
  ' _ "$SCRIPT"
  [[ "$status" -eq 0 ]]
}

@test "performance observations have zero security/privacy weight" {
  run grep -qE '\[performance\]=0([[:space:]]|$)' "$SCRIPT"
  [[ "$status" -eq 0 ]]
}

@test "raw interface and connectivity inventory has zero posture weight" {
  run grep -qE '\[interfaces\]=0([[:space:]]|$)' "$SCRIPT"
  [[ "$status" -eq 0 ]]
}

@test "generic certificate and systemd inventories have zero posture weight" {
  grep -qE '\[certificates\]=0([[:space:]]|$)' "$SCRIPT"
  grep -qE '\[systemd\]=0([[:space:]]|$)' "$SCRIPT"
}

@test "authentication is highest and broad direct boundaries receive weight five" {
  grep -qE '\[users\]=6([[:space:]]|$)' "$SCRIPT"
  grep -qE '\[kernel\]=5([[:space:]]|$)' "$SCRIPT"
  grep -qE '\[filesystem\]=5([[:space:]]|$)' "$SCRIPT"
  grep -qE '\[integrity\]=5([[:space:]]|$)' "$SCRIPT"
  grep -qE '\[browser\]=5([[:space:]]|$)' "$SCRIPT"
  grep -qE '\[session\]=5([[:space:]]|$)' "$SCRIPT"
  grep -qE '\[keyring\]=5([[:space:]]|$)' "$SCRIPT"
}

@test "audit evidence receives foundational weight three" {
  run grep -qE '\[audit\]=3([[:space:]]|$)' "$SCRIPT"
  [[ "$status" -eq 0 ]]
}

@test "heuristic and activity inventories cannot affect posture" {
  for section in rootkit processes logs fail2ban logins; do
    grep -qE "\[$section\]=0([[:space:]]|$)" "$SCRIPT"
  done
}

@test "direct secret and exposed-port evidence outrank generic services" {
  grep -qE '\[environment\]=2([[:space:]]|$)' "$SCRIPT"
  grep -qE '\[ports\]=3([[:space:]]|$)' "$SCRIPT"
  grep -qE '\[services\]=1([[:space:]]|$)' "$SCRIPT"
}

@test "one PASS and one hundred PASS findings produce the same section grade" {
  # shellcheck disable=SC2034
  CURRENT_SECTION_ID=security
  _score_record PASS
  _score_calculate
  one_grade="${SECTION_SCORE_GRADE[security]}"

  for _ in $(seq 1 99); do _score_record PASS; done
  _score_calculate
  [[ "$one_grade" -eq 100 ]]
  [[ "${SECTION_SCORE_GRADE[security]}" -eq "$one_grade" ]]
  [[ "$SCORE" -eq 100 ]]
  [[ "$SCORE_COVERAGE" -eq 60 ]]
}

@test "WARN determines a section grade of 50 regardless of PASS volume" {
  CURRENT_SECTION_ID=security
  for _ in $(seq 1 20); do _score_record PASS; done
  _score_record WARN
  _score_calculate
  [[ "${SECTION_SCORE_STATUS[security]}" == "warn" ]]
  [[ "${SECTION_SCORE_GRADE[security]}" -eq 50 ]]
  [[ "$SCORE" -eq 50 ]]
}

@test "FAIL dominates WARN and PASS within its section" {
  CURRENT_SECTION_ID=security
  _score_record PASS
  _score_record WARN
  _score_record FAIL
  _score_calculate
  [[ "${SECTION_SCORE_STATUS[security]}" == "fail" ]]
  [[ "${SECTION_SCORE_GRADE[security]}" -eq 0 ]]
  [[ "$SCORE" -eq 0 ]]
}

@test "unassessed sections reduce coverage instead of silently raising score" {
  CURRENT_SECTION_ID=security
  _score_record PASS
  CURRENT_SECTION_ID=privacy
  _score_record INFO
  _score_calculate
  [[ "${SECTION_SCORE_STATUS[privacy]}" == "unassessed" ]]
  [[ -z "${SECTION_SCORE_GRADE[privacy]}" ]]
  [[ "$SCORE" -eq 100 ]]
  [[ "$SCORE_ASSESSED_WEIGHT" -eq 6 ]]
  [[ "$SCORE_COVERAGE" -eq 60 ]]
}

@test "incomplete required evidence unassesses PASS but never hides adverse evidence" {
  CURRENT_SECTION_ID=security
  _score_record PASS
  _score_mark_incomplete
  CURRENT_SECTION_ID=privacy
  _score_record PASS
  _score_calculate
  [[ "${SECTION_SCORE_STATUS[security]}" == "unassessed" ]]
  [[ "${SECTION_SCORE_STATUS[privacy]}" == "pass" ]]
  [[ "$SCORE_ASSESSED_WEIGHT" -eq 4 ]]

  CURRENT_SECTION_ID=security
  _score_record WARN
  _score_calculate
  [[ "${SECTION_SCORE_STATUS[security]}" == "warn" ]]
  [[ "${SECTION_SCORE_GRADE[security]}" -eq 50 ]]
}

@test "fixed weights combine section grades predictably" {
  CURRENT_SECTION_ID=security
  _score_record WARN
  CURRENT_SECTION_ID=privacy
  _score_record PASS
  _score_calculate
  # (6*50 + 4*100) / 10 = 70
  [[ "$SCORE" -eq 70 ]]
  [[ "$SCORE_COVERAGE" -eq 100 ]]
}

@test "unknown section and severity cannot corrupt score state" {
  # shellcheck disable=SC2034
  CURRENT_SECTION_ID=unknown
  _score_record PASS
  [[ "${#SECTION_PASS_COUNTS[@]}" -eq 0 ]]

  # shellcheck disable=SC2034
  CURRENT_SECTION_ID=security
  run _score_record BROKEN
  [[ "$status" -eq 2 ]]
  [[ "${#SECTION_PASS_COUNTS[@]}" -eq 0 ]]
}
