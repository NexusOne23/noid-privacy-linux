#!/usr/bin/env bats

# Bats and the extracted production block consume fixture functions/globals.
# shellcheck disable=SC2317,SC2034
# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # Load only the scheduled-status block, never the optional live AIDE check.
  # shellcheck disable=SC1090
  source <(
    printf '_production_aide_probe() {\n'
    awk '/^  # 2\. Optional fresh check/ {exit}
         /^sub_header "AIDE Integrity Status"/ {found=1}
         found {print}' "$SCRIPT"
    printf 'fi\n}\n'
  )
  # Read-only report helpers; adapt only their fixed directory/owner for
  # private ordinary-user fixtures. All status, parsing and selection is real.
  # shellcheck disable=SC1090
  source <(sed -n '/^_aide_invocation_report() {$/,/^}$/p' "$SCRIPT" \
    | sed '1s/_aide_invocation_report/_native_aide_invocation_report/')
  for helper in _aide_report_count _aide_report_drift_lines _aide_print_drift_lines; do
    # shellcheck disable=SC1090
    source <(sed -n "/^${helper}() {$/,/^}$/p" "$SCRIPT")
  done
  REPORT_DIR="$BATS_TEST_TMPDIR/reports"
  mkdir -m 0700 "$REPORT_DIR"
  INVOCATION=11111111111111111111111111111111
  JOURNAL_FAILURE=false
  JOURNAL_CAPTURE="$BATS_TEST_TMPDIR/journal-arguments.txt"
  # These globals are consumed by the dynamically loaded production block.
  # shellcheck disable=SC2034
  JSON_MODE=true
  _AIDE_DB="$BATS_TEST_TMPDIR/evidence.txt"
  printf 'synthetic metadata fixture, not an AIDE database\n' > "$_AIDE_DB"
  START_TIME='2026-09-01 12:00:00 UTC'
  END_TIME='2026-09-01 12:10:00 UTC'
  START_MONO=1000000000
  END_MONO=1600000000
  DB_MTIME=$(date -d '2026-09-01 11:00:00 UTC' +%s)
  DB_CTIME="$DB_MTIME"
  ACTIVE_STATE=inactive
  SUB_STATE=dead
  EXIT_CODE=1
  EXIT_STATUS=0
  QUERY_FAILURE=""
  PARTIAL_OUTPUT=false
  STAT_FAILURE=false
  SECOND_NEWER=false
  OMIT_PROPERTY=""
}

sub_header() { :; }
require_cmd() { [[ "$1" == aide ]]; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_aide_invocation_report() {
  _native_aide_invocation_report "$1" "$REPORT_DIR" "$EUID"
}
_finding_safe() { printf '%s' "$1"; }
journalctl() {
  printf '%s\n' "$@" > "$JOURNAL_CAPTURE"
  printf '%s\n' 'f++++++++++++++++: /fixture:space name'
  $JOURNAL_FAILURE && return 7
  return 0
}

stat() {
  if [[ "${*: -1}" != "$_AIDE_DB" ]]; then command stat "$@"; return; fi
  $STAT_FAILURE && return 1
  case "$2" in
    '%Y %Z') printf '%s %s\n' "$DB_MTIME" "$DB_CTIME" ;;
    '%Y') printf '%s\n' "$DB_MTIME" ;;
    *) return 2 ;;
  esac
}

systemctl() {
  local unit="$2" key value failed=false
  local load_state=loaded start="$START_TIME" end="$END_TIME"
  local start_mono="$START_MONO" end_mono="$END_MONO" exit_status="$EXIT_STATUS"
  [[ "$QUERY_FAILURE" == all || "$QUERY_FAILURE" == "$unit" ]] && failed=true
  if $failed && ! $PARTIAL_OUTPUT; then return 1; fi
  if [[ "$unit" == aide.service ]] && $SECOND_NEWER; then
    start='2026-09-01 12:20:00 UTC'
    end='2026-09-01 12:30:00 UTC'
    start_mono=2200000000
    end_mono=2800000000
    exit_status=4
  elif [[ "$unit" != aide-check.service ]]; then
    load_state=not-found
    start=''
    end=''
    start_mono=0
    end_mono=0
  fi
  for key in LoadState ActiveState SubState ExecMainCode ExecMainStatus \
             ExecMainStartTimestamp ExecMainExitTimestamp \
             ExecMainStartTimestampMonotonic ExecMainExitTimestampMonotonic InvocationID; do
    [[ "$key" == "$OMIT_PROPERTY" ]] && continue
    case "$key" in
      InvocationID) value="$INVOCATION" ;;
      LoadState) value="$load_state" ;;
      ActiveState) value="$ACTIVE_STATE" ;;
      SubState) value="$SUB_STATE" ;;
      ExecMainCode) value="$EXIT_CODE" ;;
      ExecMainStatus) value="$exit_status" ;;
      ExecMainStartTimestamp) value="$start" ;;
      ExecMainExitTimestamp) value="$end" ;;
      ExecMainStartTimestampMonotonic) value="$start_mono" ;;
      ExecMainExitTimestampMonotonic) value="$end_mono" ;;
    esac
    # Also support the predecessor's separate --value queries for countertests.
    if [[ "${*: -1}" == --value ]]; then
      [[ "$key" == "$4" ]] && printf '%s\n' "$value"
    else
      printf '%s=%s\n' "$key" "$value"
    fi
  done
  ! $failed
}

_fixture_aide_run() {
  # Match the auditor's non-errexit execution, independently of Bats' set -e.
  if _production_aide_probe; then return 0; else return "$?"; fi
}

@test "AIDE completed clean execution retains a scoped historical PASS" {
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'PASS:AIDE: last scheduled check clean (no changes'* ]]
  [[ "$output" != *unassessed* ]]
}

@test "AIDE drift stays WARN even when active database metadata is newer" {
  DB_MTIME=$(date -d '2026-09-01 12:20:00 UTC' +%s)
  DB_CTIME="$DB_MTIME"
  for EXIT_STATUS in 1 2 3 4 5 6 7; do
    run _fixture_aide_run
    [[ "$status" -eq 0 ]]
    [[ "$output" == *'WARN:AIDE: last scheduled check'*'found changes'* ]]
    [[ "$output" != *rebaselined* && "$output" != *obsolete* && "$output" != *PASS:* ]]
  done
}

@test "AIDE baseline changes during a check cannot attest the current baseline" {
  DB_MTIME=$(date -d '2026-09-01 12:05:00 UTC' +%s)
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'current baseline is unassessed'* ]]
}

@test "AIDE ctime changes and same-second metadata cannot preserve a clean PASS" {
  for DB_CTIME in "$(date -d "$START_TIME" +%s)" "$(date -d '2026-09-01 12:20:00 UTC' +%s)"; do
    run _fixture_aide_run
    [[ "$status" -eq 0 ]]
    [[ "$output" != *PASS:* ]]
    [[ "$output" == *'current baseline is unassessed'* ]]
  done
}

@test "AIDE failed grouped queries discard partial clean evidence" {
  QUERY_FAILURE=all
  for PARTIAL_OUTPUT in false true; do
    run _fixture_aide_run
    [[ "$status" -eq 0 ]]
    [[ "$output" != *PASS:* ]]
    [[ "$output" == *'result unassessed'* ]]
  done
}

@test "AIDE failed alternate-unit query cannot establish a complete clean inventory" {
  QUERY_FAILURE=aide.service
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'service queries are incomplete'* ]]
}

@test "AIDE running invocation cannot reuse a default or previous clean status" {
  ACTIVE_STATE=activating
  SUB_STATE=start
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'no verified completed result'* ]]
}

@test "AIDE missing exit timestamp is unavailable rather than today's date" {
  END_TIME=''
  END_MONO=0
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'no verified completed result'* ]]
}

@test "AIDE inconsistent execution chronology cannot establish clean evidence" {
  END_TIME='2026-09-01 11:59:00 UTC'
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  END_TIME='2026-09-01 12:10:00 UTC'
  END_MONO=999999999
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'no verified completed result'* ]]
}

@test "AIDE signal numbers are incomplete execution instead of drift bitmasks" {
  EXIT_STATUS=4
  for EXIT_CODE in 2 3; do
    run _fixture_aide_run
    [[ "$status" -eq 0 ]]
    [[ "$output" == *'WARN:AIDE: last scheduled check terminated by a signal'* ]]
    [[ "$output" != *'found changes'* && "$output" != *PASS:* ]]
  done
}

@test "AIDE operational error exit remains an incomplete warning" {
  EXIT_STATUS=14
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:AIDE: last scheduled check failed (exit=14, result incomplete)'* ]]
  [[ "$output" != *'found changes'* && "$output" != *PASS:* ]]
}

@test "AIDE chooses the newest recorded supported service invocation" {
  SECOND_NEWER=true
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:AIDE: last scheduled check'*'found changes'* ]]
  [[ "$output" == *'2026-09-01 12:20:00 UTC'* ]]
  [[ "$output" != *PASS:* ]]
}

@test "AIDE missing properties or unreadable metadata cannot supply a clean PASS" {
  OMIT_PROPERTY=ExecMainCode
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'result unassessed'* ]]
  OMIT_PROPERTY=''
  STAT_FAILURE=true
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'database/check chronology could not be verified'* ]]
}

@test "AIDE missing active database blocks a clean PASS without suppressing recorded drift" {
  _AIDE_DB=''
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'no nonempty active trust database is available'* ]]
  EXIT_STATUS=4
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:AIDE: last scheduled check'*'found changes'* ]]
}


_fixture_report() {
  printf '  Added entries: 0\n  Removed entries: 0\n  Changed entries: %s\n' "$2" > "$1"
  chmod 0600 "$1"
}

@test "AIDE drift details use the delayed invocation report instead of a shared report" {
  EXIT_STATUS=4
  local own="$REPORT_DIR/aide-check-20260901-120500.$INVOCATION.abc123.log"
  _fixture_report "$own" 7
  _fixture_report "$REPORT_DIR/aide.log" 91
  touch -d '2026-09-01 12:07:00 UTC' "$REPORT_DIR/aide.log"
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:AIDE: last scheduled check'*'changed=7'*"inspect $own"* ]]
  [[ "$output" != *'changed=91'* && "$output" != *PASS:* ]]
}

@test "AIDE missing invocation identity cannot attach shared reports or journal context" {
  EXIT_STATUS=4
  JSON_MODE=false
  _fixture_report "$REPORT_DIR/aide.log" 91
  touch -d '2026-09-01 12:07:00 UTC' "$REPORT_DIR/aide.log"
  INVOCATION='' run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:AIDE: last scheduled check'*'found changes'* ]]
  [[ "$output" != *'changed='* && "$output" != *'/fixture:space name'* ]]
  [[ ! -e "$JOURNAL_CAPTURE" ]]
}

@test "AIDE ambiguous report files preserve drift without inventing detail counts" {
  EXIT_STATUS=4
  _fixture_report "$REPORT_DIR/aide-check-20260901-120500.$INVOCATION.abc123.log" 7
  _fixture_report "$REPORT_DIR/aide-check-20260901-120500.$INVOCATION.def456.log" 91
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:AIDE: last scheduled check'*'found changes'* ]]
  [[ "$output" != *'changed='* && "$output" != *PASS:* ]]
}

@test "AIDE journal fallback binds both unit and invocation and preserves whole paths" {
  EXIT_STATUS=4
  JSON_MODE=false
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'Added  : /fixture:space name'* ]]
  grep -qxF '_SYSTEMD_UNIT=aide-check.service' "$JOURNAL_CAPTURE"
  grep -qxF "_SYSTEMD_INVOCATION_ID=$INVOCATION" "$JOURNAL_CAPTURE"
  grep -qxF -- '--output=cat' "$JOURNAL_CAPTURE"
}

@test "AIDE failed journal reads discard partial drift context" {
  EXIT_STATUS=4
  JSON_MODE=false
  JOURNAL_FAILURE=true
  run _fixture_aide_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:AIDE: last scheduled check'*'found changes'* ]]
  [[ "$output" != *'/fixture:space name'* ]]
}
