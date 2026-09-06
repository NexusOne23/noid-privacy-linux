#!/usr/bin/env bats

# Production consumer with native command responses controlled at the boundary.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  # shellcheck disable=SC1090
  source <(awk '$0=="_abrt_audit() {" {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  UNITS='' UNIT_RC=0 REPORTING=disabled REPORT_RC=0
  CALLS="$BATS_TEST_TMPDIR/calls"
}

timeout() {
  case "$1 $2" in
    '8 systemctl')
      [[ "$*" == "8 systemctl list-units --state=active,reloading,activating,deactivating --no-legend --plain --no-pager abrtd.service abrt-*.service" ]] || return 98
      printf '%s' "$UNITS"; return "$UNIT_RC" ;;
    '5 abrt-auto-reporting')
      [[ "$#" -eq 2 ]] || return 98
      printf 'reporting-query\n' >> "$CALLS"
      printf '%s\n' "$REPORTING"; return "$REPORT_RC" ;;
    *) return 98 ;;
  esac
}
ccount() { tr -d '[:space:]'; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }

@test "successful empty ABRT system-service inventory retains a scoped PASS" {
  run _abrt_audit
  [[ "$status" -eq 0 && "$output" == 'PASS:ABRT system services not active' ]]
  [[ ! -e "$CALLS" ]]
}

@test "abrtd alone is detected and its enabled system reporting is warned" {
  UNITS='abrtd.service loaded active running ABRT daemon' REPORTING=enabled
  run _abrt_audit
  [[ "$status" -eq 0 && "$output" == *'services running or transitioning: 1'* ]]
  [[ "$output" == *'WARN:ABRT system automatic crash reporting enabled'* && "$output" != *'PASS:'* ]]
}

@test "local collection with disabled system reporting does not imply upload" {
  UNITS=$'abrtd.service loaded active running ABRT daemon\nabrt-oops.service loaded active running Oops collector'
  run _abrt_audit
  [[ "$status" -eq 0 && "$output" == *'services running or transitioning: 2'* ]]
  [[ "$output" == *'automatic upload not proven'* && "$output" == *'desktop-user preferences are separate'* ]]
  [[ "$output" != *'PASS:'* && "$output" != *'WARN:'* ]]
}

@test "failed empty and partial service inventories cannot become absence PASS" {
  UNIT_RC=1
  for UNITS in '' 'abrtd.service loaded active running ABRT daemon'; do
    run _abrt_audit
    [[ "$status" -eq 0 && "$output" == *'state unassessed (query failed)'* ]]
    [[ "$output" == *INCOMPLETE* && "$output" != *'PASS:'* && "$output" != *'WARN:'* ]]
  done
  [[ ! -e "$CALLS" ]]
}

@test "failed partial reporting output cannot establish either reporting state" {
  UNITS='abrtd.service loaded active running ABRT daemon' REPORT_RC=1
  for REPORTING in enabled disabled; do
    run _abrt_audit
    [[ "$status" -eq 0 && "$output" == *'setting unassessed'* && "$output" == *INCOMPLETE* ]]
    [[ "$output" != *'WARN:'* && "$output" != *'reporting disabled;'* ]]
  done
}

@test "unavailable and unsupported reporting values stay unassessed" {
  UNITS='abrtd.service loaded active running ABRT daemon'
  for REPORTING in '' yes 'enabled with diagnostics'; do
    run _abrt_audit
    [[ "$status" -eq 0 && "$output" == *'setting unassessed'* && "$output" == *INCOMPLETE* ]]
  done
}

@test "Snap presence does not invoke an unsupported telemetry switch or imply disabled collection" {
  # Extract the actual Snap branch without executing unrelated host checks.
  # shellcheck disable=SC1090
  source <(printf '_snap_consumer() {\n'; sed -n '/^  if command -v snap &>\/dev\/null; then/,/^  fi/p' "$SCRIPT"; printf '}\n')
  snap() { printf 'unexpected-call\n' >> "$CALLS"; return 99; }
  run _snap_consumer
  [[ "$status" -eq 0 && "$output" == 'INFO:Snap client installed; snap and store data collection is not assessed' ]]
  [[ ! -e "$CALLS" ]]
}
