#!/usr/bin/env bats

# Extract the production readers and section; only their external producers
# are replaced with deterministic unit-manager responses.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _service_unit_state _service_group_state _service_active_any _service_masked_any _service_enabled_any _failed_systemd_unit_names _failed_noid_image_unit_names check_services; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '
      $0 == signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  UNIT_DIR="$BATS_TEST_TMPDIR/units"
  mkdir "$UNIT_DIR"
  _IS_DESKTOP=true JSON_MODE=true DISTRO=noid-privacy
  QUERY_RC=0 QUERY_EMPTY=false FAILED_RC=0 TIMER_RC=0
  FAILED_ROWS='' TIMER_ROWS=''
}

unit_state() {
  printf 'LoadState=%s\nActiveState=%s\nUnitFileState=%s\n' "$2" "$3" "$4" > "$UNIT_DIR/$1"
}

systemctl() {
  local verb="$1" unit="${*: -1}" installed active
  [[ "$unit" == *.* ]] || unit+=.service
  case "$verb" in
    show)
      if ! $QUERY_EMPTY; then
        if [[ -f "$UNIT_DIR/$unit" ]]; then
          cat "$UNIT_DIR/$unit"
        else
          printf 'LoadState=not-found\nActiveState=inactive\nUnitFileState=\n'
        fi
      fi
      return "$QUERY_RC" ;;
    is-active)
      active=$(sed -n 's/^ActiveState=//p' "$UNIT_DIR/$unit" 2>/dev/null)
      [[ "$QUERY_RC" -eq 0 && "$active" == active ]] ;;
    is-enabled)
      installed=$(sed -n 's/^UnitFileState=//p' "$UNIT_DIR/$unit" 2>/dev/null)
      printf '%s\n' "$installed"
      [[ "$QUERY_RC" -eq 0 && "$installed" =~ ^(enabled|enabled-runtime|static|indirect)$ ]] ;;
    --failed) printf '%s' "$FAILED_ROWS"; return "$FAILED_RC" ;;
    list-timers) printf '%s' "$TIMER_ROWS"; return "$TIMER_RC" ;;
    *) return 1 ;;
  esac
}
should_skip() { return 1; }
header() { :; }
require_cmd() { return 1; }
_process_pids_exact() { return 1; }
_process_running_exact() { return 1; }
_ufw_is_active() { return 1; }
_plural() { if [[ "$1" == 1 ]]; then printf '%s' "$2"; else printf '%s' "$3"; fi; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_fail() { printf 'FAIL:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }

@test "confirmed absent unit group is reported as absent" {
  run check_services
  [[ "$status" -eq 0 && "$output" == *'PASS:Service units not installed: sshd'* ]]
}

@test "empty successful unit response cannot become service-off PASS" {
  QUERY_EMPTY=true
  run check_services
  [[ "$status" -eq 0 && "$output" == *'INFO:Service state unavailable: sshd'* ]]
  [[ "$output" != *'PASS:Service '* && "$output" == *'INCOMPLETE'* ]]
}

@test "failed partial inactive responses are discarded across the service groups" {
  QUERY_RC=1
  unit_state sshd.service loaded inactive disabled
  run check_services
  [[ "$status" -eq 0 && "$output" == *'INFO:Service state unavailable: sshd'* ]]
  [[ "$output" != *'PASS:Service '* && "$output" == *'INCOMPLETE'* ]]
}

@test "duplicate or missing state properties cannot confirm absence" {
  for row in $'LoadState=not-found\nActiveState=inactive' $'LoadState=not-found\nActiveState=inactive\nUnitFileState=\nActiveState=inactive'; do
    printf '%s\n' "$row" > "$UNIT_DIR/sshd.service"
    run check_services
    [[ "$output" == *'INFO:Service state unavailable: sshd'* ]]
    [[ "$output" != *'PASS:Service units not installed: sshd'* ]]
  done
}

@test "mask on one alias cannot hide another runtime-enabled alias" {
  unit_state sshd.service loaded inactive enabled-runtime
  unit_state ssh.service masked inactive masked
  run check_services
  [[ "$output" == *'WARN:Service enabled for this boot but inactive: sshd'* ]]
  [[ "$output" != *'PASS:Service masked: sshd'* ]]
}

@test "mask on one alias cannot declare an inactive unmasked alias masked" {
  unit_state sshd.service loaded inactive disabled
  unit_state ssh.service masked inactive masked
  run check_services
  [[ "$output" == *'PASS:Service units inactive: sshd'* ]]
  [[ "$output" != *'PASS:Service masked: sshd'* ]]
}

@test "all present units masked with absent aliases retains a masked PASS" {
  unit_state cups.service masked inactive masked
  unit_state cups.socket masked inactive masked
  unit_state cups.path masked inactive masked
  run check_services
  [[ "$output" == *'PASS:Service masked: cups'* ]]
}

@test "runtime-only mask is explicit in the report" {
  unit_state cups.service masked inactive masked-runtime
  run check_services
  [[ "$output" == *'PASS:Service masked for this boot: cups'* ]]
}

@test "active masked unit is still active" {
  unit_state sshd.service masked active masked
  run check_services
  [[ "$output" == *'WARN:Network service or activation unit active: sshd'* ]]
  [[ "$output" != *'PASS:Service masked: sshd'* ]]
}

@test "transitional and unknown activity cannot become inactive PASS" {
  for active in activating deactivating maintenance future-state; do
    unit_state sshd.service loaded "$active" disabled
    run check_services
    [[ "$output" != *'PASS:Service units inactive: sshd'* ]]
    [[ "$output" == *'INFO:Service state '*': sshd (unassessed)'* ]]
  done
}

@test "SSH socket activation is visible without a running SSH daemon unit" {
  unit_state ssh.socket loaded active enabled
  run check_services
  [[ "$output" == *'WARN:Network service or activation unit active: sshd'* ]]
}

@test "rpcbind socket activation is visible" {
  unit_state rpcbind.socket loaded active enabled
  run check_services
  [[ "$output" == *'WARN:Network service or activation unit active: rpcbind'* ]]
}

@test "CUPS path activation receives desktop context instead of an off PASS" {
  unit_state cups.path loaded active enabled
  run check_services
  [[ "$output" == *'INFO:Service or activation unit active: cups'* ]]
  run grep -qE '^PASS:Service .*: cups([[:space:]]|$)' <<< "$output"
  [[ "$status" -eq 1 ]]
}

@test "confirmed activity remains evidence when a separate alias is unreadable" {
  unit_state sshd.service loaded active enabled
  printf 'invalid\n' > "$UNIT_DIR/ssh.service"
  run check_services
  [[ "$output" == *'WARN:Network service or activation unit active: sshd'* ]]
}

@test "unreadable alias prevents inactive desktop certification" {
  unit_state bluetooth.service loaded inactive enabled
  printf 'invalid\n' > "$UNIT_DIR/bluetooth.socket"
  run check_services
  [[ "$output" == *'INFO:Service state unavailable: bluetooth'* ]]
  run grep -qE '^PASS:Service .*: bluetooth([[:space:]]|$)' <<< "$output"
  [[ "$status" -eq 1 ]]
}

@test "static unit is not called boot-enabled" {
  unit_state bluetooth.service loaded inactive static
  run check_services
  [[ "$output" == *'PASS:Service units inactive: bluetooth'* ]]
  [[ "$output" != *'bluetooth (activation enabled)'* ]]
}

@test "desktop runtime enablement makes no next-boot claim" {
  unit_state bluetooth.service loaded inactive enabled-runtime
  run check_services
  [[ "$output" == *'PASS:Service units inactive: bluetooth (activation enabled for this boot)'* ]]
  [[ "$output" != *'starts on demand or at next boot'* ]]
}

@test "failed failed-unit query cannot establish zero failures" {
  FAILED_RC=1
  run check_services
  [[ "$output" == *'INFO:Failed systemd units: query failed (unassessed)'* ]]
  [[ "$output" != *'PASS:0 failed'* ]]
}

@test "failed partial failed-unit inventory cannot establish image failure" {
  FAILED_RC=1 FAILED_ROWS='noid-test.service loaded failed failed fixture'
  run check_services
  [[ "$output" == *'INFO:Failed systemd units: query failed (unassessed)'* ]]
  [[ "$output" != *'WARN:1 failed NoID image'* ]]
}

@test "image failures and environment-specific failures remain visible" {
  FAILED_ROWS=$'noid-test.service loaded failed failed fixture\nsystemd-update-utmp.service loaded failed failed environment'
  run check_services
  [[ "$output" == *'WARN:1 failed NoID image unit'*'noid-test.service'* ]]
  [[ "$output" == *'INFO:1 failed systemd unit'*'systemd-update-utmp.service'* ]]
}

@test "NoID-named unit on another distro is retained in ordinary failure inventory" {
  DISTRO=other FAILED_ROWS='noid-test.service loaded failed failed fixture'
  run check_services
  [[ "$output" == *'INFO:1 failed systemd unit'*'noid-test.service'* ]]
}

@test "failed partial timer query cannot become a count" {
  TIMER_RC=1 TIMER_ROWS='partial timer row'
  run check_services
  [[ "$output" == *'INFO:Active timers: query failed (unassessed)'* ]]
  [[ "$output" != *'INFO:Active timers: 1'* && "$output" != *'INFO:Active timers: 0'* ]]
}

@test "successful empty failure and timer inventories retain their zero controls" {
  run check_services
  [[ "$output" == *'PASS:0 failed systemd units'* ]]
  [[ "$output" == *'INFO:Active timers: 0'* ]]
}

@test "unit property order does not change evidence" {
  printf 'UnitFileState=disabled\nActiveState=inactive\nLoadState=loaded\n' > "$UNIT_DIR/sshd.service"
  run check_services
  [[ "$output" == *'PASS:Service units inactive: sshd'* ]]
}
