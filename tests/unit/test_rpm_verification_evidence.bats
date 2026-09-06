#!/usr/bin/env bats

# Bats and the extracted production block invoke these fixture functions.
# shellcheck disable=SC2317
# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # Only the RPM branch is loaded; other integrity tools are never invoked.
  # shellcheck disable=SC1090
  source <(
    printf '_production_rpm_probe() {\n'
    awk '/^check_integrity\(\)/ {section=1}
         section && /^elif require_cmd debsums/ {exit}
         section && /^if _rpm_package_verifier_allowed/ {found=1}
         found {print}' "$SCRIPT"
    printf 'fi\n}\n'
  )
  local helper
  for helper in _rpm_nonconfig_lines _rpm_discrepancy_paths _rpm_missing_ghost_line \
                _plural _run_timed_capture _run_timed_capture_all_closed; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '
      $0 == signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  # Globals below are consumed by the dynamically loaded production block.
  # shellcheck disable=SC2034
  {
    JSON_MODE=true
    DISTRO=fedora
    DISTRO_FAMILY=rhel
    _PACKAGE_VERIFY_TIMEOUT=5
    NOID_RPM_BASELINE_INIT=0
    NOID_RPM_BASELINE_UPDATE=0
  }
  RPM_STDOUT=''
  RPM_STDERR=''
  RPM_EXIT=0
  FINGERPRINT_INPUT="$BATS_TEST_TMPDIR/fingerprint-input.txt"
}

_rpm_package_verifier_allowed() { return 0; }
require_cmd() { [[ "$1" == rpm ]]; }
_noid_rpm_policy_applicable() { return 1; }
_noid_mode_override_matches() { return 1; }
_rpm_runtime_metadata_matches() { return 1; }
_rpm_baseline_records() {
  # Retain the inventory handed to fingerprinting, then stop before any real
  # baseline path is read, compared, created, or updated.
  cat > "$FINGERPRINT_INPUT"
  return 127
}
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_fail() { printf 'FAIL:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }

timeout() {
  # The real production capture helper handles stdout, stderr, and exit status.
  # Replace only the external command, asserting its non-scripted query form.
  [[ "$*" == '5 env LC_ALL=C rpm -Va --noscripts' ]] || return 125
  [[ -z "$RPM_STDOUT" ]] || printf '%s\n' "$RPM_STDOUT"
  [[ -z "$RPM_STDERR" ]] || printf '%s\n' "$RPM_STDERR" >&2
  return "$RPM_EXIT"
}

_fixture_rpm_run() {
  # The auditor uses set +e; conditional context also provides it under Bats.
  if _production_rpm_probe; then return 0; else return "$?"; fi
}

@test "RPM bytecode content drift stays visible and reaches state fingerprinting" {
  RPM_STDOUT='S.5......    /usr/lib64/python3.14/site-packages/demo.pyc'
  RPM_EXIT=1
  run _fixture_rpm_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:RPM verify: 1 substantive non-config discrepancies (1 content/link/capability'* ]]
  [[ "$output" == *'examples: /usr/lib64/python3.14/site-packages/demo.pyc'* ]]
  [[ "$output" != *'PASS:RPM verify: no substantive'* ]]
  [[ "$(cat "$FINGERPRINT_INPUT")" == '/usr/lib64/python3.14/site-packages/demo.pyc' ]]
}

@test "RPM cache-directory names cannot suppress arbitrary library drift" {
  RPM_STDOUT='S.5......    /usr/lib64/__pycache__/loader.so'
  RPM_EXIT=1
  run _fixture_rpm_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:RPM verify: 1 substantive non-config discrepancies'* ]]
  [[ "$output" == *'examples: /usr/lib64/__pycache__/loader.so'* ]]
  [[ "$(cat "$FINGERPRINT_INPUT")" == '/usr/lib64/__pycache__/loader.so' ]]
}

@test "RPM bytecode permissions ownership and capabilities remain substantive" {
  local flags
  RPM_EXIT=1
  for flags in .M....... .....U... ......G.. ........P; do
    RPM_STDOUT="$flags    /usr/lib64/python3.14/__pycache__/demo.pyc"
    run _fixture_rpm_run
    [[ "$status" -eq 0 ]]
    [[ "$output" == *'WARN:RPM verify: 1 substantive non-config discrepancies'* ]]
    [[ "$output" != *'PASS:RPM verify: no substantive'* ]]
  done
}

@test "RPM missing bytecode is not automatically accepted as generated cache" {
  RPM_STDOUT='missing     /usr/lib64/demo.pyc'
  RPM_EXIT=1
  run _fixture_rpm_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:RPM verify: 1 substantive non-config discrepancies (0 content/link/capability, 0 mode/owner/group, 1 missing)'* ]]
  [[ "$(cat "$FINGERPRINT_INPUT")" == '/usr/lib64/demo.pyc' ]]
}

@test "RPM timestamp-only bytecode discrepancy retains its narrow informational classification" {
  RPM_STDOUT='.......T.    /usr/lib64/demo.pyc'
  RPM_EXIT=1
  run _fixture_rpm_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'PASS:RPM verify: no substantive non-config drift'* ]]
  [[ "$output" == *'INFO:RPM verify: 1 timestamp-only discrepancies'* ]]
  [[ -z "$(cat "$FINGERPRINT_INPUT")" ]]
}

@test "RPM ordinary content drift remains adverse alongside clean-query control" {
  run _fixture_rpm_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'PASS:RPM verify: no package-file discrepancies'* ]]
  RPM_STDOUT='S.5......    /usr/lib64/demo.py'
  RPM_EXIT=1
  run _fixture_rpm_run
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'WARN:RPM verify: 1 substantive non-config discrepancies'* ]]
}

@test "RPM stderr-only read failures cannot masquerade as a clean empty inventory" {
  RPM_STDERR='error: cannot open Packages database in fixture'
  RPM_EXIT=1
  run _fixture_rpm_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'WARN:RPM verify: unrecognized output; result not fully graded'* ]]
  [[ "$output" == *'RPM baseline comparison skipped'* ]]
  [[ ! -e "$FINGERPRINT_INPUT" ]]
}

@test "RPM operational diagnostics keep partial discrepancy output incomplete" {
  RPM_STDOUT='S.5......    /usr/lib64/demo.py'
  RPM_STDERR='error: cannot read a package header'
  RPM_EXIT=1
  run _fixture_rpm_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'result not fully graded'* ]]
  [[ "$output" == *'RPM baseline comparison skipped'* ]]
  [[ ! -e "$FINGERPRINT_INPUT" ]]
}

@test "RPM exit 1 without any evidence stays incomplete" {
  RPM_EXIT=1
  run _fixture_rpm_run
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'result incomplete'* ]]
  [[ ! -e "$FINGERPRINT_INPUT" ]]
}
