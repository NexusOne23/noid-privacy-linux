#!/usr/bin/env bats

# Bats and the extracted production function invoke these mocks indirectly.
# Each test changes only its isolated producer state.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031

setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _sysctl_integer_value _sysctl_mismatch_assessment check_sysctl; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '
      $0 == signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  BAD_KEY=''
  BAD_VALUE=''
  BAD_RC=0
  VPN_IFACES=''
  _VIRT_IFACE_REGEX='^(virbr|docker|veth)'
}

sysctl() {
  [[ "$1" == -n ]] || return 127
  local key="$2"
  if [[ "$key" == "$BAD_KEY" ]]; then
    [[ -z "$BAD_VALUE" ]] || printf '%s\n' "$BAD_VALUE"
    return "$BAD_RC"
  fi
  if [[ "$key" == net.ipv4.ip_forward ]]; then
    printf '0\n'
  elif [[ -n "${SYSCTL_CHECKS[$key]+x}" ]]; then
    printf '%s\n' "${SYSCTL_CHECKS[$key]}"
  elif [[ -n "${SYSCTL_STRICT[$key]+x}" ]]; then
    printf '%s\n' "${SYSCTL_STRICT[$key]}"
  else
    return 1
  fi
}
should_skip() { return 1; }
header() { :; }
sub_header() { :; }
systemctl() { return 3; }
ip() { :; }
_emit_pass_agg_start() { AGG_LABEL="$1"; }
_emit_pass_agg() { printf 'PASS:%s:%s\n' "$AGG_LABEL" "$1"; }
_emit_pass_agg_end() { printf 'TOTAL:%s:%s\n' "$AGG_LABEL" "$1"; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_fail() { printf 'FAIL:%s\n' "$1"; }

@test "valid basic and strict sysctl evidence retains its positive controls" {
  run check_sysctl
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'PASS:Sysctl basic:kernel.sysrq = 0'* ]]
  [[ "$output" == *'PASS:Sysctl strict:vm.unprivileged_userfaultfd = 0'* ]]
  [[ "$output" == *'TOTAL:Sysctl basic:23'* && "$output" == *'TOTAL:Sysctl strict:5'* ]]
}

@test "empty strict sysctl output cannot become a zero-valued PASS" {
  BAD_KEY=vm.unprivileged_userfaultfd
  run check_sysctl
  [[ "$status" -eq 0 ]]
  [[ "$output" != *'PASS:Sysctl strict:vm.unprivileged_userfaultfd'* ]]
  [[ "$output" == *'INFO:sysctl vm.unprivileged_userfaultfd:'*'unassessed'* ]]
  [[ "$output" == *'TOTAL:Sysctl strict:4'* ]]
}

@test "non-numeric strict sysctl output is not evaluated as a shell variable" {
  BAD_KEY=vm.unprivileged_userfaultfd BAD_VALUE=undefined_numeric_variable
  run check_sysctl
  [[ "$status" -eq 0 ]]
  [[ "$output" != *'PASS:Sysctl strict:vm.unprivileged_userfaultfd'* ]]
  [[ "$output" == *'unassessed; not counted in the strict total'* ]]
}

@test "failed partial strict sysctl output never reaches arithmetic" {
  BAD_KEY=vm.unprivileged_userfaultfd BAD_VALUE=0 BAD_RC=1
  run check_sysctl
  [[ "$status" -eq 0 ]]
  [[ "$output" != *'PASS:Sysctl strict:vm.unprivileged_userfaultfd'* ]]
  [[ "$output" != *'syntax error'* ]]
  [[ "$output" == *'unassessed; not counted in the strict total'* ]]
}

@test "oversized basic sysctl value cannot wrap to a hardened zero" {
  BAD_KEY=kernel.sysrq BAD_VALUE=18446744073709551616
  run check_sysctl
  [[ "$status" -eq 0 ]]
  [[ "$output" != *'PASS:Sysctl basic:kernel.sysrq'* ]]
  [[ "$output" == *'INFO:sysctl kernel.sysrq:'*'unassessed'* ]]
  [[ "$output" != *'Magic SysRq:'* ]]
}

@test "SysRq details reuse the successfully graded value" {
  BAD_KEY=kernel.sysrq BAD_VALUE=48
  run check_sysctl
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'only sync/remount-ro recovery functions'* ]]
  [[ "$output" == *'Magic SysRq: value=48 bits: sync remount-ro'* ]]
}

@test "failed basic sysctl reads are unassessed rather than declared inapplicable" {
  BAD_KEY=kernel.randomize_va_space BAD_RC=1
  run check_sysctl
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'INFO:sysctl kernel.randomize_va_space:'*'unassessed'* ]]
  [[ "$output" != *'not applicable to this kernel'* ]]
}

@test "integer reader accepts signed arithmetic boundaries and ordinary native values" {
  BAD_KEY=fixture
  for BAD_VALUE in 0 1 -1 65536 4294967295 9223372036854775807 -9223372036854775808; do
    run _sysctl_integer_value fixture
    [[ "$status" -eq 0 && "$output" == "$BAD_VALUE" ]]
  done
}

@test "integer reader rejects ambiguous multiple expression and overflowing values" {
  BAD_KEY=fixture
  for BAD_VALUE in '' -0 00 01 +1 1+1 word $'0\n1' 9223372036854775808 -9223372036854775809 18446744073709551616; do
    run _sysctl_integer_value fixture
    [[ "$status" -eq 2 && -z "$output" ]]
  done
}

@test "integer reader discards all partial output when its query fails" {
  BAD_KEY=fixture BAD_VALUE=0
  for BAD_RC in 1 2 124 127; do
    run _sysctl_integer_value fixture
    [[ "$status" -eq 1 && -z "$output" ]]
  done
}
