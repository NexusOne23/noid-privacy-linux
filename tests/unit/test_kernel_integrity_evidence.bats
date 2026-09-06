#!/usr/bin/env bats

# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _kernel_taint_audit _read_uint_file _ima_audit _rescue_command_audit _chrony_source_counts _module_load_state _mokutil_secure_boot_state; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT" |
      sed "s|/sys/kernel/security/integrity/ima|$BATS_TEST_TMPDIR/ima|g; s|/sys/kernel/security/ima|$BATS_TEST_TMPDIR/ima|g; s|/sys/module|$BATS_TEST_TMPDIR/modules|g")
  done
  mkdir -p "$BATS_TEST_TMPDIR/ima" "$BATS_TEST_TMPDIR/modules"
  printf '0\n' > "$BATS_TEST_TMPDIR/ima/violations"
  printf '202\n' > "$BATS_TEST_TMPDIR/ima/runtime_measurements_count"
  TAINT_VALUE=4096 TAINT_RC=0 UNIT_RC=0 UNIT_MODE=normal
  MODULE_PLAN="install /bin/false" MODULE_RC=0
  MOK_OUTPUT="SecureBoot enabled" MOK_RC=0
}
_sysctl_integer_value() { printf '%s' "$TAINT_VALUE"; return "$TAINT_RC"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }
systemctl() {
  local unit=${*: -1}
  case "$UNIT_MODE" in
    normal) printf '{ path=/usr/lib/systemd/systemd-sulogin-shell ; argv[]=/usr/lib/systemd/systemd-sulogin-shell %s ; ignore_errors=yes ; start_time=[n/a] ; status=0/0 }\n' "${unit%.service}" ;;
    empty) : ;;
    misleading) printf '{ path=/bin/sh ; argv[]=/bin/sh -c echo-sulogin ; ignore_errors=yes ; status=0/0 }\n' ;;
    extra) printf '{ path=/usr/lib/systemd/systemd-sulogin-shell ; argv[]=/usr/lib/systemd/systemd-sulogin-shell %s ; status=0/0 }\n{ path=/bin/sh ; argv[]=/bin/sh ; status=0/0 }\n' "${unit%.service}" ;;
  esac
  return "$UNIT_RC"
}

@test "taint zero and OOT inventory retain their distinct meanings" {
  run _kernel_taint_audit
  [[ "$output" == *'OOT_MODULE'* && "$output" == *'cause and module safety not inferred'* && "$output" != *WARN:* ]]
  TAINT_VALUE=0
  run _kernel_taint_audit
  [[ "$output" == 'PASS:Kernel Taint: 0 (clean)' ]]
}

@test "FWCTL debug mutation and unknown taint bits cannot vanish into benign inventory" {
  TAINT_VALUE=524288
  run _kernel_taint_audit
  [[ "$output" == *'WARN:Kernel Taint:'* && "$output" == *FWCTL_DEBUG_WRITE* ]]
  TAINT_VALUE=1048576
  run _kernel_taint_audit
  [[ "$output" == *'WARN:Kernel Taint:'* && "$output" == *UNKNOWN_BITS=1048576* ]]
  TAINT_VALUE=$((1048576+4096))
  run _kernel_taint_audit
  [[ "$output" == *OOT_MODULE* && "$output" == *UNKNOWN_BITS=1048576* && "$output" == *WARN:* ]]
}

@test "failed taint reads never become clean zero" {
  TAINT_VALUE=0 TAINT_RC=1
  run _kernel_taint_audit
  [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
}

@test "IMA counters establish only recorded measurements and violations" {
  run _ima_audit
  [[ "$output" == *'PASS:IMA violations: 0 recorded'* && "$output" == *'202 runtime measurements recorded'* ]]
  [[ "$output" != *'policy: custom'* && "$output" != *'actively measuring'* ]]
}

@test "IMA unreadable and malformed counters cannot produce zero-violation PASS" {
  rm "$BATS_TEST_TMPDIR/ima/violations"
  run _ima_audit
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS:IMA violations:'* ]]
  for value in '' unknown -1 999999999999999999999999; do
    printf '%s\n' "$value" > "$BATS_TEST_TMPDIR/ima/violations"
    run _ima_audit
    [[ "$output" == *INCOMPLETE* && "$output" != *'PASS:IMA violations:'* ]]
  done
}

@test "IMA nonzero violations and zero measurements stay visible" {
  printf '2\n' > "$BATS_TEST_TMPDIR/ima/violations"
  printf '0\n' > "$BATS_TEST_TMPDIR/ima/runtime_measurements_count"
  run _ima_audit
  [[ "$output" == *'WARN:IMA violations: 2'* && "$output" == *'WARN:IMA: 0 runtime measurements'* ]]
}

@test "missing measurement counter and absent IMA are not invented policies" {
  rm "$BATS_TEST_TMPDIR/ima/runtime_measurements_count"
  run _ima_audit
  [[ "$output" == *'measurement counter unavailable'* && "$output" == *INCOMPLETE* ]]
  rm "$BATS_TEST_TMPDIR/ima/violations"
  rmdir "$BATS_TEST_TMPDIR/ima"
  run _ima_audit
  [[ "$output" == *'measurement interface unavailable'* && "$output" != *PASS:* ]]
}

@test "native rescue command identity is separate from an exercised password challenge" {
  run _rescue_command_audit
  [[ "$output" == *'PASS:Rescue/emergency commands invoke systemd-sulogin-shell'* ]]
  [[ "$output" == *'password enforcement and force options not exercised'* ]]
}

@test "failed empty unrelated and multiple rescue commands cannot prove protection" {
  UNIT_RC=1
  run _rescue_command_audit
  [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  UNIT_RC=0
  for UNIT_MODE in empty misleading extra; do
    run _rescue_command_audit
    [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
}

@test "chrony rejects excessive jitter instead of declaring every source valid" {
  run _chrony_source_counts <<< $'^* 192.0.2.1 1 6 377 20 +1us[+1us] +/- 1ms\n^~ 192.0.2.2 1 6 377 20 +1us[+1us] +/- 1ms'
  [[ "$status" -eq 0 && "$output" == '2 1' ]]
}


timeout() { shift; "$@"; }
modprobe() { printf '%s\n' "$MODULE_PLAN"; return "$MODULE_RC"; }

@test "module deny installation is resolved from native dry-run output" {
  run _module_load_state jffs2
  [[ "$output" == suppressed ]]
  MODULE_PLAN=$'insmod /lib/modules/example/dependency.ko.xz\ninstall /bin/false'
  run _module_load_state firewire_core
  [[ "$output" == unknown ]]
  # Native softdep post: a deny command follows an already inserted target.
  MODULE_PLAN=$'insmod /lib/modules/example/squashfs.ko.xz\ninstall /bin/false'
  run _module_load_state squashfs
  [[ "$output" == unknown ]]
}

@test "a present driver cannot be hidden by a load suppression directive" {
  mkdir "$BATS_TEST_TMPDIR/modules/jffs2"
  run _module_load_state jffs2
  [[ "$output" == present ]]
}

@test "blacklist-only and commented directives do not suppress native explicit load" {
  MODULE_PLAN='insmod /lib/modules/example/squashfs.ko.xz'
  run _module_load_state squashfs
  [[ "$output" == available ]]
  MODULE_PLAN='install /bin/false; /usr/bin/custom-loader'
  run _module_load_state squashfs
  [[ "$output" == unknown ]]
}

@test "failed or empty modprobe plans remain unassessed" {
  MODULE_RC=1
  run _module_load_state jffs2
  [[ "$output" == unknown ]]
  MODULE_RC=0 MODULE_PLAN=''
  run _module_load_state jffs2
  [[ "$output" == unknown ]]
}


mokutil() { printf '%s\n' "$MOK_OUTPUT"; return "$MOK_RC"; }
@test "Secure Boot uses exact successful mokutil state instead of an enabled substring" {
  run _mokutil_secure_boot_state
  [[ "$output" == enabled ]]
  MOK_OUTPUT='SecureBoot disabled'
  run _mokutil_secure_boot_state
  [[ "$output" == disabled ]]
  MOK_RC=1 MOK_OUTPUT='SecureBoot enabled'
  run _mokutil_secure_boot_state
  [[ "$output" == unknown ]]
  MOK_RC=0 MOK_OUTPUT='SecureBoot enabled but shim validation disabled'
  run _mokutil_secure_boot_state
  [[ "$output" == unknown ]]
}
