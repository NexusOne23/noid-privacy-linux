#!/usr/bin/env bats

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  FIXTURE_DIR="${BATS_TEST_DIRNAME}/../fixtures"
  [[ -f "$SCRIPT" && -d "$FIXTURE_DIR" ]] || skip "test inputs missing"
  # shellcheck source=/dev/null
  source <(sed -n \
    '/^# BEGIN NOID AUTH CONFIG PARSERS$/,/^# END NOID AUTH CONFIG PARSERS$/p' \
    "$SCRIPT")
}

@test "later config file overrides earlier assignment" {
  run _config_last_value minlen \
    "$FIXTURE_DIR/pwquality-base.conf" \
    "$FIXTURE_DIR/pwquality-override.conf"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "16" ]]
}

@test "config parser ignores inline comments" {
  run _config_last_value dictcheck \
    "$FIXTURE_DIR/pwquality-base.conf" \
    "$FIXTURE_DIR/pwquality-override.conf"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "0" ]]
}

@test "standalone config boolean maps to one" {
  run _config_last_value enforce_for_root "$FIXTURE_DIR/pwquality-base.conf"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "1" ]]
}

@test "PAM option parser returns every active per-service override" {
  run _pam_module_option_values pam_faillock.so deny \
    "$FIXTURE_DIR/pam-auth-policy.txt"
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'3\n5' ]]
}

@test "PAM option parser ignores commented module lines" {
  run _pam_module_option_values pam_faillock.so unlock_time \
    "$FIXTURE_DIR/pam-auth-policy.txt"
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'600\n900' ]]
}

@test "PAM module presence distinguishes active and absent modules" {
  run _pam_module_present pam_pwquality.so "$FIXTURE_DIR/pam-auth-policy.txt"
  [[ "$status" -eq 0 ]]
  run _pam_module_present pam_cracklib.so "$FIXTURE_DIR/pam-auth-policy.txt"
  [[ "$status" -ne 0 ]]
}

@test "nullok parser covers Debian common-auth with exact option matching" {
  local system_auth="$BATS_TEST_TMPDIR/system-auth"
  local common_auth="$BATS_TEST_TMPDIR/common-auth"
  printf '%s\n' \
    '# auth sufficient pam_unix.so nullok' \
    'auth sufficient pam_unix.so nullok_secure' > "$system_auth"
  printf '%s\n' \
    'auth [success=2 default=ignore] /usr/lib/security/pam_unix.so nullok try_first_pass' \
    'auth sufficient pam_unix.so nullok' > "$common_auth"

  run _pam_nullok_rows "$BATS_TEST_TMPDIR/missing-password-auth" "$system_auth" "$common_auth"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "$common_auth"$'\t''auth [success=2 default=ignore] /usr/lib/security/pam_unix.so nullok try_first_pass' ]]

  local users_block
  users_block=$(sed -n '/declare -A _NULLOK_FOUND_IN=/,/# securetty/p' "$SCRIPT")
  [[ "$users_block" == *'/etc/pam.d/common-auth'* ]]
}

@test "pwquality rows retain per-stack overrides and inherited defaults" {
  local pam_one="$BATS_TEST_TMPDIR/pwquality-one"
  local pam_two="$BATS_TEST_TMPDIR/pwquality-two"
  printf '%s\n' \
    'password requisite pam_pwquality.so minlen=16 dcredit=4 dictcheck=1 enforcing=1' > "$pam_one"
  printf '%s\n' \
    'password requisite /usr/lib64/security/pam_pwquality.so ucredit=4 dictcheck=0 enforcing=0' > "$pam_two"

  run _pam_pwquality_effective_rows 16 0 0 0 0 1 1 "$pam_one" "$pam_two"
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'16\t4\t0\t0\t0\t1\t1\n16\t0\t4\t0\t0\t0\t0' ]]
}

@test "pwquality summary selects the weakest real stack without mixing credits" {
  local rows
  rows=$'16\t4\t0\t0\t0\t1\t1\n16\t0\t4\t0\t0\t0\t0'
  run _pam_pwquality_policy_summary <<< "$rows"
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'12\t0\t0' ]]
}

@test "legacy cracklib cannot produce pam_pwquality detail passes" {
  local block
  block=$(sed -n '/_PWQ_MODULE=""/,/# Accounts without password expiry/p' "$SCRIPT")
  # shellcheck disable=SC2016  # literal production-source expression
  [[ "$block" == *'[[ "$_PWQ_MODULE" == "pam_pwquality.so" ]]'* ]]
  [[ "$block" == *'Legacy pam_cracklib policy details are not graded'* ]]
}

@test "faillock backend parser includes persistent config and PAM overrides" {
  local config="$BATS_TEST_TMPDIR/faillock.conf"
  local pam="$BATS_TEST_TMPDIR/system-auth"
  printf '%s\n' 'deny = 10' 'dir = /var/lib/faillock' > "$config"
  printf '%s\n' \
    'auth required pam_faillock.so preauth' \
    'auth required pam_faillock.so authfail dir=/run/alternate-faillock' > "$pam"

  run _faillock_backend_dirs "$config" "$pam"
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'/var/lib/faillock\n/run/alternate-faillock' ]]
}

@test "faillock backend parser uses the documented runtime default" {
  local config="$BATS_TEST_TMPDIR/faillock-default.conf"
  : > "$config"
  run _faillock_backend_dirs "$config"
  [[ "$status" -eq 0 ]]
  [[ "$output" == '/var/run/faillock' ]]
}

@test "shell umask parser accepts an interactive case arm" {
  local profile="$BATS_TEST_TMPDIR/interactive-umask.sh"
  printf '%s\n' \
    'case $- in' \
    '    *i*) umask 027 ;;' \
    'esac' > "$profile"
  run _shell_init_umask_value "$profile"
  [[ "$status" -eq 0 ]]
  [[ "$output" == '027' ]]
}

@test "shell umask parser ignores a scoped helper subshell" {
  local profile="$BATS_TEST_TMPDIR/scoped-umask.sh"
  # shellcheck disable=SC2016  # literal fixture content
  printf '%s\n' '(umask 077; : > "$lock_file")' > "$profile"
  run _shell_init_umask_value "$profile"
  [[ "$status" -eq 0 ]]
  [[ -z "$output" ]]
}

@test "shell umask parser avoids mawk interval-expression panics" {
  local block
  block=$(sed -n '/_shell_init_umask_value()/,/^}/p' "$SCRIPT")
  [[ "$block" != *'{2,3}'* ]]
  [[ "$block" == *'[0-7][0-7][0-7]?'* ]]
}

@test "database checks use exit status instead of localized line counts" {
  grep -q '_PWCK_RC' "$SCRIPT"
  grep -q '_GRPCK_RC' "$SCRIPT"
  run grep -q '_PWCK_ERRORS=' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "account database parser distinguishes duplicate names from IDs" {
  run _duplicate_colon_values "$FIXTURE_DIR/account-db-duplicates.txt" 1
  [[ "$status" -eq 0 ]]
  [[ "$output" == "alice" ]]

  run _duplicate_colon_values "$FIXTURE_DIR/account-db-duplicates.txt" 3
  [[ "$status" -eq 0 ]]
  [[ "$output" == "1001" ]]
}

@test "account database parser rejects an invalid column" {
  run _duplicate_colon_values "$FIXTURE_DIR/account-db-duplicates.txt" '3+1'
  [[ "$status" -ne 0 ]]
}

@test "sudo policy checks ownership and accepts reviewed root-controlled modes" {
  grep -q '_SUDOERS_OWNER.*stat -c %u:%g /etc/sudoers' "$SCRIPT"
  # shellcheck disable=SC2016  # literal production-source variable
  grep -q '_sudoers_mode_is_safe "$_SUDOERS_PERMS"' "$SCRIPT"
  grep -q '_SUDOERSD_DIR_OWNER.*stat -c %u:%g /etc/sudoers.d' "$SCRIPT"
}

@test "sudo version detail classifier rejects a sudo-rs summary" {
  _sudo_version_report_has_policy_details \
    $'sudo.ws 1.9.17p2\nAuthentication timestamp timeout: 15.0 minutes'
  _sudo_version_report_has_policy_details \
    $'sudo.ws 1.9.17p2\nAlways run commands in a pseudo-tty'

  run _sudo_version_report_has_policy_details 'sudo-rs 0.2.13-0ubuntu1'
  [[ "$status" -ne 0 ]]
}

@test "summary-only sudo can use the installed sudo.ws policy reporter" {
  sudo_block=$(sed -n \
    '/# Reduce terminal injection exposure/,/# Password Aging/p' "$SCRIPT")
  [[ "$sudo_block" == *'[[ -x /usr/bin/sudo.ws ]]'* ]]
  [[ "$sudo_block" == *'LC_ALL=C /usr/bin/sudo.ws -V'* ]]
  # shellcheck disable=SC2016  # literal production-source variable
  [[ "$sudo_block" == *'_sudo_version_report_has_policy_details "$_SUDO_WS_DEFAULTS"'* ]]
}

@test "central NSS sources do not suppress local password lifecycle checks" {
  lifecycle_block=$(sed -n '/# Accounts without password expiry/,/# Duplicate account database keys/p' "$SCRIPT")
  [[ "$lifecycle_block" == *'cover local /etc/passwd accounts only'* ]]
  [[ "$lifecycle_block" == *'done < /etc/passwd'* ]]
  [[ "$lifecycle_block" == *'_LOCAL_LIFECYCLE_ASSESSED'* ]]
  # shellcheck disable=SC2016  # literal removed production-source variable
  run grep -E 'if ! \$_CENTRAL_AUTH|Password expiry: skipped' <<< "$lifecycle_block"
  [[ "$status" -ne 0 ]]
}
