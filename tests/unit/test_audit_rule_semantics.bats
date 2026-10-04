#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_audit_rules_cover_path\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_audit_rules_have_syscalls\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "exact path watch does not claim coverage of its parent directory" {
  rules='-a always,exit -S open -F path=/etc/ssh/sshd_config -F perm=wa'
  _audit_rules_cover_path "$rules" /etc/ssh/sshd_config
  run _audit_rules_cover_path "$rules" /etc/ssh
  [[ "$status" -ne 0 ]]
}

@test "directory filter covers descendants but not sibling prefixes" {
  rules='-a always,exit -S open -F dir=/etc/ssh -F perm=wa'
  _audit_rules_cover_path "$rules" /etc/ssh
  _audit_rules_cover_path "$rules" /etc/ssh/sshd_config
  run _audit_rules_cover_path "$rules" /etc/ssh-other/config
  [[ "$status" -ne 0 ]]
}

@test "legacy file watch matches only the watched file" {
  rules='-w /var/log/wtmp -p wa -k session'
  _audit_rules_cover_path "$rules" /var/log/wtmp
  run _audit_rules_cover_path "$rules" /var/log/wtmp.backup
  [[ "$status" -ne 0 ]]
}

@test "syscall family requires every exact syscall token" {
  rules='-a always,exit -F arch=b64 -S rename,renameat,unlink,unlinkat -F auid>=1000'
  _audit_rules_have_syscalls "$rules" rename renameat unlink unlinkat
  run _audit_rules_have_syscalls "$rules" renameat2
  [[ "$status" -ne 0 ]]
}

@test "syscalls may be distributed across effective rules" {
  rules=$'-a always,exit -S init_module,finit_module\n-a always,exit -S delete_module'
  _audit_rules_have_syscalls "$rules" init_module finit_module delete_module
}

@test "never-exit suppression cannot satisfy an audit family" {
  rules=$'-a never,exit -S adjtimex,settimeofday,clock_settime\n-a always,exit -S open'
  run _audit_rules_have_syscalls "$rules" adjtimex settimeofday clock_settime
  [[ "$status" -ne 0 ]]
}

@test "audit findings distinguish PAM events from history tamper watches" {
  block=$(sed -n '/# PAM and the kernel audit interface/,/Audit tamper watches missing for login history/p' "$SCRIPT")
  [[ "$block" == *'USER_LOGIN/USER_START/'* ]]
  [[ "$block" == *'/var/lib/lastlog/lastlog2.db'* ]]
  [[ "$block" == *'_faillock_backend_dirs'* ]]
  # shellcheck disable=SC2016  # literal production-source variable
  [[ "$block" == *'faillock:${_faillock_canonical}'* ]]
  [[ "$block" == *'tamper watches'* ]]
}
