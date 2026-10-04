#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_sysctl_mismatch_assessment\(\) \{/,/^}/ {print}' "$SCRIPT")
}

grade() {
  _sysctl_mismatch_assessment "$@" | cut -f1
}

@test "recovery-only SysRq masks are context and broader masks warn" {
  [[ "$(grade kernel.sysrq 16 0 1)" == "info" ]]
  [[ "$(grade kernel.sysrq 32 0 1)" == "info" ]]
  [[ "$(grade kernel.sysrq 48 0 1)" == "info" ]]
  [[ "$(grade kernel.sysrq 1 0 1)" == "warn" ]]
  [[ "$(grade kernel.sysrq 64 0 1)" == "warn" ]]
}

@test "redirect sending is dormant without forwarding" {
  [[ "$(grade net.ipv4.conf.all.send_redirects 1 0 1)" == "info" ]]
  [[ "$(grade net.ipv4.conf.all.send_redirects 1 1 1)" == "warn" ]]
  [[ "$(grade net.ipv4.conf.all.send_redirects 1 unknown 1)" == "warn" ]]
}

@test "martian logging is a privacy and visibility tradeoff" {
  [[ "$(grade net.ipv4.conf.all.log_martians 0 0 1)" == "info" ]]
  [[ "$(_sysctl_mismatch_assessment net.ipv4.conf.all.log_martians 0 0 1)" == *'retains network metadata'* ]]
}

@test "BPF JIT severity accounts for unprivileged BPF state" {
  [[ "$(grade net.core.bpf_jit_harden 0 0 1)" == "warn" ]]
  [[ "$(grade net.core.bpf_jit_harden 0 0 2)" == "warn" ]]
  [[ "$(grade net.core.bpf_jit_harden 0 0 0)" == "fail" ]]
  [[ "$(grade net.core.bpf_jit_harden 0 0 unknown)" == "fail" ]]
}

@test "route compatibility and sticky-directory extensions warn" {
  [[ "$(grade net.ipv4.conf.all.rp_filter 0 0 1)" == "warn" ]]
  [[ "$(grade fs.protected_fifos 1 0 1)" == "warn" ]]
  [[ "$(grade fs.protected_regular 1 0 1)" == "warn" ]]
}

@test "unprivileged pointer and ptrace baseline accepts maintained level one" {
  block=$(sed -n '/^declare -A SYSCTL_CHECKS=(/,/^)/p' "$SCRIPT")
  minimums=$(sed -n '/^declare -A SYSCTL_MIN_OK=(/,/^)/p' "$SCRIPT")
  [[ "$block" == *'["kernel.kptr_restrict"]=1'* ]]
  [[ "$block" == *'["kernel.yama.ptrace_scope"]=1'* ]]
  [[ "$minimums" == *'["kernel.kptr_restrict"]=1'* ]]
  [[ "$minimums" == *'["kernel.yama.ptrace_scope"]=1'* ]]
}

@test "faillock clean history requires an active PAM module" {
  users=$(sed -n '/# Authentication rate limiting/,/# History File Permissions/p' "$SCRIPT")
  [[ "$users" == *'_FAILLOCK_CONFIGURED=false'* ]]
  # Literal production source, not test-shell expansion.
  # shellcheck disable=SC2016
  [[ "$users" == *'if $_FAILLOCK_CONFIGURED && require_cmd faillock'* ]]
  [[ "$users" == *'Faillock history is unassessed because pam_faillock is not active'* ]]
}

@test "export metadata redacts hostname and stable disk identifiers" {
  grep -q 'hostname.*\[redacted\]' "$SCRIPT"
  grep -q 'dev/disk/by-\\2/\[redacted\]' "$SCRIPT"
  grep -Fq "_HEADER_HOSTNAME=\$(_finding_safe \"\$HOSTNAME\")" "$SCRIPT"
}
