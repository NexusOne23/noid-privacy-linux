#!/usr/bin/env bats

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_kernel_config_value\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_kernel_cmdline_value\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_kernel_lockdown_grade\(\) \{/,/^}/ {print}' "$SCRIPT")
  CONFIG_FIXTURE="$BATS_TEST_TMPDIR/config-running"
  _NOID_KERNEL_CONFIG_PATHS="$CONFIG_FIXTURE"
}

@test "kernel config reader distinguishes enabled disabled and missing keys" {
  printf '%s\n' \
    'CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y' \
    '# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set' \
    > "$CONFIG_FIXTURE"

  [[ "$(_kernel_config_value CONFIG_INIT_ON_ALLOC_DEFAULT_ON)" == "y" ]]
  [[ "$(_kernel_config_value CONFIG_INIT_ON_FREE_DEFAULT_ON)" == "n" ]]
  run _kernel_config_value CONFIG_NOT_PRESENT
  [[ "$status" -ne 0 ]]
  [[ -z "$output" ]]
}

@test "kernel command line parser returns the last exact option" {
  cmdline='quiet pti=off topic=on pti=force slab_nomerge'
  [[ "$(_kernel_cmdline_value "$cmdline" pti)" == "force" ]]
  [[ "$(_kernel_cmdline_value "$cmdline" slab_nomerge)" == "present" ]]
  run _kernel_cmdline_value "$cmdline" top
  [[ "$status" -ne 0 ]]
}

@test "boot audit uses effective defaults and runtime evidence" {
  block=$(sed -n '/# Effective boot hardening/,/_emit_pass_agg_end 7/p' "$SCRIPT")
  [[ "$block" == *'CONFIG_INIT_ON_ALLOC_DEFAULT_ON'* ]]
  [[ "$block" == *'CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT'* ]]
  [[ "$block" == *'/sys/devices/system/cpu/vulnerabilities/meltdown'* ]]
  [[ "$block" == *'debugfs not mounted'* ]]
}

@test "page allocator shuffle is context rather than a universal warning" {
  block=$(sed -n '/# Kernel Kconfig documents allocator shuffling/,/randomize_kstack_offset/p' "$SCRIPT")
  [[ "$block" == *'incidental security benefit'* ]]
  [[ "$block" == *'not graded'* ]]
  run grep -E '_emit_(warn|fail).*Page allocator' <<< "$block"
  [[ "$status" -ne 0 ]]
}

@test "kernel lockdown warning requires verified active Secure Boot" {
  [[ "$(_kernel_lockdown_grade enabled none)" == "warn" ]]
  [[ "$(_kernel_lockdown_grade disabled none)" == "info" ]]
  [[ "$(_kernel_lockdown_grade na none)" == "info" ]]
  [[ "$(_kernel_lockdown_grade unknown none)" == "info" ]]
  [[ "$(_kernel_lockdown_grade enabled integrity)" == "pass" ]]
  [[ "$(_kernel_lockdown_grade enabled '')" == "unassessed" ]]
}

@test "legacy BIOS cannot produce the Secure Boot lockdown contradiction" {
  block=$(sed -n '/# Secure Boot —/,/# Kernel Taint/p' "$SCRIPT")
  [[ "$block" == *'_SECURE_BOOT_STATE=na'* ]]
  [[ "$block" == *'none despite verified active Secure Boot'* ]]
  run grep -F 'none (despite Secure Boot)' <<< "$block"
  [[ "$status" -ne 0 ]]
}
