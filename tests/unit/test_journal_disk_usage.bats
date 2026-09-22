#!/usr/bin/env bats
#
# Regression coverage for journal storage accounting. `du --bytes` reports
# apparent length and overstates sparse/preallocated journal files; privacy
# grading must use allocated filesystem blocks instead.

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"

  # Load the standalone helper without executing the root audit.
  # shellcheck disable=SC1090
  source <(awk '/^_allocated_size_bytes\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_systemd_size_bytes\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_journal_usage_within_configured_bound\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "systemd journal size values use documented IEC multipliers" {
  [[ "$(_systemd_size_bytes 500M)" -eq $((500 * 1024 * 1024)) ]]
  [[ "$(_systemd_size_bytes 1.5G)" -eq $((1536 * 1024 * 1024)) ]]
}

@test "invalid systemd size values fail closed" {
  run _systemd_size_bytes '500MB'
  [[ "$status" -ne 0 ]]
  run _systemd_size_bytes 'not-a-size'
  [[ "$status" -ne 0 ]]
}

@test "configured journal bound includes each active file rotation allowance" {
  local mib=$((1024 * 1024))
  _journal_usage_within_configured_bound $((523 * mib)) \
    $((500 * mib)) $((50 * mib)) 2

  run _journal_usage_within_configured_bound $((601 * mib)) \
    $((500 * mib)) $((50 * mib)) 2
  [[ "$status" -ne 0 ]]
}

@test "allocated-size helper does not count sparse holes as disk usage" {
  local sparse_file="$BATS_TEST_TMPDIR/sparse.journal"
  local allocated apparent
  truncate --size=64M "$sparse_file"
  printf 'journal-data' > "$sparse_file"
  truncate --size=64M "$sparse_file"

  allocated=$(_allocated_size_bytes "$sparse_file")
  apparent=$(du --bytes "$sparse_file" | cut -f1)

  [[ "$allocated" =~ ^[0-9]+$ ]]
  [[ "$apparent" -eq $((64 * 1024 * 1024)) ]]
  [[ "$allocated" -lt "$apparent" ]]
}

@test "allocated-size helper fails instead of reporting zero for a missing path" {
  run _allocated_size_bytes "$BATS_TEST_TMPDIR/does-not-exist"
  [[ "$status" -ne 0 ]]
  [[ -z "$output" ]]
}

@test "journal privacy check uses allocated blocks and contains no old false rationale" {
  # Literal source-code patterns.
  # shellcheck disable=SC2016
  grep -q '_allocated_size_bytes "$journal_dir"' "$SCRIPT"
  grep -q 'filesystem block-usage view' "$SCRIPT"
  # Literal source-code assertion; command substitution must not expand.
  # shellcheck disable=SC2016
  grep -q '_journal_usage_within_configured_bound "$jsize"' "$SCRIPT"

  # shellcheck disable=SC2016
  run grep -nF 'du -sb "$journal_dir"' "$SCRIPT"
  [[ "$status" -ne 0 ]]
  run grep -nF 'fs-overhead/CoW/orphan-file delta' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}
