#!/usr/bin/env bats

# arch-audit output is vendor-sourced network evidence, but its machine-format
# parser is deterministic and can be tested without a network or pacman DB.

# Bats invokes setup/test bodies indirectly.
# shellcheck disable=SC2317

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_arch_audit_counts\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "arch-audit parser deduplicates affected fixed and severe packages" {
  raw=$'openssl|3.6.0-2|High risk\nopenssl|3.6.0-2|Medium risk\nlibxml2||Critical risk\ngiflib||Unknown'
  result=$(printf '%s\n' "$raw" | _arch_audit_counts)
  [[ "$result" == $'3\t1\t2' ]]
}

@test "arch-audit empty result is a valid zero match" {
  result=$(printf '%s' "" | _arch_audit_counts)
  [[ "$result" == $'0\t0\t0' ]]
}

@test "arch-audit parser rejects malformed and unknown severity records" {
  run _arch_audit_counts <<< 'bash|1.2-3|Extreme risk'
  [[ "$status" -ne 0 ]]
  run _arch_audit_counts <<< 'error: request failed'
  [[ "$status" -ne 0 ]]
}

@test "Arch update source keeps cache and advisory network semantics explicit" {
  grep -q '_PACMAN_UPDATES_RC.*-eq 1.*-z.*_PACMAN_UPDATES_OUT' "$SCRIPT"
  grep -q 'pacman -Qq' "$SCRIPT"
  grep -q 'should_skip "netleaks"' "$SCRIPT"
  grep -q 'SEC_EVIDENCE_INCOMPLETE=true' "$SCRIPT"
  # shellcheck disable=SC2016  # literal production expression
  grep -q '\$SEC_EVIDENCE_INCOMPLETE && _score_mark_incomplete' "$SCRIPT"
  grep -q "arch-audit --color never --format '%n|%v|%s'" "$SCRIPT"
  grep -q 'fixed package versions are available' "$SCRIPT"
}
