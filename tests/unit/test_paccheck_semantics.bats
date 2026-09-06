#!/usr/bin/env bats

# paccheck returns 1 both for detected discrepancies and for operational
# failures. These tests keep the recognized-result boundary and cache tiering
# independent of a live pacman database.

# Bats invokes setup/test bodies indirectly.
# shellcheck disable=SC2317

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_paccheck_generated_path\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_paccheck_detail_counts\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "paccheck parser separates substantive cache and metadata packages" {
  raw=$'coreutils: \'/usr/bin/true\' sha256sum mismatch (expected abc)\n'
  raw+=$'ghc-libs: \'/usr/lib/ghc-9.6.6/lib/package.conf.d/package.cache\' sha256sum mismatch (expected def)\n'
  raw+=$'filesystem: \'/etc/resolv.conf\' type mismatch (expected file)\n'
  raw+=$'coreutils: \'/usr/bin/true\' size mismatch (expected 1.00 K)'
  result=$(_paccheck_detail_counts "$raw")
  [[ "$result" == $'1\t1\t2\t3' ]]
}

@test "paccheck missing files remain substantive" {
  result=$(_paccheck_detail_counts "bash: '/usr/bin/bash' missing file")
  [[ "$result" == $'1\t0\t0\t1' ]]
}

@test "paccheck parser rejects an operational error" {
  run _paccheck_detail_counts "error: failed to initialize alpm"
  [[ "$status" -ne 0 ]]
}

@test "paccheck parser rejects empty and partial output" {
  run _paccheck_detail_counts ""
  [[ "$status" -ne 0 ]]
  run _paccheck_detail_counts $'bash: \'/usr/bin/bash\' sha256sum mismatch (expected abc)\nwarning: read error'
  [[ "$status" -ne 0 ]]
}
