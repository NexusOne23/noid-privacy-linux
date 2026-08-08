#!/usr/bin/env bats

# The production helpers call this mock indirectly.
# shellcheck disable=SC2317

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_process_pids_exact\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_process_running_exact\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "long executable names use anchored full-command matching" {
  pgrep() {
    [[ "$1" == "-f" && "$2" == "--" \
       && "$3" == '(^|/)baloo_file_extractor([[:space:]]|$)' ]]
    printf '%s\n' 42
  }

  run _process_pids_exact baloo_file_extractor
  [[ "$status" -eq 0 ]]
  [[ "$output" == "42" ]]
}

@test "exact process helper accepts maintained executable punctuation" {
  pgrep() { printf '%s\n' 7; }
  run _process_running_exact xdg-desktop-portal
  [[ "$status" -eq 0 ]]
}

@test "exact process helper rejects regex injection" {
  pgrep() { return 0; }
  run _process_pids_exact 'portal.*'
  [[ "$status" -eq 2 ]]
}

@test "production exact process checks avoid the 15-byte comm interface" {
  run grep -nE 'pgrep[^|;&]*(-x|--exact)|pgrep -[A-Za-z]*x' "$SCRIPT"
  [[ "$status" -ne 0 ]]
  grep -q '_process_running_exact baloo_file_extractor' "$SCRIPT"
  grep -q '_process_running_exact xdg-desktop-portal' "$SCRIPT"
}
