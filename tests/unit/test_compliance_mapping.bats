#!/usr/bin/env bats

setup() {
  REPO="${BATS_TEST_DIRNAME}/../.."
  REPORT="$REPO/scripts/coverage-report.sh"
  DOC="$REPO/Docs/CIS_RHEL9_MAPPING.md"
  [[ -x "$REPORT" && -f "$DOC" ]] || skip "coverage inputs missing"
}

@test "reviewed benchmark denominators and direct counts are stable" {
  run bash -c 'cd "$1" && scripts/coverage-report.sh' _ "$REPO"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"43 / 227 direct mappings"* ]]
  [[ "$output" == *"47 / 293 direct mappings"* ]]
  [[ "$output" == *"56 / 447 direct mappings"* ]]
}

@test "default mapping path is independent of the caller working directory" {
  run bash -c 'cd / && "$1" cis-l1' _ "$REPORT"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"43 / 227 direct mappings"* ]]
}

@test "CIS Level 2 report is cumulative and larger than Level 1" {
  l1=$(bash -c 'cd "$1" && scripts/coverage-report.sh cis-l1' _ "$REPO" \
    | awk '{for (i=1; i<=NF; i++) if ($i == "/") print $(i-1)}')
  l2=$(bash -c 'cd "$1" && scripts/coverage-report.sh cis-l2' _ "$REPO" \
    | awk '{for (i=1; i<=NF; i++) if ($i == "/") print $(i-1)}')
  [[ "$l1" -eq 43 ]]
  [[ "$l2" -eq 47 ]]
  [[ "$l2" -gt "$l1" ]]
}

@test "partial rows never enter direct coverage" {
  direct_cis=$(awk -F'|' '
    /^\|[[:space:]]*[0-9][0-9][^|]*\|/ {
      for (i=4; i<=7; i++) gsub(/^[[:space:]]+|[[:space:]]+$/, "", $i)
      if ($7 == "Direct" && $5 != "—") print $5
    }
  ' "$DOC" | sort -u | wc -l)
  [[ "$direct_cis" -eq 47 ]]
  grep -q '| Partial |' "$DOC"
}

@test "duplicate Direct CIS IDs fail validation" {
  temp_doc=$(mktemp)
  {
    echo '| 01 A | one | L1 | 1.2.3 | — | Direct |'
    echo '| 02 B | two | L1 | 1.2.3 | — | Direct |'
  } > "$temp_doc"
  run bash -c 'cd "$1" && scripts/coverage-report.sh --doc "$2"' _ "$REPO" "$temp_doc"
  rm -f "$temp_doc"
  [[ "$status" -ne 0 ]]
  [[ "$output" == *"duplicate Direct CIS IDs"* ]]
}

@test "duplicate Direct STIG IDs fail validation" {
  temp_doc=$(mktemp)
  {
    echo '| 01 A | one | — | — | RHEL-09-123456 | Direct |'
    echo '| 02 B | two | — | — | RHEL-09-123456 | Direct |'
  } > "$temp_doc"
  run bash -c 'cd "$1" && scripts/coverage-report.sh --doc "$2"' _ "$REPO" "$temp_doc"
  rm -f "$temp_doc"
  [[ "$status" -ne 0 ]]
  [[ "$output" == *"duplicate Direct STIG IDs"* ]]
}

@test "direct coverage rows require an exact CIS or STIG identifier" {
  temp_doc=$(mktemp)
  echo '| 01 A | vague evidence | — | — | — | Direct |' > "$temp_doc"
  run bash -c 'cd "$1" && scripts/coverage-report.sh --doc "$2"' _ "$REPO" "$temp_doc"
  rm -f "$temp_doc"
  [[ "$status" -ne 0 ]]
  [[ "$output" == *"invalid mapping row"* ]]
}

@test "mapping validation avoids awk intervals unsupported by Debian 12 mawk" {
  run grep -nF '[0-9]{6}' "$REPORT"
  [[ "$status" -ne 0 ]]

  run bash -c 'cd "$1" && scripts/coverage-report.sh' _ "$REPO"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"43 / 227 direct mappings"* ]]
  [[ "$output" == *"47 / 293 direct mappings"* ]]
  [[ "$output" == *"56 / 447 direct mappings"* ]]
}

@test "RHEL shadow modes use the benchmark-specific zero mode" {
  grep -q 'PERM_CHECKS\["/etc/shadow"\]="000"' "$REPO/noid-privacy-linux.sh"
  grep -q 'PERM_CHECKS\["/etc/gshadow"\]="000"' "$REPO/noid-privacy-linux.sh"
  grep -q 'PERM_CHECKS\["/etc/shadow"\]="640"' "$REPO/noid-privacy-linux.sh"
}

@test "direct shared-memory mappings have effective nodev nosuid noexec evidence" {
  grep -q '_effective_mount_record /dev/shm' "$REPO/noid-privacy-linux.sh"
  for option in nodev nosuid noexec; do
    grep -q "/dev/shm.*$option" "$DOC"
  done
}
