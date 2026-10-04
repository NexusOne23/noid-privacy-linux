#!/usr/bin/env bats

# Bats invokes fixture functions; extracted helpers use optional fixture paths.
# shellcheck disable=SC2317
# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # shellcheck disable=SC1090
  source <(sed -n '/^_aide_invocation_report() {$/,/^}$/p' "$SCRIPT")
  INVOCATION=11111111111111111111111111111111
  REPORT_DIR="$BATS_TEST_TMPDIR/reports"
  mkdir -m 0700 "$REPORT_DIR"
  REPORT="$REPORT_DIR/aide-check-20260901-120500.$INVOCATION.abc123.log"
}

report() {
  printf '  Added entries: 0\n  Removed entries: 0\n  Changed entries: 7\n' > "$1"
  chmod 0600 "$1"
}

probe() { _aide_invocation_report "$INVOCATION" "$REPORT_DIR" "$EUID"; }

@test "AIDE selects the unique exact invocation report with native file metadata" {
  report "$REPORT"
  run probe
  [[ "$status" -eq 0 && "$output" == "$REPORT" ]]
}

@test "AIDE shared and legacy reports cannot substitute for an invocation report" {
  report "$REPORT_DIR/aide.log"
  report "$REPORT_DIR/aide-check-20260901-120000.log"
  report "$REPORT_DIR/aide-check-20260901-120500.abc123.log"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
  report "$REPORT"
  run probe
  [[ "$status" -eq 0 && "$output" == "$REPORT" ]]
}

@test "AIDE foreign invocation reports cannot be associated by timestamp" {
  report "$REPORT_DIR/aide-check-20260901-120500.22222222222222222222222222222222.abc123.log"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "AIDE two reports for one invocation are ambiguous" {
  report "$REPORT"
  report "${REPORT/abc123/def456}"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "AIDE malformed matching names cannot supply report evidence" {
  for name in "aide-check-wrong.$INVOCATION.abc123.log" \
              "aide-check-20260901-120500.$INVOCATION.short.log"; do
    report "$REPORT_DIR/$name"
    run probe
    [[ "$status" -eq 1 && -z "$output" ]]
    rm -- "$REPORT_DIR/$name"
  done
}

@test "AIDE filename newlines cannot be mistaken for a complete unique inventory" {
  report "$REPORT"
  report "$REPORT_DIR/aide-check-20260901"$'\n'"-120500.$INVOCATION.def456.log"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "AIDE invalid or unavailable invocation identity selects nothing" {
  report "$REPORT"
  for INVOCATION in '' 00000000000000000000000000000000 \
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ../escape 111; do
    run probe
    [[ "$status" -eq 1 && -z "$output" ]]
  done
}

@test "AIDE report symlinks and matching directories remain unsafe" {
  report "$REPORT_DIR/target.txt"
  ln -s target.txt "$REPORT"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
  rm -- "$REPORT"
  mkdir "$REPORT"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "AIDE an unsafe second matching object cannot be ignored" {
  report "$REPORT"
  ln -s absent "${REPORT/abc123/def456}"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "AIDE empty or nonprivate report files cannot supply evidence" {
  touch "$REPORT"
  chmod 0600 "$REPORT"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
  report "$REPORT"
  chmod 0644 "$REPORT"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "AIDE hardlinked reports cannot supply evidence" {
  report "$REPORT"
  ln "$REPORT" "$REPORT_DIR/extra-link"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "AIDE report directory metadata and object type are verified" {
  report "$REPORT"
  chmod 0755 "$REPORT_DIR"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
  chmod 0700 "$REPORT_DIR"
  ln -s "$REPORT_DIR" "$BATS_TEST_TMPDIR/linked"
  REPORT_DIR="$BATS_TEST_TMPDIR/linked"
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "AIDE failed inventory discards even complete matching output" {
  report "$REPORT"
  find() { command find "$@"; return 7; }
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "AIDE failed metadata reads cannot supply report evidence" {
  report "$REPORT"
  stat() { command stat "$@"; return 7; }
  run probe
  [[ "$status" -eq 1 && -z "$output" ]]
}
