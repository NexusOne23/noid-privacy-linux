#!/usr/bin/env bats

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_debsums_path_is_code\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_debsums_code_count\(\) \{/,/^}/ {print}' "$SCRIPT")

  _NOID_ROOT_PREFIX="$BATS_TEST_TMPDIR/root"
  mkdir -p "$BATS_TEST_TMPDIR/root/usr/bin" \
    "$BATS_TEST_TMPDIR/root/usr/lib/firefox/distribution" \
    "$BATS_TEST_TMPDIR/root/usr/lib/example" \
    "$BATS_TEST_TMPDIR/root/usr/share/applications"
  printf '%s\n' '[Global]' > "$BATS_TEST_TMPDIR/root/usr/lib/firefox/distribution/distribution.ini"
  printf '%s\n' 'binary' > "$BATS_TEST_TMPDIR/root/usr/bin/tool"
  printf '%s\n' 'library' > "$BATS_TEST_TMPDIR/root/usr/lib/example/libexample.so.1"
  printf '%s\n' '#!/bin/sh' > "$BATS_TEST_TMPDIR/root/usr/lib/example/helper"
  chmod 0755 "$BATS_TEST_TMPDIR/root/usr/lib/example/helper"
  printf '%s\n' '[Desktop Entry]' > "$BATS_TEST_TMPDIR/root/usr/share/applications/example.desktop"
}

@test "executable directories are classified as code" {
  _debsums_path_is_code "$BATS_TEST_TMPDIR/root/usr/bin/tool"
}

@test "shared libraries and executable helpers below lib are code" {
  _debsums_path_is_code "$BATS_TEST_TMPDIR/root/usr/lib/example/libexample.so.1"
  _debsums_path_is_code "$BATS_TEST_TMPDIR/root/usr/lib/example/helper"
}

@test "arbitrary data below usr lib is not promoted to code" {
  run _debsums_path_is_code "$BATS_TEST_TMPDIR/root/usr/lib/firefox/distribution/distribution.ini"
  [[ "$status" -ne 0 ]]
}

@test "desktop files outside executable trees remain non-code" {
  run _debsums_path_is_code "$BATS_TEST_TMPDIR/root/usr/share/applications/example.desktop"
  [[ "$status" -ne 0 ]]
}

@test "debsums code count follows content semantics rather than lib prefix" {
  paths=$(printf '%s\n' \
    "$BATS_TEST_TMPDIR/root/usr/bin/tool" \
    "$BATS_TEST_TMPDIR/root/usr/lib/example/libexample.so.1" \
    "$BATS_TEST_TMPDIR/root/usr/lib/example/helper" \
    "$BATS_TEST_TMPDIR/root/usr/lib/firefox/distribution/distribution.ini" \
    "$BATS_TEST_TMPDIR/root/usr/share/applications/example.desktop")
  run _debsums_code_count "$paths"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "3" ]]
}
