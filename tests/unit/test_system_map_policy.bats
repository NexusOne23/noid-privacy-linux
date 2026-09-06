#!/usr/bin/env bats

# Bats calls setup and stat mocks indirectly. Per-test state is isolated.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031

setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _noid_expected_mode_for_path _noid_mode_override_matches; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '
      $0 == signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  MOCK_MODE=600
  MOCK_OWNER=0
  MOCK_GROUP=0
  MOCK_TYPE=8180
  MOCK_RC=0
}

stat() {
  [[ "$MOCK_RC" -eq 0 ]] || return "$MOCK_RC"
  case "$2" in
    %a) printf '%s\n' "$MOCK_MODE" ;;
    %u) printf '%s\n' "$MOCK_OWNER" ;;
    %g) printf '%s\n' "$MOCK_GROUP" ;;
    %f) printf '%s\n' "$MOCK_TYPE" ;;
    *) return 1 ;;
  esac
}

@test "System.map permission policy covers boot and both module path spellings" {
  local path
  for path in /boot/System.map-6.8.0-test+debug /lib/modules/6.8.0-test+debug/System.map \
              /usr/lib/modules/6.8.0-test+debug/System.map; do
    run _noid_expected_mode_for_path "$path"
    [[ "$status" -eq 0 && "$output" == 600 ]]
    _noid_mode_override_matches noid-privacy ".M.......    $path" "$path"
  done
}

@test "System.map policy rejects empty nested and traversing versions" {
  local path
  for path in /boot/System.map- /boot/System.map-../file /boot/System.map-. \
              /boot/System.map-.. /lib/modules//System.map /lib/modules/../System.map \
              /usr/lib/modules/./System.map /lib/modules/6.8/subdir/System.map \
              /var/tmp/System.map-6.8 '/boot/System.map-6.8 invalid'; do
    run _noid_expected_mode_for_path "$path"
    [[ "$status" -ne 0 ]]
  done
}

@test "System.map content links capabilities missing and unreadable RPM evidence stay visible" {
  local flags path=/boot/System.map-6.8
  _noid_mode_override_matches noid-privacy ".M.......    $path" "$path"
  for flags in SM5...... .M5...... .M..L.... .M......P .M.....T. .M?...... missing .........; do
    run _noid_mode_override_matches noid-privacy "$flags    $path" "$path"
    [[ "$status" -ne 0 ]]
  done
}

@test "System.map mode and both owners must match independently" {
  local path=/boot/System.map-6.8
  MOCK_MODE=644
  run _noid_mode_override_matches noid-privacy ".M.......    $path" "$path"
  [[ "$status" -ne 0 ]]
  MOCK_MODE=600 MOCK_OWNER=1000
  run _noid_mode_override_matches noid-privacy ".M.......    $path" "$path"
  [[ "$status" -ne 0 ]]
  MOCK_OWNER=0 MOCK_GROUP=1000
  run _noid_mode_override_matches noid-privacy ".M.......    $path" "$path"
  [[ "$status" -ne 0 ]]
}

@test "System.map changed file types cannot be mistaken for permission-only hardening" {
  local path=/boot/System.map-6.8
  for MOCK_TYPE in a180 4180 1180 2180 6180 c180; do
    run _noid_mode_override_matches noid-privacy ".M.......    $path" "$path"
    [[ "$status" -ne 0 ]]
  done
}

@test "System.map failed empty or malformed metadata never matches" {
  local path=/boot/System.map-6.8
  for MOCK_TYPE in '' unknown 8180junk 100008180; do
    run _noid_mode_override_matches noid-privacy ".M.......    $path" "$path"
    [[ "$status" -ne 0 ]]
  done
  MOCK_TYPE=8180 MOCK_RC=1
  run _noid_mode_override_matches noid-privacy ".M.......    $path" "$path"
  [[ "$status" -ne 0 ]]
}

@test "System.map exception is NoID-only and preserves existing narrow mode policy" {
  local path=/boot/System.map-6.8
  run _noid_mode_override_matches fedora ".M.......    $path" "$path"
  [[ "$status" -ne 0 ]]
  MOCK_MODE=755
  _noid_mode_override_matches noid-privacy '.M.......    /usr/bin/chage' /usr/bin/chage
  run _noid_mode_override_matches noid-privacy '.M.......    /usr/bin/arbitrary' /usr/bin/arbitrary
  [[ "$status" -ne 0 ]]
}
