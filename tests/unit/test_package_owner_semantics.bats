#!/usr/bin/env bats

# Bats invokes setup/test bodies and their command mocks indirectly.
# shellcheck disable=SC2317
# shellcheck disable=SC2034  # distribution family is consumed by sourced helper

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_path_has_package_owner\(\) \{/,/^}/ {print}' "$SCRIPT")
  require_cmd() { declare -F "$1" >/dev/null; }
}

@test "Debian package ownership accepts a verified merged-usr alias" {
  DISTRO_FAMILY=debian
  dpkg-query() { [[ "$1" == "-S" && "$2" == "/bin/true" ]]; }
  _path_has_package_owner /usr/bin/true
}

@test "Debian package ownership rejects a mere prefix rewrite" {
  DISTRO_FAMILY=debian
  dpkg-query() { [[ "$1" == "-S" && "$2" == "/bin/true" ]]; }
  run _path_has_package_owner /usr/bin/false
  [[ "$status" -ne 0 ]]
}

@test "package owner backend follows the detected distribution family" {
  DISTRO_FAMILY=debian
  rpm() { return 0; }
  dpkg-query() { [[ "$1" == "-S" && "$2" == "/usr/bin/true" ]]; }
  _path_has_package_owner /usr/bin/true
}
