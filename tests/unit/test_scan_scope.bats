#!/usr/bin/env bats

# Bats invokes the extracted production header and consumes fixture globals.
# shellcheck disable=SC2034
setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # shellcheck disable=SC1090
  source <(awk '/^header\(\) \{/,/^}/ {print}' "$SCRIPT")
  JSON_MODE=true
  SECTIONS_RUN=0
  SECTION_KEYS=(kernel selinux firewall)
  unset _SECTIONS_VISITED
}

@test "scan scope counts distinct executed sections independently of findings" {
  header 01 KERNEL
  header 02 SELINUX
  header 02 APPARMOR
  [[ "$SECTIONS_RUN" -eq 2 ]]
  header 03 FIREWALL
  [[ "$SECTIONS_RUN" -eq 3 ]]
}

@test "sections never dispatched do not inflate the completed scan" {
  header 03 FIREWALL
  [[ "$SECTIONS_RUN" -eq 1 && "${#_SECTIONS_VISITED[@]}" -eq 1 ]]
  [[ -z "${_SECTIONS_VISITED[kernel]:-}" ]]
}

@test "unknown headers cannot count as an additional canonical section" {
  header 01 KERNEL
  header 99 UNKNOWN
  [[ "$SECTIONS_RUN" -eq 1 && "$CURRENT_SECTION_ID" == unknown ]]
}
