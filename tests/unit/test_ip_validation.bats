#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # Load only the pure parsers; never run network probes or the root audit.
  # shellcheck disable=SC1090
  source <(awk '
    /^(_is_ip_address|_is_public_ip_address)\(\) \{/ { in_function=1 }
    in_function { print }
    in_function && /^}/ { in_function=0 }
  ' "$SCRIPT")
}

@test "IP validation accepts decimal boundaries and valid IPv6 compression" {
  local value
  for value in 0.0.0.0 1.1.1.1 10.0.0.1 255.255.255.255 \
    :: ::1 1:: 2001:db8::1 1:2:3:4:5:6:7:: \
    ::1:2:3:4:5:6:7 1:2:3:4:5:6:7:8 \
    FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF; do
    _is_ip_address "$value"
  done
  _is_public_ip_address 1.1.1.1
  _is_public_ip_address 2001:4860:4860::8888
}

@test "leading-zero IPv4 octets cannot bypass private-address rejection" {
  local value
  for value in 010.0.0.1 00.0.0.0 001.1.1.1 1.01.1.1 \
    192.168.001.1 192.168.1.001 1.1.1.00; do
    run _is_ip_address "$value"
    [[ "$status" -eq 1 ]]
    run _is_public_ip_address "$value"
    [[ "$status" -eq 1 ]]
  done
}

@test "IPv6 validation rejects dangling colons and invalid group counts" {
  local value
  for value in :1:2:3:4:5:6:7:8 1:2:3:4:5:6:7:8: \
    :2001:db8::1 2001:4860:4860::8888: \
    : ::1:: :::1 1::: 1:2:3:4:5:6:7 \
    1:2:3:4:5:6:7:8:9 1:2:3:4:5:6:7:8:: \
    ::1:2:3:4:5:6:7:8 2001:db8::10000; do
    run _is_ip_address "$value"
    [[ "$status" -eq 1 ]]
    run _is_public_ip_address "$value"
    [[ "$status" -eq 1 ]]
  done
}
