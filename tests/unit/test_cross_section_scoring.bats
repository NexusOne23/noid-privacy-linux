#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
}

@test "incoming ICMP redirect state is graded in one weighted section" {
  sysctl_block=$(sed -n '/^check_sysctl() {/,/^}/p' "$SCRIPT")
  network_block=$(sed -n '/^check_network() {/,/^}/p' "$SCRIPT")

  [[ "$sysctl_block" != *'net.ipv4.conf.all.accept_redirects'* ]]
  [[ "$sysctl_block" != *'net.ipv4.conf.default.accept_redirects'* ]]
  [[ "$network_block" == *'net.ipv4.conf.all.accept_redirects'* ]]
  [[ "$network_block" == *'net.ipv4.conf.default.accept_redirects'* ]]
  [[ "$network_block" == *'_emit_fail "ICMP redirects: accepted"'* ]]
}

@test "media wording does not conflate file-manager opening with autorun" {
  block=$(sed -n '/_de_automount_open_cb() {/,/^  }/p' "$SCRIPT")
  [[ "$block" == *'File manager opens automatically after removable-media mount'* ]]
  [[ "$block" != *'Automatic opening of removable media'* ]]
}
