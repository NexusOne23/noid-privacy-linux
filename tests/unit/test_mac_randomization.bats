#!/usr/bin/env bats
#
# F-385 / F-386 (v3.7.0) — NetworkManager connection-default section parser.
# Reproduces the Section 37 config-scan sed in isolation against NM config
# fixtures (cloned-mac-address + dhcp-send-hostname share the parser shape).
#
# Bug class: NM connection-default sections are ANY section whose name starts
# with "connection" — NetworkManager.conf(5): "sections with a name that all
# start with 'connection'", e.g. [connection], [connection.<name>],
# [connection-<name>]. A range anchored to the bare '^\[connection\]' (or the
# interim dot-only '^\[connection[].]') misses the named forms, so a valid
# conf.d default read as "not configured" (false negative). The final rule
# '^\[connection' matches every form — and NOT the unrelated [connectivity]
# section (diverges at the 8th char, 'o' vs 'v').
#
# Counter-increment style: var=$((var + 1)), never ((var++)) — bash
# post-increment returns rc=1 when the var was 0, which bombs under
# `set -e` (BATS default).

setup() {
  FIXTURE_DIR="${BATS_TEST_DIRNAME}/../fixtures"
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -d "$FIXTURE_DIR" ]] || skip "fixtures directory not found"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_live_mac_verdict\(\) \{/,/^}/ {print}' "$SCRIPT")
}

# Final (F-385/F-386) parser: matches ANY [connection*] section.
_parse_cloned_mac() {
  sed -n '/^\[connection/,/^\[/{ s/^ethernet\.cloned-mac-address[[:space:]]*=[[:space:]]*//p; }' "$1" 2>/dev/null | head -1
}

# Pre-F-385 broken parser: bare [connection] range only.
_parse_cloned_mac_bare() {
  sed -n '/^\[connection\]/,/^\[/{ s/^ethernet\.cloned-mac-address[[:space:]]*=[[:space:]]*//p; }' "$1" 2>/dev/null | head -1
}

# Interim F-385 parser: [connection] or [connection.<name>] (dot only, no hyphen).
_parse_cloned_mac_dotonly() {
  sed -n '/^\[connection[].]/,/^\[/{ s/^ethernet\.cloned-mac-address[[:space:]]*=[[:space:]]*//p; }' "$1" 2>/dev/null | head -1
}

@test "F-385: named [connection.<name>] (dot) section — final parser extracts 'stable'" {
  result=$(_parse_cloned_mac "$FIXTURE_DIR/nm-mac-connection-named.conf")
  [[ "$result" == "stable" ]]
}

@test "F-386: named [connection-<name>] (hyphen, NM canonical) — final parser extracts 'stable'" {
  result=$(_parse_cloned_mac "$FIXTURE_DIR/nm-mac-connection-hyphen.conf")
  [[ "$result" == "stable" ]]
}

@test "F-385: bare [connection] section still parses (no regression)" {
  result=$(_parse_cloned_mac "$FIXTURE_DIR/nm-mac-connection-bare.conf")
  [[ "$result" == "random" ]]
}

@test "bug demo: bare-only parser MISSES named dot section" {
  result=$(_parse_cloned_mac_bare "$FIXTURE_DIR/nm-mac-connection-named.conf")
  [[ -z "$result" ]]
}

@test "bug demo: dot-only parser MISSES hyphen section (NM canonical form)" {
  result=$(_parse_cloned_mac_dotonly "$FIXTURE_DIR/nm-mac-connection-hyphen.conf")
  [[ -z "$result" ]]
}

@test "final parser does NOT match unrelated [connectivity] section" {
  # A conf with only a [connectivity] section must yield no cloned-mac value.
  tmp="$(mktemp)"
  printf '[connectivity]\nethernet.cloned-mac-address=stable\n' > "$tmp"
  result=$(_parse_cloned_mac "$tmp")
  rm -f "$tmp"
  [[ -z "$result" ]]
}

@test "offline interface cannot turn equal current/permanent MAC into a warning verdict" {
  result=$(_live_mac_verdict 0 00:11:22:33:44:55 00:11:22:33:44:55)
  [[ "$result" == "inactive" ]]
}

@test "active interface with equal current/permanent MAC proves permanent use" {
  result=$(_live_mac_verdict 1 00:11:22:33:44:55 00:11:22:33:44:55)
  [[ "$result" == "permanent" ]]
}

@test "active interface with different valid MAC proves randomized use" {
  result=$(_live_mac_verdict 1 02:aa:bb:cc:dd:ee 00:11:22:33:44:55)
  [[ "$result" == "randomized" ]]
}

@test "driver zero permanent MAC stays unknown" {
  result=$(_live_mac_verdict 1 02:aa:bb:cc:dd:ee 00:00:00:00:00:00)
  [[ "$result" == "unknown" ]]
}

@test "Section 37 requires an active NetworkManager device before MAC comparison" {
  grep -qF 'nmcli -t -f DEVICE connection show --active' "$SCRIPT"
  # Literal source-code contract, not an expression for this test shell.
  # shellcheck disable=SC2016
  grep -qF '_mac_verdict=$(_live_mac_verdict "$_mac_link_active" "$_cur_mac" "$_perm_mac")' "$SCRIPT"
}
