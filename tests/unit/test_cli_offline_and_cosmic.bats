#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
}

@test "version flag is available without root and exits successfully" {
  run bash "$SCRIPT" --version
  [[ "$status" -eq 0 ]]
  [[ "$output" == "NoID Privacy for Linux 3.7.1" ]]
}

@test "conflicting compliance profiles fail instead of silently overwriting" {
  run bash "$SCRIPT" --cis-l1 --stig
  [[ "$status" -eq 1 ]]
  [[ "$output" == *"compliance profiles are mutually exclusive"* ]]
  [[ "$output" == *"--cis-l1 and --stig"* ]]
}

@test "repeating the same compliance profile is idempotent" {
  run bash "$SCRIPT" --cis-l2 --cis-l2 --version
  [[ "$status" -eq 0 ]]
  [[ "$output" == "NoID Privacy for Linux 3.7.1" ]]
}

@test "offline mode skips egress checks but preserves local VPN assessment" {
  line=$(grep -E -- '--offline\) SKIP_SECTIONS' "$SCRIPT")
  [[ "$line" == *'"interfaces" "netleaks"'* ]]
  [[ "$line" != *'"vpn"'* ]]
}

@test "every Section 05 active probe is guarded by netleaks" {
  connectivity=$(sed -n '/BEGIN NOID OUTBOUND CONNECTIVITY PROBES/,/END NOID OUTBOUND CONNECTIVITY PROBES/p' "$SCRIPT")
  lan=$(sed -n '/BEGIN NOID LAN ISOLATION PROBES/,/END NOID LAN ISOLATION PROBES/p' "$SCRIPT")

  [[ "$connectivity" == *'if ! should_skip "netleaks"; then'* ]]
  [[ "$connectivity" == *'ping -c1 -W2 1.1.1.1'* ]]
  [[ "$connectivity" == *'curl -fsS --max-time 5 http://cp.cloudflare.com/generate_204'* ]]
  [[ "$lan" == *'if should_skip "netleaks"; then'* ]]
  # Literal production source, not a test-shell expansion.
  # shellcheck disable=SC2016
  [[ "$lan" == *'ping -c1 -W1 "$GW"'* ]]
}

@test "no-VPN posture and ordinary IPv6 are not unconditional adverse findings" {
  run grep -E '_emit_(warn|fail) "No (active )?VPN|_emit_warn "IPv6 active' "$SCRIPT"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'possible VPN bypass'* ]]
  [[ "$output" != *'No VPN interface active'* ]]
  grep -q '_emit_info "No active VPN interface (valid no-VPN posture' "$SCRIPT"
}

@test "private DNS alone and an unresolved stub cannot earn a VPN PASS" {
  run grep -E '_emit_pass "DNS via VPN \(private|_emit_pass "DNS via systemd-resolved \(stub resolver' "$SCRIPT"
  [[ "$status" -ne 0 ]]
  grep -q '_dns_address_via_vpn' "$SCRIPT"
}

@test "VPN-agnostic policy does not require Fail2Ban or a specific browser tool" {
  run grep -E '_emit_(fail|warn) "fail2ban: INACTIVE|_emit_warn "No password manager detected|_emit_warn "uBlock Origin not found' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "optional telemetry tools require effective evidence before adverse grading" {
  grep -q 'Snap telemetry setting unavailable; effective collection state not inferred' "$SCRIPT"
  grep -q 'ABRT local crash collection active.*automatic upload not proven' "$SCRIPT"
  run grep -q 'ABRT crash reporter active.*sends crash data' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "COSMIC compositor can establish the desktop family under sudo" {
  grep -q 'for _de_proc in .*cosmic-comp' "$SCRIPT"
  # Literal production source, not a test-shell expansion.
  # shellcheck disable=SC2016
  grep -q '"\$_de_proc" == "cosmic-comp".*DESKTOP_ENV="COSMIC"' "$SCRIPT"
  grep -q '\*cosmic\*) _DE_FAMILY="cosmic"' "$SCRIPT"
}

@test "COSMIC idle policy uses native RON config and documented v1 default" {
  grep -q '_cosmic_config_for_users "com.system76.CosmicIdle" 1 "screen_off_time"' "$SCRIPT"
  grep -q '"Some(900000)"' "$SCRIPT"
  run grep -q 'org.gnome.*Cosmic' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}
