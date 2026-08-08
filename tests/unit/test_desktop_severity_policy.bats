#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_critical_file_policy_grade\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_usbguard_rules_allow_all\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_usbguard_policy_grade\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_block_stack_crypt_names\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_vpn_default_routes\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_sudoers_mode_is_safe\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_sudoers_nopasswd_scope\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_faillock_deny_grade\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_luks_keyslot_pbkdfs\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_resolved_llmnr_state_from_status\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "critical-file policy requires root ownership and accepts stricter modes" {
  [[ "$(_critical_file_policy_grade 0 644 644)" == "pass" ]]
  [[ "$(_critical_file_policy_grade 0 600 644)" == "pass" ]]
  [[ "$(_critical_file_policy_grade 0 664 644)" == "warn" ]]
  [[ "$(_critical_file_policy_grade 1000 600 644)" == "fail" ]]
  [[ "$(_critical_file_policy_grade invalid 600 644)" == "unassessed" ]]
}

@test "USBGuard apply-policy with implicit block and device-specific rules is restrictive" {
  rules=$'1: allow id 1d6b:0002 name "xHCI Host Controller"\n2: allow id 1050:0407 serial "test-fixture"'
  [[ "$(_usbguard_policy_grade block apply-policy "$rules")" == "restrictive" ]]
}

@test "USBGuard direct block or reject insertion policy is restrictive" {
  [[ "$(_usbguard_policy_grade allow block '1: allow')" == "restrictive" ]]
  [[ "$(_usbguard_policy_grade allow reject '1: allow')" == "restrictive" ]]
}

@test "USBGuard unconditional allow rules defeat whitelist classification" {
  for rules in '1: allow' '1: allow *:*' '1: allow id *:*'; do
    _usbguard_rules_allow_all "$rules"
    [[ "$(_usbguard_policy_grade block apply-policy "$rules")" == "permissive" ]]
  done
}

@test "USBGuard constrained allow-all identifier remains restrictive" {
  rules='1: allow id *:* if localtime(08:00-09:00)'
  run _usbguard_rules_allow_all "$rules"
  [[ "$status" -ne 0 ]]
  [[ "$(_usbguard_policy_grade reject apply-policy "$rules")" == "restrictive" ]]
}

@test "USBGuard unknown runtime parameter remains unassessed" {
  [[ "$(_usbguard_policy_grade block unknown '')" == "unassessed" ]]
}

@test "desktop severity policy does not score operational history or hardware health" {
  users_block=$(sed -n '/# Accounts without password expiry/,/# Duplicate account database keys/p' "$SCRIPT")
  faillock_block=$(sed -n '/# Recorded failures are operational evidence/,/# Password aging defaults/p' "$SCRIPT")
  hardware_block=$(sed -n '/# SMART Health/,/# USB Devices/p' "$SCRIPT")

  [[ "$users_block" == *'_emit_info "Password expired for user:'* ]]
  [[ "$faillock_block" == *'_emit_info "Faillock:'* ]]
  run grep -E '_emit_(warn|fail) "(SMART|Max temperature)' <<< "$hardware_block"
  [[ "$status" -ne 0 ]]
}

@test "NoID missing AIDE trust state is visible without self-baselining" {
  aide_block=$(sed -n '/# AIDE database existence/,/# AIDE actual integrity-check status/p' "$SCRIPT")
  [[ "$aide_block" == *'AIDE trust database not established yet'* ]]
  [[ "$aide_block" == *'leaves baseline acceptance to the operator'* ]]
  [[ "$aide_block" == *'never initializes, updates, or replaces trust state'* ]]
}

@test "LAN reachability is context and not a kill-switch verdict" {
  lan_block=$(sed -n '/BEGIN NOID LAN ISOLATION PROBES/,/END NOID LAN ISOLATION PROBES/p' "$SCRIPT")
  [[ "$lan_block" == *'_emit_info "LAN gateway reachable:'* ]]
  [[ "$lan_block" == *'reachability alone does not prove a VPN leak'* ]]
  run grep -E '_emit_(warn|fail) "LAN (gateway )?(candidate )?reachable' <<< "$lan_block"
  [[ "$status" -ne 0 ]]
}

@test "disabled global IPv6 does not claim that every physical IPv6 scope is absent" {
  grep -q 'Global IPv6 addressing disabled on physical interfaces' "$SCRIPT"
  run grep -q 'IPv6 disabled on physical interfaces.*VPN-internal IPv6 by design' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "temporary-directory noexec policy distinguishes tmp from var-tmp" {
  mount_block=$(sed -n '/# Temporary-directory mount hardening/,/# \/dev\/shm is/p' "$SCRIPT")
  [[ "$mount_block" == *'_emit_warn "/tmp: no noexec'* ]]
  [[ "$mount_block" == *'_emit_info "/var/tmp: executable by design'* ]]
}

@test "SSH root-login severity distinguishes unrestricted and constrained modes" {
  ssh_block=$(sed -n '/# PermitRootLogin/,/# PasswordAuthentication/p' "$SCRIPT")
  [[ "$ssh_block" == *'prohibit-password|without-password|forced-commands-only)'* ]]
  [[ "$ssh_block" == *'_emit_fail "SSH: PermitRootLogin yes'* ]]
  # Literal production source, not a test-shell expansion.
  # shellcheck disable=SC2016
  [[ "$ssh_block" == *'_emit_warn "SSH: PermitRootLogin $VAL'* ]]
}

@test "critical-file table avoids duplicate cron grading and accepts read-only sshd config" {
  table=$(sed -n '/declare -A PERM_CHECKS=(/,/^)/p' "$SCRIPT")
  [[ "$table" == *'["/etc/ssh/sshd_config"]="644"'* ]]
  [[ "$table" != *'/etc/crontab'* ]]
}

@test "filename-only secret matches never claim verified plaintext or emit FAIL" {
  secret_block=$(sed -n '/# F-267: subdirectory search for potential secret filenames/,/^}/p' "$SCRIPT")
  [[ "$secret_block" == *'content not inspected'* ]]
  run grep -E '_emit_fail ".*(Plaintext secret|Potential secret)' <<< "$secret_block"
  [[ "$status" -ne 0 ]]
}

@test "root encryption parser follows only the selected block ancestor stack" {
  encrypted_stack=$'cryptroot crypt\nnvme0n1p3 part\nnvme0n1 disk'
  unrelated_stack=$'sda2 part\nsda disk'
  [[ "$(printf '%s\n' "$encrypted_stack" | _block_stack_crypt_names)" == "cryptroot" ]]
  [[ -z "$(printf '%s\n' "$unrelated_stack" | _block_stack_crypt_names)" ]]

  kernel_block=$(sed -n '/# Root storage encryption/,/# Boot Performance/p' "$SCRIPT")
  [[ "$kernel_block" == *'_mount_crypt_mappings /'* ]]
  [[ "$kernel_block" != *'lsblk -o TYPE'* ]]
}

@test "encryption findings do not disclose mapping names or backing-device identifiers" {
  kernel_block=$(sed -n '/# Root storage encryption/,/# Boot Performance/p' "$SCRIPT")
  crypto_block=$(sed -n '/if require_cmd cryptsetup; then/,/# SSL\/TLS Libraries/p' "$SCRIPT")
  [[ "$kernel_block" == *'active dm-crypt ancestor '* ]]
  run grep -E '_emit_(pass|warn|info).*_ROOT_CRYPT_MAPPINGS' <<< "$kernel_block"
  [[ "$status" -ne 0 ]]
  # shellcheck disable=SC2016  # literal production-source variable names
  run grep -E '_emit_(pass|warn|info).*(\$DEV|_CRYPT_BACKING)' <<< "$crypto_block"
  [[ "$status" -ne 0 ]]
  # shellcheck disable=SC2016  # literal production-source label
  [[ "$crypto_block" == *'dm-crypt mapping #$_CRYPT_INDEX'* ]]
}

@test "VPN full-tunnel evidence checks every route table and only confirmed VPN devices" {
  _iface_is_vpn() { [[ "$1" == "wg0" ]]; }
  ip() {
    if [[ "$1" == "-4" && "$2" == "route" ]]; then
      printf '%s\n' \
        'default via 192.0.2.1 dev eth0 table main' \
        'default dev wg0 table 51820'
    elif [[ "$1" == "-6" && "$2" == "route" ]]; then
      printf '%s\n' 'default via 2001:db8::1 dev eth0 table main'
    elif [[ "$1" == "-o" && "$2" == "link" && "$3" == "show" \
            && "$4" == "up" && "$5" == "dev" && "$6" == "wg0" ]]; then
      return 0
    else
      return 1
    fi
  }

  run _vpn_default_routes
  [[ "$status" -eq 0 ]]
  [[ "$output" == 'default dev wg0 table 51820' ]]
}

@test "active split tunnel is never labeled a default-route or DNS failure" {
  vpn_block=$(sed -n '/# Main-table route is inventory/,/# DNSSEC validation status/p' "$SCRIPT")
  [[ "$vpn_block" == *'valid split-tunnel posture'* ]]
  [[ "$vpn_block" == *'no full-tunnel DNS policy inferred'* ]]
  run grep -E '_emit_(warn|fail) "Default route (NOT|remains) outside the VPN' <<< "$vpn_block"
  [[ "$status" -ne 0 ]]
}

@test "sudoers policy accepts safe root-controlled read or write modes" {
  for mode in 400 440 600 640; do
    _sudoers_mode_is_safe "$mode"
  done
  for mode in 644 660 755 invalid; do
    run _sudoers_mode_is_safe "$mode"
    [[ "$status" -ne 0 ]]
  done
}

@test "NOPASSWD classification keeps explicit ALL adverse and scoped rules informational" {
  [[ "$(_sudoers_nopasswd_scope '%wheel ALL=(ALL) NOPASSWD: ALL')" == "explicit-all" ]]
  [[ "$(_sudoers_nopasswd_scope '%wheel ALL=(root) NOPASSWD: SETENV: ALL # broad')" == "explicit-all" ]]
  [[ "$(_sudoers_nopasswd_scope '%wheel ALL=(root) NOPASSWD: /usr/local/sbin/noid-location-apply true, /usr/local/sbin/noid-location-apply false')" == "command-scoped" ]]
  [[ "$(_sudoers_nopasswd_scope '%wheel ALL=(root) NOPASSWD: NOID_SNAPPER_STATUS')" == "command-scoped" ]]
  [[ "$(_sudoers_nopasswd_scope '%wheel ALL=(root) NOPASSWD: /usr/bin/status "", PASSWD: ALL')" == "command-scoped" ]]
  [[ "$(_sudoers_nopasswd_scope '%wheel ALL=(root) PASSWD: /usr/bin/id')" == "none" ]]
  # A repeated explicit NOPASSWD: ALL tag must not be hidden by an earlier
  # command-scoped NOPASSWD: on the same user-spec (the second tag's "PASSWD:"
  # substring must not truncate the ALL away).
  [[ "$(_sudoers_nopasswd_scope '%wheel ALL=(root) NOPASSWD: /bin/cmd1, NOPASSWD: ALL')" == "explicit-all" ]]
  [[ "$(_sudoers_nopasswd_scope '%wheel ALL=(root) NOPASSWD: /a, NOPASSWD: SETENV: ALL')" == "explicit-all" ]]
}

@test "desktop faillock policy treats six through ten attempts as an INFO trade-off" {
  [[ "$(_faillock_deny_grade 0)" == "fail" ]]
  [[ "$(_faillock_deny_grade 3)" == "pass" ]]
  [[ "$(_faillock_deny_grade 5)" == "pass" ]]
  [[ "$(_faillock_deny_grade 6)" == "info" ]]
  [[ "$(_faillock_deny_grade 10)" == "info" ]]
  [[ "$(_faillock_deny_grade 11)" == "warn" ]]
  [[ "$(_faillock_deny_grade invalid)" == "unassessed" ]]
}

@test "name and inventory heuristics do not emit unsupported FAIL verdicts" {
  cron_block=$(sed -n '/# Suspect Cron Jobs/,/# F-374/p' "$SCRIPT")
  process_block=$(sed -n '/# Suspicious processes/,/# Processes running as root/p' "$SCRIPT")
  cert_block=$(sed -n '/if require_cmd openssl; then/,/sub_header "SSH Keys"/p' "$SCRIPT")
  [[ "$cron_block" == *'not evidence of compromise'* ]]
  run grep -E '_emit_(warn|fail) "Network-capable cron' <<< "$cron_block"
  [[ "$status" -ne 0 ]]
  run grep -E '_emit_fail ".*process-name heuristic' <<< "$process_block"
  [[ "$status" -ne 0 ]]
  run grep -E '_emit_(warn|fail) "Expired certificate file' <<< "$cert_block"
  [[ "$status" -ne 0 ]]
}

@test "a hostname display-name heuristic is context until exposure is verified" {
  hostname_block=$(sed -n '/local hostname/,/# IPv6 privacy posture/p' "$SCRIPT")
  [[ "$hostname_block" == *'_emit_info "Hostname shares an account display-name token;'* ]]
  run grep -F '_emit_warn "Hostname' <<< "$hostname_block"
  [[ "$status" -ne 0 ]]
}

@test "desktop telemetry ignores unrelated schema defaults and indexers" {
  telemetry_block=$(sed -n '/^check_app_telemetry() {/,/^check_network_privacy() {/p' "$SCRIPT")
  # Literal production-source variables.
  # shellcheck disable=SC2016
  [[ "$telemetry_block" == *'[[ "$_DE_FAMILY" == "gnome" ]] && _for_each_user _at_check_user'* ]]
  # shellcheck disable=SC2016
  [[ "$telemetry_block" == *'[[ "$DISTRO_FAMILY" == "rhel" || -d /etc/abrt ]]'* ]]
  [[ "$telemetry_block" == *"the current desktop's native indexer is unassessed"* ]]
}

@test "unreadable optional runtime evidence remains unassessed" {
  netprivacy_block=$(sed -n '/local resolved_conf=/,/local hostname/p' "$SCRIPT")
  dhcp_block=$(sed -n '/# Check if any active connection actually uses DHCP/,/local mdns_val=/p' "$SCRIPT")
  media_block=$(sed -n '/check_media_privacy()/,/check_bluetooth_privacy()/p' "$SCRIPT")
  bluetooth_block=$(sed -n '/check_bluetooth_privacy()/,/check_keyring_security()/p' "$SCRIPT")
  [[ "$netprivacy_block" == *'service inactive; other resolver backends not inferred'* ]]
  [[ "$dhcp_block" == *'NetworkManager evidence unavailable (not graded)'* ]]
  [[ "$media_block" == *'could not be verified'*'(not graded)'* ]]
  [[ "$bluetooth_block" == *'result unassessed'* ]]
}

@test "LLMNR grading follows effective resolved link scopes" {
  enabled=$'Global\n  Protocols: LLMNR=resolve\n\nLink 2 (eth0)\n  Current Scopes: DNS LLMNR/IPv4\n  Protocols: +DefaultRoute LLMNR=resolve -mDNS'
  ubuntu_enabled=$'Global\n  Protocols: -LLMNR\n\nLink 2 (enp0s2)\n  Current Scopes: DNS\n  Protocols: +DefaultRoute +LLMNR -mDNS'
  disabled=$'Global\n  Protocols: -LLMNR\n\nLink 2 (eth0)\n  Current Scopes: DNS\n  Protocols: +DefaultRoute -LLMNR -mDNS'
  unknown=$'Global\n  Protocols: LLMNR=resolve\n\nLink 2 (eth0)\n  Current Scopes: none\n  Protocols: +DefaultRoute -mDNS'
  mixed=$'Link 2 (eth0)\n  Current Scopes: DNS\n  Protocols: -LLMNR\n\nLink 3 (wlan0)\n  Current Scopes: DNS\n  Protocols: +DefaultRoute -mDNS'
  [[ "$(_resolved_llmnr_state_from_status <<< "$enabled")" == "enabled" ]]
  [[ "$(_resolved_llmnr_state_from_status <<< "$ubuntu_enabled")" == "enabled" ]]
  [[ "$(_resolved_llmnr_state_from_status <<< "$disabled")" == "disabled" ]]
  [[ "$(_resolved_llmnr_state_from_status <<< "$unknown")" == "unknown" ]]
  [[ "$(_resolved_llmnr_state_from_status <<< "$mixed")" == "unknown" ]]
}

@test "desktop inventory does not label maintained dash as a legacy shell" {
  shell_block=$(sed -n '/# csh\/tcsh are retained/,/done/p' "$SCRIPT")
  [[ "$shell_block" == *'/bin/csh /bin/tcsh'* ]]
  [[ "$shell_block" != *'/bin/dash'* ]]
}

@test "AppArmor pass verdict counts only enforcing profiles" {
  # shellcheck disable=SC2016  # literal production-source variable
  apparmor_block=$(sed -n '/elif \$HAS_APPARMOR; then/,/header "02" "MANDATORY ACCESS CONTROL"/p' "$SCRIPT")
  [[ "$apparmor_block" == *'profiles) enforcing"'* ]]
  [[ "$apparmor_block" == *'in complain mode (not enforced;'* ]]
  run grep -E '_emit_pass .*complain' <<< "$apparmor_block"
  [[ "$status" -ne 0 ]]
}

@test "absence of active NetworkManager evidence cannot prove IPv6 or static addressing" {
  ipv6_block=$(sed -n '/# NM-config check/,/# Check if any active connection actually uses DHCP/p' "$SCRIPT")
  dhcp_block=$(sed -n '/# Check if any active connection actually uses DHCP/,/local mdns_val=/p' "$SCRIPT")
  # shellcheck disable=SC2016  # literal production-source variables
  [[ "$ipv6_block" == *'$_has_active || _ipv6_nm_disabled=false'* ]]
  [[ "$dhcp_block" == *'local _uses_dhcp=unknown'* ]]
  # shellcheck disable=SC2016  # literal production-source variables
  [[ "$dhcp_block" == *'$_nm_active_seen && $_nm_methods_known'* ]]
}

@test "IPv6 temporary-address finding describes linkability rather than identity proof" {
  netprivacy_block=$(sed -n '/# IPv6 privacy posture/,/# Check if any active connection actually uses DHCP/p' "$SCRIPT")
  [[ "$netprivacy_block" == *'stable address can increase cross-session linkability on the same network'* ]]
  [[ "$netprivacy_block" != *'stable address reveals identity'* ]]
}

@test "Ubuntu crash telemetry separates capture consent trigger and upload evidence" {
  # shellcheck disable=SC2016  # literal production-source variable
  telemetry_block=$(sed -n '/# Ubuntu separates local crash capture/,/if \[\[ "\$DISTRO_FAMILY" == "rhel"/p' "$SCRIPT")
  [[ "$telemetry_block" == *'Apport local crash capture enabled'* ]]
  [[ "$telemetry_block" == *'automatic crash-report consent marker absent'* ]]
  [[ "$telemetry_block" == *'Whoopsie crash-submission trigger armed, but that alone does not prove'* ]]
  [[ "$telemetry_block" == *'historical submission not inferred'* ]]
  run grep -E '_emit_(warn|fail) "Ubuntu Whoopsie.*trigger armed, but' <<< "$telemetry_block"
  [[ "$status" -ne 0 ]]
}

@test "missing resolved files never imply an adverse LLMNR verdict" {
  netprivacy_block=$(sed -n '/local resolved_conf=/,/local hostname/p' "$SCRIPT")
  [[ "$netprivacy_block" == *'LLMNR active on at least one systemd-resolved link'* ]]
  [[ "$netprivacy_block" == *'no explicit active setting graded'* ]]
  run grep -F 'resolved.conf not found — LLMNR status unknown' <<< "$netprivacy_block"
  [[ "$status" -ne 0 ]]
}

@test "LUKS dump parser reports only enabled slot and KDF records" {
  dump=$'LUKS header information\nVersion: 2\nKeyslots:\n  0: luks2\n\tKey: 512 bits\n\tPBKDF: argon2id\n  7: luks2\n\tPBKDF: pbkdf2\nTokens:\nDigests:\n  0: pbkdf2\n\tHash: sha256'
  run _luks_keyslot_pbkdfs <<< "$dump"
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'0\targon2id\n7\tpbkdf2' ]]
  [[ "$output" != *'sha256'* ]]
}

@test "LUKS1 enabled slots are identified as PBKDF2 without header metadata" {
  dump=$'LUKS header information\nVersion: 1\nKey Slot 0: ENABLED\n\tIterations: 12345\nKey Slot 1: DISABLED'
  [[ "$(_luks_keyslot_pbkdfs <<< "$dump")" == $'0\tpbkdf2' ]]
}
