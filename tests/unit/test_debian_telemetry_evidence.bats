#!/usr/bin/env bats

# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _popcon_audit _config_last_value; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT" |
      sed "s|/etc/popularity-contest.conf|$BATS_TEST_TMPDIR/popcon.conf|g")
  done
  # Literal source variable in the extraction boundary is intentional.
  # shellcheck disable=SC1090,SC2016
  source <(printf '_ubuntu_block() {\n'; sed -n '/^  # Ubuntu separates local crash capture/,/^  \[\[ "\$DISTRO_FAMILY" == "rhel"/p' "$SCRIPT" | sed '$d' |
    sed "s|/var/lib/apport/|$BATS_TEST_TMPDIR/apport/|g; s|/var/lib/whoopsie/|$BATS_TEST_TMPDIR/whoopsie/|g"; printf '}\n')
  PKGS=$'bash\tinstalled\npopularity-contest\tinstalled' PKG_RC=0
  printf 'PARTICIPATE="no"\n' > "$BATS_TEST_TMPDIR/popcon.conf"
  DISTRO=ubuntu APPORT_STATE=inactive WHOOPSIE_STATE=inactive
}
timeout() { printf '%s' "$PKGS"; return "$PKG_RC"; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }
_service_unit_state() { printf '%s' "$APPORT_STATE"; }
_service_group_state() { printf '%s' "$WHOOPSIE_STATE"; }
require_cmd() { return 0; }
_passwd_lines() { :; }

@test "dpkg confirmed absence is distinct from package query failure" {
  PKGS=$'bash\tinstalled'
  run _popcon_audit
  [[ "$output" == *'PASS:popularity-contest package not installed'* ]]
  PKG_RC=1
  run _popcon_audit
  [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
}

@test "partial and malformed dpkg inventories cannot prove popcon absence" {
  for PKGS in 'database error' $'bash\tinstalled\ndatabase error' $'popularity-contest\tunexpected'; do
    run _popcon_audit
    [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
}

@test "residual configuration is not an installed popcon package" {
  PKGS=$'popularity-contest\tconfig-files'
  run _popcon_audit
  [[ "$output" == *'PASS:popularity-contest package not installed'* ]]
}

@test "main popcon preference does not establish effective sourced shell policy" {
  run _popcon_audit
  [[ "$output" == *'main config contains PARTICIPATE=no'* && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  printf 'PARTICIPATE=yes\n' > "$BATS_TEST_TMPDIR/popcon.conf"
  run _popcon_audit
  [[ "$output" == *'main config contains PARTICIPATE=yes'* && "$output" != *'active — reports installed packages'* ]]
}

@test "commented participation and shell substitutions never execute or imply consent" {
  # shellcheck disable=SC2016
  printf '%s\n' '# PARTICIPATE="yes"' 'PARTICIPATE=$(touch should-not-exist)' > "$BATS_TEST_TMPDIR/popcon.conf"
  cd "$BATS_TEST_TMPDIR"
  run _popcon_audit
  [[ "$output" == *'participation setting unassessed'* && ! -e should-not-exist ]]
}

@test "unreadable popcon configuration never becomes nonparticipation" {
  rm "$BATS_TEST_TMPDIR/popcon.conf"
  run _popcon_audit
  [[ "$output" == *'participation setting unassessed'* && "$output" != *PASS:* ]]
}

@test "Ubuntu service errors cannot become disabled-capture or inactive-trigger PASS" {
  APPORT_STATE=unknown WHOOPSIE_STATE=unknown
  run _ubuntu_block
  [[ "$output" == *'Apport service state unavailable'* && "$output" == *'Whoopsie trigger state unavailable'* ]]
  [[ "$output" != *'PASS:Ubuntu Apport'* && "$output" != *'PASS:Ubuntu Whoopsie'* ]]
}

@test "Ubuntu inactive and armed triggers preserve the consent distinction" {
  run _ubuntu_block
  [[ "$output" == *'PASS:Ubuntu Whoopsie units inactive'* ]]
  WHOOPSIE_STATE=enabled
  run _ubuntu_block
  [[ "$output" == *'armed, but that alone does not prove'* && "$output" != *'PASS:Ubuntu Whoopsie'* ]]
}
