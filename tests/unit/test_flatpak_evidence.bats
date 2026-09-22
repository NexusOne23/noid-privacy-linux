#!/usr/bin/env bats

# Production readers and consumers, with controlled command/account responses.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _flatpak_permission_flags _flatpak_permission_audit; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  ROWS='fixture:x:1000:1000::/fixture:/bin/bash'
  APPS=$'org.noid.Fixture/x86_64/stable\tuser'
  PERMS=$'[Context]\nsockets=wayland;fallback-x11;\ndevices=dri;'
  ACCOUNT_RC=0 LIST_RC=0 INFO_RC=0 NATIVE_RC=0 NATIVE_ERR='' NATIVE_OUT=''
  CALLS="$BATS_TEST_TMPDIR/flatpak-calls"
}

flatpak() { return 98; }
_passwd_lines() { printf '%s\n' "$ROWS"; return "$ACCOUNT_RC"; }
_is_human_uid() { [[ "$1" -ge 1000 && "$1" -le 65533 ]]; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }
_flatpak_query() {
  printf '%s\n' "$*" >> "$CALLS"
  if [[ "$4" == list ]]; then printf '%s\n' "$APPS"; return "$LIST_RC"; fi
  printf '%s\n' "$PERMS"
  return "$INFO_RC"
}

@test "broad filesystem grants include read-only and create modes" {
  local path mode
  for path in home host host-os host-etc host-root; do
    for mode in '' :ro :rw :create; do
      PERMS=$'[Context]\nfilesystems='"$path$mode;"
      run _flatpak_permission_flags <<< "$PERMS"
      [[ "$status" -eq 0 && "$output" == '1 0 0 0' ]]
    done
  done
}

@test "broad grants are found after ordinary list entries" {
  run _flatpak_permission_flags <<< $'[Context]\nfilesystems=xdg-download;/fixture;home:ro;'
  [[ "$status" -eq 0 && "$output" == '1 0 0 0' ]]
}

@test "lookalike filesystem tokens and subpaths are outside the broad-token screen" {
  run _flatpak_permission_flags <<< $'[Context]\nfilesystems=/fixture/host;~/home;homework;'
  [[ "$status" -eq 0 && "$output" == '0 0 0 0' ]]
}

@test "unfiltered bus sockets are distinguished from ordinary GUI sockets" {
  local socket
  for socket in session-bus system-bus; do
    run _flatpak_permission_flags <<< $'[Context]\nsockets=wayland;'"$socket;"
    [[ "$status" -eq 0 && "$output" == '0 1 0 0' ]]
  done
  run _flatpak_permission_flags <<< "$PERMS"
  [[ "$status" -eq 0 && "$output" == '0 0 0 0' ]]
}

@test "Flatpak service access includes own and ancestor namespace wildcards" {
  local name policy
  for name in org.freedesktop.Flatpak 'org.freedesktop.Flatpak.*' 'org.freedesktop.*' 'org.*'; do
    for policy in talk own; do
      run _flatpak_permission_flags <<< $'[Session Bus Policy]\n'"$name=$policy"
      [[ "$status" -eq 0 && "$output" == '0 0 1 0' ]]
    done
  done
}

@test "bus visibility denies lookalikes and unrelated bus groups do not grant host commands" {
  local value
  for value in $'[Session Bus Policy]\norg.freedesktop.Flatpak=see' \
      $'[Session Bus Policy]\norg.freedesktop.Flatpak=none' \
      $'[Session Bus Policy]\norg.freedesktop.Flatpakoops=talk' \
      $'[System Bus Policy]\norg.freedesktop.Flatpak=talk'; do
    run _flatpak_permission_flags <<< "$value"
    [[ "$status" -eq 0 && "$output" == '0 0 0 0' ]]
  done
}

@test "environment values cannot become permission findings or report content" {
  PERMS=$'[Environment]\nfilesystems=host;\nDECOY=org.freedesktop.Flatpak=talk\nsockets=session-bus;\ndevices=all;'
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *'PASS:'* && "$output" != *WARN:* && "$output" != *DECOY* ]]
}

@test "devices all retains an informational finding" {
  PERMS=$'[Context]\ndevices=all;'
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *'INFO:Flatpak devices=all'* && "$output" != *WARN:* ]]
}

@test "empty successful permissions and an empty flattened filesystem list are valid" {
  local value
  for value in '' $'[Context]\nfilesystems='; do
    run _flatpak_permission_flags <<< "$value"
    [[ "$status" -eq 0 && "$output" == '0 0 0 0' ]]
  done
  PERMS=''
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *'PASS:'* && "$output" != *INCOMPLETE* ]]
}

@test "unsupported escaping cannot split a path into a false host grant" {
  run _flatpak_permission_flags <<< '[Context]
filesystems=/fixture/a\\;host:ro;'
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "unflattened denies duplicate fields invalid modes and malformed rows are unassessed" {
  local value
  for value in 'filesystems=host;' $'[Context]\nbroken' \
      $'[Context]\nfilesystems=!home;' $'[Context]\nfilesystems=home;\nfilesystems=' \
      $'[Context]\nfilesystems=home:unknown;' $'[Context]\nfilesystems=home;;' \
      $'[Session Bus Policy]\norg.freedesktop.Flatpak=unknown'; do
    run _flatpak_permission_flags <<< "$value"
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "successful ordinary permissions produce a bounded screen PASS" {
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *'1 inspected app/account configurations'* ]]
  [[ "$output" == *'running sandboxes are unassessed'* && "$output" != *INCOMPLETE* ]]
}

@test "a broad grant generates a warning without a global all-clear" {
  PERMS=$'[Context]\nfilesystems=home:ro;'
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *'WARN:Flatpak grants'* && "$output" != *'PASS:'* ]]
}

@test "failed app listing discards partial inventory and cannot PASS" {
  LIST_RC=1
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  [[ "$(wc -l < "$CALLS")" -eq 1 ]]
}

@test "failed permission queries discard partial grants and cannot PASS" {
  INFO_RC=1 PERMS=$'[Context]\nfilesystems=home;'
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* && "$output" != *WARN:* ]]
}

@test "invalid permission representation is visible as incomplete" {
  PERMS='not metadata'
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
}

@test "an empty successful installation inventory is inventory not security credit" {
  APPS=''
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *'no installed apps'* && "$output" != *PASS:* && "$output" != *INCOMPLETE* ]]
}

@test "full refs retain branch architecture and installation identity" {
  APPS=$'org.noid.Fixture/x86_64/stable\tsystem\norg.noid.Fixture/aarch64/beta\tuser\norg.noid.Fixture/x86_64/stable\tsystem (extra)'
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *'3 inspected app/account configurations'* ]]
  grep -Fq 'info --system --show-permissions app/org.noid.Fixture/x86_64/stable' "$CALLS"
  grep -Fq 'info --user --show-permissions app/org.noid.Fixture/aarch64/beta' "$CALLS"
  grep -Fq 'info --installation=extra --show-permissions app/org.noid.Fixture/x86_64/stable' "$CALLS"
}

@test "unknown installations malformed refs and duplicate list rows are incomplete" {
  local value
  for value in $'org.noid.Fixture/x86_64/stable\textra' $'bad ref\tuser' \
      $'org.noid.Fixture/x86_64/stable\tuser\textra' "$APPS"$'\n'"$APPS"; do
    APPS="$value"
    run _flatpak_permission_audit
    [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
}

@test "system apps are queried in each eligible account context" {
  ROWS=$'root:x:0:0::/root:/bin/bash\nfixture:x:1000:1000::/fixture:/bin/bash\nsecond:x:1001:1001::/custom home:/bin/bash\nservice:x:2000:2000::/service:/sbin/nologin'
  APPS=$'org.noid.Fixture/x86_64/stable\tsystem'
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *'3 inspected app/account configurations'* ]]
  [[ "$(wc -l < "$CALLS")" -eq 6 ]]
  grep -Fq 'second 1001 /custom home info --system' "$CALLS"
}

@test "failed empty and malformed account snapshots cannot establish complete scope" {
  ACCOUNT_RC=1
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && ! -e "$CALLS" ]]
  ACCOUNT_RC=0
  for ROWS in '' malformed; do
    run _flatpak_permission_audit
    [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
}

@test "bounded app inventory never promotes an uninspected remainder to PASS" {
  APPS=''
  local i
  for ((i=0;i<257;i++)); do APPS+="org.noid.Fixture$i/x86_64/stable"$'\tuser\n'; done
  APPS=${APPS%$'\n'}
  run _flatpak_permission_audit
  [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  [[ "$(wc -l < "$CALLS")" -eq 257 ]]
}

# Keep the production stream/status/cleanup logic; replace only the command
# transport. The native before/after tests additionally exercise real Flatpak.
timeout() {
  [[ "$1" == 8 && "$2" == sudo && "$3" == -n && "$4" == -H && "$5" == -u && "$6" == '#1000' && "$7" == -- && "$8" == env && "$9" == -i ]] || return 98
  printf '%s' "$NATIVE_OUT"
  printf '%s' "$NATIVE_ERR" >&2
  return "$NATIVE_RC"
}
_load_query() {
  # shellcheck disable=SC1090
  source <(awk '$0=="_flatpak_query() {" {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
}

@test "native reader accepts successful empty output" {
  _load_query
  run _flatpak_query fixture 1000 /fixture list --app
  [[ "$status" -eq 0 && -z "$output" ]]
}

@test "native reader rejects diagnostic stderr even with successful status" {
  _load_query
  NATIVE_OUT="$APPS" NATIVE_ERR='Unable to load details of a deployment'
  run _flatpak_query fixture 1000 /fixture list --app
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "native reader rejects failed and timed-out partial output" {
  _load_query
  NATIVE_OUT="$PERMS"
  for NATIVE_RC in 1 124 127; do
    run _flatpak_query fixture 1000 /fixture info --show-permissions app/org.noid.Fixture/x86_64/stable
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "native reader returns only a successful clean stream" {
  _load_query
  NATIVE_OUT="$PERMS"
  run _flatpak_query fixture 1000 /fixture info --show-permissions app/org.noid.Fixture/x86_64/stable
  [[ "$status" -eq 0 && "$output" == "$PERMS" ]]
}

@test "invalid numeric identities are rejected before command execution" {
  _load_query
  local uid
  for uid in '' 01000 -1 'array[1]' 999999999999999999; do
    run _flatpak_query fixture "$uid" /fixture list --app
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}
