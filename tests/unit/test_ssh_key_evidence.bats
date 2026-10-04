#!/usr/bin/env bats

# Production readers with native file/awk operations and controlled keygen
# responses; real OpenSSH fixtures are verified separately on the live host.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _ssh_public_key_grade _ssh_public_key_record _ssh_public_key_records _ssh_collect_key_files _ssh_key_inventory; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  HOME_FIXTURE="$BATS_TEST_TMPDIR/custom home"
  mkdir -p "$HOME_FIXTURE/.ssh"
  FILE="$HOME_FIXTURE/.ssh/id_fixture.pub"
  ACCOUNT_ROWS="fixture:x:1000:1000::$HOME_FIXTURE:/bin/bash"
  ACCOUNT_RC=0 READ_RC=0 KEYGEN_RC=0 KEYGEN_AVAILABLE=true REALPATH_RC=0
  FP='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  CALLS="$BATS_TEST_TMPDIR/keygen-calls"
  _SSH_KEY_PATHS=()
}

_passwd_lines() { printf '%s\n' "$ACCOUNT_ROWS"; return "$ACCOUNT_RC"; }
realpath() { [[ "$REALPATH_RC" -eq 0 ]] || return "$REALPATH_RC"; command realpath "$@"; }
require_cmd() { $KEYGEN_AVAILABLE; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_fail() { printf 'FAIL:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }
_plural() { if [[ "$1" == 1 ]]; then printf '%s' "$2"; else printf '%s' "$3"; fi; }
timeout() {
  local duration="$1" command_name="$2" line bits type
  shift 2
  if [[ "$command_name" == head ]]; then
    command head "$@"
    return "$READ_RC"
  fi
  [[ "$command_name" == ssh-keygen && "$duration" == 5 && "$*" == '-l -E sha256 -f -' ]] || return 98
  IFS= read -r line
  printf 'called\n' >> "$CALLS"
  case "$line" in
    valid) bits=256 type=ED25519 ;;
    weak-cert) bits=1024 type=RSA-CERT ;;
    weak) bits=1024 type=RSA ;;
    future) bits=256 type=FUTURE-KEY ;;
    duplicate-output)
      printf '256 SHA256:%s comment (ED25519)\n256 SHA256:%s comment (ED25519)\n' "$FP" "$FP"
      return 0 ;;
    *) return 255 ;;
  esac
  printf '%s SHA256:%s private-comment-marker (%s)\n' "$bits" "$FP" "$type"
  return "$KEYGEN_RC"
}

@test "weak RSA certificates obey the same size rule as bare RSA keys" {
  [[ "$(_ssh_public_key_grade 1024 RSA)" == fail ]]
  [[ "$(_ssh_public_key_grade 1024 RSA-CERT)" == fail ]]
  [[ "$(_ssh_public_key_grade 2048 RSA-CERT)" == pass ]]
}

@test "DSA and undersized ECDSA certificate subjects remain adverse" {
  [[ "$(_ssh_public_key_grade 1024 DSA-CERT)" == fail ]]
  [[ "$(_ssh_public_key_grade 192 ECDSA-CERT)" == fail ]]
}

@test "supported hardware-backed subject types are not mistaken for unknown keys" {
  for type in ECDSA-SK ECDSA-SK-CERT ED25519-SK ED25519-SK-CERT; do
    [[ "$(_ssh_public_key_grade 256 "$type")" == pass ]]
  done
}

@test "unknown key types are unassessed without rejecting vendor support" {
  [[ "$(_ssh_public_key_grade 256 FUTURE-KEY)" == unassessed ]]
  [[ "$(_ssh_public_key_grade 256 FUTURE-KEY-CERT)" == unassessed ]]
  [[ "$(_ssh_public_key_grade 2048 RSA-CERT-CERT)" == unassessed ]]
}

@test "zero malformed leading-zero and overflowing key sizes never reach arithmetic" {
  for bits in 0 0256 -1 'x[1]' 2147483648 99999999999999999999999; do
    run _ssh_public_key_grade "$bits" RSA
    [[ "$status" -eq 0 && "$output" == unassessed ]]
  done
}

@test "unexpected curve sizes remain unassessed" {
  [[ "$(_ssh_public_key_grade 512 ED25519)" == unassessed ]]
  [[ "$(_ssh_public_key_grade 999 ECDSA)" == unassessed ]]
  [[ "$(_ssh_public_key_grade 384 ECDSA)" == pass ]]
  [[ "$(_ssh_public_key_grade 521 ECDSA-CERT)" == pass ]]
}

@test "native-record reader emits only size and type" {
  run _ssh_public_key_record "256 SHA256:$FP private-comment-marker (ED25519)"
  [[ "$status" -eq 0 && "$output" == '256 ED25519' ]]
}

@test "native-record reader rejects partial malformed and multiple records" {
  for raw in "256 SHA256:$FP missing-type" '256 invalid (ED25519)' $'256 SHA256:'"$FP"$' comment (ED25519)\n256 invalid (RSA)'; do
    run _ssh_public_key_record "$raw"
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "valid line-format key file has one reduced record and complete counts" {
  printf 'valid\n' > "$FILE"
  run _ssh_public_key_records "$FILE"
  [[ "$status" -eq 0 && "$output" == $'key 256 ED25519\ncounts 1 1 0' ]]
  [[ "$output" != *"$FP"* && "$output" != *'private-comment-marker'* ]]
}

@test "mixed valid and invalid lines retain the good record and expose the missing assessment" {
  printf '# comment\nvalid\ninvalid\n \n' > "$FILE"
  run _ssh_public_key_records "$FILE"
  [[ "$status" -eq 0 && "$output" == $'key 256 ED25519\ncounts 2 1 1' ]]
}

@test "empty and comment-only files require no keygen invocation" {
  printf '\n  # comment\n' > "$FILE"
  run _ssh_public_key_records "$FILE"
  [[ "$status" -eq 0 && "$output" == 'counts 0 0 0' && ! -e "$CALLS" ]]
}

@test "failed partial input read cannot become empty or valid key evidence" {
  printf 'valid\n' > "$FILE"
  READ_RC=1
  run _ssh_public_key_records "$FILE"
  [[ "$status" -ne 0 && -z "$output" && ! -e "$CALLS" ]]
}

@test "failed partial keygen output is discarded" {
  printf 'valid\n' > "$FILE"
  KEYGEN_RC=1
  run _ssh_public_key_records "$FILE"
  [[ "$status" -eq 0 && "$output" == 'counts 1 0 1' ]]
}

@test "multiple keygen output records for one input line are not accepted" {
  printf 'duplicate-output\n' > "$FILE"
  run _ssh_public_key_records "$FILE"
  [[ "$status" -eq 0 && "$output" == 'counts 1 0 1' ]]
}

@test "NUL-bearing input is rejected before Bash can silently strip bytes" {
  printf 'valid\000\n' > "$FILE"
  run _ssh_public_key_records "$FILE"
  [[ "$status" -ne 0 && -z "$output" && ! -e "$CALLS" ]]
}

@test "oversized and excessive-line inputs are unassessed rather than partially certified" {
  awk 'BEGIN {for(i=0;i<1048577;i++) printf "a"}' > "$FILE"
  run _ssh_public_key_records "$FILE"
  [[ "$status" -ne 0 && -z "$output" && ! -e "$CALLS" ]]
  awk 'BEGIN {for(i=0;i<1025;i++) print "valid"}' > "$FILE"
  run _ssh_public_key_records "$FILE"
  [[ "$status" -ne 0 && -z "$output" && ! -e "$CALLS" ]]
}

@test "non-regular key candidates are not opened as streams" {
  mkfifo "$FILE"
  run _ssh_public_key_records "$FILE"
  [[ "$status" -ne 0 && -z "$output" && ! -e "$CALLS" ]]
}

@test "local snapshot includes custom homes and service-account keys" {
  ACCOUNT_ROWS="service:x:99:99::$HOME_FIXTURE:/sbin/nologin"
  printf 'valid\n' > "$FILE"
  _ssh_collect_key_files
  [[ "${#_SSH_KEY_PATHS[@]}" -eq 1 && "${_SSH_KEY_PATHS[0]}" == "$FILE" ]]
}

@test "canonical home aliases are enumerated once" {
  printf 'valid\n' > "$FILE"
  ln -s "$HOME_FIXTURE" "$BATS_TEST_TMPDIR/alias"
  ACCOUNT_ROWS+=$'\n'"other:x:1001:1001::$BATS_TEST_TMPDIR/alias:/bin/bash"
  _ssh_collect_key_files
  [[ "${#_SSH_KEY_PATHS[@]}" -eq 1 ]]
}

@test "newline and shell-syntax filenames remain literal array values" {
  FILE="$HOME_FIXTURE/.ssh/"$'line\n'"\$(touch should-not-exist).pub"
  printf 'valid\n' > "$FILE"
  _ssh_collect_key_files
  [[ "${#_SSH_KEY_PATHS[@]}" -eq 1 && "${_SSH_KEY_PATHS[0]}" == "$FILE" ]]
  [[ ! -e should-not-exist ]]
}

@test "authorized key files are enumerated alongside public-key files" {
  touch "$FILE" "$HOME_FIXTURE/.ssh/authorized_keys" "$HOME_FIXTURE/.ssh/authorized_keys2"
  _ssh_collect_key_files
  [[ "${#_SSH_KEY_PATHS[@]}" -eq 3 ]]
}

@test "failed or empty account snapshots cannot establish absence" {
  ACCOUNT_RC=1
  run _ssh_key_inventory grade
  [[ "$output" == *'inventory incomplete'* && "$output" != *'No conventional'* && "$output" == *'INCOMPLETE'* ]]
  ACCOUNT_RC=0 ACCOUNT_ROWS=''
  run _ssh_key_inventory inventory
  [[ "$output" == *'inventory incomplete'* && "$output" != *'No conventional'* ]]
}

@test "failed canonicalization remains incomplete rather than a zero inventory" {
  REALPATH_RC=1
  run _ssh_key_inventory inventory
  [[ "$output" == *'inventory incomplete'* && "$output" != *'No conventional'* ]]
}

@test "certificate subject-key grading does not attest trust or authorization" {
  printf 'weak-cert\n' > "$FILE"
  run _ssh_key_inventory grade
  [[ "$output" == *'FAIL:SSH certificate subject key:'*'1024 bit RSA-CERT'* ]]
  [[ "$output" == *'certificate CA trust/signature/validity'* && "$output" != *"$FP"* ]]
}

@test "mixed-file unknown lines stay visible alongside individual good keys" {
  printf 'valid\ninvalid\n' > "$FILE"
  run _ssh_key_inventory grade
  [[ "$output" == *'PASS:SSH public key:'* && "$output" == *'1 of 2 active lines could not be assessed'* && "$output" == *'INCOMPLETE'* ]]
}

@test "unknown vendor key type produces INFO rather than a guessed PASS or FAIL" {
  printf 'future\n' > "$FILE"
  run _ssh_key_inventory grade
  [[ "$output" == *'no reviewed size/type rule; unassessed'* && "$output" != *'PASS:'* && "$output" != *'FAIL:'* ]]
}

@test "certificate-section inventory counts parsed records, never physical authorized-key lines" {
  printf '# comment\nvalid\ninvalid\n' > "$HOME_FIXTURE/.ssh/authorized_keys"
  run _ssh_key_inventory inventory
  [[ "$output" == *'1 parsed record across 1 conventional file candidate'* && "$output" == *'1 of 2 active lines could not be assessed'* ]]
  [[ "$output" != *'PASS:'* && "$output" != *'FAIL:'* ]]
}

@test "unreadable file cannot be mislabeled empty" {
  printf 'valid\n' > "$FILE"
  READ_RC=1
  run _ssh_key_inventory grade
  [[ "$output" == *'unreadable, non-regular or outside the bounded text scope'* && "$output" != *'has no active lines'* && "$output" != *'PASS:'* ]]
}

@test "known empty home inventory remains explicitly scoped" {
  run _ssh_key_inventory inventory
  [[ "$output" == 'INFO:No conventional SSH key files detected in enumerated local-account homes' ]]
}

@test "missing parser leaves key records unassessed" {
  KEYGEN_AVAILABLE=false
  printf 'valid\n' > "$FILE"
  run _ssh_key_inventory grade
  [[ "$output" == *'SSH key records unassessed (ssh-keygen unavailable)'* && "$output" == *'INCOMPLETE'* && "$output" != *'No conventional'* ]]
}
