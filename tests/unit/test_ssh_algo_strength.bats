#!/usr/bin/env bats
#
# F-383 (v3.7.0) — SSH algorithm-strength classifier.
# Reproduces the Section 09 weak-algorithm case-match in isolation against
# captured `sshd -T` fixtures (strong vs weak algorithm sets).
#
# Weak families related to CIS RHEL 9 v2 controls 5.1.4-5.1.6:
# 96-bit tags, CBC modes, 3des, arcfour/rc4, blowfish, cast128, umac-64.
# umac-128 and the sha2/ctr/gcm families must NOT be flagged.
#
# Counter-increment style: var=$((var + 1)), never ((var++)) — bash
# post-increment returns rc=1 when the var was 0, which bombs under
# `set -e` (BATS default).

setup() {
  FIXTURE_DIR="${BATS_TEST_DIRNAME}/../fixtures"
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -d "$FIXTURE_DIR" && -f "$SCRIPT" ]] || skip "test inputs not found"
  # shellcheck disable=SC1090
  source <(awk '/^_ssh_public_key_grade\(\) \{/,/^}/ {print}' "$SCRIPT")
}

# Reproduce the classifier: print weak tokens from a comma-separated list.
_weak_tokens() {
  local _list="$1" _tok _weak=""
  while IFS= read -r _tok; do
    [[ -z "$_tok" ]] && continue
    case "$_tok" in
      *-cbc|*-cbc@*|3des*|*arcfour*|*rc4*|*blowfish*|*cast128*) _weak+="$_tok " ;;
      *hmac-md5*|*hmac-sha1*|*umac-64*|*-96|*-96@*) _weak+="$_tok " ;;
      *group1-sha1*|*group14-sha1*|*group-exchange-sha1*) _weak+="$_tok " ;;
    esac
  done < <(echo "$_list" | tr ',' '\n')
  printf '%s' "${_weak% }"
}

_fixture_list() {
  awk -v k="$2" '$1==k {print $2; exit}' "$FIXTURE_DIR/$1"
}

@test "F-383: weak fixture — ciphers flag aes256-cbc + 3des-cbc only" {
  result=$(_weak_tokens "$(_fixture_list sshd-T-algos-weak.txt ciphers)")
  [[ "$result" == "aes256-cbc 3des-cbc" ]]
}

@test "F-383: weak fixture — MACs flag hmac-sha1 + hmac-md5-96 only" {
  result=$(_weak_tokens "$(_fixture_list sshd-T-algos-weak.txt macs)")
  [[ "$result" == "hmac-sha1 hmac-md5-96" ]]
}

@test "F-383: weak fixture — kex flags group14-sha1, keeps curve25519-sha256" {
  result=$(_weak_tokens "$(_fixture_list sshd-T-algos-weak.txt kexalgorithms)")
  [[ "$result" == "diffie-hellman-group14-sha1" ]]
}

@test "F-383: strong fixture — zero weak tokens across all three lists" {
  for key in ciphers macs kexalgorithms; do
    result=$(_weak_tokens "$(_fixture_list sshd-T-algos-strong.txt "$key")")
    [[ -z "$result" ]]
  done
}

@test "F-383: umac-128-etm and hmac-sha2 are NOT flagged (no sha1-substring FP)" {
  result=$(_weak_tokens "umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512-etm@openssh.com")
  [[ -z "$result" ]]
}

@test "F-382: permitemptypasswords classification (yes=FAIL-class, no=PASS-class)" {
  weak_val=$(_fixture_list sshd-T-algos-weak.txt permitemptypasswords)
  strong_val=$(_fixture_list sshd-T-algos-strong.txt permitemptypasswords)
  [[ "$weak_val" == "yes" ]]
  [[ "$strong_val" == "no" ]]
}

@test "accepted RSA keys are not penalized by an invented 4096-bit policy" {
  [[ "$(_ssh_public_key_grade 2048 RSA)" == "pass" ]]
  [[ "$(_ssh_public_key_grade 3072 RSA)" == "pass" ]]
  run grep -q '4096 recommended' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "SSH public-key grade enforces only explicit legacy size boundaries" {
  [[ "$(_ssh_public_key_grade 1024 RSA)" == "fail" ]]
  [[ "$(_ssh_public_key_grade 2048 RSA)" == "pass" ]]
  [[ "$(_ssh_public_key_grade 192 ECDSA)" == "fail" ]]
  [[ "$(_ssh_public_key_grade 256 ECDSA)" == "pass" ]]
  [[ "$(_ssh_public_key_grade 1024 DSA)" == "fail" ]]
  [[ "$(_ssh_public_key_grade 256 ED25519)" == "pass" ]]
  [[ "$(_ssh_public_key_grade invalid ED25519)" == "unassessed" ]]
}

@test "SSH key audit includes authorized key files without emitting identity metadata" {
  # shellcheck disable=SC2016  # literal production-source path
  grep -q '"$USER_HOME"/.ssh/authorized_keys' "$SCRIPT"
  grep -q 'fingerprints and comments are deliberately discarded' "$SCRIPT"
  run grep -q 'No SSH public keys found for any user' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}
