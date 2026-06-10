#!/usr/bin/env bats
#
# F-383 (v3.7.0) — SSH algorithm-strength classifier.
# Reproduces the Section 09 weak-algorithm case-match in isolation against
# captured `sshd -T` fixtures (strong vs weak algorithm sets).
#
# Weak classes (CIS 5.2.13-15 + 2026 hardening guidance): sha1, md5,
# 96-bit tags, CBC modes, 3des, arcfour/rc4, blowfish, cast128, umac-64.
# umac-128 and the sha2/ctr/gcm families must NOT be flagged.
#
# Counter-increment style: var=$((var + 1)), never ((var++)) — bash
# post-increment returns rc=1 when the var was 0, which bombs under
# `set -e` (BATS default).

setup() {
  FIXTURE_DIR="${BATS_TEST_DIRNAME}/../fixtures"
  [[ -d "$FIXTURE_DIR" ]] || skip "fixtures directory not found"
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
