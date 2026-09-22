#!/usr/bin/env bats

# Native file/date operations with controlled OpenSSL and p11-kit responses.
# Native valid/expired/invalid/unreadable certificates are also checked on host.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _ca_anchor_count _ca_bundle_block_count _ca_inventory _tls_certificate_expiry _tls_certificate_inventory; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  DIR="$BATS_TEST_TMPDIR/certificates"
  mkdir -p "$DIR"
  FILE="$DIR/fixture.crt"
  printf 'fixture\n' > "$FILE"
  CERT_DATE='notAfter=Jan  1 00:00:00 2040 GMT'
  CERT_RC=0 TRUST_RC=0 HEAD_RC=0 DATE_RC=0
  CERT_AVAILABLE=true TRUST_AVAILABLE=true
  TRUST_DATA=$'pkcs11:token=fixture;type=cert\n    type: certificate\n    label: fixture\n    trust: anchor\n    category: authority'
  NOW=1704067200
  CALLS="$BATS_TEST_TMPDIR/openssl-calls"
}

require_cmd() {
  case "$1" in openssl) $CERT_AVAILABLE ;; trust) $TRUST_AVAILABLE ;; *) return 1 ;; esac
}
_plural() { if [[ "$1" == 1 ]]; then printf '%s' "$2"; else printf '%s' "$3"; fi; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_fail() { printf 'FAIL:%s\n' "$1"; }
date() {
  if [[ "$*" == '-u +%s' ]]; then printf '%s\n' "$NOW"; return "$DATE_RC"; fi
  command date "$@"
  return "$DATE_RC"
}
timeout() {
  local duration="$1" program="$2"
  shift 2
  case "$program" in
    openssl)
      [[ "$duration" == 3 && "$1" == x509 && "$2" == -enddate && "$3" == -in && "$5" == -noout ]] || return 98
      printf '%s\0' "$4" >> "$CALLS"
      printf '%s\n' "$CERT_DATE"
      return "$CERT_RC" ;;
    trust)
      [[ "$duration" == 10 && "$*" == 'list --filter=ca-anchors' ]] || return 98
      printf '%s' "$TRUST_DATA"
      return "$TRUST_RC" ;;
    head)
      command head "$@"
      return "$HEAD_RC" ;;
    *) return 98 ;;
  esac
}

@test "expiry needs a successful parsed future date" {
  run _tls_certificate_expiry "$FILE" "$NOW"
  [[ "$status" -eq 0 && "$output" == not-expired ]]
}

@test "expired and pre-epoch certificate dates are detected" {
  for CERT_DATE in 'notAfter=Jan  1 00:00:00 2001 GMT' 'notAfter=Jan  1 00:00:00 1960 GMT'; do
    run _tls_certificate_expiry "$FILE" "$NOW"
    [[ "$status" -eq 0 && "$output" == expired ]]
  done
}

@test "the exact expiry boundary is expired" {
  CERT_DATE='notAfter=Jan  1 00:00:00 2024 GMT'
  run _tls_certificate_expiry "$FILE" "$NOW"
  [[ "$status" -eq 0 && "$output" == expired ]]
}

@test "failed partial OpenSSL output never establishes expiry" {
  CERT_DATE='notAfter=Jan  1 00:00:00 2001 GMT'
  for CERT_RC in 1 124 127; do
    run _tls_certificate_expiry "$FILE" "$NOW"
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "empty malformed multiple and invalid-calendar dates are unassessed" {
  for CERT_DATE in '' 'notAfter=Bad time value' 'notAfter=Feb 30 00:00:00 2001 GMT' \
      $'notAfter=Jan  1 00:00:00 2001 GMT\nnotAfter=Jan  1 00:00:00 2040 GMT' \
      'notAfter=Jan  1 00:00:00 2001 UTC'; do
    run _tls_certificate_expiry "$FILE" "$NOW"
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "failed date conversion discards its otherwise valid output" {
  DATE_RC=1
  run _tls_certificate_expiry "$FILE" "$NOW"
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "malformed and overflowing timestamps never enter arithmetic" {
  for NOW in '' '00042' -1 'x[1]' 999999999999999999999; do
    run _tls_certificate_expiry "$FILE" "$NOW"
    [[ "$status" -ne 0 && -z "$output" ]]
  done
  date() { printf '%s\n' 999999999999999999999; }
  run _tls_certificate_expiry "$FILE" 1704067200
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "non-regular inputs never reach the OpenSSL parser" {
  mkfifo "$DIR/fifo.crt"
  for candidate in "$DIR/fifo.crt" "$DIR" "$DIR/missing.crt"; do
    run _tls_certificate_expiry "$candidate" "$NOW"
    [[ "$status" -ne 0 && -z "$output" ]]
  done
  [[ ! -e "$CALLS" ]]
}

@test "expired file findings remain INFO without inferring active usage" {
  CERT_DATE='notAfter=Jan  1 00:00:00 2001 GMT'
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'INFO:Expired certificate in file:'* ]]
  [[ "$output" == *'1 expiry date read, 1 expired, 0 unassessed, 0 skipped'* ]]
  [[ "$output" == *'active service usage unassessed'* ]]
  [[ "$output" != *'PASS:'* && "$output" != *'FAIL:'* && "$output" != *'WARN:'* ]]
}

@test "inventory reports input failures instead of expired certificates" {
  CERT_RC=1
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'Certificate expiry unassessed:'* ]]
  [[ "$output" == *'0 expiry dates read, 0 expired, 1 unassessed, 0 skipped'* ]]
  [[ "$output" != *'Expired certificate in file:'* ]]
}

@test "missing parser and unavailable current time stay explicit" {
  CERT_AVAILABLE=false
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'openssl unavailable'* ]]
  CERT_AVAILABLE=true DATE_RC=1
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'current time unavailable'* ]]
  [[ ! -e "$CALLS" ]]
}

@test "directory names ending in crt are not certificate files" {
  mkdir "$DIR/not-a-file.crt"
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'1 expiry date read'* ]]
  [[ "$output" != *'not-a-file'* ]]
}

@test "directory and file aliases are parsed once" {
  ln -s "$DIR" "$BATS_TEST_TMPDIR/alias"
  ln -s fixture.crt "$DIR/symlink.pem"
  ln "$FILE" "$DIR/hardlink.crt"
  run _tls_certificate_inventory "$DIR" "$BATS_TEST_TMPDIR/alias"
  [[ "$status" -eq 0 && "$output" == *'1 expiry date read'* ]]
  [[ "$(tr -cd '\000' < "$CALLS" | wc -c)" -eq 1 ]]
}

@test "filename whitespace newlines and shell syntax remain literal" {
  local marker="$BATS_TEST_TMPDIR/marker" actual
  cd "$BATS_TEST_TMPDIR"
  # Literal command substitution in a filename must not execute.
  # shellcheck disable=SC2016
  actual="$DIR/"$' space\n''$(touch marker).crt'
  mv "$FILE" "$actual"
  _tls_certificate_inventory "$DIR" > "$BATS_TEST_TMPDIR/output"
  IFS= read -r -d '' candidate < "$CALLS"
  [[ "$candidate" == "$actual" && ! -e "$marker" ]]
}

@test "broken links remain unassessed without opening a stream" {
  ln -s missing "$DIR/broken.crt"
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'1 expiry date read, 0 expired, 1 unassessed'* ]]
  [[ "$output" == *'broken.crt'* ]]
}

@test "the file limit is visible with deterministic bounded selection" {
  local index
  for index in {1..41}; do printf 'fixture\n' > "$DIR/$index.crt"; done
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'40 expiry dates read, 0 expired, 0 unassessed, 2 skipped'* ]]
  [[ "$output" == *'TLS inventory limit: 40 files or 15 seconds'* ]]
}

@test "successful file inventory states its first-certificate and trust limits" {
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'first parsed certificate per top-level .pem/.crt file'* ]]
  [[ "$output" == *'remaining bundle entries, notBefore, chain trust'* ]]
}

@test "CA count uses the explicit anchor filter" {
  run _ca_anchor_count
  [[ "$status" -eq 0 && "$output" == 1 ]]
}

@test "a successful empty anchor inventory is zero" {
  TRUST_DATA=''
  run _ca_anchor_count
  [[ "$status" -eq 0 && "$output" == 0 ]]
}

@test "failed empty or partial anchor queries are unavailable" {
  TRUST_RC=1
  run _ca_inventory
  [[ "$status" -eq 0 && "$output" == *'inventory unavailable'* ]]
  [[ "$output" != *'anchor objects:'* ]]
  TRUST_DATA=''
  run _ca_inventory
  [[ "$status" -eq 0 && "$output" == *'inventory unavailable'* ]]
}

@test "malformed incomplete and duplicate anchor records do not produce counts" {
  for TRUST_DATA in 'unexpected response' 'pkcs11:incomplete' $'    type: certificate\n' \
      $'pkcs11:duplicate\n    type: certificate\n    type: certificate\n'; do
    run _ca_anchor_count
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "bundle fallback counts complete blocks without asserting trust" {
  TRUST_AVAILABLE=false
  printf '%s\n' '# fixture bundle' '-----BEGIN CERTIFICATE-----' 'fixture' '-----END CERTIFICATE-----' \
    '-----BEGIN CERTIFICATE-----' 'fixture' '-----END CERTIFICATE-----' > "$FILE"
  run _ca_inventory "$FILE"
  [[ "$status" -eq 0 && "$output" == *'2 complete PEM certificate blocks'* ]]
  [[ "$output" == *'certificate parsing and trust purposes unassessed'* ]]
  [[ "$output" != *'anchor objects:'* ]]
}

@test "bundle truncation empty data and malformed delimiters are unassessed" {
  for data in '' 'garbage' '-----BEGIN CERTIFICATE-----' '-----END CERTIFICATE-----' \
      $'-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----'; do
    printf '%s\n' "$data" > "$FILE"
    run _ca_bundle_block_count "$FILE"
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "failed partial bundle reads cannot produce a successful count" {
  printf '%s\n' '-----BEGIN CERTIFICATE-----' 'fixture' '-----END CERTIFICATE-----' > "$FILE"
  TRUST_AVAILABLE=false HEAD_RC=1
  run _ca_inventory "$FILE"
  [[ "$status" -eq 0 && "$output" == *'bundle inventory unavailable'* ]]
  [[ "$output" != *'complete PEM certificate blocks'* ]]
}

@test "NUL and oversized bundle input are rejected" {
  printf '%s\n' '-----BEGIN CERTIFICATE-----' 'fixture' '-----END CERTIFICATE-----' > "$FILE"
  printf '\0' >> "$FILE"
  run _ca_bundle_block_count "$FILE"
  [[ "$status" -ne 0 && -z "$output" ]]
  truncate -s 16777217 "$FILE"
  run _ca_bundle_block_count "$FILE"
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "missing CA sources do not become a certificate filename count" {
  TRUST_AVAILABLE=false
  run _ca_inventory "$DIR/missing-bundle.crt"
  [[ "$status" -eq 0 && "$output" == *'trust tool and standard CA bundle absent'* ]]
  [[ "$output" != *'System CA certificates:'* ]]
}

@test "unreadable certificate directories remain explicitly incomplete" {
  chmod 000 "$DIR"
  run _tls_certificate_inventory "$DIR"
  chmod 700 "$DIR"
  [[ "$status" -eq 0 && "$output" == *'directory unreadable:'* ]]
  [[ "$output" == *'inventory incomplete'* && ! -e "$CALLS" ]]
}

@test "failed directory identity queries do not imply an empty successful inventory" {
  stat() { printf '123:456\n'; return 1; }
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'directory unreadable:'* ]]
  [[ ! -e "$CALLS" ]]
}

@test "the time budget leaves known candidates explicitly skipped" {
  require_cmd() { SECONDS=$((SECONDS + 16)); return 0; }
  run _tls_certificate_inventory "$DIR"
  [[ "$status" -eq 0 && "$output" == *'0 expiry dates read, 0 expired, 0 unassessed, 1 skipped'* ]]
  [[ "$output" == *'TLS inventory limit:'* && ! -e "$CALLS" ]]
}
