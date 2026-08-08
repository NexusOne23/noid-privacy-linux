#!/usr/bin/env bats
#
# Regression coverage for NoID Workstation's exact RPM expected-state policy.
# Known distro overrides are accepted only when their state record or explicit
# mode/ownership predicate matches; path-only suppression is forbidden.

# Bats invokes setup/test bodies and their command mocks indirectly.
# shellcheck disable=SC2317

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"

  # shellcheck disable=SC1090
  source <(awk '/^_noid_rpm_policy_applicable\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_rpm_package_verifier_allowed\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_rpm_baseline_records\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_rpm_policy_records_valid\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_noid_expected_mode_for_path\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_noid_mode_override_matches\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_rpm_missing_ghost_line\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_rpm_runtime_metadata_matches\(\) \{/,/^}/ {print}' "$SCRIPT")

  # `getcap` is a fail-closed production requirement on RPM-family systems,
  # but Debian need not install the unrelated RPM/libcap tooling to unit-test
  # deterministic records with an empty capability set.
  if ! command -v getcap &>/dev/null; then
    getcap() { return 0; }
  fi
}

@test "NoID policy activation is rejected on Fedora and Ubuntu" {
  _noid_rpm_policy_applicable noid-privacy

  run _noid_rpm_policy_applicable fedora
  [[ "$status" -ne 0 ]]
  run _noid_rpm_policy_applicable ubuntu
  [[ "$status" -ne 0 ]]
}

@test "Debian family cannot select RPM verification even when rpm exists" {
  _rpm_package_verifier_allowed rhel
  _rpm_package_verifier_allowed suse

  run _rpm_package_verifier_allowed debian
  [[ "$status" -ne 0 ]]
}

@test "every top-level RPM backend entry is Debian-family gated" {
  local guarded
  # Literal source-code assertion; the variable name must not expand here.
  # shellcheck disable=SC2016
  guarded=$(grep -c '^if _rpm_package_verifier_allowed "$DISTRO_FAMILY" && require_cmd rpm; then$' "$SCRIPT")
  [[ "$guarded" -eq 3 ]]

  run grep -n '^if require_cmd rpm; then$' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "policy records validate exact path hashes and missing states" {
  local present="$BATS_TEST_TMPDIR/present" missing="$BATS_TEST_TMPDIR/missing"
  printf 'known-state\n' > "$present"
  records=$(printf '%s\n%s\n' "$present" "$missing" | _rpm_baseline_records)
  printf '%s\n' "$records" | _rpm_policy_records_valid
  [[ "$(printf '%s\n' "$records" | wc -l)" -eq 2 ]]
}

@test "policy validator rejects a path-hash mismatch and duplicate paths" {
  local path="$BATS_TEST_TMPDIR/object" records bad
  printf 'state\n' > "$path"
  records=$(printf '%s\n' "$path" | _rpm_baseline_records)
  # Corrupt the first path-hash digit to a guaranteed-different value. A plain
  # "0" prefix is a no-op ~1/16 of the time (when the hash already starts with
  # 0, since the path — and thus the hash — varies per run), which made this
  # assertion flaky.
  if [[ "${records:0:1}" == "0" ]]; then bad="1${records:1}"; else bad="0${records:1}"; fi
  run _rpm_policy_records_valid <<< "$bad"
  [[ "$status" -ne 0 ]]

  run _rpm_policy_records_valid <<< "$records"$'\n'"$records"
  [[ "$status" -ne 0 ]]
}

@test "NoID mode override requires exact RPM status mode and root ownership" {
  stat() {
    case "$2" in
      %a) printf '%s\n' 755 ;;
      %u|%g) printf '%s\n' 0 ;;
      *) return 1 ;;
    esac
  }
  _noid_mode_override_matches noid-privacy '.M.......    /usr/bin/chage' /usr/bin/chage

  run _noid_mode_override_matches noid-privacy 'S.5......    /usr/bin/chage' /usr/bin/chage
  [[ "$status" -ne 0 ]]
}

@test "normal Fedora cannot consume NoID permission overrides" {
  stat() {
    case "$2" in
      %a) printf '%s\n' 755 ;;
      %u|%g) printf '%s\n' 0 ;;
      *) return 1 ;;
    esac
  }
  run _noid_mode_override_matches fedora '.M.......    /usr/bin/chage' /usr/bin/chage
  [[ "$status" -ne 0 ]]
}

@test "NoID mode override rejects a wrong current mode" {
  stat() {
    case "$2" in
      %a) printf '%s\n' 4755 ;;
      %u|%g) printf '%s\n' 0 ;;
      *) return 1 ;;
    esac
  }
  run _noid_mode_override_matches noid-privacy '.M.......    /usr/bin/chage' /usr/bin/chage
  [[ "$status" -ne 0 ]]
}

@test "fwupd StateDirectory runtime mode is explicit and narrowly scoped" {
  local unit="$BATS_TEST_TMPDIR/fwupd.service"
  printf '%s\n' '[Service]' 'StateDirectory=fwupd' > "$unit"
  _FWUPD_VENDOR_UNITS="$unit"
  stat() {
    case "$2" in
      %a) printf '%s\n' 755 ;;
      %u|%g) printf '%s\n' 0 ;;
      *) return 1 ;;
    esac
  }
  _rpm_runtime_metadata_matches '.M.......    /var/lib/fwupd' /var/lib/fwupd

  run _rpm_runtime_metadata_matches '.M.......    /boot/grub2' /boot/grub2
  [[ "$status" -ne 0 ]]
}

@test "fwupd runtime exception requires the vendor StateDirectory declaration" {
  local unit="$BATS_TEST_TMPDIR/fwupd.service"
  printf '%s\n' '[Service]' 'ExecStart=/usr/libexec/fwupd/fwupd' > "$unit"
  _FWUPD_VENDOR_UNITS="$unit"
  stat() {
    case "$2" in
      %a) printf '%s\n' 755 ;;
      %u|%g) printf '%s\n' 0 ;;
      *) return 1 ;;
    esac
  }
  run _rpm_runtime_metadata_matches '.M.......    /var/lib/fwupd' /var/lib/fwupd
  [[ "$status" -ne 0 ]]
}

@test "only missing ghost objects are treated as expected runtime state" {
  _rpm_missing_ghost_line 'missing   g /var/lib/example/runtime.db'

  run _rpm_missing_ghost_line '.M.......  g /var/lib/example/runtime.db'
  [[ "$status" -ne 0 ]]
}

@test "NoID policy integration has no path-only allow-list fallback" {
  grep -q '_NOID_RPM_POLICY_HEADER="# noid-rpm-expected-drift-v1"' "$SCRIPT"
  grep -q '_rpm_policy_records_valid' "$SCRIPT"
  grep -q 'NoID-managed RPM policy drift' "$SCRIPT"
  # Literal source-code assertion; command substitution must not expand.
  # shellcheck disable=SC2016
  grep -q '_RPM_NOID_POLICY_EXACT_RECORDS=$(comm -12' "$SCRIPT"
}

@test "missing NoID image policy cannot be replaced by a generic baseline" {
  grep -q 'NoID intentionally has no self-generated image expected-state policy' "$SCRIPT"
  grep -q 'RPM baseline request refused without a valid, independently reviewed NoID image expected-state policy' "$SCRIPT"
  grep -q 'remain unclassified at the NoID image trust boundary' "$SCRIPT"
}

@test "missing fingerprint tooling reduces RPM baseline coverage without an adverse verdict" {
  integrity_block=$(sed -n '/_RPM_STATE_RC=0/,/elif _noid_rpm_policy_applicable/p' "$SCRIPT")
  [[ "$integrity_block" == *'RPM baseline unavailable: full state fingerprinting requires'* ]]
  run grep -F '_emit_warn "RPM baseline unavailable:' <<< "$integrity_block"
  [[ "$status" -ne 0 ]]
}
