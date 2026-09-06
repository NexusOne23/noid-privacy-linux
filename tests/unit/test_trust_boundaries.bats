#!/usr/bin/env bats
# Regression coverage for privileged PATH and operator-owned AIDE trust state.

# Bats invokes setup/test bodies indirectly.
# shellcheck disable=SC2317

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "project script not found"

  # Load only the standalone helpers; never execute the root audit in unit tests.
  # shellcheck disable=SC1090
  source <(awk '/^_noid_owner_mode_safe\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_noid_path_root_controlled\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_aide_database_record\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "privileged PATH metadata rejects foreign ownership and writable modes" {
  _noid_owner_mode_safe 0 755 0

  run _noid_owner_mode_safe 1000 755 0
  [[ "$status" -ne 0 ]]
  run _noid_owner_mode_safe 0 775 0
  [[ "$status" -ne 0 ]]
  run _noid_owner_mode_safe 0 757 0
  [[ "$status" -ne 0 ]]
}

@test "resolved PATH chain accepts a root-controlled command and rejects tmp" {
  _noid_path_root_controlled /bin/true 0

  run _noid_path_root_controlled /tmp 0
  [[ "$status" -ne 0 ]]
}

@test "PATH trust rejects a mutable symlink even when its target is root-controlled" {
  ln -s /usr/bin/true "$BATS_TEST_TMPDIR/command"
  run _noid_path_root_controlled "$BATS_TEST_TMPDIR/command" 0
  [[ "$status" -ne 0 ]]
}

@test "PATH trust rejects a mutable directory alias to a root-controlled tree" {
  ln -s /usr/bin "$BATS_TEST_TMPDIR/bin"
  run _noid_path_root_controlled "$BATS_TEST_TMPDIR/bin/true" 0
  [[ "$status" -ne 0 ]]
}

@test "PATH trust checks directories before dot-dot traversal" {
  _noid_path_root_controlled /usr/bin/../bin/true 0
  run _noid_path_root_controlled /tmp/../usr/bin/true 0
  [[ "$status" -ne 0 ]]
}

@test "PATH trust rejects file components used as directories" {
  _noid_path_root_controlled /usr/bin/true 0
  run _noid_path_root_controlled /usr/bin/true/ 0
  [[ "$status" -ne 0 ]]
  run _noid_path_root_controlled /usr/bin/true/../true 0
  [[ "$status" -ne 0 ]]
}

@test "local PATH admission checks every candidate and resolved symlink target" {
  local block
  block=$(sed -n '/^_noid_local_bin_dir_trusted()/,/^}/p' "$SCRIPT")
  [[ "$block" == *"-mindepth 1 -maxdepth 1"* ]]
  [[ "$block" == *"_noid_owner_mode_safe \"\$owner\" \"\$mode\""* ]]
  [[ "$block" == *"_noid_path_root_controlled \"\$entry\""* ]]
  [[ "$block" == *"scan_complete=true"* ]]
}

@test "pending AIDE candidate is never selected as the active database" {
  mkdir -p "$BATS_TEST_TMPDIR/aide"
  printf 'candidate\n' > "$BATS_TEST_TMPDIR/aide/aide.db.new.gz"

  result=$(_aide_database_record "$BATS_TEST_TMPDIR/aide")
  [[ "$result" == $'pending\t'"$BATS_TEST_TMPDIR/aide/aide.db.new.gz" ]]
}

@test "active AIDE database takes precedence over a pending candidate" {
  mkdir -p "$BATS_TEST_TMPDIR/aide"
  printf 'active\n' > "$BATS_TEST_TMPDIR/aide/aide.db"
  printf 'candidate\n' > "$BATS_TEST_TMPDIR/aide/aide.db.new.gz"

  result=$(_aide_database_record "$BATS_TEST_TMPDIR/aide")
  [[ "$result" == $'active\t'"$BATS_TEST_TMPDIR/aide/aide.db" ]]
}

@test "missing AIDE state is explicitly absent" {
  mkdir -p "$BATS_TEST_TMPDIR/aide"

  result=$(_aide_database_record "$BATS_TEST_TMPDIR/aide")
  [[ "$result" == $'absent\t' ]]
}

@test "AIDE database presence uses only the active input path" {
  local block
  block=$(sed -n '/# AIDE database existence/,/# 2. Optional fresh check/p' "$SCRIPT")
  # shellcheck disable=SC2016  # literal production-source variables
  [[ "$block" == *'[[ "$_AIDE_DB_STATE" == "active" ]] && _AIDE_DB="$_AIDE_DB_PATH"'* ]]
  [[ "$block" == *'candidate database exists but is not the active input database'* ]]
  [[ "$block" == *'no PASS granted'* ]]
  # shellcheck disable=SC2016  # literal production-source variables
  [[ "$block" == *'[[ -n "${_AIDE_DB:-}" && -s "$_AIDE_DB" ]]'* ]]
  [[ "$block" == *'no nonempty active trust database is available'* ]]
  [[ "$block" == *'database/check chronology could not be verified'* ]]
}
