#!/usr/bin/env bats
#
# v3.6.1 — Three context-aware classification fixes:
#   F-273: Empty-PW finding now severity-coupled with PAM nullok presence
#   F-274: Umask "conflict" recognizes intentional system/interactive split
#   F-275: passwd -S NP-status reported separately from L/LK locked accounts
#
# Each block tests the underlying classification logic in isolation, using
# fixtures or inline maps. We intentionally do NOT source the main script —
# these are unit tests of the discrete branches, not integration tests.
#
# Counter-increment style: PASS=$((PASS + 1)), never ((PASS++)) — because
# bash post-increment returns rc=1 when the var was 0, which bombs under
# `set -e` (BATS default). See feedback_bash_double_paren_increment.md.

setup() {
  FIXTURE_DIR="${BATS_TEST_DIRNAME}/../fixtures"
  [[ -d "$FIXTURE_DIR" ]] || skip "fixtures directory not found"
}

# --- F-273: Empty-PW + PAM nullok severity coupling ---------------------------

@test "F-273: NP-shadow has 2 accounts with empty \$2 (root + liveuser)" {
  result=$(awk -F: '$2 == "" {print $1}' "$FIXTURE_DIR/shadow-np-accounts.txt" | wc -l)
  [[ "$result" == "2" ]]
}

@test "F-273: passworded-shadow has 0 accounts with empty \$2" {
  result=$(awk -F: '$2 == "" {print $1}' "$FIXTURE_DIR/shadow-passworded.txt" | wc -l)
  [[ "$result" == "0" ]]
}

@test "F-273: pam-with-nullok detects nullok keyword (uncommented)" {
  grep -qE '^[[:space:]]*[^#[:space:]].*nullok' "$FIXTURE_DIR/pam-with-nullok.txt"
}

@test "F-273: pam-no-nullok contains no nullok keyword" {
  ! grep -qE '^[[:space:]]*[^#[:space:]].*nullok' "$FIXTURE_DIR/pam-no-nullok.txt"
}

@test "F-273: NP-shadow + no-nullok = INFO classification" {
  # Reproduce the v3.6.1 classification logic
  declare -A _NULLOK_FOUND_IN=()
  if grep -qE '^[[:space:]]*[^#[:space:]].*nullok' "$FIXTURE_DIR/pam-no-nullok.txt"; then
    _NULLOK_FOUND_IN["test"]="hit"
  fi
  EMPTY_PW=$(awk -F: '$2 == "" {print $1}' "$FIXTURE_DIR/shadow-np-accounts.txt" | wc -l)

  if [[ "$EMPTY_PW" -eq 0 ]]; then
    severity="PASS"
  elif [[ "${#_NULLOK_FOUND_IN[@]}" -gt 0 ]]; then
    severity="FAIL"
  else
    severity="INFO"
  fi

  [[ "$severity" == "INFO" ]]
}

@test "F-273: NP-shadow + nullok-set = FAIL classification" {
  declare -A _NULLOK_FOUND_IN=()
  if grep -qE '^[[:space:]]*[^#[:space:]].*nullok' "$FIXTURE_DIR/pam-with-nullok.txt"; then
    _NULLOK_FOUND_IN["test"]="hit"
  fi
  EMPTY_PW=$(awk -F: '$2 == "" {print $1}' "$FIXTURE_DIR/shadow-np-accounts.txt" | wc -l)

  if [[ "$EMPTY_PW" -eq 0 ]]; then
    severity="PASS"
  elif [[ "${#_NULLOK_FOUND_IN[@]}" -gt 0 ]]; then
    severity="FAIL"
  else
    severity="INFO"
  fi

  [[ "$severity" == "FAIL" ]]
}

@test "F-273: passworded-shadow = PASS regardless of nullok" {
  # Whether nullok is set or not, no empty-$2 = PASS
  EMPTY_PW=$(awk -F: '$2 == "" {print $1}' "$FIXTURE_DIR/shadow-passworded.txt" | wc -l)

  declare -A _NULLOK_FOUND_IN=()
  _NULLOK_FOUND_IN["test"]="hit"   # simulate nullok present

  if [[ "$EMPTY_PW" -eq 0 ]]; then
    severity="PASS"
  elif [[ "${#_NULLOK_FOUND_IN[@]}" -gt 0 ]]; then
    severity="FAIL"
  else
    severity="INFO"
  fi

  [[ "$severity" == "PASS" ]]
}

# --- F-274: Umask intentional defense-in-depth split detection ----------------

@test "F-274: system=022 + interactive=027 = intentional-split PASS" {
  declare -A _UMASK_BY_FILE=(
    ["/etc/login.defs"]="022"
    ["/etc/profile.d/99-noid-security-umask.sh"]="027"
  )

  _LOGIN_DEFS_UMASK="${_UMASK_BY_FILE[/etc/login.defs]:-}"
  _INTERACTIVE_MAX=""
  for _file in "${!_UMASK_BY_FILE[@]}"; do
    [[ "$_file" == "/etc/login.defs" ]] && continue
    _v="${_UMASK_BY_FILE[$_file]}"
    [[ -z "$_v" ]] && continue
    if [[ -z "$_INTERACTIVE_MAX" ]]; then
      _INTERACTIVE_MAX="$_v"
    else
      _val_dec=$((8#${_v#0}))
      _max_dec=$((8#${_INTERACTIVE_MAX#0}))
      [[ "$_val_dec" -gt "$_max_dec" ]] && _INTERACTIVE_MAX="$_v"
    fi
  done

  _INTENTIONAL_SPLIT=0
  if [[ -n "$_LOGIN_DEFS_UMASK" && -n "$_INTERACTIVE_MAX" ]]; then
    _ldef_dec=$((8#${_LOGIN_DEFS_UMASK#0}))
    _imax_dec=$((8#${_INTERACTIVE_MAX#0}))
    if [[ "$_imax_dec" -ge "$_ldef_dec" ]] && [[ "$_INTERACTIVE_MAX" =~ ^0*(27|77)$ ]]; then
      _INTENTIONAL_SPLIT=1
    fi
  fi

  [[ "$_INTENTIONAL_SPLIT" -eq 1 ]]
}

@test "F-274: system=077 + interactive=022 = NOT intentional-split (interactive less-restrictive)" {
  declare -A _UMASK_BY_FILE=(
    ["/etc/login.defs"]="077"
    ["/etc/profile.d/loose.sh"]="022"
  )

  _LOGIN_DEFS_UMASK="${_UMASK_BY_FILE[/etc/login.defs]:-}"
  _INTERACTIVE_MAX=""
  for _file in "${!_UMASK_BY_FILE[@]}"; do
    [[ "$_file" == "/etc/login.defs" ]] && continue
    _v="${_UMASK_BY_FILE[$_file]}"
    if [[ -z "$_INTERACTIVE_MAX" ]]; then
      _INTERACTIVE_MAX="$_v"
    fi
  done

  _INTENTIONAL_SPLIT=0
  if [[ -n "$_LOGIN_DEFS_UMASK" && -n "$_INTERACTIVE_MAX" ]]; then
    _ldef_dec=$((8#${_LOGIN_DEFS_UMASK#0}))
    _imax_dec=$((8#${_INTERACTIVE_MAX#0}))
    if [[ "$_imax_dec" -ge "$_ldef_dec" ]] && [[ "$_INTERACTIVE_MAX" =~ ^0*(27|77)$ ]]; then
      _INTENTIONAL_SPLIT=1
    fi
  fi

  [[ "$_INTENTIONAL_SPLIT" -eq 0 ]]
}

@test "F-274: system=022 + interactive=055 (arbitrary value) = NOT intentional" {
  # 055 is more restrictive than 022 numerically (8#55=45 > 8#22=18)
  # but 055 is not in the recommended-range whitelist {027, 077}
  declare -A _UMASK_BY_FILE=(
    ["/etc/login.defs"]="022"
    ["/etc/profile.d/weird.sh"]="055"
  )

  _LOGIN_DEFS_UMASK="${_UMASK_BY_FILE[/etc/login.defs]:-}"
  _INTERACTIVE_MAX=""
  for _file in "${!_UMASK_BY_FILE[@]}"; do
    [[ "$_file" == "/etc/login.defs" ]] && continue
    _v="${_UMASK_BY_FILE[$_file]}"
    [[ -z "$_INTERACTIVE_MAX" ]] && _INTERACTIVE_MAX="$_v"
  done

  _INTENTIONAL_SPLIT=0
  if [[ -n "$_LOGIN_DEFS_UMASK" && -n "$_INTERACTIVE_MAX" ]]; then
    _ldef_dec=$((8#${_LOGIN_DEFS_UMASK#0}))
    _imax_dec=$((8#${_INTERACTIVE_MAX#0}))
    if [[ "$_imax_dec" -ge "$_ldef_dec" ]] && [[ "$_INTERACTIVE_MAX" =~ ^0*(27|77)$ ]]; then
      _INTENTIONAL_SPLIT=1
    fi
  fi

  [[ "$_INTENTIONAL_SPLIT" -eq 0 ]]
}

@test "F-274: octal arithmetic — 027 evaluates as octal not decimal" {
  # Sanity-check that 8#027 = 23 decimal, not 27.
  result=$((8#027))
  [[ "$result" == "23" ]]
}

# --- F-275: passwd -S NP-status case-match -----------------------------------

@test "F-275: passwd -S 'NP' status routes to _NP_USERS" {
  # Simulate passwd -S output for three accounts: locked, NP, normal
  _LOCKED_ACCOUNTS=0
  _NP_ACCOUNTS=0
  declare -a _NP_USERS=()

  for entry in "alice L never -1 -1 -1 -1" \
               "bob NP never -1 -1 -1 -1"  \
               "charlie P 04/30/2026 0 90 7 -1"; do
    user=$(echo "$entry" | awk '{print $1}')
    status=$(echo "$entry" | awk '{print $2}')
    case "$status" in
      L|LK) _LOCKED_ACCOUNTS=$((_LOCKED_ACCOUNTS + 1)) ;;
      NP)   _NP_USERS+=("$user"); _NP_ACCOUNTS=$((_NP_ACCOUNTS + 1)) ;;
    esac
  done

  [[ "$_LOCKED_ACCOUNTS" -eq 1 ]]
  [[ "$_NP_ACCOUNTS" -eq 1 ]]
  [[ "${_NP_USERS[0]}" == "bob" ]]
}

@test "F-275: passwd -S 'LK' status counts as locked" {
  _LOCKED_ACCOUNTS=0
  for status in L LK; do
    case "$status" in
      L|LK) _LOCKED_ACCOUNTS=$((_LOCKED_ACCOUNTS + 1)) ;;
    esac
  done
  [[ "$_LOCKED_ACCOUNTS" -eq 2 ]]
}

@test "F-275: passwd -S 'P' (passworded) routes to neither bucket" {
  _LOCKED_ACCOUNTS=0
  _NP_ACCOUNTS=0
  status="P"
  case "$status" in
    L|LK) _LOCKED_ACCOUNTS=$((_LOCKED_ACCOUNTS + 1)) ;;
    NP)   _NP_ACCOUNTS=$((_NP_ACCOUNTS + 1)) ;;
  esac
  [[ "$_LOCKED_ACCOUNTS" -eq 0 ]]
  [[ "$_NP_ACCOUNTS" -eq 0 ]]
}

@test "F-275: counter increment uses safe \$((var+1)) form" {
  # Anti-regression: must not use ((var++)) which returns rc=1 when var=0
  # under set -e (BATS default). Verify the source script in the relevant
  # block uses the safe form.
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"

  # Locate the C1 block via the unique header text
  block=$(awk '/^# Locked user accounts \+ NP/,/^if \[\[ "\$_NP_ACCOUNTS" -gt 0 \]\];/' "$SCRIPT")
  [[ -n "$block" ]] || skip "C1 block not found in main script"

  # Block must use _LOCKED_ACCOUNTS=$((... + 1)), not ((_LOCKED_ACCOUNTS++))
  echo "$block" | grep -q '_LOCKED_ACCOUNTS=\$((_LOCKED_ACCOUNTS + 1))'
  ! echo "$block" | grep -qE '\(\(_LOCKED_ACCOUNTS\+\+\)\)'
}
