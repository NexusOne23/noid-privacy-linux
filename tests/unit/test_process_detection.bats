#!/usr/bin/env bats

# Production process readers use a disposable proc tree and a checked candidate
# producer. Native executable/interpreter probes complement these error cases.
# shellcheck disable=SC2317,SC2034
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _process_pid_matches _process_pids_exact _process_running_exact _process_has_any_arg; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '
      $0 == signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  PROC_ROOT="$BATS_TEST_TMPDIR/proc"
  mkdir "$PROC_ROOT"
  PGREP_ROWS=123 PGREP_RC=0
}

pgrep() {
  printf '%s\n' "$3" > "$BATS_TEST_TMPDIR/pattern-${1#-}"
  printf '%s' "$PGREP_ROWS"
  return "$PGREP_RC"
}

process_fixture() {
  local pid="$1" executable="$2"
  shift 2
  mkdir -p "$PROC_ROOT/$pid"
  ln -s "$executable" "$PROC_ROOT/$pid/exe"
  printf '%s\0' "$@" > "$PROC_ROOT/$pid/cmdline"
}

@test "long native executable name is confirmed without the comm length limit" {
  process_fixture 123 /usr/libexec/baloo_file_extractor /usr/libexec/baloo_file_extractor
  run _process_pids_exact baloo_file_extractor "$PROC_ROOT"
  [[ "$status" -eq 0 && "$output" == 123 ]]
}

@test "deleted executable still has its observed basename" {
  process_fixture 123 '/usr/libexec/xdg-desktop-portal (deleted)' /usr/libexec/xdg-desktop-portal
  run _process_running_exact xdg-desktop-portal "$PROC_ROOT"
  [[ "$status" -eq 0 ]]
}

@test "argument and argv0 lookalikes cannot identify another native executable" {
  process_fixture 123 /usr/bin/sleep /usr/bin/wsdd 60
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "CPython file operand is recognized after standard grouped flags" {
  process_fixture 123 /usr/bin/python3.14 /usr/bin/python3 -sP /usr/bin/wsdd --no-host
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 0 && "$output" == 123 ]]
}

@test "Python inline code with a lookalike argument is not the named script" {
  process_fixture 123 /usr/bin/python3.14 python3 -c 'import time' /usr/bin/wsdd
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "Python interpreter option operands are not script names" {
  process_fixture 123 /usr/bin/python3.14 python3 -W /usr/bin/wsdd -X dev /usr/bin/other.py /usr/bin/wsdd
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "Python option terminator preserves the script operand" {
  process_fixture 123 /usr/bin/python3.14 python3 -- /path/with\ space/wsdd --no-host
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 0 && "$output" == 123 ]]
}

@test "unsupported interpreter or option scheme remains unassessed" {
  process_fixture 123 /usr/bin/bash bash /usr/bin/wsdd
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 2 && -z "$output" ]]
}

@test "Python module invocation is not misrepresented as a verified file operand" {
  process_fixture 123 /usr/bin/python3.14 python3 -m wsdd
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 2 && -z "$output" ]]
}

@test "dot and plus characters are escaped in candidate matching" {
  process_fixture 123 /usr/bin/a+b.name /usr/bin/a+b.name
  run _process_pids_exact a+b.name "$PROC_ROOT"
  [[ "$status" -eq 0 && "$output" == 123 ]]
  [[ "$(cat "$BATS_TEST_TMPDIR/pattern-f")" == '(^|[[:space:]]|/)a\+b\.name([[:space:]]|$)' ]]
}

@test "exact process helper rejects regex injection before invoking pgrep" {
  run _process_pids_exact 'portal.*' "$PROC_ROOT"
  [[ "$status" -eq 2 && ! -e "$BATS_TEST_TMPDIR/pattern-f" ]]
}

@test "failed candidate producer discards partial PID output" {
  process_fixture 123 /usr/bin/wsdd /usr/bin/wsdd
  PGREP_RC=2
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 2 && -z "$output" ]]
}

@test "empty successful candidate response is incomplete not absent" {
  PGREP_ROWS=''
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 2 && -z "$output" ]]
}

@test "successful no-match producer retains known absence" {
  PGREP_ROWS='' PGREP_RC=1
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "malformed PID inventory is rejected before any partial match is returned" {
  process_fixture 123 /usr/bin/wsdd /usr/bin/wsdd
  PGREP_ROWS=$'123\n../../other'
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 2 && -z "$output" ]]
}

@test "a vanished candidate is distinct from an unreadable existing process" {
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 1 && -z "$output" ]]
  mkdir "$PROC_ROOT/123"
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 2 && -z "$output" ]]
}

@test "known presence survives another unreadable candidate but PID inventory is incomplete" {
  process_fixture 123 /usr/bin/wsdd /usr/bin/wsdd
  mkdir "$PROC_ROOT/456"
  PGREP_ROWS=$'123\n456'
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 2 && "$output" == 123 ]]
  run _process_running_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 0 ]]
}

@test "newline bytes in executable names cannot be silently trimmed into a match" {
  process_fixture 123 $'/usr/bin/wsdd\n' /usr/bin/wsdd
  run _process_pids_exact wsdd "$PROC_ROOT"
  [[ "$status" -eq 1 && -z "$output" ]]
}

@test "argument inventory uses exact NUL tokens and excludes argv0" {
  process_fixture 123 /usr/bin/wsdd --no-host '/path/--no-host suffix'
  run _process_has_any_arg 123 "$PROC_ROOT" --no-host -o
  [[ "$status" -eq 1 ]]
  printf '%s\0' wsdd --no-host > "$PROC_ROOT/123/cmdline"
  run _process_has_any_arg 123 "$PROC_ROOT" --no-host -o
  [[ "$status" -eq 0 ]]
}

@test "empty and missing process arguments remain unassessed" {
  mkdir "$PROC_ROOT/123"
  run _process_has_any_arg 123 "$PROC_ROOT" --no-host -o
  [[ "$status" -eq 2 ]]
  : > "$PROC_ROOT/123/cmdline"
  run _process_has_any_arg 123 "$PROC_ROOT" --no-host -o
  [[ "$status" -eq 2 ]]
}
