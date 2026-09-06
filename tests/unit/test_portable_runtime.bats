#!/usr/bin/env bats

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_portable_uptime\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_login_defs_value\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_portable_hostname\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_logind_desktop_env\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_logind_local_graphical_user\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "portable uptime prefers supported pretty output" {
  # Called indirectly through _portable_uptime.
  # shellcheck disable=SC2317
  uptime() {
    [[ "${1:-}" == "-p" ]] || return 1
    printf '%s\n' 'up 2 hours, 4 minutes'
  }

  run _portable_uptime
  [[ "$status" -eq 0 ]]
  [[ "$output" == "up 2 hours, 4 minutes" ]]
}

@test "portable uptime falls back to proc uptime without diagnostics" {
  # Called indirectly through _portable_uptime.
  # shellcheck disable=SC2317
  uptime() { return 1; }
  printf '%s\n' '93784.50 90000.00' > "$BATS_TEST_TMPDIR/uptime"
  _NOID_PROC_UPTIME_PATH="$BATS_TEST_TMPDIR/uptime"

  run _portable_uptime
  [[ "$status" -eq 0 ]]
  [[ "$output" == "up 1d 2h 3m" ]]
}

@test "portable uptime reports unavailable for malformed fallback data" {
  # Called indirectly through _portable_uptime.
  # shellcheck disable=SC2317
  uptime() { return 1; }
  printf '%s\n' 'not-a-duration' > "$BATS_TEST_TMPDIR/uptime"
  _NOID_PROC_UPTIME_PATH="$BATS_TEST_TMPDIR/uptime"

  run _portable_uptime
  [[ "$status" -eq 0 ]]
  [[ "$output" == "N/A" ]]
}

@test "login defs parser tolerates missing files and uses the final directive" {
  run _login_defs_value PASS_MAX_DAYS "$BATS_TEST_TMPDIR/missing"
  [[ "$status" -ne 0 ]]
  [[ -z "$output" ]]

  printf '%s\n' \
    '# PASS_MAX_DAYS 7' \
    'PASS_MAX_DAYS 90' \
    'PASS_WARN_AGE 14' \
    'PASS_MAX_DAYS 60 # local override' \
    > "$BATS_TEST_TMPDIR/login.defs"
  run _login_defs_value PASS_MAX_DAYS "$BATS_TEST_TMPDIR/login.defs"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "60" ]]
}

@test "portable hostname prefers an available utility" {
  # Called indirectly through _portable_hostname.
  # shellcheck disable=SC2317
  hostname() { printf '%s\n' 'utility-host'; }

  run _portable_hostname
  [[ "$status" -eq 0 ]]
  [[ "$output" == "utility-host" ]]
}

@test "portable hostname falls back to the kernel interface" {
  # Called indirectly through _portable_hostname.
  # shellcheck disable=SC2317
  hostname() { return 127; }
  printf '%s\n' 'kernel-host' > "$BATS_TEST_TMPDIR/hostname"
  _NOID_HOSTNAME_PATH="$BATS_TEST_TMPDIR/hostname"

  run _portable_hostname
  [[ "$status" -eq 0 ]]
  [[ "$output" == "kernel-host" ]]
}

@test "logind desktop detection selects the preferred local graphical user" {
  # Called indirectly through _logind_desktop_env.
  # shellcheck disable=SC2317
  require_cmd() { [[ "$1" == "loginctl" ]]; }
  # Called indirectly through _logind_desktop_env.
  # shellcheck disable=SC2317
  loginctl() {
    if [[ "$1" == "list-sessions" ]]; then
      printf '%s\n' \
        '8 1000 noidtest - - active no -' \
        'c2 1000 noidtest seat0 tty7 active no -' \
        'c3 1001 other seat1 tty8 active no -'
      return
    fi
    case "$2:$4" in
      8:Name) printf '%s\n' noidtest ;;
      8:Remote) printf '%s\n' yes ;;
      8:Class) printf '%s\n' user ;;
      8:Desktop) printf '%s\n' cinnamon ;;
      c2:Name) printf '%s\n' noidtest ;;
      c2:Remote) printf '%s\n' no ;;
      c2:Class) printf '%s\n' user ;;
      c2:Desktop) printf '%s\n' cinnamon ;;
      c3:Name) printf '%s\n' other ;;
      c3:Remote) printf '%s\n' no ;;
      c3:Class) printf '%s\n' user ;;
      c3:Desktop) printf '%s\n' plasma ;;
    esac
  }

  run _logind_desktop_env noidtest
  [[ "$status" -eq 0 ]]
  [[ "$output" == "cinnamon" ]]
}

@test "logind desktop detection rejects remote-only sessions" {
  # Called indirectly through _logind_desktop_env.
  # shellcheck disable=SC2317
  require_cmd() { [[ "$1" == "loginctl" ]]; }
  # Called indirectly through _logind_desktop_env.
  # shellcheck disable=SC2317
  loginctl() {
    if [[ "$1" == "list-sessions" ]]; then
      printf '%s\n' '8 1000 noidtest - - active no -'
      return
    fi
    case "$4" in
      Name) printf '%s\n' noidtest ;;
      Remote) printf '%s\n' yes ;;
      Class) printf '%s\n' user ;;
      Desktop) printf '%s\n' cinnamon ;;
    esac
  }

  run _logind_desktop_env noidtest
  [[ "$status" -ne 0 ]]
  [[ -z "$output" ]]
}

@test "logind graphical-user fallback handles an empty GNOME Desktop property" {
  # Called indirectly through _logind_local_graphical_user.
  # shellcheck disable=SC2317
  require_cmd() { [[ "$1" == "loginctl" ]]; }
  # Called indirectly through _logind_local_graphical_user.
  # shellcheck disable=SC2317
  loginctl() {
    if [[ "$1" == "list-sessions" ]]; then
      printf '%s\n' \
        '2 0 root - ttyS0 active no -' \
        '3 1001 remote - - active no -' \
        '4 1000 noidtest seat0 tty2 active no -'
      return
    fi
    case "$2:$4" in
      2:Name) printf '%s\n' root ;;
      2:Remote) printf '%s\n' no ;;
      2:Class) printf '%s\n' user ;;
      2:Type) printf '%s\n' tty ;;
      2:State) printf '%s\n' active ;;
      3:Name) printf '%s\n' remote ;;
      3:Remote) printf '%s\n' yes ;;
      3:Class) printf '%s\n' user ;;
      3:Type) printf '%s\n' wayland ;;
      3:State) printf '%s\n' active ;;
      4:Name) printf '%s\n' noidtest ;;
      4:Remote) printf '%s\n' no ;;
      4:Class) printf '%s\n' user ;;
      4:Type) printf '%s\n' wayland ;;
      4:State) printf '%s\n' active ;;
    esac
  }

  run _logind_local_graphical_user
  [[ "$status" -eq 0 ]]
  [[ "$output" == "noidtest" ]]
  run _logind_local_graphical_user remote
  [[ "$status" -ne 0 ]]
  [[ -z "$output" ]]
}

@test "direct-root desktop detection uses only a confirmed local graphical owner" {
  # Literal production-source patterns.
  # shellcheck disable=SC2016
  detection=$(sed -n '/# --- Detect Desktop Environment/,/DESKTOP_ENV="${DESKTOP_ENV:-unknown}"/p' "$SCRIPT")
  # shellcheck disable=SC2016
  [[ "$detection" == *'_logind_local_graphical_user "$_detect_user"'* ]]
  # shellcheck disable=SC2016
  [[ "$detection" == *'"$_detect_user" == "$_detect_local_user"'* ]]
}
