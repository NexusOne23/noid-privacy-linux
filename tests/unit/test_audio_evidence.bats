#!/usr/bin/env bats

# Exercise the production readers; only user transport and response streams
# are replaced. Standard server discovery uses an actual private Unix socket.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _audio_default_source_audit _audio_network_audit; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT" |
      sed "s|/run/user/|$BATS_TEST_TMPDIR/user/|g")
  done
  mkdir -p "$BATS_TEST_TMPDIR/user/1000/pulse"
  python3 - "$BATS_TEST_TMPDIR/user/1000/pulse/native" <<'PY'
import socket, sys
with socket.socket(socket.AF_UNIX) as endpoint:
    endpoint.bind(sys.argv[1])
PY
  AUDIO_OUT='Volume: 0.50 [MUTED]' AUDIO_RC=0
  MODULE_OUT=$'0\tmodule-native-protocol-unix\t\t1' MODULE_RC=0
  SOCKET_OUT='' SOCKET_RC=0
  CALLS="$BATS_TEST_TMPDIR/calls"
}

command() {
  [[ "$1" == -v && "$2" == pactl ]] && return 0
  builtin command "$@"
}
timeout() {
  printf '%s\n' "$*" >> "$CALLS"
  if [[ "$*" == *'list modules short' ]]; then
    printf '%s' "$MODULE_OUT"; return "$MODULE_RC"
  fi
  printf '%s' "$AUDIO_OUT"; return "$AUDIO_RC"
}
ss() { printf '%s' "$SOCKET_OUT"; return "$SOCKET_RC"; }
_passwd_lines() { printf 'fixture:x:1000:1000::/home/fixture:/bin/bash\n'; }
_is_human_uid() { [[ "$1" == 1000 ]]; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }

@test "wpctl mute evidence is limited to the default source" {
  run _audio_default_source_audit fixture 1000 wpctl
  [[ "$status" -eq 0 && "$output" == *'PASS:Default audio source muted'* ]]
  [[ "$output" == *'other inputs and direct device access unassessed'* ]]
}

@test "unmuted wpctl and pactl responses do not establish recording" {
  AUDIO_OUT='Volume: 0.50'
  run _audio_default_source_audit fixture 1000 wpctl
  [[ "$output" == *'unmuted'* && "$output" == *'does not prove recording'* && "$output" != *PASS:* ]]
  AUDIO_OUT='Mute: no'
  run _audio_default_source_audit fixture 1000 pactl
  [[ "$output" == *'unmuted'* && "$output" != *PASS:* ]]
}

@test "pactl accepts only the explicit affirmative mute response" {
  AUDIO_OUT='Mute: yes'
  run _audio_default_source_audit fixture 1000 pactl
  [[ "$output" == *PASS:* ]]
  AUDIO_OUT='Mute: unknown'
  run _audio_default_source_audit fixture 1000 pactl
  [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
}

@test "failed and diagnostic-bearing volume queries cannot establish mute or absent hardware" {
  for AUDIO_RC in 1 2 124; do
    run _audio_default_source_audit fixture 1000 wpctl
    [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
  AUDIO_RC=0
  for AUDIO_OUT in '' 'Translate ID error: no valid default' $'Volume: 0.50 [MUTED]\nserver error' $'note\nVolume: 0.50 [MUTED]'; do
    run _audio_default_source_audit fixture 1000 wpctl
    [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* && "$output" != *'no microphone hardware'* ]]
  done
}

@test "audio reads are bounded and select the existing Unix server explicitly" {
  run _audio_default_source_audit fixture 1000 wpctl
  [[ "$status" -eq 0 ]]
  run _audio_network_audit
  [[ "$status" -eq 0 ]]
  grep -q '^5 sudo -u fixture .*wpctl get-volume @DEFAULT_AUDIO_SOURCE@$' "$CALLS"
  grep -q 'pactl --server=unix:.*pulse/native list modules short$' "$CALLS"
}

@test "successful module and socket inventories retain bounded absence findings" {
  SOCKET_OUT='LISTEN 0 128 127.0.0.1:5900 0.0.0.0:*'
  run _audio_network_audit
  [[ "$output" == *'PASS:No PulseAudio-compatible TCP module in the queried server'* ]]
  [[ "$output" == *'PASS:No TCP listeners attributed to PipeWire/PulseAudio'* && "$output" != *INCOMPLETE* ]]
}

@test "TCP module and listener observations do not infer unauthenticated remote access" {
  MODULE_OUT=$'0\tmodule-native-protocol-tcp\tlisten=127.0.0.1\t1'
  SOCKET_OUT='LISTEN 0 128 127.0.0.1:4713 0.0.0.0:* users:(("pipewire-pulse",pid=12,fd=3))'
  run _audio_network_audit
  [[ "$output" == *'TCP module loaded'* && "$output" == *'TCP listener observed'* ]]
  [[ "$output" != *PASS:* && "$output" != *FAIL:* && "$output" != *WARN:* ]]
}

@test "failed or malformed module inventories cannot produce module absence PASS" {
  MODULE_RC=1
  run _audio_network_audit
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS:No PulseAudio-compatible TCP module'* ]]
  MODULE_RC=0 MODULE_OUT='connection failed'
  run _audio_network_audit
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS:No PulseAudio-compatible TCP module'* ]]
}

@test "failed or malformed listener streams cannot produce listener absence PASS" {
  for SOCKET_RC in 1 124; do
    run _audio_network_audit
    [[ "$output" == *INCOMPLETE* && "$output" != *'PASS:No TCP listeners'* ]]
  done
  SOCKET_RC=0 SOCKET_OUT='netlink failed'
  run _audio_network_audit
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS:No TCP listeners'* ]]
}

@test "unrelated process names and module arguments do not supply audio identities" {
  MODULE_OUT=$'0\tmodule-null-sink\tsink_name=module-native-protocol-tcp\t1'
  SOCKET_OUT='LISTEN 0 128 127.0.0.1:4713 0.0.0.0:* users:(("pipewire-fake",pid=12,fd=3))'
  run _audio_network_audit
  [[ "$output" == *'PASS:No PulseAudio-compatible TCP module'* && "$output" == *'PASS:No TCP listeners'* ]]
}
