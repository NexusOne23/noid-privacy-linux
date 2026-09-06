#!/usr/bin/env bats

# Bats invokes these fixture functions indirectly.
# shellcheck disable=SC2317
# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  local helper
  for helper in require_cmd _fw_get_policies \
    _firewalld_target_is_default_deny _firewalld_word_list_contains \
    _firewalld_view_field _firewalld_prepare_listener_cache \
    _firewalld_runtime_zone_target _firewall_port_specs_match \
    _firewalld_service_allows_port _firewalld_zone_port_state \
    _firewalld_listener_ingress_state _listener_ingress_state; do
    # shellcheck disable=SC1090
    source <(awk -v name="$helper" '$0 == name "() {" {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  # Load production snapshot defaults; arrays must survive this setup call.
  # shellcheck disable=SC1090
  source <(sed -n '/^_FIREWALLD_LISTENER_CACHE_READY=false$/,/^_firewalld_prepare_listener_cache()/p' "$SCRIPT" \
    | sed '$d;s/^declare -A /declare -gA /')
  declare -gA _LISTENER_FW_STATE_CACHE=()
  declare -gA _CAPS=([firewalld_policies]=--get-policies)
  # Used by the production helpers loaded above.
  # shellcheck disable=SC2034
  PRIMARY_IFACE=eth-fixture
  FW_FAILURE=""
  FW_PARTIAL=false
  FW_NO_ZONE=false
  FW_PORTS=""
  FW_CALLS="$BATS_TEST_TMPDIR/firewall.calls"
}

systemctl() { return 0; }

firewall-cmd() {
  printf '%s\n' "$*" >> "$FW_CALLS"
  if [[ "$*" == "$FW_FAILURE" ]] && ! $FW_PARTIAL; then
    return 36
  fi
  case "$*" in
    --get-zone-of-interface=eth-fixture)
      if $FW_NO_ZONE; then printf '%s\n' 'no zone' >&2; return 2; fi
      printf '%s\n' public ;;
    --get-default-zone|--get-zones) printf '%s\n' public ;;
    '--zone=public --list-all')
      printf 'public\n  target: DROP\n  sources:\n  ports: %s\n  services:\n  rich rules:\n' "$FW_PORTS" ;;
    --get-policies|'--direct --get-all-rules') ;;
    *) return 2 ;;
  esac
  [[ "$*" != "$FW_FAILURE" ]] || return 36
  return 0
}

reset_snapshot() {
  _FIREWALLD_LISTENER_CACHE_READY=false
  _LISTENER_FW_STATE_CACHE=()
}

query_ingress() {
  # The auditor does not use errexit. Preserve that behavior under Bats so a
  # negative regression checks the verdict, not Bats aborting on a mock error.
  _listener_ingress_state "$@" || return 1
}

@test "complete runtime snapshot distinguishes open and blocked listeners" {
  FW_PORTS=22/tcp
  query_ingress tcp 22
  [[ "$LISTENER_INGRESS_STATE" == allowed ]]
  query_ingress tcp 8443
  [[ "$LISTENER_INGRESS_STATE" == blocked ]]
}

@test "failed global firewall queries cannot establish blocked ingress" {
  for FW_FAILURE in --get-zone-of-interface=eth-fixture --get-default-zone \
    --get-zones --get-policies '--direct --get-all-rules'; do
    reset_snapshot
    query_ingress tcp 8443
    [[ "$LISTENER_INGRESS_STATE" == unknown ]]
  done
}

@test "partial stdout from failed firewall queries is not positive evidence" {
  FW_PARTIAL=true
  FW_PORTS=22/tcp
  for FW_FAILURE in --get-zone-of-interface=eth-fixture --get-default-zone \
    --get-zones --get-policies '--direct --get-all-rules'; do
    reset_snapshot
    query_ingress tcp 22
    [[ "$LISTENER_INGRESS_STATE" == unknown ]]
  done
}

@test "native no-zone exit 2 retains default-zone classification" {
  FW_NO_ZONE=true
  FW_PORTS=22/tcp
  query_ingress tcp 22
  [[ "$LISTENER_INGRESS_STATE" == allowed ]]
  query_ingress tcp 8443
  [[ "$LISTENER_INGRESS_STATE" == blocked ]]
}

@test "failed cache stays unassessed on repeated and direct helper calls" {
  FW_FAILURE='--direct --get-all-rules'
  query_ingress tcp 8443
  [[ "$LISTENER_INGRESS_STATE" == unknown ]]
  calls_before=$(wc -l < "$FW_CALLS")
  FW_FAILURE=""
  query_ingress udp 8443
  [[ "$LISTENER_INGRESS_STATE" == unknown ]]
  [[ "$(_firewalld_listener_ingress_state 22 tcp)" == unknown ]]
  [[ "$(wc -l < "$FW_CALLS")" == "$calls_before" ]]
}

@test "successful snapshot is reused across protocol and port queries" {
  FW_PORTS=22/tcp
  query_ingress tcp 22
  [[ "$LISTENER_INGRESS_STATE" == allowed ]]
  calls_before=$(wc -l < "$FW_CALLS")
  query_ingress tcp 8443
  [[ "$LISTENER_INGRESS_STATE" == blocked ]]
  query_ingress udp 22
  [[ "$LISTENER_INGRESS_STATE" == blocked ]]
  [[ "$(wc -l < "$FW_CALLS")" == "$calls_before" ]]
}

@test "unavailable policy capability cannot prove absence of host policies" {
  _CAPS[firewalld_policies]=""
  query_ingress tcp 8443
  [[ "$LISTENER_INGRESS_STATE" == unknown ]]
}

@test "failed zone view remains unknown even with plausible partial output" {
  FW_FAILURE='--zone=public --list-all'
  FW_PARTIAL=true
  query_ingress tcp 8443
  [[ "$LISTENER_INGRESS_STATE" == unknown ]]
}
