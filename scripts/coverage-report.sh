#!/usr/bin/env bash
# Static, direct-control coverage report for the reviewed RHEL 9 mapping.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
DOC="$REPO_ROOT/Docs/CIS_RHEL9_MAPPING.md"
MODE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --doc)
      [[ $# -ge 2 && -n "$2" ]] || {
        echo "ERROR: --doc requires a path" >&2
        exit 1
      }
      DOC="$2"
      shift 2
      ;;
    cis-l1|cis-l2|stig) MODE="$1"; shift ;;
    -h|--help)
      echo "Usage: $0 [cis-l1|cis-l2|stig] [--doc PATH]"
      exit 0
      ;;
    *) printf 'Unknown arg: %q\n' "$1" >&2; exit 1 ;;
  esac
done

[[ -f "$DOC" ]] || {
  echo "ERROR: Mapping doc not found: $DOC" >&2
  exit 1
}

# Markdown split positions: 2=section, 3=evidence, 4=profile, 5=CIS,
# 6=STIG, 7=quality. Only numbered section rows are data.
_mapping_rows() {
  awk -F'|' '
    /^\|[[:space:]]*[0-9][0-9][^|]*\|/ {
      for (i=2; i<=7; i++) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $i)
      }
      print $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 "\t" $7
    }
  ' "$DOC"
}

_validate_mapping() {
  local invalid
  invalid=$(_mapping_rows | awk -F'\t' '
    $1 !~ /^(0[1-9]|[1-3][0-9]|4[0-2])([[:space:]]|$)/ { print; next }
    $3 !~ /^(L1|L2|—)$/ || $6 !~ /^(Direct|Partial)$/ { print; next }
    $4 != "—" && $4 !~ /^[0-9]+([.][0-9]+)+$/ { print; next }
    ($3 == "—") != ($4 == "—") { print; next }
    $5 != "—" {
      value=$5
      # Debian 12 ships mawk 1.3.4 (20200120), which does not recognize the
      # six-digit ERE interval form. Spell out all six digit positions so
      # validation remains identical across the supported awk implementations.
      gsub(/RHEL-09-[0-9][0-9][0-9][0-9][0-9][0-9]/, "", value)
      gsub(/[,[:space:]]/, "", value)
      if (value != "") print
    }
    $6 == "Direct" && $4 == "—" && $5 == "—" { print; next }
  ')
  [[ -z "$invalid" ]] || {
    echo "ERROR: invalid mapping row:" >&2
    printf '%s\n' "$invalid" >&2
    return 1
  }

  local duplicates
  duplicates=$(_mapping_rows | awk -F'\t' '$6 == "Direct" && $4 != "—" {print $4}' \
    | sort | uniq -d)
  [[ -z "$duplicates" ]] || {
    printf 'ERROR: duplicate Direct CIS IDs: %s\n' "$duplicates" >&2
    return 1
  }

  duplicates=$(_mapping_rows | awk -F'\t' '
    $6 == "Direct" && $5 != "—" {
      count=split($5, ids, /[ ,]+/)
      for (i=1; i<=count; i++)
        if (ids[i] ~ /^RHEL-09-[0-9][0-9][0-9][0-9][0-9][0-9]$/) print ids[i]
    }
  ' | sort | uniq -d)
  [[ -z "$duplicates" ]] || {
    printf 'ERROR: duplicate Direct STIG IDs: %s\n' "$duplicates" >&2
    return 1
  }
}

_cis_ids() {
  local requested="$1"
  _mapping_rows | awk -F'\t' -v requested="$requested" '
    $6 == "Direct" && $4 != "—" &&
      ($3 == "L1" || (requested == "L2" && $3 == "L2")) { print $4 }
  ' | sort -u
}

_stig_ids() {
  _mapping_rows | awk -F'\t' '
    $6 == "Direct" && $5 != "—" {
      count=split($5, ids, /[ ,]+/)
      for (i=1; i<=count; i++)
        if (ids[i] ~ /^RHEL-09-[0-9][0-9][0-9][0-9][0-9][0-9]$/) print ids[i]
    }
  ' | sort -u
}

_count_lines() {
  awk 'NF { count++ } END { print count + 0 }'
}

_validate_mapping

CIS_L1_TOTAL=227
CIS_L2_TOTAL=293
STIG_TOTAL=447
CIS_L1_COUNT=$(_cis_ids L1 | _count_lines)
CIS_L2_COUNT=$(_cis_ids L2 | _count_lines)
STIG_COUNT=$(_stig_ids | _count_lines)

_print_line() {
  local name="$1" count="$2" total="$3"
  printf '%-38s %3d / %3d direct mappings (%d%%)\n' \
    "$name" "$count" "$total" "$((count * 100 / total))"
}

case "$MODE" in
  cis-l1)
    _print_line "CIS RHEL 9 v2.0 L1 Workstation:" "$CIS_L1_COUNT" "$CIS_L1_TOTAL"
    ;;
  cis-l2)
    _print_line "CIS RHEL 9 v2.0 L2 Workstation:" "$CIS_L2_COUNT" "$CIS_L2_TOTAL"
    ;;
  stig)
    _print_line "DISA RHEL 9 STIG V2R6:" "$STIG_COUNT" "$STIG_TOTAL"
    ;;
  "")
    echo "NoID Privacy for Linux — static compliance cross-reference"
    echo
    _print_line "CIS RHEL 9 v2.0 L1 Workstation:" "$CIS_L1_COUNT" "$CIS_L1_TOTAL"
    _print_line "CIS RHEL 9 v2.0 L2 Workstation:" "$CIS_L2_COUNT" "$CIS_L2_TOTAL"
    _print_line "DISA RHEL 9 STIG V2R6:" "$STIG_COUNT" "$STIG_TOTAL"
    echo
    echo "Direct mappings are deduplicated control IDs, not runtime PASS results."
    echo "Partial evidence is excluded. Use CIS-CAT Pro or OpenSCAP for formal audits."
    ;;
esac
