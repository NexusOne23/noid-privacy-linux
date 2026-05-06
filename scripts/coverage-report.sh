#!/usr/bin/env bash
#
# Coverage-Report Generator (v3.6.2)
#
# Parses Docs/CIS_RHEL9_MAPPING.md and generates a summary of how many
# CIS L1 / L2 / STIG controls NoID maps to. Used by the main script when
# --cis-l1 / --cis-l2 / --stig flags are set, and standalone for users
# inspecting the mapping doc.
#
# Usage:
#   bash scripts/coverage-report.sh                   # full summary
#   bash scripts/coverage-report.sh cis-l1            # L1 only
#   bash scripts/coverage-report.sh cis-l2            # L2 only
#   bash scripts/coverage-report.sh stig              # STIG only
#   bash scripts/coverage-report.sh --doc PATH        # custom mapping doc

set -euo pipefail

DOC="Docs/CIS_RHEL9_MAPPING.md"
MODE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --doc) DOC="$2"; shift 2 ;;
    cis-l1|cis-l2|stig) MODE="$1"; shift ;;
    -h|--help)
      echo "Usage: $0 [cis-l1|cis-l2|stig] [--doc PATH]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ ! -f "$DOC" ]]; then
  echo "ERROR: Mapping doc not found: $DOC" >&2
  exit 1
fi

# Extract mapping rows: lines starting with `| 0` (NoID section number) and
# having 4 pipe-separated columns. Skip "..." separator rows.
_extract_rows() {
  awk '
    /^\| [0-9]/ {
      # Filter to data rows only (4+ columns of real content)
      n = split($0, cols, "|")
      if (n >= 6 && cols[6] !~ /^[[:space:]]*\.\.\.[[:space:]]*$/) {
        print $0
      }
    }
  ' "$DOC"
}

# Count rows where column N (1-indexed across `|` splits, position 4 = CIS L1,
# 5 = CIS L2, 6 = STIG) is non-empty (not "—" or whitespace).
_count_mapped() {
  local _col="$1"
  _extract_rows | awk -F'|' -v col="$_col" '
    {
      val = $col
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
      if (val != "" && val != "—") count++
    }
    END { print count + 0 }
  '
}

L1_COUNT=$(_count_mapped 4)
L2_COUNT=$(_count_mapped 5)
STIG_COUNT=$(_count_mapped 6)
TOTAL_ROWS=$(_extract_rows | wc -l)

print_section() {
  local _name="$1" _count="$2" _benchmark_total="$3"
  local _pct
  if [[ "$_benchmark_total" -gt 0 ]]; then
    _pct=$(( _count * 100 / _benchmark_total ))
  else
    _pct=0
  fi
  printf "%-25s %3d / %3d controls mapped  (%d%%)\n" "$_name" "$_count" "$_benchmark_total" "$_pct"
}

# Approximate benchmark totals (from CIS RHEL 9 v2.0.0 ToC counts):
CIS_L1_TOTAL=232
CIS_L2_TOTAL=64
STIG_TOTAL=250

case "$MODE" in
  cis-l1)
    print_section "CIS RHEL 9 Level 1:" "$L1_COUNT" "$CIS_L1_TOTAL"
    ;;
  cis-l2)
    print_section "CIS RHEL 9 Level 2:" "$L2_COUNT" "$CIS_L2_TOTAL"
    ;;
  stig)
    print_section "DISA STIG RHEL 9:" "$STIG_COUNT" "$STIG_TOTAL"
    ;;
  "")
    echo "NoID Privacy for Linux — Compliance coverage (from $DOC)"
    echo ""
    print_section "CIS RHEL 9 Level 1:" "$L1_COUNT" "$CIS_L1_TOTAL"
    print_section "CIS RHEL 9 Level 2:" "$L2_COUNT" "$CIS_L2_TOTAL"
    print_section "DISA STIG RHEL 9:" "$STIG_COUNT" "$STIG_TOTAL"
    echo ""
    echo "Total NoID checks mapped: $TOTAL_ROWS"
    echo ""
    echo "Note: NoID is a hardening posture audit, not a compliance scanner."
    echo "Mapping is for cross-reference. Official audits should use cis-cat-pro."
    ;;
esac
