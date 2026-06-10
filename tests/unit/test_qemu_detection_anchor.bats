#!/usr/bin/env bats
#
# F-388 (v3.7.0) — standalone-qemu detection anchor.
# Section 18 counts non-libvirt qemu via `pgrep -f <pattern>`. libvirt AND
# livemedia-creator (the F-287 use-case) launch qemu by ABSOLUTE path
# (`/usr/bin/qemu-system-x86_64 …`), so a start-of-cmdline anchor `^qemu-system-`
# never matches on a standard system → the check silently counted 0 always.
# The pattern must anchor to a path-component boundary `(^|/)qemu-system-`:
# matches `/usr/bin/qemu-system-…` and bare `qemu-system-…`, but NOT a shell
# that merely mentions the string (no leading `/` or start-of-line before it).
#
# Counter-increment style note: var=$((var+1)), never ((var++)) — bash
# post-increment returns rc=1 when the var was 0 (bombs under set -e / BATS).

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # Extract the actual pgrep pattern the script uses for qemu detection.
  QEMU_RE=$(grep -oE "pgrep -c -f '[^']*qemu-system-[^']*'" "$SCRIPT" | head -1 \
            | sed -E "s/.*-f '([^']*)'.*/\1/")
}

@test "F-388: qemu-detection pattern is extractable + non-empty" {
  [[ -n "$QEMU_RE" ]]
}

@test "F-388: pattern matches libvirt/livemedia ABSOLUTE-path qemu" {
  echo "/usr/bin/qemu-system-x86_64 -name guest=vm1 -machine q35" | grep -qE "$QEMU_RE"
}

@test "F-388: pattern matches a bare (relative) qemu invocation" {
  echo "qemu-system-aarch64 -M virt -cpu host" | grep -qE "$QEMU_RE"
}

@test "F-388: pattern does NOT match a shell merely mentioning qemu-system-" {
  ! echo "/bin/bash -c echo qemu-system-x86_64" | grep -qE "$QEMU_RE"
}

@test "F-388: source no longer uses the bare '^qemu-system-' anchor (regression)" {
  ! grep -qF "pgrep -c -f '^qemu-system-'" "$SCRIPT"
}
