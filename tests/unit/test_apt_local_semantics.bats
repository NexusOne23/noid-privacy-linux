#!/usr/bin/env bats

# Bats invokes setup/test bodies indirectly.
# shellcheck disable=SC2317

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_apt_local_is_retained_kernel_package\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_apt_local_counts\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "non-running Pop kernel image headers and modules are retention candidates" {
  running="7.0.11-76070011-generic"
  _apt_local_is_retained_kernel_package \
    linux-image-6.16.3-76061603-generic "$running"
  _apt_local_is_retained_kernel_package \
    linux-modules-6.16.3-76061603-generic "$running"
  _apt_local_is_retained_kernel_package \
    linux-headers-6.16.3-76061603 "$running"
  _apt_local_is_retained_kernel_package \
    linux-headers-6.16.3-76061603-generic "$running"
}

@test "running kernel packages remain in the provenance-review bucket" {
  running="7.0.11-76070011-generic"
  run _apt_local_is_retained_kernel_package \
    linux-image-7.0.11-76070011-generic "$running"
  [[ "$status" -ne 0 ]]
  run _apt_local_is_retained_kernel_package \
    linux-headers-7.0.11-76070011 "$running"
  [[ "$status" -ne 0 ]]
}

@test "kernel meta packages and driver modules do not receive the exception" {
  running="7.0.11-76070011-generic"
  run _apt_local_is_retained_kernel_package linux-image-generic "$running"
  [[ "$status" -ne 0 ]]
  run _apt_local_is_retained_kernel_package \
    linux-modules-nvidia-580-6.16.3-76061603-generic "$running"
  [[ "$status" -ne 0 ]]
}

@test "ordinary local packages and malformed records fail closed" {
  running="7.0.11-76070011-generic"
  run _apt_local_is_retained_kernel_package noid-local-tool "$running"
  [[ "$status" -ne 0 ]]
  run _apt_local_is_retained_kernel_package \
    linux-image-not-a-version "$running"
  [[ "$status" -ne 0 ]]
  run _apt_local_is_retained_kernel_package \
    linux-image-6.16.3-76061603-generic unexpected-kernel
  [[ "$status" -ne 0 ]]
}

@test "APT local parser separates retained kernels from review packages" {
  raw=$'Listing...\nlinux-headers-6.16.3-76061603/now 1 all [installed,local]\nlinux-image-6.16.3-76061603-generic/now 1 amd64 [installed,local]\nlinux-image-7.0.11-76070011-generic/now 1 amd64 [installed,local]\nexample/now 1 amd64 [installed,local]\nbash/noble 5 amd64 [installed]'
  run _apt_local_counts "7.0.11-76070011-generic" <<< "$raw"
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'2\t2' ]]
}

@test "APT local parser treats an unexpected local record as review evidence" {
  run _apt_local_counts "7.0.11-76070011-generic" \
    <<< 'unexpected local record [installed,local]'
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'1\t0' ]]
}

@test "kernel-only output does not claim that no package is marked local" {
  grep -q 'no other installed packages marked local/unavailable' "$SCRIPT"
  # shellcheck disable=SC2016  # literal production-source condition
  grep -Fq 'if [[ "$APT_LOCAL" -eq 0 && "$APT_RETAINED_KERNEL" -eq 0 ]]; then' \
    "$SCRIPT"
}
