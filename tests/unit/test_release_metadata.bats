#!/usr/bin/env bats

setup() {
  REPO_ROOT="${BATS_TEST_DIRNAME}/../.."
  SCRIPT="${REPO_ROOT}/noid-privacy-linux.sh"
  README="${REPO_ROOT}/README.md"
  SUPPORT="${REPO_ROOT}/Docs/SUPPORT.md"
  [[ -f "$SCRIPT" && -f "$README" && -f "$SUPPORT" ]] \
    || skip "release metadata sources not found"
}

@test "source checkout hash and size match the current script while tag downloads retain their published hash" {
  local actual_hash actual_bytes documented_hashes
  actual_hash=$(sha256sum "$SCRIPT" | awk '{print $1}')
  actual_bytes=$(wc -c < "$SCRIPT")

  grep -Fq "\`${actual_hash}\` and is" "$SUPPORT"
  grep -Fq "${actual_bytes} bytes. Verify what you are running:" "$SUPPORT"

  documented_hashes=$(
    sed -n '/^## ⚡ Quick Start/,/^## 🀄/p' "$README" \
      | grep -B1 -F "'noid-privacy-linux.sh' | sha256sum" \
      | grep -oE '[0-9a-f]{64}' \
      | sort -u
  )
  [[ "$documented_hashes" == "$actual_hash" ]]

  local published_hash download_hashes
  # shellcheck disable=SC2016  # Markdown backticks are literal delimiters.
  published_hash=$(sed -n 's/^Published script SHA-256: `\([0-9a-f]\{64\}\)`\.$/\1/p' "$SUPPORT")
  [[ "$published_hash" =~ ^[0-9a-f]{64}$ ]]
  download_hashes=$(
    sed -n '/^## 📥 Installation/,/^## 🚀 GitHub Action/p' "$README" \
      | grep -B1 -F "'noid-privacy-linux.sh' | sha256sum" \
      | grep -oE '[0-9a-f]{64}' | sort -u
  )
  [[ "$download_hashes" == "$published_hash" ]]
}

@test "documented BATS count matches the unit suite" {
  local test_count
  test_count=$(grep -Rh '^@test ' "${REPO_ROOT}/tests/unit" | wc -l)
  grep -Fq "and ${test_count} BATS checks pass on these exact bytes." "$SUPPORT"
}

@test "download trust wording matches tag-relative or commit-pinned URLs" {
  local version tag_url commit_url
  version=$(sed -n 's/^NOID_PRIVACY_VERSION="\([^"]*\)"/\1/p' "$SCRIPT")
  tag_url="https://raw.githubusercontent.com/NexusOne23/noid-privacy-linux/v${version}/noid-privacy-linux.sh"
  commit_url='https://raw.githubusercontent.com/NexusOne23/noid-privacy-linux/[0-9a-f]{40}/noid-privacy-linux.sh'

  if grep -Fq "$tag_url" "$README"; then
    grep -Fq 'The release tag resolves to the reviewed release commit, whose full immutable' "$README"
    run grep -F 'The full commit ID prevents the documented command' "$README"
    [[ "$status" -ne 0 ]]
  elif grep -Eq "$commit_url" "$README"; then
    grep -Fq 'The full commit ID prevents the documented command from silently following a' "$README"
    run grep -F 'The release tag resolves to the reviewed release commit' "$README"
    [[ "$status" -ne 0 ]]
  else
    false
  fi
}
