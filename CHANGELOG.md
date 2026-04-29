# Changelog

All notable changes to NoID Privacy for Linux will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.6.0] - 2026-04-30

### 🎯 Posture-Communication, Detection-Depth, Engineering-Discipline & Compliance — Four-Tier Sprint

A four-themed sprint compressed into one release: honest score communication
(v3.6 theme), real detection depth via journalctl/HSI/baseline-diff (v3.7),
engineering rigor through capability layer + BATS tests + 8-pattern lint
(v3.8), and CIS Level 1/Level 2/STIG mapping (v3.9). Plus 13 bugs surfaced
by two passes of line-by-line audit on the released v3.5.0.

#### Added — Posture-Communication (v3.6 tier)

- **Tagline rename**: "Privacy & Security Audit" → "Hardening Posture Audit"
  (banner, README, help, header comment, GitHub Action description). The
  word "Audit" suggested compromise-detection, which the script doesn't do.
  "Hardening Posture" matches what it actually verifies: configuration state.
- **Score-Disclaimer block** (Final Results layout): Defense-Foundation
  framing between Total-checks and Score lines:
  ```
  ║  Hardening posture is your defense foundation — the layer
  ║  attackers must defeat first. Complement with:
  ║    ✓ AIDE / IMA   — file & kernel integrity
  ║    ✓ auditd       — behavioral monitoring
  ║    ✓ chkrootkit   — known-malware scanner
  ```
  Replaces silent "98% FORTRESS" framing that invited "I'm unhackable" misread.
- **Rating wording renames**: `FORTRESS` → `FULLY HARDENED`, `EXCELLENT` →
  `WELL-HARDENED`, `SOLID` → `MOSTLY-HARDENED` for ≥95/≥90/≥80 scores.
  Lower thresholds (NEEDS WORK / CRITICAL) unchanged — they correctly
  describe incomplete hardening.
- **Score label rename**: `SECURITY & PRIVACY SCORE` → `HARDENING POSTURE
  SCORE` matches the new tagline.
- **README "Scope — What this IS / NOT" section**: Defense-in-Depth-Layers
  table making explicit that NoID is Layer 1 (Configuration Hardening),
  with Layers 2/3 (Integrity/Behavioral) listed as complementary — not
  replacements.
- **PASS-Aggregation**: Boot hardening (8 params) + Sysctl basic (~25 keys)
  + Sysctl strict (5 keys) collapse to 3 summary lines in default output
  (e.g. "Boot hardening: 8/8 params set"). `--verbose` flag opt-in for full
  per-item detail. JSON mode always emits per-item findings (consumers
  need detail). Reduces "439 inflated checks" to ~150 unique signals
  visible by default while preserving the score counter.
- **`--verbose` / `-v` flag**: full PASS detail (boot params + sysctl keys
  individually). Explicit short flag for quick toggle.

#### Added — Detection-Depth (v3.7 tier)

- **AIDE actual integrity-check status** (Section 30): reads last
  `aide-check.service` run from `journalctl -u aide-check.service` (last
  7 days), classifies as PASS (0 changes) / WARN (drift detected) / INFO
  (status unclear). Regex covers both Fedora's notify-send wrapper output
  ("Changes Detected"/"new files"/"files modified") and raw AIDE log
  vocabulary ("added"/"removed"/"changed"/"mismatch").
- **`NOID_AIDE_LIVE=1`** env var: opt-in fresh `aide --check` run with
  bitmask exit-code parsing (1=new, 2=removed, 4=changed, ≥14=errors).
  Slow (up to 5min); cleans up tmp log on success, keeps it on drift for
  user review.
- **IMA runtime measurement count**: reads
  `/sys/kernel/security/integrity/ima/runtime_measurements_count` to
  distinguish "IMA active and measuring" (>100 measurements) from
  "IMA active but policy too narrow" (1–100) and "IMA loaded but not
  measuring" (0). Was previously only "IMA: active" without a load signal.
- **HSI (Host Security ID) firmware trust tier** (FIRMWARE & THUNDERBOLT
  block): parses `fwupdmgr security` output for HSI:0–5 level. Tier
  classification: HSI:0 = FAIL, HSI:1 = WARN, HSI:2 = PASS, HSI:3 = PASS,
  HSI:4–5 = PASS. Plus failing-attestation count via `✘`-marker grep.
  Adds concrete hardware-trust signal beyond "fwupd installed?".
- **RPM `-V` baseline diff** (Section 34): on first run with
  `NOID_RPM_BASELINE_INIT=1` captures current modified-file list to
  `/var/lib/noid-privacy/rpm-baseline.txt`. Subsequent runs `comm -13`
  the baseline against current state and alert on **new** modifications
  only. Catches XZ-Backdoor-class drift (modified binary, valid
  signature, new since baseline). `NOID_RPM_BASELINE_UPDATE=1` rewrites
  the baseline.

#### Added — Engineering-Discipline (v3.8 tier)

- **Capability detection layer** (`_detect_capabilities()` + `_CAPS[]`
  associative array): runs once at script startup. Detects firewalld
  policies API (`--get-policies` 0.9+ vs `--list-policies` 0.8-),
  systemd version, nft version, systemd-masked-method (always
  `is-enabled-output` since `is-masked` is not a valid systemctl verb).
  Section code calls `_fw_get_policies()` helper that queries `_CAPS`
  instead of hardcoding the API flag.
- **BATS test-suite** (`tests/`): 5 unit tests + 7 fixtures covering
  the 5 bug-pattern classes from the audit:
  - `test_emit_functions.bats` — verifies `_emit_*` definitions exist,
    no bare `pass()/fail()/warn()/info()` re-introduced
  - `test_chage_locale.bats` — locale-bug-class regression test
  - `test_pass_aggregation.bats` — aggregator helpers (default vs
    verbose vs JSON modes)
  - `test_systemctl_masked.bats` — `is-masked` verb non-existence
  - `test_vpn_regex_consistency.bats` — `$_VPN_IFACE_REGEX` global
    vs hand-written subsets (Bug Pattern #5)
  Plus `tests/README.md` and `tests/fixtures/` with German/English
  chage outputs, systemctl is-enabled outputs, firewall-cmd output.
- **`scripts/lint-api-usage.sh`**: 8-pattern static analysis catching
  re-introduction of any of the 5 + 3 bug-pattern classes. Run as a
  standalone CI job (`api-lint`):
  1. Direct firewalld policy API calls bypassing `_fw_get_policies`
  2. `systemctl is-masked` (verb does not exist)
  3. `grep -r` on `/etc/pam.d` (must be `-R` for symlink-following)
  4. Bare `pass/fail/warn/info()` definitions
  5. `chage -l` without `LC_ALL=C` (locale-bug class)
  6. Hardcoded VPN-iface regex (must use `$_VPN_IFACE_REGEX`)
  7. `df -T … awk NR==2` (wrap-vulnerable on long device names)
  8. `fwupdmgr`/`bluetoothctl` invocation without `LC_ALL=C`
- **CI workflow `bats-tests` job**: runs `bats tests/unit/` on Ubuntu
  with `bats` from package repo.
- **CI workflow `audit-locale` job**: matrix over `en_US.UTF-8`,
  `de_DE.UTF-8`, `fr_FR.UTF-8` running the audit under each locale via
  `locale-gen` + `LC_ALL=$locale sudo -E` invocation. Catches the
  chage-locale-bug class automatically.
- **CI `syntax-compat` matrix expanded**: now covers Fedora 42/43/44,
  Ubuntu 22.04/24.04, Debian 12, **Arch Linux** (was 5 distros, now 7).
- **`# CAP-LINT-EXEMPT` marker**: inline comment to whitelist the
  `_detect_capabilities()` body itself from Pattern 1 (it must use the
  raw API to discover whether the API exists).

#### Added — Compliance (v3.9 tier)

- **`Docs/CIS_RHEL9_MAPPING.md`**: 52-row mapping table from NoID checks
  to CIS RHEL 9 Level 1 / Level 2 / DISA STIG control IDs. Covers
  `~33 L1 / 18 L2 / 29 STIG` controls with explicit out-of-scope notes
  for server-stack benchmarks (databases, mail, webservers — that's
  Lynis territory).
- **`--cis-l1` / `--cis-l2` / `--stig` flags**: when set, append a
  Compliance Coverage block at the end of the audit summarizing how
  many controls of the chosen tier are mapped (parsed from the doc).
  Static doc-based summary for v3.6.0 — runtime per-finding tagging
  is v3.10 backlog.
- **`scripts/coverage-report.sh`**: standalone parser for
  `Docs/CIS_RHEL9_MAPPING.md` that emits coverage statistics. Used by
  the main script when compliance flags are set; also runnable
  manually for cross-reference.

#### Changed — Function-Naming Refactor

- **`pass()/fail()/warn()/info()` → `_emit_pass()/_emit_fail()/_emit_warn()
  /_emit_info()`**: 4 definitions + 838 call sites renamed. Eliminates
  the function-shadow class permanently — `command -v pass` would have
  found the script's `pass()` formatter instead of the `pass` CLI tool
  (password-store), which was the actual bug behind Section 42's
  "Password manager installed: pass" false positive on systems without
  pass installed. Underscore prefix prevents future collisions with
  `info` (texinfo), `warn`, etc. Migration via word-boundary-safe
  `sed -E` against character-class lookbehind to avoid substring
  matches like `flatpak info "$app"`.

#### Changed — `--verbose` flag added to argument parser

- New flag `--verbose` / `-v` complements `--ai`, `--json`, `--skip`,
  `--offline`, `--cis-l1/-l2`, `--stig` in the help text. ENV-vars block
  added documenting `NOID_AIDE_LIVE`, `NOID_RPM_BASELINE_INIT`,
  `NOID_RPM_BASELINE_UPDATE`.

#### Fixed — Bug Pattern #5 reintroductions (5 sites, found by audit re-pass)

- **Line 924-927** (`LAN_GW` awk filter): hardcoded VPN-iface regex
  `^(tun|tap|wg|proton|pvpn|tailscale|zt|nebula|mullvad|nordlynx)`
  replaced with `awk -v vpn_re="$_VPN_IFACE_REGEX"` so new families
  added to the global propagate.
- **Line 1803** (IPv6 leak check): hardcoded subset → `$_VPN_IFACE_REGEX`.
- **Line 2175** (`_VPN_TUNNEL_ADDRS` awk in port-classify): hardcoded
  subset → `awk -v vpn_re=...`.
- **Line 5632** (IPv6 phys-iface scan): hardcoded subset → global.
- **Line 5648** (nmcli active-connection loop): hardcoded subset → global.

#### Fixed — Other audit findings

- **`fwupdmgr security --no-history-check` flag does not exist** for
  the `security` subcommand (only for `get-updates`). Removed; HSI
  detection now works on Fedora 43 (live-test caught this).
- **AIDE journal regex too narrow**: Fedora's `aide-check.service`
  notify-send output uses "Changes Detected"/"new files"/"files
  modified" — the previous "added/removed/changed" regex missed it,
  classifying real drift as INFO instead of WARN. Regex extended to
  cover both notify and raw-log vocabulary.
- **`df -T / | awk 'NR==2{print $2}'` wraps on long device names**:
  3 sites (Section 12 ACL, Section 20 inode, Section 38 /tmp fs)
  switched to `findmnt -no FSTYPE /` (or `df -PT … | tail -1` fallback
  when findmnt absent).
- **HSI `'✘|FAIL'` regex over-counts**: "FAIL" as a substring also
  matches benign body text. Now `grep -c '✘'` only — the cross marker
  is the unambiguous failure indicator.
- **`bluetoothctl show` locale-translation**: BlueZ translates body
  labels on de_DE/fr_FR even though the prefix is stable. `LC_ALL=C`
  prepended defensively for both `show` and `devices Paired` calls.
- **`fwupdmgr get-updates` translates "New version"/"No upgrades"**:
  `LC_ALL=C` prepended (the body is locale-aware even though the HSI:N
  prefix is not).
- **`journalctl --disk-usage` regex `\d+\.?\d*[GMKT]`**: misses comma
  decimals on de_DE/fr_FR (`280,0M`). `LC_ALL=C journalctl` prepended.
- **`chage -l` extracting `\d+$` matched negative-`-1` as `1`**: edge
  case where `chage -M -1` (never expire) was returned as positive.
  Switched to awk extracting the value after `:`, then case-match on
  `never|-1|99999` for unambiguous detection.
- **`should_skip()` loop variable `s` not declared `local`**: silently
  polluted global scope. Added `local … s`.
- **AIDE on-demand check log**: tmp file was never deleted on rc=0
  ("0 changes"). Now `rm -f` on success; preserved on drift for review.

#### Internal — Engineering Discipline

- The 5 bug-pattern classes documented in
  `feedback_noid_audit_bug_patterns.md` are now anti-regression-checked
  by `scripts/lint-api-usage.sh` in CI. New classes (df-wrap, locale-tools,
  hardcoded-VPN-regex) added to lint as Patterns 6–8.
- Live-host test on Fedora 43 (NoID author's workstation) revealed the
  `--no-history-check` and AIDE-regex bugs that static audit missed —
  reinforces the principle that integration tests catch what unit tests
  don't. Both fixes plus 11 other audit findings shipped in this release.

---

## [3.5.0] - 2026-04-27

### 🎯 Phase 8 Audit Closure + Post-Audit Polish — DE Dispatcher, Cross-Distro, ShellCheck-Clean, 15 Final Fixes

Closes the open findings from the v3.4.x line code audit (346 findings
catalogued; 5 HIGH + 30 MEDIUM shipped in v3.4.0/v3.4.1, remainder addressed
in v3.5.0). Plus a final post-audit second-pass review that surfaced 15
additional polish items, all fixed before release (see "Post-Audit Polish"
section below).

#### Added — DE Dispatcher (Sections 26, 36, 38, 39, 42)

- New helpers `_kreadconfig_for_users` (KDE Plasma — kreadconfig6 → kreadconfig5
  → INI parse fallback) and `_xfconf_for_users` (XFCE via xfconf-query).
- Screen lock, lock-delay, idle-delay, lock-on-suspend, notifications-on-lock,
  user-switching, file indexer, clipboard, and keyring-PAM checks now cover
  GNOME, KDE Plasma 5/6, XFCE, MATE, Cinnamon. Previously GNOME-only.
- KDE Baloo file-indexer detection added (Section 36).
- KDE Klipper history-disabled check via klipperrc (Section 38) replaces
  blanket WARN on every Plasma install.
- KDE KWallet PAM auto-unlock detection added (Section 42).

#### Added — Cross-Distro Path Normalization

- GRUB password and config detection now uses `_grub_main_cfg` helper
  probing /boot/grub2/, /boot/grub/, EFI variants. Adds direct grub.cfg
  content scan as authoritative third fallback (catches Anaconda/debconf
  insertions). PERM_CHECKS uses derived path instead of hardcoded.
- Browser detection split by privacy posture: `warn` for Chrome/Edge/Opera/
  Vivaldi (vendor telemetry); `info` for Chromium upstream and Brave
  (privacy-focused fork); flatpak detection for com.brave.Browser and
  com.microsoft.Edge.
- Password manager list extended from 8 to 17 entries (KeeWeb, Buttercup,
  qtpass, NordPass, LessPass, Enpass, rbw, bw-cli + originals).
- Disabled FS module check extended to CIS Level 2 (affs, befs, sysv,
  qnx4, qnx6 added alongside cramfs/freevxfs/jffs2/hfs/hfsplus/squashfs/udf).
- LAN gateway list extended from 3 to 9 hardcoded defaults plus dynamic
  ARP-table neighbors. Picks physical-interface gateway (LAN_GW) separately
  from VPN gateway when VPN is up.
- VPN-interface regex covers tailscale, zt (ZeroTier), nebula, mullvad,
  nordlynx in addition to tun/wg/proton/pvpn.

#### Added — Architecture & Lifecycle

- **Exit codes** (F-007): script returns 0 (clean), 1 (FAIL present),
  2 (WARN-only). Matches Lynis/OpenSCAP/Tripwire convention.
- **Signal handler** (F-008): Ctrl-C / SIGTERM during long checks (rpm -Va
  can take 5+ min) prints partial PASS/FAIL/WARN/INFO counter and exits
  130/143 cleanly instead of dying mid-output.
- **`SECTION_KEYS` array** (F-014): TOTAL_SECTIONS now derived from single
  source of truth instead of hardcoded constant.
- **entrypoint.sh** captures audit exit code, propagates SIGINT/SIGTERM as
  workflow warnings (F-271). rc=2 (WARN-only) deliberately not a job
  failure — strict users use higher fail-threshold input.

#### Changed — MEDIUM Findings Addressed

- F-002 `_human_size`: GiB/MiB/KiB (IEC binary) labels — values use 2^30
  boundaries.
- F-003 `_systemd_conf_val`: sed-based extraction preserves '=' in values.
  Same fix applied to F-128 (dnf5-automatic upgrade_type extraction).
- F-018 Secure Boot: explicit "N/A (legacy BIOS)" on non-UEFI systems.
- F-021 Kernel taint: decodes all 19 flags per kernel docs; classifies
  8 as benign user choice (PROPRIETARY, OOT, CRAP, AUX, RANDSTRUCT,
  LIVEPATCH, UNSIGNED, TEST) and 11 as runtime issues.
- F-026 spec_store_bypass_disable: only WARNs when CPU is actually
  vulnerable (reads `/sys/devices/system/cpu/vulnerabilities/...`).
  Modern Intel Alder Lake+/Zen3+ get INFO instead of false alarm.
- F-054 Kill-switch rule count filtered to drop-rules only (not all
  oifname rules including accept).
- F-062 DNS via systemd-resolved: queries upstream via `resolvectl status`
  to verify it's actually in VPN range, not just stub presence.
- F-105 umask: scans all /etc/ sources individually; reports conflicts
  if multiple files set different values.
- F-109 history coverage: 14 history-file types (shell + DB clients +
  Python REPL + editor histories) with severity tier.
- F-115 permission display: annotates "stricter than recommended" when
  ACTUAL is more restrictive than EXPECTED.
- F-117 banner regex: extends to Arch/openSUSE/Manjaro/Mint/Pop!_OS/Rocky/
  AlmaLinux/EndeavourOS.
- F-133 crontab: reads /var/spool/cron/<user> directly (survives cron.deny).
- F-160 inode check: detects FS type, skips Btrfs/ZFS/F2FS/Bcachefs (dynamic
  allocation), adds 80% WARN tier for fixed-inode FS.
- F-180 chrony NTS: detects chrony version before authdata call (4.0+ only).
- F-186 sudo activity: bucketized (zero/low/moderate/high) instead of
  exact count which leaks behavioral metadata when output is shared.
- F-189 compiler check: distinguishes desktop / CI build host (jenkins/
  gitlab-runner/buildbot/drone-server signatures) / production server.
- F-222 browser password saving: 3-state classification (disabled = pass,
  enabled with primary password = info, enabled without = warn). Avoids
  the "use a password manager" advice when Firefox's own encrypted store
  IS one.
- F-232 Ethernet MAC=stable: promoted from INFO to PASS-with-note (it's a
  deliberate privacy choice — better than no randomization).
- F-259 PipeWire: prefers pw-dump (authoritative running state) over
  config-grep heuristic.

#### Fixed — Code Quality

- ShellCheck **clean at -S style level** for both noid-privacy-linux.sh
  and entrypoint.sh. .shellcheckrc documents project-wide disable for
  SC2059 (color-var format strings — readability) and SC2329 (callback
  dispatch / signal traps — false-positive class).
- 6× `grep | wc -l` → `grep -c` (SC2126).
- 6× `ls` parsing → shell glob with nullglob array (SC2012).
- 1× `for x in $(cat f)` → `while read` (SC2013).
- mapfile -t replaces array-from-cmd-substitution (SC2207).

#### Fixed — Disk Output Regression (post-v3.4.1)

- Section 20 disk-usage parsed `df -h -T` output with the wrong column
  indices ($5/$6 = pre-`-T` layout) producing absurd "Disk 47%: 507G%
  used" output and bash arithmetic errors. Fixed to use $6 (Use%) and
  $NF (mount path) with numeric guard.

#### Architecture — F-013 Refactor (done in v3.5.0, not deferred)

- F-013 inline→function refactor **completed**: All 34 security sections
  (01-34) are now wrapped as `check_*()` functions matching the privacy
  sections (35-42) which were already function-based. Each gates on
  `should_skip "X" && return` and prints its own header. SECTION_KEYS
  array (F-014) is the single source of truth for `--skip` keys and
  TOTAL_SECTIONS count.

#### Internal — Architecture Deferrals

- F-015 (nested function definitions becoming globals) deferred to v4.0 —
  callbacks like `_de_lock_check_cb` defined inside `check_desktop_session`
  leak to global scope per Bash semantics. Refactor to top-level helpers
  is a large surface-area change that warrants a major version bump.

---

### 🔧 Post-Audit Polish (15 second-pass fixes, 2026-04-27)

A line-by-line re-read of the 6358-line script after the main v3.5.0 work
surfaced 15 additional items — all fixed before release:

#### Display Bugs (3)

- **CA_COUNT multi-line trap** (Sec 23): legacy `grep -c | echo "?"` would
  produce two-line `0\n?` output when `trust list` succeeded with no certs.
  Now uses `${var:-0}` default consistent with the rest of the codebase.
- **UFW_RULES regex** (Sec 03): old `^[0-9.]+:` matched IP:PORT format
  which `ufw status verbose` never emits (UFW uses `22/tcp` syntax). Now
  counts ALLOW/DENY/REJECT/LIMIT action keywords — accurate on Ubuntu/Debian.
- **rescue-Kernel as latest** (Sec 01): `sort -V` placed `vmlinuz-rescue-*`
  lexicographically after numeric versions (`r` > `6`), causing false
  "reboot recommended" warns on systems with both rescue and regular
  kernels. Now filters `-rescue` before sorting.

#### Consistency Refactors (4)

- **UID-Hardcoding → `_is_human_uid`** (14 call sites): F-004 introduced
  `_is_human_uid` which reads /etc/login.defs UID_MIN/UID_MAX, but 14
  call sites still used hardcoded `[[ "$uid" -ge 1000 && "$uid" -lt 65534 ]]`.
  All converted; comment block updated to reflect canonical pattern.
- **`_safe_find_home` timeout + Atomic Fedora `/var/home`**: matches
  `_safe_find_root` with `timeout 30` to prevent indefinite hangs on huge
  homes / stuck NFS mounts. Includes `/var/home/*` for Atomic Fedora
  (Silverblue/Kinoite) where `/home → /var/home` symlink may or may not
  be present.
- **`_iter_user_homes` helper** for the 4 `for USER_HOME in /home/* /root`
  loops in Sec 09/12/15/23. Deduplicates `/home/nexus` and `/var/home/nexus`
  via `realpath` so Atomic users aren't iterated twice.
- **`USER` loop variable shadowing**: Section 20 `ps -eo` while-read used
  uppercase `USER`, shadowing the environment variable. Renamed to
  `_user`/`_cron_user`/`_ssh_user` at all 3 affected loops.

#### Help-Text & Docs (2)

- **`--help` section order** matches SECTION_KEYS array (was: `hardening,
  permissions, modules, boot, integrity`; now: `hardening, modules,
  permissions, boot, integrity`).
- **Virtual flags documented**: `netleaks` (sub-check inside Sec 05) and
  `summary` (final results block) are not full sections in SECTION_KEYS
  but are valid `--skip` targets. `--help` now lists them under a dedicated
  "Virtual flags" subheader.

#### Style/Cleanup (3)

- **Redundant `2>/dev/null`** on 2 `[[ ]]` tests removed (Sec 12, Sec 39).
  `[[ ]]` writes nothing to stderr under normal conditions.
- **15 BRE `\|` → ERE `-E`** alternations: GNU grep accepts `\|` BRE
  alternation but it's a non-POSIX extension. Converted to `-E` flag with
  `|` for portability/style consistency. (One intentional mixed pattern
  in `_SH_PATTERN` left untouched — it relies on literal `|` matching for
  `curl | bash` detection alongside ERE alternation between sub-patterns.)
- **`nullglob` for home iteration** auto-resolved by `_iter_user_homes`
  helper using `shopt -s nullglob` internally.

#### Behavior Refinements (3)

- **`systemd-coredump.socket` context-aware** (Sec 30): old check WARNed
  whenever socket was active, even with `Storage=none`. Modern Fedora
  defaults to socket-activated coredump, so this fired on every Fedora
  desktop. Now: `Storage=none` + socket-active = INFO (no persistence,
  socket harmless); `Storage!=none` + socket-active = WARN (real risk).
- **PAM nullok line context** (Sec 11): FAIL message now shows the
  offending line content (truncated to 100 chars) so users can audit
  whether `nullok` is in `pam_unix` (real risk) vs. another module.
- **SUID/SGID thresholds as documented constants**: `_SUID_PASS_MAX=30`,
  `_SUID_WARN_MAX=45`, `_SGID_PASS_MAX=10`, `_SGID_WARN_MAX=20` declared
  at the top of the section with calibration baseline notes (Fedora
  desktop ~22-32 SUID, Ubuntu ~28-38, server-minimal ~12-18). Single
  source of truth; output annotates the threshold (`SUID files: 15 (≤30)`).

---

## [3.4.1] - 2026-04-27

### 🐛 Post-Release Fixup (after v3.4.0 user testing)

Live test on Snapper+Podman+bootc-build system revealed remaining FPs that
v3.4.0 didn't catch:

- **`_safe_find_root` extended**: Excludes `/var/lib/containers/storage/*`
  (Podman default), `/var/lib/docker/*`, `/var/lib/lxd/*`, `/var/lib/lxc/*`,
  `/var/lib/machines/*`, and OSTree object stores (`*/ostree/repo/objects/*`).
  Container/image-build systems had 60+ phantom SUIDs from layer overlays
  containing complete /usr/bin trees with sudo/mount/passwd binaries.
- **`_safe_find_home` extended**: Also excludes `__pycache__/*` and `target/*`
  (Rust builds).
- **Section 20 (Disk Usage)**: Now skips read-only image filesystems by both
  type (iso9660, squashfs, erofs, cramfs, romfs) and mount-flag (`ro,`).
  Previously FAILed on Fedora ISO loopback mounts (always 100% full by design).
- **Section 39 (VNC/RDP detection)**: Distinguishes localhost-only (INFO —
  qemu SPICE/VNC console, normal for VM development) from externally-bound
  (WARN). Previously WARNed on every system running qemu-system with SPICE.
- **Section 42 (Plaintext secrets)**: Severity-tiered by permissions:
  - World-accessible (007 bits): FAIL
  - Group-accessible (070 bits): WARN
  - Private (600/400): INFO with "consider encrypting" hint

  Previously FAILed on private dev `.env` files which is normal workflow.

Verified on auditor's system: SUID count 81 → 15 (matches actual rootfs count).

---

## [3.4.0] - 2026-04-27

### 🔥 Critical Bug Fixes (False-FAIL elimination)

These fixes eliminate false-FAILs on Snapper/Timeshift systems (openSUSE
default, Mint default, many Fedora/Ubuntu setups).

- **Section 12**: SUID/SGID/world-writable/unowned file scans now exclude
  `*/.snapshots/*`, `*/timeshift-*/*`, `*/.btrfs-snapshots/*`, `*/.snapper/*`.
  Previously inflated counts massively on btrfs+snapshot systems (real example:
  81 → 15 SUID files on Snapper-installed Fedora).
- **Section 24**: Private-key detection now uses content magic-string
  verification (PEM headers) instead of filename matching. Eliminates FPs
  from uBlock Origin IDB (`key_*.key`), test fixtures, API config files.
  Permission threshold tightened from 077 to 007 (group-readable is often
  intentional for service accounts like libvirt's `kvm:kvm`).
- **Section 15**: rkhunter (last release 2018-02-24) is now reported as INFO
  with deprecation warning. Signatures haven't been updated for 8 years and
  miss XZ Backdoor, Bootkitty, BPFDoor, Kovid. chkrootkit (last release
  2025-05-12) remains the recommended scanner.

### 🛡️ Honesty in Documentation

- **README**: Distro support claim narrowed from "Tested on 8 distros" to
  "Optimized for Fedora/RHEL · Tested on Ubuntu/Debian · Best-effort on
  Arch/openSUSE/Mint/Pop!_OS"
- **README + SECURITY.md**: "no network requests" claim made honest. Tool
  now clearly documents that `vpn`/`interfaces`/`netleaks` sections issue
  3rd-party requests (Mozilla, Akamai, Cloudflare, Google) by default.
- **SECURITY.md**: Removed theatrical SHA256 verification step (no published
  hashes) and broken "verify read-only" grep command. Recommends human code
  review as the meaningful integrity check.
- **CHECKS.md**: Section descriptions corrected to match actual code (Sec 16
  process check is heuristic, Sec 17 is sysctl-based not deep-analysis,
  Sec 24 scans key files not env vars).

### ✨ New Helpers + Flags

- `_safe_find_root` / `_safe_find_home` — Snapshot-aware find wrappers
- `_is_real_private_key` — Content-based crypto-key detection
- `has_firewall_block_on_phys` — Generalized firewall-block (nft + iptables + ufw)
- `_grub_main_cfg` / `_grub_password_paths` — Cross-distro GRUB paths
- `_service_active_any` / `_service_masked_any` / `_service_enabled_any` —
  Cross-distro service-name normalization (httpd|apache2, smb|smbd)
- `--offline` flag: shorthand for `--skip vpn --skip interfaces --skip netleaks`

### 🐛 Bug Fixes (28 medium findings)

- **Sec 1 (Kernel)**: Secure Boot check now correctly classifies legacy BIOS
  as N/A (was reporting DISABLED). Adds efivars-based fallback when mokutil
  missing.
- **Sec 3 (Firewall)**: Default-zone false-positive fixed when no interfaces
  assigned but services declared
- **Sec 5 (VPN)**: Connectivity check ICMP-first (no Mozilla tracking);
  Cloudflare's `cp.cloudflare.com/generate_204` as HTTP fallback
- **Sec 5 (VPN)**: Promiscuous-mode check excludes virtualization bridges
  (virbr/docker/br-/veth/lxcbr/cni-/podman/tap)
- **Sec 7 (Services)**: cups/avahi-daemon/bluetooth severity now context-aware
  (INFO on desktop with explanation, WARN on server). Service names
  generalized for cross-distro: httpd|apache2, smb|smbd, nmb|nmbd
- **Sec 8 (Ports)**: Externally-bound port firewall-block check generalized
  to cover iptables-only systems and ufw (not just nftables)
- **Sec 11 (Users)**: NOPASSWD detection regex correctly skips tab-indented
  comments
- **Sec 14 (Updates)**: dnf5-automatic upgrade_type parser uses parameter
  expansion (no more `cut -d= -f2` truncation)
- **Sec 15 (Rootkit)**: chkrootkit now `timeout 120s`-wrapped; FP filter
  surfaces filtered findings as INFO (transparency)
- **Sec 16 (Process)**: Suspicious-process name-pattern check annotates PASS
  ("real malware renames — see AIDE/IMA") to prevent false reassurance
- **Sec 18 (Containers)**: Docker daemon distinguishes rootless (INFO) from
  rootful (WARN)
- **Sec 19 (Logs)**: dmesg error count limited to last 1 hour. Empty-log
  check only runs when rsyslog/syslog-ng active.
- **Sec 20 (Performance)**: RAM threshold uses `available` instead of `used`.
  I/O-wait read directly from `/proc/stat` (instant, no 2-second blocking).
- **Sec 21 (Hardware)**: lm_sensors detection distinguishes "not installed"
  from "installed but unconfigured"
- **Sec 22 (Interfaces)**: DNS resolution test queries root nameservers
  (`. NS`) instead of `google.com`
- **Sec 23 (Certs)**: CA-cert count cross-distro (trust / ca-certificates.crt
  / /etc/ssl/certs/)
- **Sec 29 (Logins)**: Failed-login display redacts source IPs
- **Sec 30 (Hardening)**: Home-directory permissions tier-aware. Suspicious
  history shows first 3 examples instead of just count.
- **Sec 31 (Modules)**: Suspicious-module name-pattern check annotates PASS
  to prevent false reassurance
- **Sec 33 (Boot)**: Module signing detection now covers compile-time, runtime
  sig_enforce, and kernel cmdline enforcement
- **Sec 34 (Integrity)**: `rpm -Va` wrapped in `timeout 90s`. PATH security
  detects `.`, empty entries, and relative entries (privesc vectors).
- **Sec 35 (Browser)**: LibreWolf, Tor Browser, Waterfox profile detection
- **Sec 37 (NetPriv)**: Hostname-real-name detection raised to 5-char minimum
  + word-boundary match (eliminates "fox" matching "firefox-test")
- **Sec 38 (DataPriv)**: Bash-history scan replaced size-threshold with
  sensitive-content pattern scan; covers .zsh/.fish/.python/.psql/.mysql
  histories. Klipper detection KDE-aware (INFO on Plasma).
- **Sec 42 (Keyring)**: Plaintext-secret-files check now searches
  subdirectories (most `.env` files live in dev project subdirs)

### 🏗️ Architecture

- **`--ai` and `--json` no longer mutually exclusive**: JSON output now
  includes `ai_prompt` field when both flags set. Eliminates the
  entrypoint.sh double-run problem in CI/CD.
- **entrypoint.sh refactored**: Single audit run instead of double,
  `badge_color` and `badge_url` outputs added (Shields.io integration),
  grouped redirects (SC2129 clean), variable name clarity
- **AI prompt hardened**: Now includes "Verify each command against current
  system state before suggesting. If you cannot verify a fact, say so." to
  reduce LLM hallucination risk

### 🚀 CI Improvements

- CI now triggers on develop/release branches and version tags (was main-only)
- Distro-test matrix renamed to "Bash Syntax Compat" (honest scope — was
  pretending to be cross-distro logic test)
- New "Audit Smoke Test" job actually runs the audit on Ubuntu in offline
  mode and validates JSON parses cleanly
- ShellCheck job split into blocking warnings and non-blocking style/info
- Example workflow pinned to `@v3.4.0` instead of `@main` (supply-chain
  best practice — example documentation should model good security)

### 🎨 Style/Cosmetic

- 7 ShellCheck issues fixed (SC2086 unquoted vars, SC2126 grep|wc-l → grep -c,
  SC2004 ${} in arithmetic, SC2129 multiple redirects)
- entrypoint.sh: `xargs` replaced with `${var// /}` parameter expansion (no fork)

---

## [3.3.0] - 2026-04-09

### ✨ New Checks (32 additions from Lynis comparison)

**Kernel & Boot (Section 01)**
- Running latest installed kernel vs. installed kernel packages

**Firewall (Section 03)**
- Firewall logging status (firewalld/ufw/iptables — denied packet logging)

**VPN & Network (Section 05)**
- DNSSEC validation status via systemd-resolved

**Users & Authentication (Section 11)**
- Password hashing method detection (YESCRYPT > SHA512 > SHA256 > MD5)
- Password hashing rounds/cost factor from login.defs
- PAM password quality enforcement (pam_pwquality/pam_cracklib)
- Password expiry check for all human accounts
- Duplicate UID detection
- Duplicate GID detection

**Filesystem Security (Section 12)**
- Swappiness level (vm.swappiness)
- ACL support verification on root filesystem

**Encryption & Crypto (Section 13)**
- Hardware RNG detection (/dev/hwrng, hw_random, RDRAND/RDSEED)

**Process Security (Section 16)**
- Zombie/dead process count

**Network Security (Section 17)**
- TCP TIME_WAIT connection monitoring
- ARP monitoring software detection (arpwatch/arpon/addrwatch)

**Logs & Monitoring (Section 19)**
- Deleted log files still held open by processes

**Systemd Security (Section 25)**
- Expanded to 13 services across 3 tiers: security (sshd, firewalld, auditd, usbguard, chronyd), hardware (gdm, thermald), user-facing (NetworkManager, colord, fwupd, etc.)

**Advanced Hardening (Section 30)**
- IMA (Integrity Measurement Architecture) status, policy, and violation count
- EVM (Extended Verification Module) status
- binfmt_misc non-native binary format registration check
- FireWire/IEEE 1394 DMA attack surface (module blacklist check)
- Home directory permissions and ownership for all human users
- Shell idle timeout (TMOUT) across profile configs
- AIDE database existence and size
- Shell history analysis for suspicious commands (curl|bash, /dev/tcp, nc -e)

**System Integrity (Section 34)**
- /etc/hosts duplicate entry detection
- /etc/hosts localhost entry verification
- AIDE checksum algorithm strength
- Valid shells in /etc/shells count

### 🐛 Bug Fixes

- **Bluetooth "not available" logic**: `&&` changed to `||` — now correctly detects BT absence when either bluetoothctl OR bluetooth.service is missing (was requiring BOTH)
- **Double sysrq reporting**: Magic SysRq standalone check downgraded from `warn` to `info` (the sysctl loop already issues `fail` for non-zero values)
- **squashfs false message**: "loaded (required by Flatpak)" now only shows when the module is actually loaded; otherwise shows "not disabled but not loaded"
- **gsettings integer guard**: Screen lock delay and idle timeout callbacks now validate numeric input before integer comparison (prevents bash errors on malformed gsettings output)
- **FINAL RESULTS box**: Added missing right `║` border on title line
- **Score formula comment**: Fixed example result from 90% to correct 91%
- **printf format-string safety**: Kernel, uptime, and duration values in summary now use `%s` format specifier instead of embedded variables (prevents `%` characters from corrupting output)
- **Home directory stat fallback**: Empty `stat` result now skips the check instead of falling back to `777` (which caused spurious warnings)
- **TCP Wrappers false positive**: Downgraded "no deny rules" from `warn` to `info` (TCP wrappers are deprecated on modern systemd-based systems)
- **CPU vulnerability "Unknown"**: Changed from `pass` to `warn` for unrecognized vulnerability status (only "Not affected" and "Mitigation" now get `pass`)
- **auditctl "No rules" counted as 1**: Now filters the "No rules" message before counting
- **Double Bluetooth warning**: "active with no paired devices" now only fires when `pairable != yes` (avoids duplicate with "pairable but no devices" warning)
- **HISTSIZE regex**: Now also matches `export HISTSIZE=` form (was only matching bare `HISTSIZE=`)
- **Dead RPM_NOSIG code**: Removed redundant first `rpm -qa` query that was immediately overwritten
- **Hostname privacy check**: Now checks both first AND last name from GECOS field against hostname
- **Umask check**: Added `/etc/profile.d/*.sh` to search paths (Fedora sets umask there)
- **Skip keywords count**: Corrected from 43 back to 44 (42 sections + `netleaks` + `summary` sub-skip targets — the v3.2.5 "correction" was itself wrong)

### ✨ Additional Checks (5 — closing final Lynis gaps)

- **Password file consistency** (`pwck -rq`) — detects corrupted /etc/passwd entries (Section 11)
- **Locked user accounts** (`passwd -S`) — reports locked accounts, handles Fedora `LK` and Debian `L` status (Section 11)
- **Sudoers security audit** — permissions check (440), sudoers.d drop-in permissions, NOPASSWD scan, `visudo -c` syntax validation (Section 11)
- **Empty log files** — checks /var/log/messages, syslog, auth.log, secure, kern.log for zero-byte files indicating broken logging (Section 19)
- **NTP source quality** — chronyc sources analysis for unreachable/falseticker peers (Section 27)

### 🔧 Improvements

- **binfmt_misc.mount filtered** from failed services (expected failure on hardened systems)
- **Journal error threshold** raised from 10 to 15 (reduces false warnings on desktop with NVIDIA/SELinux)
- **ps self-reference filtered** from Top 5 CPU/Memory output
- **4× useless `cat`** replaced with `$(< /proc/...)` on procfs/sysfs reads
- **4× redundant `2>&1`** removed after `&>/dev/null`
- **Debian/Ubuntu compatibility**: Added `/etc/bash.bashrc` to umask and TMOUT checks, `gdm3` to systemd-analyze hardware services
- Check count updated: 300+ → 390+

---

## [3.2.5] - 2026-04-09

### 🔴 High Fixes

- **IPv6 false positive on VPN interfaces**: Global unicast addresses on VPN tunnel interfaces (e.g. `2a07:b944::2:2` on `proton0`) were counted as "IPv6 active — leak risk". These addresses are internal to the WireGuard tunnel and not internet-facing. Script now skips addresses on VPN interfaces (`tun*`, `wg*`, `proton*`, `pvpn*`) when counting global IPv6.

- **Audit watch detection missed `-F path=` syntax**: Script only matched short-form watches (`-w /etc/passwd`) but not the equivalent long-form (`-a always,exit -F path=/etc/passwd`). Systems using syscall-based audit rules (standard on modern Fedora/RHEL) showed 5 false "Audit watch missing" warnings. Now matches `-w`, `-F path=`, and `-F dir=` syntax, including sub-path matches.

- **Faillock counted header lines as failed attempts**: `grep -c "^[a-zA-Z]"` matched username headers (`nexus:`) and table headers (`When  Type  Source`) — not actual failures. Systems with zero failed attempts showed "4 account(s) with failed login attempts". Now counts only actual failure entries (lines starting with `YYYY-MM-DD`).

### 🟡 Medium Fixes

- **RPM unsigned: kmod packages indistinguishable from real issues**: Locally-built kernel modules (akmods/dkms) inherently cannot carry RPM GPG signatures — they are compiled on the user's machine. Previously lumped together with genuinely unsigned third-party packages. Now reported separately: `1 unsigned RPM packages (+ 2 locally-built kmod)`.

- **Journal critical: Intel watchdog false positive**: `watchdog: watchdog0: watchdog did not stop!` is logged at every shutdown on virtually all Intel systems with iTCO watchdog. Not a security or stability event. Added to benign-process filter alongside sudo, systemd-coredump, and auth messages.

- **os-release parsing used `eval`**: `eval "$(grep ... /etc/os-release)"` could theoretically execute injected code from a compromised os-release file. Replaced with explicit `while IFS='=' read` loop with key whitelist. Zero practical risk (root-owned file), but cleaner for a security audit tool.

### 🟢 Low Fixes

- **HTTP connectivity check undocumented**: `curl http://detectportal.firefox.com` uses unencrypted HTTP in a privacy tool. This is intentional (captive portal detection requires HTTP to detect redirects). Added explanatory comment.

- **CI: Fedora 39 (EOL) in test matrix**: Replaced with Fedora 42. Matrix now tests Ubuntu 22.04/24.04, Fedora 42/43, Debian 12.

- **CI: Docs/CHECKS.md not validated**: `validate-structure` job checked 7 required files but missed `Docs/CHECKS.md`. Added to the check list.

- **README: "44 skip keywords" incorrect**: Actual count is 43. Corrected.

- **Footer branding**: Removed co-author credit from scan output footer. Now shows `by NexusOne23` only.

### ✨ Improvements

- **GPL v3 copyright header**: Added full copyright notice with license text to the main script header, as recommended by GPL v3 for source files.

---

## [3.2.4] - 2026-03-30

### 🔴 Critical Fixes

- **RPM signature check was completely broken**: `grep -c "not signed"` never matched — RPM outputs `(none)` for unsigned packages, not "not signed". Every system falsely reported "All RPM packages signed". Fixed to check all three signature headers (RSAHEADER for modern Fedora, SIGPGP/SIGGPG for legacy RHEL). Also excludes `gpg-pubkey` meta-packages from the count.

- **NetworkManager connectivity check ignored conf.d drop-ins**: Only parsed `/etc/NetworkManager/NetworkManager.conf`. Fedora configures connectivity in `/etc/NetworkManager/conf.d/` drop-in files. Systems with connectivity disabled via drop-in (standard Fedora hardening) were falsely flagged as "may phone home". Now iterates all config files.

- **DNS resolution test leaked IP to Cloudflare**: `dig +short google.com @1.1.1.1` bypassed VPN/DoH setup and sent a query directly to Cloudflare in a privacy audit tool. Replaced with system-resolver query (`dig +short google.com`). Connectivity test now uses `curl detectportal.firefox.com` with ICMP fallback.

### 🔴 High Fixes

- **aes-cbc classified as "strong"**: LUKS with aes-cbc-essiv has known watermarking weaknesses. Now correctly warns and recommends migration to aes-xts.

- **SSH PubkeyAuthentication false positive**: When PubkeyAuthentication was not explicitly set (OpenSSH default = yes), script warned "not explicitly yes". Now recognizes the default as correct and shows PASS.

- **Kernel-UDP sockets all labeled "likely WireGuard"**: Any kernel-owned UDP socket (IPVS, conntrack, etc.) was assumed to be WireGuard. Now checks if WireGuard interfaces actually exist before labeling.

- **LLMNR/MulticastDNS: `head -1` instead of `tail -1`**: systemd uses last-value-wins semantics for duplicate keys. Script took the first value, potentially returning the wrong setting. Fixed to `tail -1` in both main config and drop-in parsing.

- **IPv6 manual/link-local falsely treated as "disabled"**: `ipv6.method=manual` with configured addresses means IPv6 IS active. Now checks if addresses are actually configured before classifying as disabled.

- **IPv6 ULA misclassified as "link-local"**: `fdxx::` addresses (Unique Local) were counted as link-local in the summary message. Now correctly distinguished.

- **Kernel Lockdown: empty value = PASS**: If `/sys/kernel/security/lockdown` existed but couldn't be parsed, the empty result fell through to PASS. Now explicitly warns on parse failure.

- **AppArmor ignored when getenforce exists but SELinux=Disabled**: `HAS_SELINUX` was set based on `getenforce` binary existence, not actual SELinux status. On systems with SELinux disabled but AppArmor enforcing, AppArmor was silently skipped. MAC detection now checks actual enforcement status.

### 🟡 Medium Fixes

- **Faillock counted login attempts, reported "accounts"**: `grep -c "When"` counted individual failed attempts, but the message said "X accounts". Fixed to count unique usernames.

- **Core dump check missed systemd-coredump Storage=none**: `ulimit -c` and `core_pattern` were checked, but `systemd-coredump` with `Storage=none` (the Fedora standard) was not recognized. Now checks all three mechanisms. Also fixed relative path bug in `_systemd_conf_val` call.

- **net.ipv4.conf.default.rp_filter never checked**: Was in `SYSCTL_MIN_OK` but missing from `SYSCTL_CHECKS` — dead code. Now included in the check loop.

- **cups-browsed: FAIL even when patched**: CVE-2024-47176 was fixed in cups-filters >= 2.0.1. Downgraded from FAIL to WARN with version note.

- **Flatpak: `filesystems=home` not detected**: Only `host` and `host-os` were flagged. Apps with `home` access (full user data) were silently passed. Now detected.

- **Snap telemetry: wrong config key**: `system.telemetry.enabled` doesn't exist. Changed to `experimental.telemetry`.

- **DHCP hostname: last connection file won in global check**: If one connection had `dhcp-send-hostname=true` and a later one had `false`, only `false` was seen. Now flags any single connection with hostname leaking.

- **Journal error count inflated by continuation lines**: Multi-line log entries (stack traces) were counted as separate errors. Now filters to timestamp-prefixed lines only (consistent with critical-level check).

- **chkrootkit FP filter missing `linux_ldiscs` and `suckit`**: Known false positives on modern kernels not filtered. Added to pattern.

- **Suspicious process regex issues**: `reverse.shell` unescaped dot, `nc -l` didn't match with flags (`-lvnp`), `socat`/`cobalt` too broad. Tightened all patterns.

- **Cron file permissions too strict**: Any group/other bit triggered WARN — standard Fedora `/etc/crontab` (644) was always flagged. Now allows read-only for group/other, warns only on write/execute.

- **Coredump check duplicated in two sections**: Section 12 (Filesystem) and Section 38 (Data Privacy) both produced pass/warn for the same coredump check, inflating the score. Section 38 now shows INFO only with reference to Section 12.

- **AutomaticLogin grep matched AutomaticLoginEnable**: `grep AutomaticLogin` also matched `AutomaticLoginEnable=true`, extracting "true" as the username. Fixed with negative lookahead. Also fixed duplicate check in Section 26.

- **`_for_each_user` processed UID 65534 (nobody)**: Missing upper bound caused unnecessary checks on system accounts. Now filters `uid < 65534` consistently.

- **Firmware findings in wrong JSON section**: `CURRENT_SECTION` was still set to "PASSWORD & KEYRING" when firmware checks ran. Added explicit section assignment.

- **bluetooth.socket not checked**: Only `bluetooth.service` was in the disabled-services list. Bluetooth could start via socket activation. Added `bluetooth.socket`.

- **Fedora countme default text incorrect**: Warned about countme being "enabled per-repo" on unset systems. Since Fedora 36+, the default is disabled. Changed to INFO with correct text.

- **IPv6 privacy extensions: false positive on VPN interfaces**: VPN killswitch interfaces (pvpnksintrf1) with internal ULA addresses triggered "IPv6 privacy extensions disabled" warning. VPN-internal interfaces are now skipped in the privacy check.

### 🟢 Low Fixes

- **Section comment numbers off-by-one**: Comments said "Section 36-43" but headers showed 35-42. All 8 comments corrected.

- **`rpm -Va` no progress indicator**: Full package verification can take 5-15 minutes with no output. Added progress message.

- **iptables rule count wrong**: Counted chain headers (`^[A-Z]`) instead of actual rules. Fixed to exclude headers and empty lines.

- **`cat /proc/loadavg | awk`**: Useless use of cat. Changed to `awk ... /proc/loadavg`.

- **`ip_forward` empty value error**: Missing default caused bash integer comparison error on stderr. Added `|| echo "0"` fallback.

- **systemd-analyze dead else branch**: `if [[ "$SVC" == "sshd" || ... ]]` was always true because the for-loop only contained those 4 values. Removed dead code.

- **`HAS_SELINUX`/`HAS_APPARMOR` undefined with `--skip selinux`**: MAC detection moved before the skip check so AI context always has correct values.

- **`txtf` dead code removed**: Never called anywhere in the script.

- **policies.json `"Value".*true` global match**: `EnableTrackingProtection` check matched any `"Value": true` in the entire file. Now scoped to the specific JSON block via `sed`.

- **vmstat column 16 hardcoded**: I/O wait column position varies across distros. Now dynamically parsed from header.

- **Score integer division truncation**: Always rounded down. Added `+ DENOM/2` for proper rounding.

- **`_human_size` crash on empty input**: No validation for non-numeric or empty arguments. Added regex guard.

- **PipeWire TCP check matched inline comments**: `grep -vE '^\s*#'` only filtered full-line comments. Strings like `value # tcp:4713` still matched. Added second grep to re-validate match after comment removal.

- **ANSI escapes in AI copy markers**: `echo -e "${GRN}..."` in copy markers included terminal color codes when copied. Changed to plain `echo`.

- **Suspicious module check label**: Added "(basic name-based heuristic)" caveat — real rootkits use innocuous names.

- **os-release sourcing**: `. /etc/os-release` could execute arbitrary code on compromised systems. Changed to `eval "$(grep ...)"` with restricted key whitelist.

- **`grep -qw "$GW"` regex wildcard**: Dots in IP addresses interpreted as regex "any character". Changed to `grep -qwF` (fixed string).

- **`ip route show default` missing `2>/dev/null`**: Inconsistent with other `ip` commands. Added error suppression.

---

## [3.2.3] - 2026-03-25

### 🔴 High Fixes

- **Unusual destination ports check was completely dead**: `ss -tnp state established | awk '{print $5}'` grabbed the Process column instead of Peer Address:Port (`$4`). The check always reported "All connections on standard ports" regardless of actual connections. Fixed to `awk '{print $4}'`.

- **Firefox DoH Mode 2/3 descriptions swapped**: Mode 2 was labeled "strict" and Mode 3 was labeled "fallback". In reality, Mode 2 = "DoH first, fallback to native DNS" and Mode 3 = "DoH only, no fallback" (the strictest setting). Both labels and severity corrected (Mode 3 now PASS instead of INFO).

### 🟡 Medium Fixes

- **Flatpak dangerous permissions: triple pattern failure**: (1) `talk-name=org.freedesktop.Flatpak` never matched — actual format is `org.freedesktop.Flatpak=talk`. (2) `filesystems=host` only matched when `host` was the first element; `filesystems=xdg-run;host;` was missed. (3) `\bhost\b` false-positived on `host-etc` (Brave Browser). Rewritten with precise delimiter-aware pattern.

- **Failed services: printed LOAD status instead of unit name**: `awk '{print $2}'` extracted the LOAD column, not the unit name (`$1`). Also added Unicode bullet (`●`/`×`) handling for newer systemd versions.

- **Kernel Taint: exact match instead of bitmask**: Checked `== 4096` (out-of-tree module only). NVIDIA sets both Bit 0 (proprietary) and Bit 12 (out-of-tree), producing 4097. Fixed to `(TAINT & 4096) || (TAINT & 1)` with corrected label.

- **AppArmor profile count wrong (Debian/Ubuntu)**: `grep -c "enforce"` counted all lines containing "enforce" including summary lines ("37 profiles are in enforce mode" + "15 processes are in enforce mode" = 2 instead of 37). Fixed with precise regex extracting the number from the summary line.

- **Umask 4-digit values not recognized**: `0027` and `0077` (common in CIS benchmarks and login.defs) were flagged as insecure. Initial strip-one-zero fix was incomplete (`0027` → `027` ≠ `27`). Fixed with regex `^0*27$` / `^0*77$` matching any number of leading zeros.

- **Hidden processes: inflated count from sort incompatibility**: `sort -n` (numeric) + `comm` (requires lexicographic sort) produced false positives. PIDs like `9, 10` sorted as `9, 10` numerically but `10, 9` lexicographically, causing `comm` to report phantom differences. Fixed to `sort -u` (lexicographic).

- **Cron directory 777 reported as PASS**: A directory with permissions 777 fell through all check branches to the default PASS. Restructured into explicit file/directory branches with proper warnings.

- **GNOME Tracker checked system scope instead of user scope**: `systemctl is-active tracker-miner-fs-3.service` (without `--user`) always returned inactive because Tracker runs as a user service. Now checks per-user via `sudo -u USER systemctl --user`. Added `localsearch-3.service` for Ubuntu 24.04+ (GNOME 46 rebranding).

- **Filesystem module checks missed `blacklist` directive**: Only `install cramfs /bin/false` was detected. `blacklist cramfs` (the common method) was ignored, causing false "not explicitly disabled" messages. USB-storage check already had `blacklist` — now consistent.

- **PipeWire TCP check: false negative then false positive**: Original pattern `module-protocol-pulse.*tcp` never matched real configs. Replaced with `tcp:[0-9]`, which then matched commented-out examples (`#"tcp:4713"`). Final fix: grep for pattern + filter comment lines.

- **GRUB password check: false positive from comments**: `grep -q "password"` matched `# password_pbkdf2 is recommended`. Fixed to `grep -rqE '^\s*(password_pbkdf2|password)\s+'`. Also expanded from `40_custom` only to all files in `/etc/grub.d/`.

- **DHCP hostname check: wrong INI section**: Searched for `[ipv4]` in `NetworkManager.conf`, but global config uses `[connection]` with `ipv4.dhcp-send-hostname`. Now checks both global config (`[connection]` section) and per-connection `.nmconnection` files (`[ipv4]` section). Also accepts `0` as disabled.

- **SSH key type extraction broke on comments with spaces**: `awk '{print $4}'` assumed fixed field position. Comments like `user@host generated 2026` shifted the type field. Fixed to `awk '{print $NF}'` (always last field).

- **auditctl status parsing not portable**: Newer auditd outputs `enabled 1` (multiline), older versions output `AUDIT_STATUS: enabled=1 flag=2` (single line). Fixed with dual-format regex matching both.

- **fwupdmgr false positive from `||` short-circuit**: `[[ $fw_exit -eq 2 ]] || echo "$fw_output" | grep -qi 'no updates'` — the grep ran unconditionally. If exit code was 1 (error) and error text contained "no updates", it falsely reported "up to date". Split into separate `elif` branches.

### 🟢 Low Fixes

- **lock-enabled fallback mislabeled as "Lock on suspend"**: On non-Ubuntu GNOME (Fedora, Arch), the `ubuntu-lock-on-suspend` key doesn't exist. Fallback to `lock-enabled` used the same callback, displaying "Lock on suspend enabled" instead of "Screen locking enabled". Now uses separate callback with correct text.

- **.netrc false positive as "Plaintext secret file"**: `.netrc` is a legitimate credentials file. Removed from secret_patterns list; separate permissions check (must be 600/400) retained.

- **Firmware/Thunderbolt checks skipped by `--skip keyring`**: fwupdmgr and Thunderbolt DMA checks were inside `check_keyring_security()`. Moved to independent block after all function calls.

- **link-local falsely classified as DHCP**: `ipv4.method=link-local` (RFC 3927 zeroconf) does not send DHCP requests. No longer triggers DHCP hostname warnings.

- **NM Connectivity: missing `uri=` key treated as "disabled"**: A `[connectivity]` section without explicit `uri=` key uses NetworkManager's default URI (phones home). Only an explicitly empty `uri=` disables it. Now distinguishes both cases.

- **Root excluded from empty-password check**: `$1 != "root"` filter removed. Root with empty password is the most critical finding and must be reported.

- **Faillock: inconsistent terminology**: WARN said "failed login attempts" but PASS said "no locked accounts". Now consistently uses "failed login attempts" in both cases.

- **modprobe.d pattern missed `/usr/bin/false`**: Only `/bin/false` was matched. Fedora and modern distros use `/usr/bin/false`. Pattern expanded to `/(usr/)?s?bin/(false|true)`.

- **rescue/emergency always reported as "enabled"**: These are static systemd units — `is-enabled` always returns 0. Now checks `ExecStart` for `sulogin` (password-protected rescue shell) and only warns if sulogin is absent.

- **dpkg -l exit 0 for removed packages (Debian/Ubuntu)**: `dpkg -l package` returns 0 even for status "rc" (removed, config remaining). Now checks for `^ii` (actually installed).

- **xclip in clipboard manager daemon list**: xclip is a CLI tool, not a persistent daemon. Removed from detection list.

- **`local` outside function (2 locations)**: `local` keyword in rescue/emergency check and AI prompt block caused Bash warnings. Removed.

### 🔧 Calibration Fixes

- **User list on login screen: WARN → INFO with LUKS**: On LUKS-encrypted systems, physical access requires the encryption passphrase before reaching the login screen. User enumeration is not a meaningful risk. Now INFO with explanation instead of WARN.

- **DoH Mode 3 corrected**: v3.2.2 miscalibrated Mode 3 as INFO ("fallback"). Mode 3 is actually the strictest DoH setting (no fallback). Now correctly PASS.

### ✨ Improvements

- **AI Prompt redesigned**: Added tool URL (`github.com/NexusOne23/noid-privacy-linux`), score with counts, and auto-detected system context (LUKS, VPN, Flatpak, SELinux/AppArmor). Visual upgrade with colored box and clear copy markers.

---

## [3.2.2] - 2026-03-02

### 🔴 High Fixes

- **Permissions: numeric comparison instead of bitwise**: `stat -c %a` returns octal strings that were compared as decimal integers (`555 < 600` → false PASS, but `555 = r-xr-xr-x` = world-readable). Fixed at 5 locations (history files, system file permissions, private keys, cron dirs/files) using proper octal bitmask comparison: `(( (8#${PERMS} & 8#077) != 0 ))`.

- **Firewalld: hardcoded zone list + default zone logic**: Zone enumeration used a hardcoded list missing `trusted`, `home`, `internal`, `work`, `FedoraServer`, `nm-shared`, and custom zones. Replaced with dynamic `firewall-cmd --get-zones`. Additionally, the default zone without explicit interfaces was skipped entirely — but it applies to ALL unassigned interfaces. Now evaluates services/ports on the default zone as exposed.

- **openssl x509 -checkend: grep substring match**: `grep -q "will expire"` matched both "Certificate will expire" AND "Certificate will **not** expire" (substring). Every valid cert was falsely flagged. Fixed by using `openssl x509 -checkend` exit code (0 = valid, 1 = expired) instead of text parsing. Also added multi-distro cert paths (`/etc/pki/tls/certs` + `/etc/ssl/certs`).

### 🟡 Medium Fixes

- **IPv6 NetworkManager: break on first disabled connection**: `break` after first `disabled` result caused false PASS when multiple connections were active (e.g. eth0=disabled, wg0=auto). Now checks ALL active connections; breaks only on first NOT disabled.

- **ICMP Redirect: only conf.all checked**: Missing `net.ipv4.conf.default.accept_redirects` check. New interfaces inherit from `conf.default`, so `conf.all=0` alone is insufficient. Now checks both and warns if only `conf.all` is disabled.

- **Unowned files find without timeout**: `find / -xdev -nouser -o -nogroup` could hang on slow/remote filesystems. Added `timeout 30`.

- **SSH service name: Debian/Ubuntu uses `ssh.service`**: Only `sshd.service` was checked. Debian/Ubuntu uses `ssh.service` (alias). Added `ssh` to service detection and SSH hardening section.

- **RDP remote_found set before value check**: `remote_found=1` was set unconditionally when the gsettings key existed, before checking if RDP was actually enabled (`true`). Now only sets flag when value is `true`.

- **APT security updates: locale-dependent parsing**: `apt-check --human-readable` output depends on system locale. Switched to raw `apt-check` (outputs `UPDATES;SECURITY` to stderr, locale-independent).

- **World-writable detail find without timeout**: Added `timeout 30` to prevent hangs on slow filesystems.

### 🟢 Low Fixes

- **ssh-keygen double execution**: `ssh-keygen -l -f` was called twice per key (once for bits, once for type). Cached result in variable.

- **Podman user/root identical scope**: Both `podman ps -q` calls ran as root, producing identical results. Removed misleading "user" count, kept only root container count.

- **Audit watch sub-path matching**: Grep for `-w /etc/ssh ` (trailing space) didn't match more specific rules like `-w /etc/ssh/sshd_config`. Fixed to match sub-paths.

- **systemctl --user portal check removed**: `systemctl --user` as root returns root's user session, not the desktop user's. Removed redundant portal check (already covered by device enumeration).

- **Chrony status message**: `"chronyd: active"` → `"chrony: active"` for consistency with service naming.

### 🔧 Calibration Fixes

- **SUID files threshold**: Pass ≤25 → Pass ≤30, Warn 31-45, Fail >45. Fedora Workstation with GNOME + NVIDIA has ~23 SUID binaries; ≤30 is normal for a desktop install.

- **SGID files threshold**: Pass ≤15 → Pass ≤10, Warn 11-20, Fail >20. Typical systems have 5-8 SGID files.

- **Unowned files threshold**: Pass ≤10 → Pass =0, Warn 1-5, Fail >5. Hardened systems should have zero unowned files; 10 was too permissive.

- **Btrfs snapshot exclusion**: All `find` commands in Section 12 (SUID, SGID, World-Writable, Unowned) now exclude `/.snapshots/*` to prevent false positives from Btrfs snapshots with stale UIDs/permissions.

- **GDM runtime files exclusion**: Unowned files check now excludes `/var/lib/gdm/*` — GDM creates runtime files (ibus, PulseAudio, dconf, WirePlumber) in a user namespace that appear as unowned to `find -nouser/-nogroup`.

- **`recent-files-max-age=0` logic bug**: Was reported as WARN "kept forever" — but GNOME defines `max-age=0` as "list always empty" (disabled). Now correctly reported as PASS.

- **DoH mode 3 severity**: Was PASS like mode 2 (strict). Mode 3 is fallback-only (falls back to plain DNS on failure). Now INFO to distinguish from strict DoH.

- **IPv6 privacy extensions false positive**: NM check was too strict — `ipv6.method=manual` and `link-local` (functionally equivalent to disabled without configured addresses) were not accepted. Loopback interface was also checked unnecessarily. Now accepts `manual`/`link-local` as IPv6-off and skips `lo`.

- **sshd systemd-security severity**: Was WARN at score 9.6. sshd inherently needs root/PAM/filesystem access — a high exposure score is expected and unavoidable. Now INFO (same as firewalld, fail2ban, auditd).

- **openssl checkend stdout leak**: `openssl x509 -checkend -noout` still prints "Certificate will not expire" to stdout in some OpenSSL versions. Only stderr was suppressed (`2>/dev/null`), causing raw text to leak into the report. Fixed with `&>/dev/null`.

- **at.allow/deny false positive**: Check warned "Neither at.allow nor at.deny exists" even when `at` was not installed. Now skips entirely if `at` command is not available.

---

## [3.2.1] - 2026-02-27

### 🐛 Bug Fixes

- **wsdd gvfsd child process false positive**: `pgrep -x wsdd` also matches the wsdd child process spawned by GNOME's `gvfsd-wsdd` (network browsing). That child always runs with `--no-host`, meaning it does **not** announce the machine on the LAN. The script now reads each matching process's cmdline and only warns if a wsdd process lacks `--no-host` (i.e. is a true standalone broadcast daemon). Systems with GNOME running correctly show PASS.

- **SELinux AVC false positive (aide/usbguard/logind)**: AVC denials from `aide`, `usbguard-daemon`, and `systemd-logind` are normal MAC operation — AIDE reads restricted paths during integrity checks, USBGuard interacts with udev/systemd, logind does session-management accesses at boot. Script now inspects the `comm=` field of each AVC denial and only warns if processes *other than* these expected ones generate denials. Systems with AVC activity from these daemons only now show INFO instead of WARN.

- **Journal critical count inflated by coredump stack traces**: `journalctl -p crit` in short format outputs multi-line entries: one coredump event generates hundreds of continuation lines (stack frames + loaded module list), each counted as a separate "critical" message. The script now only counts lines that start with a timestamp prefix (actual journal entries) and ignores indented continuation lines. One crash = one event, not 700+.

- **Journal errors inflated by sudo-without-TTY messages**: `sudo` logs an error for each invocation without a TTY (e.g. from CI tools or IDE integrations). These are operational noise, not security events. Script now filters `sudo[` lines from the 1-hour error count.

- **RPM verify: `/usr/lib/issue` and `/usr/lib/issue.net` counted as binaries**: These login-banner files (owned by the `setup` package) are plain text, not binaries. They are commonly cleared during system hardening (removing OS identification from login prompts). RPM flags them as modified because they lack the `c` (config) marker in the RPM database. Script now excludes `/usr/lib/issue*` from the binary-changed count. `.pyc` / `__pycache__` exclusion (Python bytecode, previously added) retained.

---

## [3.2.0] - 2026-02-27

### 🐛 False Positive Fixes (Real-World Hardened Systems)

These fixes were identified by running NoID on a fully-hardened Fedora 43 workstation.
Every single fix removes a genuine false positive from a correctly-secured system.

#### nftables & Firewall
- **nftables false positive**: `nftables.service` is correctly `inactive` when firewalld manages it as its backend (default on Fedora 31+, RHEL 8+). Script now detects `FirewallBackend=nftables` in `/etc/firewalld/firewalld.conf` and reports PASS instead of WARN.
- **Firewall policies**: Added detection of `firewall-cmd --list-policies` (firewalld 0.9+). Inter-zone policies (e.g. `block-lan-out` blocking RFC1918) are now reported and evaluated.

#### Kernel & sysctl
- **`net.ipv4.conf.all.rp_filter = 2` false positive**: Value `2` (loose mode) is required for WireGuard and other VPN setups. Script now accepts `>= 1` as valid for rp_filter (both strict and loose modes are secure; strict mode breaks multi-homed VPN routing).
- **`kernel.unprivileged_bpf_disabled = 2` false positive**: Value `2` is stricter than `1`. Script now accepts `>= 1` for this parameter. General `SYSCTL_MIN_OK` mechanism introduced for params where "higher = more hardened".

#### Swap / Memory
- **ZRAM false positive**: ZRAM (`/dev/zram*`) is in-memory compression, not a persistent disk device. It cannot leak data after reboot and needs no encryption. Previously flagged as "Swap: NOT encrypted". Now correctly reported as PASS with explanation.

#### Core Dumps
- **Coredump drop-in override ignored**: Script only read `/etc/systemd/coredump.conf` and missed drop-in overrides in `/etc/systemd/coredump.conf.d/`. A system with `Storage=external` in the main file but `Storage=none` in a drop-in was incorrectly flagged as WARN. Added `_systemd_conf_val()` helper that reads main config + all drop-ins (last wins), mirroring actual systemd behavior. Applied to both Section 30 and Section 38.

#### Network Privacy
- **Avahi config false positive**: `publish-hostname` config was flagged even when `avahi-daemon` was masked or disabled. Config file contents are irrelevant if the service cannot run. Check now skipped for masked/disabled services.
- **DHCP hostname false positive**: DHCP hostname leak warning was shown for systems with static IP where no DHCP is ever sent. Script now checks if any active NM connection uses `ipv4.method=auto` before checking `dhcp-send-hostname`.
- **Ethernet MAC `stable` vs `random`**: `stable` and `random` were both reported as PASS. `stable` generates a consistent MAC per connection-UUID (not truly random). With a static IP, it provides no privacy benefit. Now correctly reported as INFO with explanation.

#### Automated Updates
- **`dnf5-automatic.timer` not detected**: Fedora 41+ uses `dnf5-automatic` (not `dnf-automatic`). The old timer was not found → false WARN. Script now checks `dnf5-automatic.timer` first and reports the configured `upgrade_type` (security vs. default).

### ✨ New Checks

- **WireGuard/ProtonVPN ip-rule killswitch**: Kill-switch implemented via `ip rule` policy routing (ProtonVPN, NetworkManager WireGuard plugin) was not detected — only nftables DROP rules were checked. Script now also detects `suppress_prefixlength` and `fwmark`-based routing rules.
- **NTS-secured NTP (reliable detection)**: Fixed NTS detection: `chronyc sources` does not output "NTS" literally. Now uses `chronyc authdata` (chrony 4.0+) which shows active NTS sessions, with fallback to checking `nts` keyword on `server`/`pool` lines in chrony.conf.

### 🔧 Internal

- Added `_systemd_conf_val()` helper: reads systemd unit config with full drop-in support (mirrors actual systemd override behavior). Reusable for any systemd config file.
- Added `SYSCTL_MIN_OK` associative array: allows specifying minimum-acceptable values for sysctl params where "higher = stricter". Eliminates per-param special-casing.

---

## [3.1.0] - 2026-02-22

### 🔧 Quality & Correctness Release

**27 issues fixed from comprehensive code review. Zero new features — pure quality improvement.**

### 🔴 Critical Fix
- **Network requests now documented and skippable**: DNS leak test (`dig whoami.akamai.net`) and IP check (`curl ifconfig.me`) are wrapped in `--skip netleaks`. README and SECURITY.md updated to reflect actual behavior.

### 🟠 High Fixes
- **Pipe-to-while counter bug**: 22 instances of `cmd | while` refactored to `while ... done < <(cmd)` using process substitution. Prevents counter loss in subshells — score calculation is now accurate.
- **JSON schema mismatch**: Changed `"status":"pass"` to `"severity":"PASS"` (uppercase) to match entrypoint.sh's `jq` selectors. JSON output now works correctly in GitHub Actions.
- **Documentation accuracy**: Removed "zero network requests" claims from README and SECURITY.md.
- **Temperature parsing false positive**: `sensors` output now filters threshold values (`high`, `crit`, `low`, `hyst`) — only actual readings are compared. Previously `high = +65261.8°C` was parsed as a real temperature.
- **IPv4-mapped IPv6 localhost false positive**: Port check now recognizes `::ffff:127.0.0.1` as localhost. Previously flagged as "EXTERNALLY REACHABLE".

### 🟡 Medium Fixes
- Replaced all 78 `echo -e` with `printf` for POSIX portability, with proper `%%` escaping for literal percent signs
- Fixed unquoted `$0` in root check error message
- IPv6 check now filters link-local (`fe80::`) and multicast (`ff`) addresses to avoid false positives
- GitHub Actions pinned to specific versions (`@v4.2.2`)
- CI now tests on Ubuntu 22.04/24.04, Fedora 39/43, Debian 12 via Docker matrix
- ShellCheck is now enforced in CI (no longer `continue-on-error`)
- Version consistency across script, README, and SECURITY.md
- Hardened 19 `|| echo 0` patterns to `|| true` with `${VAR:-0}` defaults — prevents double-output in command substitutions
- **Flatpak Firefox support**: Browser privacy checks now scan both `~/.mozilla/firefox` and `~/.var/app/org.mozilla.firefox/.mozilla/firefox`
- **`rpm -Va` performance**: Cached output to avoid redundant second scan (saves ~60-120s on large systems)
- Fixed literal `\n` in firewall zone output — multi-line zones now display correctly

### 🧠 Desktop Intelligence (False-Positive Reduction)
- **TCP port check**: Externally bound TCP ports now check for VPN kill-switch before flagging as FAIL (same logic UDP already had)
- **Swap on LUKS**: Swapfiles on LUKS-encrypted volumes are now correctly recognized as encrypted at rest
- **IPv6 ULA filter**: Private `fd00::/8` (ULA) addresses and `::` loopback are no longer counted as global/leak-risk
- **Flatpak permissions**: Only `host`/`host-os` filesystem access triggers a warning — `xdg-download` etc. no longer false-positive
- **Compiler check**: Compilers on desktop systems show INFO instead of WARN (detected via `$XDG_CURRENT_DESKTOP`)
- **squashfs module**: Loaded squashfs is now INFO when Flatpak is installed (Flatpak requires squashfs)
- **Kill-switch duplicates**: VPN-managed duplicate rules downgraded from WARN to INFO (temporary, harmless)
- **Boot params**: `iommu=force` and `lockdown=confidentiality` are now INFO (optional — can break NVIDIA/hardware)
- **Journal criticals**: sudo auth retries are filtered before counting critical journal entries

### 🌍 Multi-Distro Support (Arch + openSUSE)
- **Arch Linux support**: pacman updates, security updates (rolling), package count, SigLevel verification, file integrity via `pacman -Qkk`
- **openSUSE support**: zypper updates, zypper security patches, PackageKit auto-updates detection
- **MAC framework fix**: SELinux/AppArmor detection is now tool-based instead of distro-based — openSUSE correctly uses AppArmor
- **Distro detection expanded**: Arch, Manjaro, EndeavourOS, Garuda, Artix, openSUSE, SLES, Linux Mint, Pop!_OS now recognized
- **False PASS eliminated**: Security updates on unsupported distros now show INFO instead of false PASS
- **Silent skips fixed**: Package count and signature checks now show INFO when package manager is unsupported

### 🐧 Debian/Ubuntu Feature Parity
- **Security updates detection**: apt systems now check for pending security updates via `apt-check` / `apt-get -s`
- **APT package authentication**: Check for unauthenticated/local packages (Debian equivalent of RPM GPG check)
- **debsums hint**: Debian systems without `debsums` now get an installation recommendation

### 🔧 Additional Bugfixes (Post-Review)
- **JSON mode clean output**: ~48 unguarded `printf` sub-headers and raw-dump blocks now suppressed in `--json` mode. Introduced `sub_header()` helper. `--json | jq .` now produces valid JSON.
- **Firewall zone REJECT**: `firewall-cmd --get-target` returns `REJECT` on modern firewalld (not `%%REJECT%%`). Both variants now matched.
- **USB storage pattern**: `usb-storage` (hyphen) and `usb_storage` (underscore) both matched via `usb[-_]storage`
- **ABRT service count**: `systemctl list-units | ccount` was extracting random digits from text output. Fixed to `| wc -l | ccount`.
- **PipeWire socket check**: `grep -rqs` (quiet) piped to `grep -v` always returned empty. Fixed: `-q` moved to second grep.
- **Empty password false positive**: `!` and `!!` in `/etc/shadow` mean "locked" (secure default for system accounts), not "empty". No longer counted as empty passwords. Fixes false positives on Debian/Ubuntu.
- **Screen lock check**: Now uses per-user DBUS session bus (`_gsettings_for_users`) instead of running `gsettings` as root (which returns system defaults, not actual user settings).
- **Compiler desktop detection**: Uses script's own `$DESKTOP_ENV` (set via `/proc`) instead of `$XDG_CURRENT_DESKTOP` (stripped by `sudo`).
- **AI marker in entrypoint.sh**: GitHub Action now correctly finds AI prompt block (`AI ASSISTANT PROMPT` instead of old `AI-READY PROMPT`).
- **SSH config parsing**: `sshd_cfg_val()` now uses `sshd -T` (OpenSSH's own parser) as primary method, with `head -1` fallback. Previously `tail -1` violated OpenSSH's first-match-wins semantics.
- **SUID/SGID find -xdev**: Added `-xdev` to SUID and SGID file searches. Prevents script from hanging on NFS/CIFS/FUSE mounts.
- **Shadow permissions false positive**: `/etc/shadow` and `/etc/gshadow` expected permissions relaxed from `000` to `640`. Debian/Ubuntu use `640` (root:shadow) for PAM password validation — no longer triggers false WARN.
- **VPN DNS range expansion**: DNS-over-VPN check now recognizes all RFC1918 (`10.x`, `172.16-31.x`, `192.168.x`) and CGNAT (`100.64-127.x`) ranges. Fixes false "DNS leak" warnings for Tailscale, WireGuard, and other VPNs.
- **User switching GNOME key**: Changed from `disable-lock-screen` to `disable-user-switching` with corrected logic. Lock screen is already checked via `org.gnome.desktop.screensaver lock-enabled`.

### 🟢 Low & Nitpick Fixes
- Fixed `local i` used outside function scope in JSON output
- Added `.editorconfig` for consistent formatting
- Expanded `.gitignore` (already covered in previous commit)
- Documented score formula: `PASS×100 / (PASS + FAIL×2 + WARN)`
- Documented SSH key strength thresholds (NIST guidelines)
- Documented `ccount()` helper function purpose
- Fixed credits: "Clawde" → "Claude"
- Added Troubleshooting section to README
- Clarified comparison table: "Zero compiled dependencies"
- Expanded AI flag description in `action.yml`
- Added ShellCheck requirement to CONTRIBUTING.md
- Fixed counter variable names in CONTRIBUTING.md docs
- Improved Security Policy SLAs with precise timelines
- Added `netleaks` to skip keywords list in `--help`

---

## [3.0.0] - 2026-02-13

### 🚀 Major Release — Privacy & Security Audit for Linux Desktops

**Complete repositioning: From server security tool to the first desktop privacy & security auditor for Linux.**

### 🌟 Release Highlights

✅ **300+ Checks** — Expanded from 250+ with 8 new privacy & desktop sections  
✅ **42 Sections** — Up from 34 (8 new privacy/desktop sections)  
✅ **AI-Ready Prompt** — `--ai` flag generates copy-paste prompts for ChatGPT/Claude/Gemini  
✅ **JSON Output** — `--json` flag for machine-readable results  
✅ **Desktop-First** — Browser privacy, app telemetry, webcam, Bluetooth, keyring auditing  
✅ **Zero Dependencies** — Still pure Bash, still zero external requirements  

### ✅ Added — Privacy Audit (8 New Sections, 60+ New Checks)

#### 🔒 Browser Privacy (Section 35)
- Firefox telemetry, health reports, WebRTC IP leaks
- DNS-over-HTTPS configuration
- Tracking protection level, third-party cookie policy
- Shield Studies, password saving
- uBlock Origin detection
- Chrome/Chromium presence warning

#### 🔒 Application Telemetry (Section 36)
- GNOME Location Services, problem reporting, usage stats
- GNOME Tracker/file indexer detection
- Recent files tracking configuration
- Flatpak dangerous permissions (filesystem=host, portal escape)
- Snap telemetry
- ABRT crash reporter
- Fedora countme / Ubuntu popularity-contest
- NetworkManager captive portal detection

#### 🔒 Network Privacy (Section 37)
- WiFi MAC address randomization
- Ethernet MAC cloning configuration
- Avahi/mDNS hostname broadcasting
- LLMNR status
- Hostname privacy (real name detection)
- IPv6 privacy extensions
- DHCP hostname leaking
- cups-browsed RCE risk (CVE-2024-47176)

#### 🔒 Data & Disk Privacy (Section 38)
- Recently used files size per user
- Thumbnail cache (reveals viewed images after deletion)
- Trash size monitoring
- Clipboard manager detection (password leak risk)
- Core dump configuration (may contain secrets)
- Bash history size audit
- Journald persistent log size
- /tmp filesystem type (tmpfs vs persistent)

#### 🖥️ Desktop Session Security (Section 39)
- Screen lock delay, idle timeout
- Lock on suspend
- Notification previews on lock screen
- GDM auto-login, guest account, timed login
- Remote desktop/VNC/RDP detection
- Autostart programs audit
- User list visibility on login screen

#### 🖥️ Webcam & Audio Privacy (Section 40)
- Webcam device detection
- Microphone mute status (PipeWire/PulseAudio)
- Network audio modules (TCP exposure)
- PipeWire remote access
- Screen sharing portal status

#### 🖥️ Bluetooth Privacy (Section 41)
- Bluetooth service status
- Discoverable mode (visible to nearby devices)
- Pairable mode without paired devices
- Active Bluetooth without usage

#### 🖥️ Password & Keyring Security (Section 42)
- Password manager detection (keepassxc, bitwarden, pass, etc.)
- GNOME Keyring PAM auto-unlock
- SSH AddKeysToAgent timeout
- GPG agent cache TTL
- Plaintext secret files in home directories
- Firmware update status (fwupdmgr)
- Thunderbolt security level (DMA attack prevention)

### ✅ Added — New Features
- `--ai` flag: Generates AI-ready prompt with all findings for ChatGPT/Claude/Gemini
- `--json` flag: Machine-readable JSON output for scripts and dashboards
- `--skip` support for all new sections: browser, telemetry, netprivacy, dataprivacy, session, media, btprivacy, keyring
- Summary now shows "Security & Privacy Score" (not just "Security Score")

### 🔧 Changed
- Repositioned as "Privacy & Security Audit for Linux Desktops"
- Total sections: 34 → 42
- Total checks: 250+ → 300+
- README completely rewritten with new positioning
- 5 new helper functions for multi-user gsettings/Firefox profile iteration
- All desktop checks iterate over all human users (UID ≥ 1000)

### 🔧 Technical
- gsettings checks use proper DBUS_SESSION_BUS_ADDRESS
- bluetoothctl calls use timeout to prevent hangs
- Fedora 43 + Ubuntu 24.04 compatible

---

## [2.0.1] - 2026-02-13

### 🔨 Bugfix Release

### Fixed
- `VERSION` variable collision with `/etc/os-release` → renamed to `FORTIFY_VERSION`
- Subshell counter bug in pipe loops → process substitution
- nftables kill-switch parsing (3-field output)
- `--skip` without argument → clean error message
- Duplicate entropy section removed
- Section name mismatches fixed
- CPU vulnerability glob guard added
- Swap disabled detection
- RPM verify: config vs binary changes distinguished
- DNS leak false positive for systemd-resolved (127.0.0.53)
- PATH world-writable false positive for Fedora symlinks
- chkrootkit Linux.Xor.DDoS false positive filtered
- Cron directory 755 on Fedora recognized as normal

---

## [2.0.0] - 2026-02-13

### 🚀 Major Release — Full Security Audit

### Added
- AppArmor support (Debian/Ubuntu)
- NTS (Network Time Security) check
- USB Guard detection
- Compiler presence check
- AIDE/Tripwire detection
- Cron/At permission audit
- Swap encryption check
- History file permissions
- Login banner check
- Boot security analysis
- PATH security audit
- Entropy check
- 35 sections total, 250+ checks
- 2283 lines

### Changed
- Dual distro support: Fedora/RHEL + Debian/Ubuntu
- Comprehensive kernel hardening section
- Advanced network security checks
- Container and virtualization detection

---

## [1.2.0] - 2026-02-12

### 🎉 Initial Public Release

- 212+ checks across 30 sections
- Fedora/RHEL primary support
- Pure Bash, zero dependencies
- Basic reporting with PASS/FAIL/WARN/INFO

---

**NoID Privacy for Linux** — *Know your system. Harden your privacy.*
