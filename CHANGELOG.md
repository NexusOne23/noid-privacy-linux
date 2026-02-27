# Changelog

All notable changes to NoID Privacy for Linux will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
