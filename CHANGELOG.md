# Changelog

All notable changes to NoID Privacy for Linux will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
