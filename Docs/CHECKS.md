# 📋 NoID Privacy for Linux — Section Overview

Section-by-section overview of what the audit checks and why it matters.

> **Version:** 3.5.0 | **Total Checks:** 390+ | **Sections:** 42

> **Cross-distro coverage** — Optimized for Fedora 43+ / RHEL 9+. Debian 12+ / Ubuntu 24.04+, Arch, openSUSE Tumbleweed work but some checks may produce false positives (Snapper-aware, GNOME-centric). DE-aware checks cover GNOME, KDE Plasma 5/6, XFCE, MATE, Cinnamon (since v3.5.0). See `--help` for `--skip` options to suppress sections that don't apply.

> **Note**: This is a high-level overview. For the full enumeration of every
> individual check, severity-trigger conditions, and pass/fail values, read
> [`noid-privacy-linux.sh`](../noid-privacy-linux.sh) directly — the script
> is intentionally one file in pure Bash, designed to be readable.

---

## 🛡️ Security Sections (01–34)

### Section 01: Kernel & Boot Integrity
Verifies the foundation of system security: Secure Boot status, kernel lockdown mode, LUKS full-disk encryption, UEFI firmware, and boot parameter integrity. A compromised boot chain means nothing else matters.

### Section 02: SELinux / AppArmor (MAC)
Checks Mandatory Access Control enforcement. SELinux (Fedora/RHEL) or AppArmor (Ubuntu/Debian) — verifies enforcing mode, policy status, and confined processes. MAC prevents privilege escalation even if an app is compromised.

### Section 03: Firewall
Audits iptables/nftables/firewalld rules, default policies (INPUT/OUTPUT/FORWARD), and zone configuration. Checks for open ports that shouldn't be exposed and validates that the firewall is actually running.

### Section 04: nftables & Kill-Switch
Checks nftables ruleset for VPN kill-switch configuration — ensuring all traffic is blocked if the VPN drops. Validates that non-VPN traffic is properly denied.

### Section 05: VPN & Network
Detects active VPN connections (WireGuard, OpenVPN, ProtonVPN, etc.), validates default route through VPN, checks for DNS leaks, IPv6 leaks, and WebRTC leaks. Verifies the VPN is actually protecting your traffic.

### Section 06: Kernel Hardening (sysctl)
Audits critical sysctl parameters: ASLR level, kernel pointer hiding (`kptr_restrict`), dmesg restriction, unprivileged BPF/userns, SYN cookies, ICMP redirects, IP forwarding, and core dump limits. These are your kernel's immune system.

### Section 07: Services & Daemons
Identifies unnecessary running services that increase attack surface: Avahi, CUPS, SSH, Samba, NFS, rpcbind, telnet, FTP. Each unnecessary service is a potential entry point.

### Section 08: Open Ports & Listeners
Uses `ss` to enumerate all listening TCP/UDP ports, identifies the process behind each, and flags unexpected listeners. Compares against expected services.

### Section 09: SSH Hardening
Comprehensive SSH audit: root login, password authentication, key-only auth, protocol version, port, X11 forwarding, empty passwords, max auth tries, login grace time, and authorized key files.

### Section 10: Audit System
Checks if auditd is running, validates audit rules, log file permissions, and configuration. The audit system is your security camera — if it's off, you're blind.

### Section 11: Users & Authentication
Audits user accounts: UID 0 accounts (should only be root), empty passwords, login shell assignments, password aging policies, sudo group membership, and PAM configuration.

### Section 12: Filesystem Security
Checks mount options (noexec, nosuid, nodev on /tmp, /var/tmp, /dev/shm), world-writable directories, SUID/SGID binaries, and sticky bits. Prevents privilege escalation via filesystem tricks.

### Section 13: Encryption & Crypto
Validates LUKS encryption status, cipher strength (aes-xts-plain64), key size (512-bit), swap encryption, and available system entropy. Weak crypto = false sense of security.

### Section 14: Updates & Packages
Checks for pending security updates, automatic update configuration (dnf-automatic/unattended-upgrades), repository integrity (GPG keys), and package verification.

### Section 15: Rootkit & Malware Scan
Runs **chkrootkit** (active maintenance, last release 2025-05; detects modern
threats like XZ Backdoor, Bootkitty, BPFDoor) if installed. Filters known
false positives.

**Note on rkhunter**: If rkhunter is installed, it's reported as INFO with a
deprecation warning — last release was 2018-02 and signatures don't cover
post-2018 rootkits. Use chkrootkit + AIDE + IMA for modern integrity.

### Section 16: Process Security
Process counts, zombie processes, deleted-but-running binaries, and a basic
name-pattern check (annotated as heuristic — real malware renames binaries).
For actual integrity verification, rely on AIDE/IMA (Section 30) and
chkrootkit (Section 15).

### Section 17: Network Security (Advanced)
Anti-spoofing kernel settings (ICMP redirects sysctl), TCP wrapper config
(deprecated on modern systems — informational only), TCP TIME_WAIT connection
counts, and ARP-monitoring tool detection (arpwatch/arpon/addrwatch).

### Section 18: Containers & Virtualization
Detects Docker, Podman, LXC, and VM hypervisors. Checks container runtime security, socket permissions, and whether containers run as root.

### Section 19: Logs & Monitoring
Validates journald configuration, log rotation, remote logging setup, and log file permissions. Checks if critical logs are being collected and retained.

### Section 20: Performance & Resources
Monitors system resource usage that could indicate compromise: unusual CPU usage, memory pressure, disk space, and process counts.

### Section 21: Hardware & Firmware
Checks CPU microcode updates, firmware update status (fwupd), CPU vulnerability mitigations (Spectre, Meltdown, etc.), and TPM presence.

### Section 22: Network Interfaces (Detail)
Detailed network interface audit: all interfaces, IP addresses, MTU, promiscuous mode, and unusual configurations.

### Section 23: Crypto & Certificates
Audits system certificate store, checks for untrusted or expired certificates, and validates crypto library versions.

### Section 24: Environment & Secrets
Scans for **world-readable private key files** (content-verified via PEM
magic strings — filename `.key` alone is NOT sufficient since uBlock Origin
IDB and test fixtures use the same extension), `.env` files in user homes
(uses snapshot/cache-aware find), and configuration files in `/etc` containing
credential patterns. Snapshot directories (`.snapshots`, `timeshift-btrfs`)
are excluded to prevent inflated counts on Snapper/Timeshift systems.

### Section 25: Systemd Security
Audits systemd unit files for security features: sandboxing (ProtectSystem, ProtectHome, NoNewPrivileges), capability restrictions, and namespace isolation.

### Section 26: Desktop & GUI Security
Checks display server security (Wayland vs X11), screen lock state across **GNOME / KDE Plasma / XFCE / MATE / Cinnamon** (DE-aware dispatcher reads kscreenlockerrc on KDE, xfce4-screensaver on XFCE, the appropriate gsettings schema on GNOME-family DEs). Falls back to GNOME-only behavior when DE cannot be detected.

### Section 27: Time Sync & NTP
Validates NTP configuration, checks for NTS (Network Time Security) support, and ensures time is properly synchronized. Time drift can break TLS and Kerberos.

### Section 28: Fail2Ban
Checks if Fail2Ban is installed and running, validates jail configuration, and verifies SSH protection is active.

### Section 29: Recent Logins & Activity
Audits recent login activity: failed login attempts, unusual login times, and root login history.

### Section 30: Advanced Hardening
Checks advanced security features: USBGuard daemon + rules, coredump service state (storage-aware), compiler presence (build-host vs production-server vs desktop), AIDE/Tripwire integrity monitoring, IMA/EVM kernel integrity, FireWire DMA-attack surface, home directory permissions, shell idle TMOUT, AIDE database existence, and shell history sensitive-pattern scan. (Login banner check is in Section 12 / Filesystem.)

### Section 31: Kernel Modules & Integrity
Audits loaded kernel modules: heuristic name-pattern scan for suspicious modules, 12 disabled filesystem modules per CIS Level 2 (cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, affs, befs, sysv, qnx4, qnx6), USB storage module blacklist, and kernel module-loading lockdown state. (Thunderbolt device security and FireWire blacklist are checked in Section 21 / Hardware and Section 30 / Hardening respectively.)

### Section 32: Permissions & Access Control
Deep file permission audit: world-writable files, SUID/SGID binaries, cron job permissions, and sensitive file access controls.

### Section 33: Boot Security & Integrity
Validates GRUB configuration, boot password protection, and bootloader integrity.

### Section 34: System Integrity Checks
Runs package verification (rpm -Va / debsums), checks for modified system binaries, and validates critical file checksums.

---

## 🔒 Privacy Sections (35–38)

### Section 35: Browser Privacy
Comprehensive Firefox audit: telemetry (`toolkit.telemetry.enabled`), health reports, WebRTC IP leaks, DNS-over-HTTPS mode, tracking protection level, third-party cookie policy, Shield Studies, saved passwords, and extension inventory. Warns about Chrome/Chromium presence due to Google telemetry.

### Section 36: Application Telemetry & Privacy
Detects and audits application-level data collection: GNOME Location Services, problem reporting (ABRT), usage statistics, **file indexer (GNOME Tracker / KDE Baloo / Recoll — DE-aware)**, Flatpak sandbox escapes (`filesystem=host`), Snap telemetry, Fedora `countme`, Ubuntu `popularity-contest`, and captive portal detection.

### Section 37: Network Privacy
Audits network-level privacy: WiFi MAC address randomization, Ethernet MAC cloning, Avahi/mDNS hostname broadcasting, LLMNR status, hostname privacy (detects real names), IPv6 privacy extensions, DHCP hostname leaking, and cups-browsed RCE risk (CVE-2024-47176).

### Section 38: Data & Disk Privacy
Checks data-at-rest privacy: recently used files size, thumbnail caches (reveal viewed images after deletion), trash size, clipboard managers (password leak risk), core dump configuration, bash history size, journald log retention, and /tmp filesystem type (tmpfs vs persistent).

---

## 🖥️ Desktop Sections (39–42)

### Section 39: Desktop Session Security
Audits session-level security across **GNOME / KDE Plasma / XFCE / MATE / Cinnamon**: screen lock delay (KDE LockGrace, XFCE delay-from-activation, GNOME lock-delay), idle timeout (KDE/XFCE return minutes, normalized to seconds), lock-on-suspend (KDE LockOnResume), notification previews on lock screen (KDE plasmanotifyrc DoNotDisturb), GDM auto-login, guest accounts, timed login, remote desktop/VNC/RDP detection (localhost-only listeners reported as INFO, not WARN), autostart programs, and user-switching policy (KDE kdeglobals KDE Action Restrictions).

### Section 40: Webcam & Audio Privacy
Checks media device security: webcam device detection and permissions, microphone mute status (PipeWire/PulseAudio), network audio modules (TCP exposure), PipeWire remote access, and screen sharing portal status.

### Section 41: Bluetooth Privacy
Audits Bluetooth exposure: service status, discoverable mode (visible to nearby devices), pairable mode without paired devices, and active Bluetooth without usage.

### Section 42: Password & Keyring Security
Comprehensive credential audit: password manager detection (17 tools — KeePassXC, KeePass2, KeeWeb, Bitwarden + bw-cli, rbw, 1Password + op, pass, gopass, lesspass, NordPass, Buttercup, qtpass, Enpass), **GNOME Keyring AND KDE KWallet** PAM auto-unlock, SSH `AddKeysToAgent` timeout, GPG agent cache TTL, plaintext secret files in home directories (subdirectory-aware via `_safe_find_home`, severity-tiered by permissions: world-readable=FAIL, group-readable=WARN, private=INFO), firmware update status (fwupdmgr), and Thunderbolt security level (DMA attack prevention).

---

## 📊 Summary

After all 42 sections, NoID Privacy for Linux calculates a **Security & Privacy Score** based on the ratio of PASS/FAIL/WARN results. The score provides an at-a-glance assessment:

| Score | Rating | Meaning |
|-------|--------|---------|
| 95%+ | 🏰 FORTRESS | Exceptionally hardened system |
| 90-94% | 🛡️ EXCELLENT | Well-hardened system |
| 80-89% | 🛡️ SOLID | Good baseline, some improvements possible |
| 70-79% | ⚠️ NEEDS WORK | Significant gaps in security/privacy |
| <70% | 🔴 CRITICAL | Immediate attention required |

---

## 🤖 AI Integration

With the `--ai` flag, all findings are compiled into a structured prompt that you can paste directly into ChatGPT, Claude, or Gemini. The AI will:
1. Explain each finding in plain language
2. Provide exact commands to fix each issue
3. Prioritize fixes by severity
4. Ask before making changes

This is the **unique selling point** of NoID Privacy for Linux — no other audit tool generates AI-ready remediation prompts.

---

*For the full script, see [noid-privacy-linux.sh](../noid-privacy-linux.sh)*  
*For usage instructions, see [README.md](../README.md)*
