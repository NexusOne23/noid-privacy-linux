<div align="center">

# 🛡️ NoID Privacy for Linux

### Privacy & Security Audit for Linux Desktops

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](https://github.com/NexusOne23/noid-privacy-linux/blob/main/LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0-green.svg)](https://github.com/NexusOne23/noid-privacy-linux/releases)
[![Pure Bash](https://img.shields.io/badge/pure-bash-4EAA25.svg?logo=gnu-bash&logoColor=white)](https://github.com/NexusOne23/noid-privacy-linux)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](https://github.com/NexusOne23/noid-privacy-linux)
[![Checks](https://img.shields.io/badge/checks-300%2B-orange.svg)](https://github.com/NexusOne23/noid-privacy-linux)
[![CI](https://github.com/NexusOne23/noid-privacy-linux/actions/workflows/ci.yml/badge.svg)](https://github.com/NexusOne23/noid-privacy-linux/actions)

**300+ checks · 42 sections · Zero dependencies · Pure Bash · AI-powered fixes**

[Quick Start](#-quick-start) · [What it Checks](#-what-it-checks) · [AI Fixes](#-fix-with-ai) · [Comparison](#-comparison) · [Discussions](https://github.com/NexusOne23/noid-privacy-linux/discussions)

</div>

---

## ⚡ Quick Start

```bash
curl -fsSL https://github.com/NexusOne23/noid-privacy-linux/raw/main/noid-privacy-linux.sh -o noid-privacy-linux.sh
sudo bash noid-privacy-linux.sh --ai
```

300+ privacy & security checks. Zero dependencies. The `--ai` flag generates a ready-to-paste prompt — hand it to ChatGPT, Claude, or Gemini to **fix every finding automatically**.

> **This tool is read-only.** It does not modify your system. No files changed, no configs touched, no services restarted.

---

## 🤔 Why This Exists

Most Linux security tools were built for **servers**. They check SSH configs and firewall rules — but ignore your browser leaking DNS queries, apps phoning home, or the webcam accessible to every process.

**NoID Privacy for Linux** audits both **privacy and security** on Linux desktops:

| | Server Tools (Lynis, CIS) | NoID Privacy for Linux |
|---|:---:|:---:|
| Kernel hardening | ✅ | ✅ |
| Firewall & SSH | ✅ | ✅ |
| Browser privacy | ❌ | ✅ |
| App telemetry | ❌ | ✅ |
| DNS leak testing | ❌ | ✅ |
| VPN kill-switch | ❌ | ✅ |
| Webcam & Bluetooth | ❌ | ✅ |
| AI-powered fixes | ❌ | ✅ |

---

## 🤖 Fix with AI

This is what sets NoID Privacy for Linux apart:

```bash
sudo bash noid-privacy-linux.sh --ai
```

The `--ai` flag generates a **structured prompt** at the end of the scan containing all your findings. Copy it. Paste it into ChatGPT, Claude, or Gemini. The AI will explain each finding, provide exact commands to fix it, and prioritize by severity.

**Audit → AI → Fixed.** What used to take hours takes minutes.

```bash
# AI-ready prompt (recommended)
sudo bash noid-privacy-linux.sh --ai

# Plain text for manual review
sudo bash noid-privacy-linux.sh --no-color > report.txt

# Machine-readable JSON for scripts/dashboards
sudo bash noid-privacy-linux.sh --json
```

> No other Linux audit tool generates an AI remediation prompt. The `--ai` flag is our USP.

---

## 📋 What it Checks

### 🛡️ Security (Sections 01–34)

| Category | Examples |
|---|---|
| **Kernel & Boot** | Secure Boot, kernel lockdown, LUKS encryption, UEFI, sysctl hardening |
| **Firewall & Network** | iptables/nftables rules, default policies, open ports, VPN, kill-switch, DNS leaks |
| **SSH & Auth** | Key-only auth, root login, password aging, PAM, sudo group |
| **Encryption** | LUKS cipher strength, key size, swap encryption, entropy, certificate store |
| **MAC & Integrity** | SELinux/AppArmor enforcing, rootkit scans, AIDE/Tripwire, package verification |
| **Updates & Packages** | Security patches, auto-updates, repo integrity, GPG verification |
| **Advanced** | Fail2Ban, USB Guard, containers, systemd sandboxing, kernel modules |

### 🔒 Privacy & Desktop (Sections 35–42)

| Category | Examples |
|---|---|
| **Browser Privacy** | Firefox telemetry, WebRTC leaks, DNS-over-HTTPS, tracking protection, Chrome warning |
| **App Telemetry** | GNOME telemetry, crash reporters, Flatpak sandbox escapes, Snap telemetry |
| **Network Privacy** | MAC randomization, mDNS, LLMNR, hostname privacy, IPv6 privacy extensions |
| **Data Privacy** | Recent file tracking, thumbnail caches, core dumps, bash history, journald retention |
| **Session Security** | Screen lock, idle detection, auto-login, lock-on-suspend, VNC/RDP |
| **Webcam & Audio** | Device permissions, microphone, PipeWire remote access, screen sharing |
| **Bluetooth** | Discoverability, pairable mode, active without usage |
| **Keyring & Secrets** | Password manager, GNOME Keyring auto-unlock, SSH agent timeout, plaintext secrets |

📖 **[Full Check Reference →](Docs/CHECKS.md)** — all 42 sections with descriptions

---

## 📸 Sample Output

```
$ sudo bash noid-privacy-linux.sh --ai

  NoID Privacy for Linux v3.0.0 — Privacy & Security Audit for Linux Desktops
  2026-02-13 15:03:15 | mydesktop | 6.18.9-200.fc43.x86_64
  Arch: x86_64 | Distro: Fedora Linux 43 (Workstation Edition)
  Checks: 300+ across 42 sections

━━━ [01/42] KERNEL & BOOT INTEGRITY ━━━
  ✅ PASS  Secure Boot: ENABLED
  ✅ PASS  Kernel Lockdown: integrity
  ✅ PASS  LUKS encryption active

━━━ [05/42] VPN & NETWORK ━━━
  ✅ PASS  VPN interface proton0: active
  ✅ PASS  Default route via VPN
  ✅ PASS  IPv6: completely disabled

━━━ [35/42] BROWSER PRIVACY ━━━
  ✅ PASS  Firefox telemetry disabled
  ✅ PASS  WebRTC disabled — no IP leak
  ⚠️  WARN  google-chrome installed — Google telemetry risk

━━━ SUMMARY ━━━
  Total checks:      341 (228 pass, 4 fail, 19 warn, 90 info)
  SECURITY & PRIVACY SCORE:    89% SOLID

🤖 AI-READY PROMPT saved. Copy & paste it to your AI assistant.
```

---

## ⚙️ Options

| Flag | Description |
|------|-------------|
| `--ai` | Generate AI-ready fix prompt with all findings |
| `--json` | Machine-readable JSON output |
| `--no-color` | Disable colored output (for piping/logging) |
| `--skip SECTION` | Skip specific sections (repeatable) |
| `--help` | Show all available options and skip keywords |

44 skip keywords available — run `--help` for the full list.

---

## 📊 Comparison

| Feature | **NoID Privacy for Linux** | **Lynis** | **privacy.sexy** | **CIS Benchmark** |
|---|:---:|:---:|:---:|:---:|
| **Focus** | Privacy + Security for desktops | Server compliance | Script generator | Server compliance |
| **Tests** | 300+ | 480+ | N/A | varies |
| **Browser privacy** | ✅ | ❌ | ⚠️ Partial | ❌ |
| **App telemetry** | ✅ | ❌ | ✅ | ❌ |
| **DNS / VPN / MAC** | ✅ | ❌ | ❌ | ❌ |
| **Webcam / Bluetooth** | ✅ | ❌ | ❌ | ❌ |
| **AI-ready output** | ✅ | ❌ | ❌ | ❌ |
| **JSON output** | ✅ | ✅ | N/A | ❌ |
| **Kernel & firewall** | ✅ | ✅ | ⚠️ Partial | ✅ |
| **Zero dependencies** | ✅ | ✅ | ❌ | ❌ |
| **Desktop-focused** | ✅ | ❌ | ✅ | ❌ |
| **Modifies system** | ❌ | ❌ | ✅ | ❌ |

**[Lynis](https://cisofy.com/lynis/)** (15k ⭐, since 2007) — Gold standard for server compliance. Doesn't cover browser privacy, telemetry, webcams, or desktop-specific concerns.

**[privacy.sexy](https://privacy.sexy)** (5k ⭐) — Script generator for Windows/macOS/Linux. Modifies your system directly without auditing first.

---

## 📥 Installation

| Requirement | Details |
|---|---|
| **OS** | Fedora 39+, Ubuntu 22.04+, Debian 12+, RHEL 9+ |
| **Shell** | Bash 4+ |
| **Privileges** | Root (`sudo`) for full system access |
| **Dependencies** | None |

```bash
# One-liner
curl -fsSL https://github.com/NexusOne23/noid-privacy-linux/raw/main/noid-privacy-linux.sh -o noid-privacy-linux.sh
sudo bash noid-privacy-linux.sh --ai

# Or clone
git clone https://github.com/NexusOne23/noid-privacy-linux.git
cd noid-privacy-linux
sudo bash noid-privacy-linux.sh --ai
```

---

## ✅ Perfect For

- **Privacy-conscious developers** — Know what your desktop is leaking
- **Power users** — A second pair of eyes on your hardening
- **Team leads** — Baseline audit for your team's workstations
- **Linux newcomers** — Clear findings with AI-guided fixes
- **Security consultants** — Quick desktop audit with professional output

## ❌ Not For

- **Server admins** → [Lynis](https://cisofy.com/lynis/)
- **Enterprise compliance (CIS/STIG)** → [OpenSCAP](https://www.open-scap.org/)
- **Automated remediation** → [privacy.sexy](https://privacy.sexy)
- **Windows** → [NoID Privacy](https://github.com/NexusOne23/noid-privacy) (our sister project)

---

## 🔗 Sister Project

**[NoID Privacy](https://github.com/NexusOne23/noid-privacy)** — Windows 11 Security & Privacy Hardening Framework. 630+ settings, 7 modules, Backup → Apply → Verify → Restore pattern.

---

## 🔒 Privacy Promise

This script makes **zero network requests**. No telemetry, no analytics, no phone-home. One file, pure Bash — read every line yourself.

---

## 🤝 Contributing

Contributions welcome — new checks, bug fixes, distro support.

- [Contributing Guide](CONTRIBUTING.md) — Code architecture, style, testing
- [Bug Reports](https://github.com/NexusOne23/noid-privacy-linux/issues) — Found a false positive?
- [Feature Requests](https://github.com/NexusOne23/noid-privacy-linux/issues)
- [Discussions](https://github.com/NexusOne23/noid-privacy-linux/discussions)
- [Security Policy](SECURITY.md) — Report vulnerabilities privately

---

## 📜 License

**GPL v3.0** — Free for personal and commercial use. Derivatives must also be GPL v3.0.

For commercial licensing without GPL requirements, open a [Discussion](https://github.com/NexusOne23/noid-privacy-linux/discussions).

[Full License →](LICENSE)

---

<div align="center">

**[⭐ Star this repo](https://github.com/NexusOne23/noid-privacy-linux)** if it's useful — helps others find the project.

**NoID Privacy for Linux** — *Know your system. Harden your privacy.*

</div>
