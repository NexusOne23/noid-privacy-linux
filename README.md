<div align="center">

# 🛡️ NoID Privacy for Linux

### Privacy & Security Audit for Linux Desktops

*Know your system. Harden your privacy. Let AI fix the rest.*

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](https://github.com/NexusOne23/noid-privacy-linux/blob/main/LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0-green.svg)](https://github.com/NexusOne23/noid-privacy-linux/releases)
[![Pure Bash](https://img.shields.io/badge/pure-bash-4EAA25.svg?logo=gnu-bash&logoColor=white)](https://github.com/NexusOne23/noid-privacy-linux)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](https://github.com/NexusOne23/noid-privacy-linux)
[![Checks](https://img.shields.io/badge/checks-300%2B-orange.svg)](https://github.com/NexusOne23/noid-privacy-linux)
[![Sections](https://img.shields.io/badge/sections-42-blue.svg)](Docs/CHECKS.md)
[![Fedora | Ubuntu | Debian](https://img.shields.io/badge/distros-Fedora%20%7C%20Ubuntu%20%7C%20Debian-informational.svg)](https://github.com/NexusOne23/noid-privacy-linux)
[![CI](https://github.com/NexusOne23/noid-privacy-linux/actions/workflows/ci.yml/badge.svg)](https://github.com/NexusOne23/noid-privacy-linux/actions)

---

**300+ checks · 42 sections · Zero dependencies · Pure Bash · AI-powered fixes**

[⚡ Quick Start](#-in-30-seconds) · [📋 What it Checks](#-what-it-checks) · [🤖 Fix with AI](#-fix-with-ai--our-unique-feature) · [📊 Comparison](#-comparison) · [💬 Community](https://github.com/NexusOne23/noid-privacy-linux/discussions)

</div>

---

## ⚡ In 30 Seconds

```bash
curl -fsSL https://github.com/NexusOne23/noid-privacy-linux/raw/main/noid-privacy-linux.sh -o noid-privacy-linux.sh
sudo bash noid-privacy-linux.sh --ai
```

**That's it.** 300+ privacy & security checks. Zero dependencies. The `--ai` flag generates a ready-to-paste prompt — hand it to ChatGPT, Claude, or Gemini to **fix every finding automatically**.

> **💡 The `--ai` flag is what makes NoID Privacy for Linux unique.** No other Linux audit tool gives you an AI-ready remediation prompt. Audit → AI → Fixed. In minutes, not hours.

---

## ⚠️ Disclaimer

> **This tool is read-only.** It audits your system — it does **not** modify anything.  
> No files changed, no configs touched, no services restarted. Safe to run anytime.

NoID Privacy for Linux is designed for Linux **desktops** (workstations, laptops, developer machines). For server hardening, see [Lynis](https://cisofy.com/lynis/).

---

## 🤔 Why NoID Privacy for Linux?

Most Linux security tools were built for **servers**. They check SSH configs and firewall rules — but ignore the browser leaking your DNS queries, the apps phoning home, or the webcam that's accessible to every process.

**NoID Privacy for Linux** is the first tool that audits both **privacy and security** on Linux desktops:

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

**The gap is real.** You can have a perfectly hardened kernel and still leak your browsing history through Firefox telemetry.

---

## 🤖 Fix with AI — Our Unique Feature

This is what sets NoID Privacy for Linux apart from every other audit tool:

### The Problem
Traditional audit tools give you a list of findings. Then you spend hours Googling each one, figuring out the right commands, and hoping you don't break anything.

### The Solution
```bash
sudo bash noid-privacy-linux.sh --ai
```

The `--ai` flag generates a **structured prompt** at the end of the scan with all your findings. Copy it. Paste it into ChatGPT, Claude, or Gemini. The AI will:

1. **Explain** each finding in plain language
2. **Provide** exact commands to fix each issue
3. **Prioritize** fixes by severity (FAILs first, then WARNs)
4. **Ask** before making any changes

**Audit → AI → Fixed.** What used to take hours now takes minutes.

### Three Ways to Use It

```bash
# Option A: AI-ready prompt (recommended)
sudo bash noid-privacy-linux.sh --ai

# Option B: Copy raw output to AI manually
sudo bash noid-privacy-linux.sh --no-color > report.txt

# Option C: Machine-readable for scripts/dashboards
sudo bash noid-privacy-linux.sh --json
```

> **No other Linux audit tool does this.** Not Lynis, not CIS Benchmark, not privacy.sexy. The `--ai` flag is our USP.

---

## 🔒 Our Privacy Promise

**"We practice what we preach."**

| | |
|---|---|
| 🍪 **Zero Cookies** | No cookie banners, no tracking cookies, no consent popups |
| 📊 **Zero Analytics** | No Google Analytics, no third-party tracking scripts |
| 🔍 **Zero Telemetry** | No usage tracking, no phone-home, no data collection |
| 🌐 **Zero Network** | The script makes no network requests at runtime |
| ✅ **100% Verifiable** | One file, pure Bash — read every line yourself |

**Actions speak louder than privacy policies.** This script doesn't even have the ability to phone home.

---

## 📋 What it Checks

### 🔒 Privacy (Sections 35–42)

| Category | What We Check |
|---|---|
| **Browser Privacy** | Firefox telemetry, WebRTC IP leaks, DNS-over-HTTPS, tracking protection, cookie policy, extensions, Chrome presence warning |
| **App Telemetry** | GNOME telemetry, crash reporters, Flatpak sandbox escapes, Snap telemetry, Fedora countme, Ubuntu popularity-contest |
| **Network Privacy** | MAC randomization, mDNS broadcasting, LLMNR, hostname privacy, IPv6 privacy extensions, DHCP hostname leaking, cups-browsed CVE |
| **Data Privacy** | Recent file tracking, thumbnail caches, clipboard managers, core dumps, bash history, journald retention, tmpfs |

### 🛡️ Security (Sections 01–34)

| Category | What We Check |
|---|---|
| **Kernel & Boot** | Secure Boot, kernel lockdown, LUKS encryption, UEFI, sysctl hardening (ASLR, kptr_restrict, BPF) |
| **Firewall & Network** | iptables/nftables rules, default policies, open ports, VPN detection, kill-switch, DNS leaks |
| **SSH & Auth** | Key-only auth, root login, protocol, password aging, PAM, empty passwords, sudo group |
| **Encryption** | LUKS cipher strength, key size, swap encryption, entropy, certificate store |
| **MAC & Integrity** | SELinux/AppArmor enforcing, rootkit scans, AIDE/Tripwire, package verification |
| **Updates & Packages** | Security patches, auto-updates, repo integrity, GPG verification |
| **Advanced** | Fail2Ban, USB Guard, containers, systemd sandboxing, kernel modules |

### 🖥️ Desktop (Sections 39–42)

| Category | What We Check |
|---|---|
| **Session Security** | Screen lock timeout, idle detection, auto-login, lock-on-suspend, notification previews, VNC/RDP detection |
| **Webcam & Audio** | Device permissions, microphone mute, network audio exposure, PipeWire remote access, screen sharing |
| **Bluetooth** | Discoverability, pairable mode, active without usage |
| **Keyring & Secrets** | Password manager detection, GNOME Keyring auto-unlock, SSH agent timeout, GPG cache TTL, plaintext secrets, firmware updates, Thunderbolt DMA |

📖 **[Full Check Reference →](Docs/CHECKS.md)** (all 42 sections with detailed descriptions)

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
  ✅ PASS  DNS-over-HTTPS active (mode 3)
  ✅ PASS  Tracking protection set to strict
  ✅ PASS  uBlock Origin installed
  ⚠️  WARN  google-chrome installed — Google telemetry/tracking risk

━━━ [37/42] NETWORK PRIVACY ━━━
  ✅ PASS  WiFi scan MAC randomization enabled
  ✅ PASS  Ethernet MAC cloning set to 'random'
  ⚠️  WARN  IPv6 privacy extensions disabled — stable address reveals identity

━━━ SUMMARY ━━━
  Total checks:      341 (228 pass, 4 fail, 19 warn, 90 info)
  SECURITY & PRIVACY SCORE:    89% SOLID

🤖 AI-READY PROMPT saved. Copy & paste it to your AI assistant to fix all findings.
```

---

## ⚙️ Configuration & Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--ai` | Generate AI-ready prompt with all findings | `sudo bash noid-privacy-linux.sh --ai` |
| `--json` | Machine-readable JSON output | `sudo bash noid-privacy-linux.sh --json` |
| `--no-color` | Disable colored output (for piping/logging) | `sudo bash noid-privacy-linux.sh --no-color > report.txt` |
| `--skip SECTION` | Skip specific sections (repeatable) | `sudo bash noid-privacy-linux.sh --skip bluetooth --skip rootkit` |
| `--help` | Show all available options | `sudo bash noid-privacy-linux.sh --help` |

### Available `--skip` Keywords

| Keyword | Section |
|---------|---------|
| `kernel` | Kernel & Boot Integrity |
| `selinux` / `apparmor` | Mandatory Access Control |
| `firewall` | Firewall |
| `nftables` | nftables & Kill-Switch |
| `vpn` | VPN & Network |
| `sysctl` | Kernel Hardening |
| `services` | Services & Daemons |
| `ports` | Open Ports |
| `ssh` | SSH Hardening |
| `audit` | Audit System |
| `users` | Users & Authentication |
| `filesystem` | Filesystem Security |
| `encryption` | Encryption |
| `updates` | Updates & Packages |
| `rootkit` | Rootkit Scan |
| `containers` | Containers |
| `browser` | Browser Privacy |
| `telemetry` | App Telemetry |
| `netprivacy` | Network Privacy |
| `dataprivacy` | Data Privacy |
| `session` | Desktop Session |
| `media` | Webcam & Audio |
| `btprivacy` | Bluetooth |
| `keyring` | Password & Keyring |

---

## 📊 Comparison

| Feature | **NoID Privacy for Linux** | **Lynis** | **privacy.sexy** | **CIS Benchmark** |
|---|:---:|:---:|:---:|:---:|
| **Focus** | Privacy + Security for desktops | Server compliance | Script generator | Server compliance |
| **Checks** | **300+** | ~200 | N/A (generates scripts) | ~250 (manual) |
| **Sections** | **42** | ~65 (server-focused) | N/A | ~20 |
| **Browser privacy** | ✅ Firefox + Chrome | ❌ | ⚠️ Partial | ❌ |
| **App telemetry** | ✅ GNOME, Flatpak, Snap | ❌ | ✅ | ❌ |
| **DNS leak testing** | ✅ | ❌ | ❌ | ❌ |
| **VPN kill-switch** | ✅ | ❌ | ❌ | ❌ |
| **Webcam/Bluetooth** | ✅ | ❌ | ❌ | ❌ |
| **MAC randomization** | ✅ | ❌ | ⚠️ Partial | ❌ |
| **AI-ready output** | ✅ `--ai` flag | ❌ | ❌ | ❌ |
| **JSON output** | ✅ `--json` flag | ✅ | N/A | ❌ |
| **Kernel hardening** | ✅ | ✅ | ⚠️ Partial | ✅ |
| **Firewall audit** | ✅ | ✅ | ❌ | ✅ |
| **Rootkit detection** | ✅ Runs scanners | ⚠️ Checks if installed | ❌ | ❌ |
| **Zero dependencies** | ✅ Pure Bash | ✅ Shell | ❌ Electron | ❌ |
| **Desktop-focused** | ✅ | ❌ Server-focused | ✅ | ❌ Server-focused |
| **Modifies system** | ❌ Audit only | ❌ Audit only | ✅ Generates scripts | ❌ Manual |

**[Lynis](https://cisofy.com/lynis/)** (15k ⭐, since 2007) — The gold standard for server compliance. Great tool, but it doesn't check browsers, telemetry, webcams, or anything desktop-related.

**[privacy.sexy](https://privacy.sexy)** (5k ⭐) — Generates hardening scripts for Windows/macOS/Linux. It's a script builder, not an auditor — it changes your system without telling you what's wrong first.

**NoID Privacy for Linux** — The only tool that audits both privacy and security on Linux desktops, with AI-powered remediation.

---

## 📥 Installation

### Requirements

| Requirement | Details |
|---|---|
| **OS** | Linux desktop — Fedora 39+, Ubuntu 22.04+, Debian 12+ |
| **Shell** | Bash 4+ (pre-installed on all supported distros) |
| **Privileges** | Root access (`sudo`) for comprehensive system checks |
| **Dependencies** | **None.** Pure Bash. No Python, Ruby, Node.js, or packages. |

### Option A: One-Liner (Recommended)

```bash
curl -fsSL https://github.com/NexusOne23/noid-privacy-linux/raw/main/noid-privacy-linux.sh -o noid-privacy-linux.sh
sudo bash noid-privacy-linux.sh --ai
```

### Option B: Git Clone

```bash
git clone https://github.com/NexusOne23/noid-privacy-linux.git
cd noid-privacy-linux
sudo bash noid-privacy-linux.sh --ai
```

### Option C: Download from Releases

Download the latest release from [GitHub Releases](https://github.com/NexusOne23/noid-privacy-linux/releases) and verify the checksum:

```bash
sha256sum noid-privacy-linux.sh
# Compare with the checksum in the release notes
```

---

## 🔧 Troubleshooting

### "Permission denied"

```bash
# Must run as root
sudo bash noid-privacy-linux.sh
```

### "bash: noid-privacy-linux.sh: No such file"

```bash
# Make sure you're in the right directory
ls -la noid-privacy-linux.sh

# Or use the full path
sudo bash ./noid-privacy-linux.sh
```

### Checks showing unexpected results?

```bash
# Run with debug output
sudo bash -x noid-privacy-linux.sh 2>debug.log

# Skip problematic sections
sudo bash noid-privacy-linux.sh --skip rootkit --skip bluetooth
```

### JSON output not valid?

```bash
# Validate JSON output
sudo bash noid-privacy-linux.sh --json | python3 -m json.tool > /dev/null
```

### Output too long for terminal?

```bash
# Save to file
sudo bash noid-privacy-linux.sh --no-color > report.txt

# Or use a pager
sudo bash noid-privacy-linux.sh 2>&1 | less -R
```

---

## ✅ Perfect For

| Audience | Why |
|---|---|
| **Privacy-conscious developers** | You run Linux daily and want to know what's leaking. You don't have time to manually check 300 things. |
| **Power users** | You've hardened your system before but want a second pair of eyes. NoID Privacy for Linux catches what you forgot. |
| **Small team leads** | You need a baseline for your team's Linux workstations. Run it, share the report, fix what's red. |
| **Linux newcomers** | You switched from Windows/Mac and want to know where you stand. Every FAIL comes with a clear explanation. |
| **Security consultants** | Quick desktop audit for clients. Professional output. AI-powered remediation saves hours. |

## ❌ Not Ideal For

| Audience | Why | Alternative |
|---|---|---|
| **Server administrators** | We focus on desktops, not data centers | [Lynis](https://cisofy.com/lynis/) |
| **Enterprise compliance** | No CIS/STIG reporting | [OpenSCAP](https://www.open-scap.org/) |
| **Automated remediation** | We audit, we don't modify | [privacy.sexy](https://privacy.sexy) |
| **Non-Linux systems** | Linux only | [NoID Privacy](https://github.com/NexusOne23/noid-privacy) (Windows) |

---

## 📈 Project Status

| | |
|---|---|
| **Version** | 3.0.0 |
| **Last Updated** | February 13, 2026 |
| **Status** | Production-Ready |
| **Script Size** | 3,661 lines |
| **Checks** | 300+ |
| **Sections** | 42 |
| **Dependencies** | Zero |
| **Supported Distros** | Fedora, RHEL, Ubuntu, Debian |

---

## ⚠️ What This Does NOT Protect Against

| Threat | Why |
|---|---|
| **Social engineering** | If you run malicious commands, no audit tool can save you |
| **Supply-chain attacks** | Malware in legitimate packages is beyond audit scope |
| **Physical access** | Stolen device without FDE — use LUKS! |
| **Nation-state actors** | Targeted attacks require dedicated security teams |
| **Zero-day exploits** | Unknown vulnerabilities can't be checked for |
| **Kernel exploits** | If the kernel is compromised, userspace tools can't detect it |

**NoID Privacy for Linux tells you what's wrong. Fixing it is up to you (or your AI assistant).**

---

## 🔄 How Often Should You Run It?

| Scenario | Frequency |
|---|---|
| After initial system setup | Once |
| After installing new software | As needed |
| After system updates | Monthly |
| Regular security hygiene | Weekly to monthly |
| After changing network/VPN config | Immediately |
| Before sharing your machine with others | Once |

**Pro tip:** Add it to a cron job for regular audits:
```bash
# Monthly audit saved to file
echo '0 9 1 * * root /path/to/noid-privacy-linux.sh --no-color > /var/log/noid-privacy-audit.txt 2>&1' | sudo tee /etc/cron.d/noid-privacy
```

---

## 🔗 Sister Project: NoID Privacy (Windows)

Looking for Windows 11 hardening? Check out our sister project:

**[NoID Privacy](https://github.com/NexusOne23/noid-privacy)** — Professional Windows 11 Security & Privacy Hardening Framework

- 630+ security settings across 7 modules
- Microsoft Security Baseline 25H2 implementation
- Full Backup → Apply → Verify → Restore pattern
- Production-ready since 2025

**Two operating systems. One mission: Your privacy.**

---

## 💬 Community & Support

| Channel | Purpose |
|---|---|
| [💬 Discussions](https://github.com/NexusOne23/noid-privacy-linux/discussions) | Questions, ideas, general chat |
| [🐛 Issues](https://github.com/NexusOne23/noid-privacy-linux/issues) | Bug reports and feature requests |
| [📖 Docs](Docs/CHECKS.md) | Complete check reference (all 42 sections) |
| [📋 Changelog](CHANGELOG.md) | Version history and release notes |
| [🔒 Security](SECURITY.md) | Report vulnerabilities privately |
| [☕ Buy Me a Coffee](https://buymeacoffee.com/noidprivacy) | Support development |

---

## 🙏 Acknowledgments

- The **Linux security community** for decades of hardening knowledge
- **[Lynis](https://cisofy.com/lynis/)** by CISOfy for pioneering Linux security auditing
- **[ShellCheck](https://www.shellcheck.net/)** for keeping our Bash clean
- The **Firefox** team for providing privacy-respecting defaults
- Everyone who runs `--ai` and shares their results to help improve the checks

---

## 📜 License

### Dual-License Model

#### 🆓 Open Source (GPL v3.0)

**For individuals, researchers, and open-source projects:**

This project is licensed under the **GNU General Public License v3.0**.

- ✅ Use freely for personal and commercial purposes
- ✅ Modify and distribute
- ⚠️ Derivatives must also be GPL v3.0
- ⚠️ Source code must be disclosed when distributing

[Read the full license →](LICENSE)

#### 💼 Commercial License

**For organizations that need to integrate without GPL requirements:**

Contact via [GitHub Discussions](https://github.com/NexusOne23/noid-privacy-linux/discussions) for commercial licensing options.

---

## 🤝 Contributing

Contributions welcome! Whether it's a new check, a bug fix, or distro support.

- 📖 **[Contributing Guide](CONTRIBUTING.md)** — How to add checks, code style, testing
- 🐛 **[Bug Reports](https://github.com/NexusOne23/noid-privacy-linux/issues)** — Found a false positive?
- ✨ **[Feature Requests](https://github.com/NexusOne23/noid-privacy-linux/issues)** — Missing a check?
- 💬 **[Discussions](https://github.com/NexusOne23/noid-privacy-linux/discussions)** — Questions and ideas
- 🔒 **[Security Policy](SECURITY.md)** — Report vulnerabilities privately

---

<div align="center">

**[⭐ Star this repo](https://github.com/NexusOne23/noid-privacy-linux)** if you find it useful — it helps others find the project.

**NoID Privacy for Linux** — *Know your system. Harden your privacy.*

[noid-privacy.com/linux](https://noid-privacy.com/linux) · Built with 🛡️ for the Linux desktop community

</div>
