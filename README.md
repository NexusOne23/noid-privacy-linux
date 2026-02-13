<div align="center">

<!-- LOGO PLACEHOLDER -->
<!-- <img src="assets/fortify-logo.svg" alt="NoID Privacy for Linux" width="400"> -->

# NoID Privacy for Linux

**Privacy & Security Audit for Linux Desktops**

*Know your system. Harden your privacy.*

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](https://github.com/NexusOne23/noid-privacy-linux/blob/main/LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0-green.svg)](https://github.com/NexusOne23/noid-privacy-linux/releases)
[![Pure Bash](https://img.shields.io/badge/pure-bash-4EAA25.svg?logo=gnu-bash&logoColor=white)](https://github.com/NexusOne23/noid-privacy-linux)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](https://github.com/NexusOne23/noid-privacy-linux)
[![Checks](https://img.shields.io/badge/checks-300%2B-orange.svg)](https://github.com/NexusOne23/noid-privacy-linux)
[![Fedora | Ubuntu | Debian](https://img.shields.io/badge/distros-Fedora%20%7C%20Ubuntu%20%7C%20Debian-informational.svg)](https://github.com/NexusOne23/noid-privacy-linux)

300+ checks · 42 sections · Zero dependencies · Pure Bash

[Install](#one-liner-install) · [What it Checks](#what-it-checks) · [Fix with AI](#fix-with-ai) · [Contributing](#contributing)

</div>

---

## One-Liner Install

```bash
curl -fsSL https://github.com/NexusOne23/noid-privacy-linux/raw/main/noid-privacy-linux.sh -o noid-privacy-linux.sh
sudo bash noid-privacy-linux.sh --ai
```

The `--ai` flag generates a ready-to-paste prompt at the end — hand it to ChatGPT, Claude, or Gemini to fix every finding.

Or clone:

```bash
git clone https://github.com/NexusOne23/noid-privacy-linux.git
cd noid-privacy-linux
sudo bash noid-privacy-linux.sh --ai
```

<!-- DEMO GIF HERE -->
<!-- Replace with asciinema recording: asciinema rec demo.cast -->
<!-- [![asciicast](https://asciinema.org/a/XXXXX.svg)](https://asciinema.org/a/XXXXX) -->

---

## Why NoID Privacy for Linux?

Most Linux security tools were built for servers. They check SSH configs and firewall rules — but ignore the browser leaking your DNS queries, the apps phoning home, or the webcam that's accessible to every process.

NoID Privacy for Linux audits what actually matters on a desktop:

- **Privacy + Security in one tool.** Browser tracking, app telemetry, DNS leaks, VPN kill-switches — alongside kernel hardening, firewall, encryption, and rootkit detection.
- **Zero dependencies.** Pure Bash. No Python, no Ruby, no package managers. Download and run.
- **Built for desktops, not data centers.** Session security, Bluetooth exposure, webcam access, keyring configuration, Flatpak permissions — things Lynis has never heard of.
- **Human-readable output.** PASS/FAIL/WARN with clear explanations. No compliance jargon, no 200-page PDF.

---

## What it Checks

### 🔒 Privacy

| Category | Examples |
|---|---|
| **Browser Privacy** | Firefox/Chrome telemetry, tracking protection, WebRTC leaks, DNS-over-HTTPS, cookie policy, extension auditing |
| **App Telemetry** | GNOME telemetry, crash reporters, Flatpak permissions, analytics opt-outs |
| **Network Privacy** | DNS leak testing, DNS-over-HTTPS, MAC randomization, mDNS exposure, IPv6 privacy extensions |
| **Data Privacy** | Recent file tracking, thumbnail caches, clipboard managers, core dumps, swap encryption |

### 🛡️ Security

| Category | Examples |
|---|---|
| **Kernel Hardening** | ASLR, kernel pointer hiding, dmesg restriction, unprivileged BPF, core dump limits |
| **Firewall** | iptables/nftables rules, default policies, open port audit, zone configuration |
| **VPN** | Connection status, kill-switch detection, DNS leak testing, default route validation |
| **SSH** | Key-only auth, root login, protocol version, port, password authentication |
| **Encryption** | LUKS full-disk encryption, cipher strength, swap encryption, entropy |
| **SELinux/AppArmor** | Enforcing mode, policy status, confined processes |
| **Rootkit Detection** | Suspicious files, hidden processes, known rootkit signatures |
| **Updates** | Pending security patches, automatic update configuration, repo integrity |

### 🖥️ Desktop

| Category | Examples |
|---|---|
| **Session Security** | Screen lock timeout, auto-login, idle detection, Wayland vs X11 isolation |
| **Webcam & Microphone** | Device permissions, access controls, kernel module status |
| **Bluetooth** | Discoverability, paired devices, default agent settings |
| **Keyring** | GNOME Keyring auto-unlock, password manager detection, SSH key config, plaintext secrets |
| **Flatpak** | Sandbox permissions, dangerous filesystem access |
| **Firmware** | fwupd update status, Thunderbolt DMA protection |

---

## Sample Output

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

## Quick Start

### Requirements

- Linux desktop (Fedora, RHEL, Debian, Ubuntu)
- Bash 4+
- Root access (`sudo`)

That's it. No other dependencies.

### Installation

**Option A — One-liner:**
```bash
curl -fsSL https://github.com/NexusOne23/noid-privacy-linux/raw/main/noid-privacy-linux.sh -o noid-privacy-linux.sh && sudo bash noid-privacy-linux.sh
```

**Option B — Git clone:**
```bash
git clone https://github.com/NexusOne23/noid-privacy-linux.git
cd noid-privacy-linux
```

### Usage

```bash
# Full audit
sudo bash noid-privacy-linux.sh

# Skip specific sections
sudo bash noid-privacy-linux.sh --skip bluetooth --skip keyring

# Disable colored output
sudo bash noid-privacy-linux.sh --no-color

# Show all options
sudo bash noid-privacy-linux.sh --help
```

---

## Fix with AI

NoID Privacy for Linux tells you what's wrong. Your AI assistant fixes it.

### Option A: Copy & Paste
```bash
sudo bash noid-privacy-linux.sh --no-color > report.txt
```
Copy the output and paste it to ChatGPT, Claude, Gemini, or any AI assistant with:
> "Here's my NoID Privacy for Linux audit. Help me fix the FAILs and WARNs. Explain each fix and ask before changing anything."

### Option B: AI-Ready Prompt
```bash
sudo bash noid-privacy-linux.sh --ai
```
Generates a ready-to-paste prompt at the end of the scan with all findings formatted for your AI assistant.

### Option C: Machine-Readable
```bash
sudo bash noid-privacy-linux.sh --json | your-tool
```
JSON output for scripts, dashboards, or AI agent pipelines.

---

## Comparison

| Feature | NoID Privacy for Linux | Lynis | privacy.sexy | CIS Benchmark |
|---|:---:|:---:|:---:|:---:|
| Browser privacy checks | ✅ | ❌ | ⚠️ partial | ❌ |
| App telemetry detection | ✅ | ❌ | ✅ | ❌ |
| DNS leak testing | ✅ | ❌ | ❌ | ❌ |
| VPN kill-switch detection | ✅ | ❌ | ❌ | ❌ |
| Webcam/Bluetooth audit | ✅ | ❌ | ❌ | ❌ |
| Kernel hardening | ✅ | ✅ | ⚠️ partial | ✅ |
| Firewall audit | ✅ | ✅ | ❌ | ✅ |
| Rootkit detection | ✅ | ⚠️ checks tools | ❌ | ❌ |
| Zero dependencies | ✅ | ✅ | ❌ (Electron) | ❌ |
| Human-readable output | ✅ | ⚠️ | N/A | ❌ |
| Desktop-focused | ✅ | ❌ | ✅ | ❌ |
| Audits (not modifies) system | ✅ | ✅ | ❌ (generates scripts) | ❌ (manual) |

**Lynis** (15k ⭐, since 2007) is the standard for server compliance. Pure shell, great tool — but it doesn't check browsers, telemetry, or anything desktop-related. It checks if rootkit scanners are installed but doesn't run them.

**privacy.sexy** (5k ⭐) generates hardening scripts for Windows, macOS and Linux. It's a script builder, not an auditor — it changes your system, it doesn't tell you what's wrong.

**NoID Privacy for Linux** is the only tool that audits both privacy and security on Linux desktops.

---

## Who Is This For?

**Privacy-conscious developer** — You run Linux as your daily driver and want to know what's leaking. You don't have time to manually check 300 things.

**Power user** — You've hardened your system before but want a second pair of eyes. NoID Privacy for Linux catches the things you forgot.

**Small team lead** — You need a baseline for your team's Linux workstations. Run NoID Privacy for Linux, share the report, fix what's red.

**Linux newcomer** — You switched from Windows/Mac and want to know where you stand. Every FAIL comes with a clear explanation of what to do.

---

## Contributing

Contributions welcome. Here's how:

1. Fork the repo
2. Create a branch (`git checkout -b fix/browser-check`)
3. Make your changes
4. Test on at least one supported distro
5. Submit a PR

**Good first contributions:**
- Add checks for a new application's telemetry
- Improve detection for your distro
- Fix false positives
- Improve documentation

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting.

---

## License

[GPL-3.0](LICENSE) — Free as in freedom.

---

<div align="center">

**[⭐ Star NoID Privacy for Linux on GitHub](https://github.com/NexusOne23/noid-privacy-linux)** — it helps others find the project.

*Built by [Clawde](https://github.com/ClawdeRaccoon) 🦝 · [noid-privacy.com/linux](https://noid-privacy.com/linux)*

</div>
