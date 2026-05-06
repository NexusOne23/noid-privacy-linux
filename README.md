<div align="center">

# 🛡️ NoID Privacy for Linux

### Hardening Posture Audit for Linux Desktops

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](https://github.com/NexusOne23/noid-privacy-linux/blob/main/LICENSE)
[![Version](https://img.shields.io/badge/version-3.6.2-green.svg)](https://github.com/NexusOne23/noid-privacy-linux/releases)
[![Pure Bash](https://img.shields.io/badge/pure-bash-4EAA25.svg?logo=gnu-bash&logoColor=white)](https://github.com/NexusOne23/noid-privacy-linux)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](https://github.com/NexusOne23/noid-privacy-linux)
[![Checks](https://img.shields.io/badge/checks-420%2B-orange.svg)](https://github.com/NexusOne23/noid-privacy-linux)
[![CI](https://github.com/NexusOne23/noid-privacy-linux/actions/workflows/ci.yml/badge.svg)](https://github.com/NexusOne23/noid-privacy-linux/actions)
[![GitHub Stars](https://img.shields.io/github/stars/NexusOne23/noid-privacy-linux?style=flat&logo=github)](https://github.com/NexusOne23/noid-privacy-linux/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/NexusOne23/noid-privacy-linux?style=flat)](https://github.com/NexusOne23/noid-privacy-linux/commits)
[![Website](https://img.shields.io/badge/Website-noid--privacy.com-0078D4?style=flat)](https://noid-privacy.com)

**420+ checks · 42 sections · Pure Bash · AI-friendly remediation prompts**
**Optimized for Fedora/RHEL · Tested on Ubuntu/Debian · Best-effort on Arch/openSUSE/Mint/Pop!_OS**

[Quick Start](#-quick-start) · [What it Checks](#-what-it-checks) · [AI Fixes](#-fix-with-ai) · [Comparison](#-comparison) · [Discussions](https://github.com/NexusOne23/noid-privacy-linux/discussions)

</div>

---

## ⚡ Quick Start

```bash
curl -fsSL https://github.com/NexusOne23/noid-privacy-linux/raw/main/noid-privacy-linux.sh -o noid-privacy-linux.sh
sudo bash noid-privacy-linux.sh --ai
```

420+ privacy & security checks. Zero dependencies. The `--ai` flag generates a ready-to-paste prompt — hand it to ChatGPT, Claude, or Gemini to **fix every finding automatically**.

> **This tool is read-only.** It does not modify your system. No files changed, no configs touched, no services restarted.

> **🪟 Running Windows too?** [NoID Privacy for Windows](https://noid-privacy.com) hardens **630+ settings** with full Backup → Apply → Verify → Restore. One-time purchase, no subscription.

---

## 🎯 Scope — What this IS / NOT

NoID is a **hardening posture audit** — it verifies your defense foundation is properly applied. The score reflects configuration state, not compromise resistance.

| ✅ This tool **does** | ❌ This tool does **not** |
|---|---|
| Verify hardening recipes are applied | Replace an Intrusion Detection System |
| Detect privacy misconfigurations | Scan for active rootkits (use AIDE/IMA/chkrootkit) |
| Report drift from secure baselines | Find vulnerabilities (use OSV/Lynis-CVE) |
| Generate AI-ready remediation prompts | Perform penetration testing (use OpenVAS/Nessus) |
| Audit 42 desktop-specific surfaces | Behavioral / memory-only malware detection |

**A 98% score means hardening recipes are well-applied — not that the system is unhackable.** Defense in depth requires complementary layers:

- **Layer 1** ✅ Configuration Hardening *(this tool)*
- **Layer 2** ➕ Integrity Detection *(AIDE, IMA, chkrootkit)*
- **Layer 3** ➕ Behavioral Monitoring *(auditd, EDR)*

Configuration is the foundation. The other layers detect what hardening cannot prevent.

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
| **MAC & Integrity** | SELinux/AppArmor (auto-detected), rootkit scans, AIDE/Tripwire, package verification |
| **Updates & Packages** | Security patches, auto-updates, repo integrity, GPG verification (dnf/apt/pacman/zypper) |
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

  NoID Privacy for Linux v3.6.2 — Hardening Posture Audit for Linux Desktops
  YYYY-MM-DD HH:MM:SS | mydesktop | 6.19.x-200.fc43.x86_64
  Arch: x86_64 | Distro: Fedora Linux 43 (Workstation Edition)
  Checks: 420+ across 42 sections

━━━ [01/42] KERNEL & BOOT INTEGRITY ━━━
  ✅ PASS  Secure Boot: ENABLED
  ✅ PASS  Kernel Lockdown: integrity
  ✅ PASS  LUKS encryption active

━━━ [05/42] VPN & NETWORK ━━━
  ✅ PASS  VPN interface proton0: active
  ✅ PASS  Default route via VPN
  ✅ PASS  IPv6: disabled/minimal

━━━ [35/42] BROWSER PRIVACY ━━━
  ✅ PASS  Firefox telemetry disabled
  ✅ PASS  WebRTC disabled — no IP leak
  ⚠️  WARN  google-chrome installed — Google telemetry risk

━━━ SUMMARY ━━━
  Total checks:      420 (293 pass, 0 fail, 5 warn, 122 info)

  Hardening posture is your defense foundation — the layer
  attackers must defeat first. Complement with:
    ✓ AIDE / IMA   — file & kernel integrity
    ✓ auditd       — behavioral monitoring
    ✓ chkrootkit   — known-malware scanner

  HARDENING POSTURE SCORE:    98% 🏰 FULLY HARDENED

Score formula: PASS×100 / (PASS + FAIL×2 + WARN)
Exit codes:    0 = clean · 1 = FAIL present · 2 = WARN-only · 130/143 = interrupted
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
| **Tests** | 420+ | 480+ | N/A | varies |
| **Browser privacy** | ✅ | ❌ | ⚠️ Partial | ❌ |
| **App telemetry** | ✅ | ❌ | ✅ | ❌ |
| **DNS / VPN / MAC** | ✅ | ❌ | ❌ | ❌ |
| **Webcam / Bluetooth** | ✅ | ❌ | ❌ | ❌ |
| **AI-ready output** | ✅ | ❌ | ❌ | ❌ |
| **JSON output** | ✅ | ✅ | N/A | ❌ |
| **Kernel & firewall** | ✅ | ✅ | ⚠️ Partial | ✅ |
| **Zero compiled dependencies** | ✅ | ✅ | ❌ | ❌ |
| **Desktop-focused** | ✅ | ❌ | ✅ | ❌ |
| **Modifies system** | ❌ | ❌ | ✅ | ❌ |

**[Lynis](https://cisofy.com/lynis/)** (15k ⭐, since 2007) — Gold standard for server compliance. Doesn't cover browser privacy, telemetry, webcams, or desktop-specific concerns.

**[privacy.sexy](https://privacy.sexy)** (5k ⭐) — Script generator for Windows/macOS/Linux. Modifies your system directly without auditing first.

---

## 📥 Installation

| Requirement | Details |
|---|---|
| **OS** | Fedora 39+, Ubuntu 22.04+, Debian 12+, RHEL 9+, Arch Linux, openSUSE, Mint, Pop!_OS |
| **Shell** | Bash 4.3+ |
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

## 🚀 GitHub Action

Use NoID Privacy for Linux in your CI/CD pipeline to enforce privacy & security baselines:

```yaml
- name: Hardening Posture Audit
  # SECURITY: Pin to specific version, never @main (supply chain risk)
  uses: NexusOne23/noid-privacy-linux@v3.6.2
  id: audit
  with:
    min-score: '70'   # Fail if score < 70%
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `min-score` | `0` | Minimum score to pass (0 = never fail). |
| `fail-threshold` | `''` | DEPRECATED alias for `min-score`. Use `min-score` in new workflows. |
| `ai` | `false` | Generate AI remediation prompt in summary |
| `skip` | `''` | Comma-separated sections to skip |
| `args` | `''` | Additional arguments for the script |

### Outputs

| Output | Description |
|--------|-------------|
| `score` | Hardening posture score (0-100) |
| `total` | Total checks performed |
| `pass` / `fail` / `warn` / `info` | Check counts by severity |
| `json` | Full JSON output |

### Example: Fail PR if score drops

```yaml
name: Security Gate
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4.2.2
      - uses: NexusOne23/noid-privacy-linux@v3.6.2  # Pin to version, not @main
        with:
          min-score: '70'
```

Results appear as a rich **GitHub Actions Summary** with score, findings table, and optional AI fix prompt.

📖 See [`.github/workflows/example-noid-audit.yml`](.github/workflows/example-noid-audit.yml) for a full example.

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
- **Windows** → [NoID Privacy PRO](https://noid-privacy.com) — 630+ settings, full hardening framework

---

## 🔗 The NoID Privacy Ecosystem

| Platform | Link |
|----------|------|
| 🌐 **Website** | [NoID-Privacy.com](https://noid-privacy.com) — All platforms, pricing, and documentation |
| 🪟 **Windows** | [NoID Privacy PRO](https://noid-privacy.com) — 630+ settings, 7 modules, Backup → Apply → Verify → Restore |
| 🐧 **Linux** | You're here! |
| 📱 **Android** | [NoID Privacy on Google Play](https://play.google.com/store/apps/details?id=com.noid.privacy) — 81 checks, 10 categories, permission audit, Chrome hardening, anti-theft |

---

## 🔒 Privacy Promise

**No telemetry, no analytics, no phone-home.** This tool does not collect or transmit any data about you or your system. One file, pure Bash — read every line yourself.

> **⚠️ Default-mode network requests:** Three sections issue requests to third parties to test for connectivity/DNS/VPN leaks:
> - **Section 5 (vpn):** `curl detectportal.firefox.com` (Mozilla), `curl ifconfig.me` (Cloudflare-fronted)
> - **Section 5 (netleaks):** `dig whoami.akamai.net` (Akamai)
> - **Section 22 (interfaces):** `dig google.com` (Google)
>
> For a **fully offline audit** that makes zero outbound requests, use:
> ```bash
> sudo bash noid-privacy-linux.sh --skip vpn --skip interfaces --skip netleaks
> ```
> The leak tests themselves require these third-party endpoints to function — there's no way to test "does my IP leak?" without contacting an external service.

---

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| `Requires root` error | Run with `sudo bash noid-privacy-linux.sh` |
| False positive on a check | Open an [issue](https://github.com/NexusOne23/noid-privacy-linux/issues) with your distro and the finding |
| DNS leak test fails/hangs | Skip it: `--skip netleaks`. Requires `dig` and `curl`. |
| Score seems too low | Check if `--skip` sections are relevant to your setup. Desktop-only checks may warn on servers. |
| Script hangs on Bluetooth | Known `bluetoothctl` timeout issue. Skip: `--skip btprivacy` |
| Missing checks for my distro | Fedora/RHEL, Ubuntu/Debian, Arch, and openSUSE are fully supported. Other distros may show more `info` results. |

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
