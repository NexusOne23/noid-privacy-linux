# 🛠️ Contributing to NoID Privacy for Linux

Thank you for your interest in contributing to NoID Privacy for Linux! This guide will help you get started.

---

## 📋 Table of Contents

1. [Getting Started](#getting-started)
2. [Development Setup](#development-setup)
3. [Code Architecture](#code-architecture)
4. [Adding a New Check](#adding-a-new-check)
5. [Adding a New Section](#adding-a-new-section)
6. [Code Style](#code-style)
7. [Testing](#testing)
8. [Submitting Changes](#submitting-changes)
9. [Good First Contributions](#good-first-contributions)
10. [Reporting Issues](#reporting-issues)

---

## 🚀 Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/noid-privacy-linux.git
   cd noid-privacy-linux
   ```
3. **Create a branch:**
   ```bash
   git checkout -b fix/your-change
   ```
4. Make your changes
5. **Test** on at least one supported distro
6. **Submit** a Pull Request

---

## 💻 Development Setup

### Requirements

- Linux desktop (Fedora 43+, Ubuntu 24.04+, Debian 12+)
- Bash 4+
- Root access for testing (`sudo`)
- Optional but recommended: [ShellCheck](https://www.shellcheck.net/)

### Quick Validation

```bash
# Syntax check (must pass)
bash -n noid-privacy-linux.sh

# ShellCheck (recommended)
shellcheck --severity=warning noid-privacy-linux.sh

# Full test run
sudo bash noid-privacy-linux.sh

# Test with all flags
sudo bash noid-privacy-linux.sh --ai
sudo bash noid-privacy-linux.sh --json > /dev/null
sudo bash noid-privacy-linux.sh --no-color
sudo bash noid-privacy-linux.sh --skip browser --skip bluetooth
```

---

## 🏗️ Code Architecture

### Single-File Design

NoID Privacy for Linux is intentionally a **single Bash script** (`noid-privacy-linux.sh`). This makes it:
- Easy to download and run (one `curl` command)
- Easy to audit (one file to read)
- Zero dependencies (no imports, no libraries)
- Portable across distributions

### Script Structure

```
noid-privacy-linux.sh
├── Header & Version
├── Color Definitions & Globals
├── Helper Functions (pass, fail, warn, info, header, etc.)
├── CLI Argument Parsing (--ai, --json, --skip, --no-color, --help)
├── System Detection (distro, desktop, init system)
│
├── Security Sections (01-34)
│   ├── 01: Kernel & Boot Integrity
│   ├── 02: SELinux / AppArmor
│   ├── 03-04: Firewall & nftables
│   ├── 05: VPN & Network
│   ├── ...
│   └── 34: System Integrity Checks
│
├── Privacy & Desktop Sections (35-42)
│   ├── 35: Browser Privacy
│   ├── 36: Application Telemetry
│   ├── 37: Network Privacy
│   ├── 38: Data & Disk Privacy
│   ├── 39: Desktop Session Security
│   ├── 40: Webcam & Audio Privacy
│   ├── 41: Bluetooth Privacy
│   └── 42: Password & Keyring Security
│
├── Summary & Score Calculation
└── AI Prompt Generation (--ai flag)
```

### Helper Functions

| Function | Purpose | Example |
|----------|---------|---------|
| `pass "msg"` | Green ✅ PASS result | `pass "Secure Boot: ENABLED"` |
| `fail "msg"` | Red ❌ FAIL result | `fail "Root login allowed via SSH"` |
| `warn "msg"` | Yellow ⚠️ WARN result | `warn "Bluetooth discoverable"` |
| `info "msg"` | Blue ℹ️ INFO result | `info "Kernel: 6.18.9"` |
| `header "N" "TITLE"` | Section header | `header "01" "KERNEL & BOOT"` |

### Counters

The script tracks results via global counters:
- `PASS`, `FAIL`, `WARN`, `INFO`
- These are used to calculate the final score

---

## ✅ Adding a New Check

### 1. Find the Right Section

Look at the existing 42 sections and find where your check fits. For example:
- Browser telemetry → Section 35 (Browser Privacy)
- New sysctl check → Section 06 (Kernel Hardening)
- New service check → Section 07 (Services & Daemons)

### 2. Write the Check

```bash
# Check if something is configured securely
if [ -f /etc/some-config ]; then
    if grep -q "^secure_setting=yes" /etc/some-config; then
        pass "Some feature is securely configured"
    else
        fail "Some feature is not configured — risk of X"
    fi
else
    info "Some feature config not found (not installed)"
fi
```

### 3. Follow These Rules

- **Handle missing files/commands gracefully** — use `[ -f file ]` or `command -v`
- **Quote all variables** — `"$var"`, not `$var`
- **Support both distro families** — Fedora/RHEL and Debian/Ubuntu
- **Use clear, actionable messages** — tell the user what's wrong AND why it matters
- **Don't modify the system** — read-only checks only!

### 4. Example: Complete Check

```bash
# Check NetworkManager MAC randomization
if command -v nmcli &>/dev/null; then
    wifi_rand=$(nmcli -t -f wifi.scan-rand-mac-address connection show 2>/dev/null | head -1)
    if [[ "$wifi_rand" == *"yes"* ]]; then
        pass "WiFi scan MAC randomization enabled"
    else
        warn "WiFi scan MAC randomization disabled — device trackable across networks"
    fi
else
    info "NetworkManager not found — skipping MAC randomization check"
fi
```

---

## 📦 Adding a New Section

If your checks don't fit any existing section, you can propose a new one:

1. **Increment the section count** in the header
2. **Add the section function:**
   ```bash
   check_your_section() {
       header "43" "YOUR SECTION NAME"
       # ... your checks ...
   }
   ```
3. **Add the `--skip` keyword** in the argument parser
4. **Call the function** in the execution flow
5. **Update `TOTAL_SECTIONS`** constant
6. **Update documentation** (README, Docs/CHECKS.md)

---

## 🎨 Code Style

### General Rules

- **Pure Bash.** No external dependencies (Python, Ruby, Node.js, etc.)
- **Quote all variables.** `"$var"`, not `$var`
- **Use `[[` for conditionals** (Bash-specific, safer than `[`)
- **Use `command -v`** instead of `which` for command detection
- **Use `&>/dev/null`** for suppressing output
- **Use `printf` instead of `echo -e`** for portable colored output
- **4-space indentation** (no tabs)
- **Max line length:** 120 characters (soft limit)
- **ShellCheck must pass.** Run `shellcheck --severity=warning noid-privacy-linux.sh` before submitting. CI enforces this.

### Naming Conventions

| Type | Convention | Example |
|------|-----------|---------|
| Functions | `snake_case` | `check_browser_privacy` |
| Variables | `UPPER_CASE` | `PASS_COUNT` |
| Local vars | `lower_case` | `kernel_version` |
| Sections | `check_*` | `check_network_privacy` |

### Do's and Don'ts

```bash
# ✅ DO: Quote variables
if [ -f "$config_file" ]; then

# ❌ DON'T: Unquoted variables
if [ -f $config_file ]; then

# ✅ DO: Handle missing commands
if command -v nmcli &>/dev/null; then

# ❌ DON'T: Assume commands exist
nmcli connection show

# ✅ DO: Use process substitution for counters
while IFS= read -r line; do
    ...
done < <(some_command)

# ❌ DON'T: Pipe into while (loses counter updates)
some_command | while read -r line; do
    ...
done

# ✅ DO: Clear, actionable messages
fail "SSH root login enabled — disable with 'PermitRootLogin no' in /etc/ssh/sshd_config"

# ❌ DON'T: Vague messages
fail "SSH config insecure"
```

---

## 🧪 Testing

### Minimum Testing Requirements

Before submitting a PR, test on **at least one** supported distro:

```bash
# 1. Syntax check (MUST pass)
bash -n noid-privacy-linux.sh

# 2. Full audit run
sudo bash noid-privacy-linux.sh

# 3. AI prompt generation
sudo bash noid-privacy-linux.sh --ai

# 4. JSON output
sudo bash noid-privacy-linux.sh --json | python3 -m json.tool > /dev/null

# 5. Skip your section
sudo bash noid-privacy-linux.sh --skip YOUR_SECTION

# 6. No-color mode
sudo bash noid-privacy-linux.sh --no-color
```

### Cross-Distro Testing

If you can, test on both families:
- **Fedora/RHEL**: Different package manager (dnf), SELinux, firewalld
- **Ubuntu/Debian**: Different package manager (apt), AppArmor, ufw

### ShellCheck

```bash
# Install
sudo dnf install ShellCheck     # Fedora
sudo apt install shellcheck     # Ubuntu/Debian

# Run
shellcheck --severity=warning noid-privacy-linux.sh
```

---

## 📤 Submitting Changes

### Pull Request Process

1. **Push** your branch to your fork
2. **Create a PR** against `main`
3. **Fill out the PR template** completely
4. **Wait for CI** — syntax check must pass
5. **Address review comments** if any

### Commit Messages

Use clear, descriptive commit messages:

```
✅ Add Firefox Enhanced Tracking Protection check (Section 35)
🐛 Fix false positive for systemd-resolved DNS (Section 37)
📝 Update CHECKS.md with new section documentation
🔧 Refactor kernel hardening checks for readability
🐧 Add Arch Linux support for package update checks
```

### What Makes a Good PR

- **One logical change per PR** — don't mix bug fixes with new features
- **Tested on at least one distro** — include test results
- **CHANGELOG.md updated** — document your change
- **Documentation updated** — if adding sections or flags

---

## 🎯 Good First Contributions

Looking for something to work on? Here are some ideas:

### 🟢 Easy

- Add telemetry detection for a specific application (VS Code, Spotify, etc.)
- Improve an existing check's error message
- Fix a false positive you've encountered
- Add a missing `--skip` keyword
- Improve documentation or examples

### 🟡 Medium

- Add checks for a new application category
- Improve detection for your distro (Arch, openSUSE, etc.)
- Add JSON output support for a section that's missing it
- Write better detection for desktop environments (KDE, XFCE)

### 🔴 Advanced

- Add a new section with 5+ checks
- Support a new distro family (Arch, Alpine, etc.)
- Implement parallel check execution for performance
- Add HTML report output

---

## 🐛 Reporting Issues

### Bug Reports

- Include your **distro and version**
- Include the **relevant output** from the script
- If it's a **false positive**, explain why
- Use `bash -x noid-privacy-linux.sh 2>debug.log` for debug output

### Feature Requests

- Check if a similar request exists
- Explain the **use case** and **impact**
- If possible, suggest **implementation** details

---

## 📜 License

By contributing, you agree that your contributions will be licensed under **GPL-3.0**.

For commercial licensing inquiries, see [LICENSE](LICENSE) or contact via [GitHub Discussions](https://github.com/NexusOne23/noid-privacy-linux/discussions).

---

## 🔗 Related Projects

- **[NoID Privacy](https://github.com/NexusOne23/noid-privacy)** — Windows 11 Security & Privacy Hardening Framework (sister project)
- **[noid-privacy.com](https://noid-privacy.com)** — Project website

---

**Thank you for contributing to NoID Privacy for Linux!** Every check you add helps someone secure their desktop. 🛡️
