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
5. **Test** proportionately and record the exact environment
6. **Submit** a Pull Request

---

## 💻 Development Setup

### Requirements

- Linux desktop listed in the release-specific [support matrix](Docs/SUPPORT.md)
- Bash 4.3+ (negative array indices required)
- Root access for testing (`sudo`)
- Optional but recommended: [ShellCheck](https://www.shellcheck.net/)

### Quick Validation

```bash
# Syntax check (must pass)
bash -n noid-privacy-linux.sh

# ShellCheck (required at style level; this is the exact CI gate)
shellcheck --severity=style --shell=bash noid-privacy-linux.sh entrypoint.sh scripts/*.sh tests/test_helper.bash tests/unit/*.bats

# Regression and policy invariants
bash scripts/lint-api-usage.sh
bash scripts/coverage-report.sh
bats tests/unit/

# Full test run
sudo bash noid-privacy-linux.sh

# Test with all flags
sudo bash noid-privacy-linux.sh --ai
sudo bash noid-privacy-linux.sh --json > /dev/null
sudo bash noid-privacy-linux.sh --no-color
sudo bash noid-privacy-linux.sh --skip browser --skip btprivacy
```

---

## 🏗️ Code Architecture

### Single-File Design

The downloadable audit remains a **single Bash script**
(`noid-privacy-linux.sh`). The repository also contains tests, documentation,
the GitHub Action wrapper, and validation helpers. The single-script boundary
makes the audit:
- Easy to download and run (one `curl` command)
- Easy to audit (one file to read)
- Independent of a language package ecosystem or generated dependency tree
- Portable across distributions

The script invokes common operating-system utilities. Optional capabilities
such as `ss`, `nft`, `debsums`, `paccheck`, `chkrootkit`, or `fwupdmgr` are
detected at runtime; their absence can narrow evidence and must never be
mislabeled as a PASS.

### Script Structure

```
noid-privacy-linux.sh
├── Header & Version
├── Color Definitions & Globals
├── Severity Emitters (_emit_pass / _emit_fail / _emit_warn / _emit_info)
├── PASS-Aggregator (_emit_pass_agg_start / _emit_pass_agg / _emit_pass_agg_end)
├── Capability Detection Layer (_detect_capabilities, _CAPS, _fw_get_policies)
├── CLI Argument Parsing (--ai, --json, --verbose, --cis-l1/-l2, --stig, --skip, --no-color, --version, --help)
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
├── Firmware & Thunderbolt block (HSI level + TB device security)
├── section-risk-v1 Score + Coverage Calculation
├── Compliance Coverage block (--cis-l1/-l2/--stig)
└── AI Prompt Generation (--ai flag)
```

### Helper Functions

| Function | Purpose | Example |
|----------|---------|---------|
| `_emit_pass "msg"` | Green ✅ PASS result | `_emit_pass "Secure Boot: ENABLED"` |
| `_emit_fail "msg"` | Red ❌ FAIL result | `_emit_fail "Root login allowed via SSH"` |
| `_emit_warn "msg"` | Yellow ⚠️ WARN result | `_emit_warn "Bluetooth discoverable"` |
| `_emit_info "msg"` | Blue ℹ️ INFO result | `_emit_info "Kernel: 6.18.9"` |
| `_emit_pass_agg_start "Label"` | Begin a PASS-aggregation block | `_emit_pass_agg_start "Boot hardening"` |
| `_emit_pass_agg "item"` | Emit one item (collapsed in default, detailed in --verbose/--json) | `_emit_pass_agg "init_on_alloc=1"` |
| `_emit_pass_agg_end N "noun"` | Close block, emit summary | `_emit_pass_agg_end 7 "effective controls"` |
| `header "N" "TITLE"` | Section header | `header "01" "KERNEL & BOOT"` |
| `_fw_get_policies` | Capability-aware firewalld policy lister | `FWD_POLICIES=$(_fw_get_policies)` |
| `_service_masked_any svc1 svc2` | Returns 0 if any service is masked | `_service_masked_any sshd ssh` |

> **Naming convention**: all emitters are underscore-prefixed
> (`_emit_*`) to prevent name-collision with CLI tools like `pass`
> (password-store) or `info` (texinfo). The lint script
> `scripts/lint-api-usage.sh` rejects bare-name reintroduction.

### Counters

The script tracks emitted findings via global counters:
- `PASS`, `FAIL`, `WARN`, `INFO`
- These are reporting totals, **not score inputs**
- The PASS-aggregator increments `PASS` per item even when display is collapsed

The score uses the worst assessed severity in each fixed-weight section. New
loop iterations therefore cannot inflate posture. Read
[Docs/SCORING.md](Docs/SCORING.md) before changing severities, section keys,
weights, ratings, or coverage.
Review [Docs/REFERENCE_REVIEW.md](Docs/REFERENCE_REVIEW.md) before importing a
control from another scanner or benchmark.

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
if [[ -f /etc/some-config ]]; then
    if grep -q "^secure_setting=yes" /etc/some-config; then
        _emit_pass "Some feature is securely configured"
    else
        _emit_fail "Some feature is not configured — risk of X"
    fi
else
    _emit_info "Some feature config not found (not installed)"
fi
```

### 3. Follow These Rules

- **Handle missing files/commands gracefully** — use `[[ -f file ]]` or `command -v`
- **Quote all variables** — `"$var"`, not `$var`
- **Do not generalize one distro's path or default** — add fixtures for every
  claimed parser/configuration branch
- **PASS only on affirmative evidence** — missing tools, permission failures,
  timeouts, stale metadata, and ambiguous output are INFO/WARN as documented
- **Choose severity by impact and confidence** — an operational count or
  heuristic name match is not automatically a security failure
- **Use clear, actionable messages** — state the observation and risk without
  claiming compromise, compliance, or universal policy
- **Don't remediate or refresh state by default** — any stateful opt-in must be explicit, narrowly scoped, documented, permission-safe, and tested
- **Bound slow/external commands** and preserve exit status, partial-output,
  and timeout semantics. A timed-out scan cannot emit a clean PASS.
- **Minimize network disclosure** — every new endpoint must be necessary,
  documented, bounded, and suppressed by `--offline`
- **Force `LC_ALL=C`** when grepping translatable command output (`chage -l`,
  `bluetoothctl`, `fwupdmgr`, `journalctl --disk-usage`). The lint script
  enforces this for known offenders.
- **Use `$_VPN_IFACE_REGEX`** for VPN-interface detection — never hand-write
  the family list. New VPN tools propagate via the global definition.
- **Use `_fw_get_policies` / `_service_masked_any`** instead of raw API calls
  when the capability layer covers the operation. Direct calls trip the lint.

### 4. Example: Complete Check

```bash
# Parse the effective value, not merely the presence of a matching line.
if effective_value=$(read_effective_setting 2>/dev/null); then
  case "$effective_value" in
    enabled)  _emit_pass "Example control: enabled" ;;
    disabled) _emit_warn "Example control: disabled — explain the bounded risk" ;;
    *)        _emit_info "Example control: effective value is not understood" ;;
  esac
else
  _emit_info "Example control: effective value is unavailable"
fi
```

---

## 📦 Adding a New Section

If your checks don't fit any existing section, you can propose a new one:

1. **Add the section function with skip-gate and header:**
   ```bash
   check_your_section() {
       should_skip "yourkey" && return
       header "43" "YOUR SECTION NAME"
       # ... your checks ...
   }
   ```
2. **Append the skip keyword to `SECTION_KEYS` and assign a reviewed weight.**
   The weights must remain unique by key and sum to exactly 100. Changing the
   model requires documentation, tests, and normally a new model identifier.
3. **Call the function** in the execution flow at the bottom of the script
4. **Update documentation** (`README.md` skip-list, `Docs/CHECKS.md`,
   `Docs/CIS_RHEL9_MAPPING.md` if compliance-relevant)
5. **Add BATS regression tests** for secure, insecure, absent, malformed,
   overridden, permission-denied, and timeout states that apply. The API lint's
   11 pattern classes are a floor, not a reason to omit semantic tests.
6. **Update `--help`** skip-keyword list (alphabetical inside its tier
   — see existing format)

---

## 🎨 Code Style

### General Rules

- **Pure Bash implementation.** Do not add a language runtime or package-manager
  dependency to the downloadable audit; normal OS utilities remain capability-
  detected external commands.
- **Quote all variables.** `"$var"`, not `$var`
- **Use `[[` for conditionals** (Bash-specific, safer than `[`)
- **Use `command -v`** instead of `which` for command detection
- **Use `&>/dev/null`** for suppressing output
- **Use `printf` instead of `echo -e`** for portable colored output
- **2-space indentation** (no tabs)
- **Max line length:** 120 characters (soft limit)
- **ShellCheck must pass at style level.** Run the complete command from Quick
  Validation before submitting. Function-scoped `SC2317` exceptions are
  permitted only when a trap, callback, or Bats runtime invokes the function by
  name and the call is covered by an executable test; do not use a repository-
  wide exclusion.

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
if [[ -f "$config_file" ]]; then

# ❌ DON'T: Unquoted variables or single brackets
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
_emit_fail "SSH root login enabled — disable with 'PermitRootLogin no' in /etc/ssh/sshd_config"

# ❌ DON'T: Vague messages
_emit_fail "SSH config insecure"
```

---

## 🧪 Testing

### Minimum Testing Requirements

Before submitting a PR, run all static/unit gates and a proportionate real
audit. Changes to distro, desktop, package-manager, PAM, display-manager,
filesystem, or scoring logic require the affected support-matrix environments;
one unrelated distro is not sufficient evidence.

```bash
# 1. Syntax check (MUST pass)
bash -n noid-privacy-linux.sh

# 2. Static policy, compliance mapping, and unit tests
bash scripts/lint-api-usage.sh
bash scripts/coverage-report.sh
bats tests/unit/

# 3. Full audit run
sudo bash noid-privacy-linux.sh

# 4. AI prompt generation
sudo bash noid-privacy-linux.sh --ai

# 5. JSON output and scoring schema
sudo bash noid-privacy-linux.sh --json | jq -e . > /dev/null

# 6. Verbose mode (per-item PASS detail)
sudo bash noid-privacy-linux.sh --verbose

# 7. Compliance flag (Coverage block at end)
sudo bash noid-privacy-linux.sh --cis-l1

# 8. Skip your section and verify score coverage decreases as expected
sudo bash noid-privacy-linux.sh --skip YOUR_SECTION

# 9. Offline and no-color modes
sudo bash noid-privacy-linux.sh --offline
sudo bash noid-privacy-linux.sh --no-color
```

### Cross-Distro Testing

If you can, test on both families:
- **Fedora/RHEL**: Different package manager (dnf), SELinux, firewalld
- **Ubuntu/Debian**: Different package manager (apt), AppArmor, ufw

CI's container matrix is explicitly a syntax-compatibility gate, not desktop
validation. The real-run smoke job checks JSON/score consistency, and the
3-locale matrix covers locale-sensitive parsing. Release claims require the
separate VM evidence recorded in [Docs/SUPPORT.md](Docs/SUPPORT.md).

### ShellCheck + API-Lint

```bash
# Install ShellCheck
sudo dnf install ShellCheck     # Fedora
sudo apt install shellcheck     # Ubuntu/Debian

# Run the exact CI gate
shellcheck --severity=style --shell=bash noid-privacy-linux.sh entrypoint.sh scripts/*.sh tests/test_helper.bash tests/unit/*.bats

# Run the API-layer / bug-pattern lint (CI gate)
bash scripts/lint-api-usage.sh noid-privacy-linux.sh
```

The 11-pattern lint enforces:

1. No direct firewalld policy API calls (use `_fw_get_policies`)
2. No `systemctl is-masked` (use `_service_masked_any`)
3. No `grep -r` on `/etc/pam.d` (use `-R` for symlinks)
4. No bare `pass()/fail()/warn()/info()` definitions
5. No `chage -l` without `LC_ALL=C`
6. No hardcoded VPN-iface regex (use `$_VPN_IFACE_REGEX`)
7. No `df -T … awk NR==2` (use `findmnt -no FSTYPE`)
8. No `fwupdmgr`/`bluetoothctl` invocation without `LC_ALL=C`
9. No `((var<op>))` arithmetic-command counters — use `var=$((var + N))` form
   (F-291 + F-306: `((var++))` returns rc=1 when result==0, bombs under `set -e`)
10. No `systemd-analyze`/`virsh`/`resolvectl`/`free` invocation without `LC_ALL=C`
    (F-298 + F-307: locale-translatable labels silently break parsing)
11. No unanchored `grep nameserver` on `/etc/resolv.conf` — must anchor
    `^[[:space:]]*nameserver[[:space:]]` (F-296: matches commented entries
    reported as active DNS servers)

### BATS Unit Tests

Install bats and run:

```bash
sudo dnf install bats           # Fedora
sudo apt install bats           # Ubuntu/Debian

bats tests/unit/
```

When fixing a bug-class regression, add a fixture under
`tests/fixtures/` and a `.bats` test under `tests/unit/`. See
`tests/README.md` for the layout convention.

---

## 📤 Submitting Changes

### Pull Request Process

1. **Push** your branch to your fork
2. **Create a PR** against `main`
3. **Fill out the PR template** completely
4. **Wait for CI** — every required quality gate must pass
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
- **Tested on every affected matrix environment** — include commands, release,
  desktop, duration, exit code, and whether the evidence was VM/container/host
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

- Add evidence-backed checks for a desktop application category
- Improve detection for your distro (Arch, openSUSE, etc.)
- Add JSON output support for a section that's missing it
- Write better detection for desktop environments (KDE, XFCE)

### 🔴 Advanced

- Add a new section with a documented threat model and score-weight review
- Support a new distro family (Arch, Alpine, etc.)
- Add a bounded parser for another native desktop/settings backend
- Build a repeatable VM fixture for an existing support-matrix gap

---

## 🐛 Reporting Issues

### Bug Reports

- Include your **distro and version**
- Include the **relevant output** from the script
- If it's a **false positive**, explain why
- Do not attach a blanket `bash -x` log: it can contain usernames, paths,
  addresses, configuration values, and secret-adjacent metadata. Reproduce the
  smallest relevant parser with a sanitized fixture; if tracing is necessary,
  review and redact it locally before sharing.

### Feature Requests

- Check if a similar request exists
- Explain the **use case** and **impact**
- If possible, suggest **implementation** details

---

## 📜 License

By contributing, you agree that your contributions will be licensed under
**GPL-3.0-or-later**.

For commercial licensing inquiries, see [LICENSE](LICENSE) or contact via [GitHub Discussions](https://github.com/NexusOne23/noid-privacy-linux/discussions).

---

## 🔗 Related Projects

- **[NoID Privacy](https://github.com/NexusOne23/noid-privacy)** — Windows 11 Security & Privacy Hardening Framework (sister project)
- **[NoID Privacy Workstation 44](https://github.com/NexusOne23/noid-privacy-workstation)** — hardened Fedora 44 / GNOME 50 privacy workstation
- **[NoID Privacy for Android](https://play.google.com/store/apps/details?id=com.noid.privacy)** — current Google Play listing
- **[noid-privacy.com](https://noid-privacy.com)** — Project website

---

**Thank you for contributing to NoID Privacy for Linux.** Evidence quality and
low false-positive rates matter more than the number of checks. 🛡️
