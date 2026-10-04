# Security Policy

## 🔒 Reporting Security Vulnerabilities

We take the security of NoID Privacy for Linux seriously. If you discover a security vulnerability, please follow responsible disclosure practices.

### ✅ How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, use GitHub's private vulnerability-reporting flow:

1. **GitHub Security Advisory** (Preferred)
   - Go to: https://github.com/NexusOne23/noid-privacy-linux/security/advisories
   - Click "Report a vulnerability"
   - Fill out the private security advisory form

If the private form is unavailable, do not place exploit details in an Issue or
Discussion. Open a minimal public issue asking the maintainers to enable a
private reporting channel, without describing the vulnerability.

### 📋 What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What can an attacker achieve?
- **Affected Versions**: Which versions are affected?
- **Steps to Reproduce**: Detailed reproduction steps
- **Proof of Concept**: PoC code if applicable (optional)
- **Suggested Fix**: If you have one (optional)

### ⏱️ Response Targets

These are maintainer targets, not a contractual SLA. Coordinated disclosure
timing is agreed with the reporter and can vary with reproducibility, upstream
coordination, and release safety.

| Severity | Acknowledgement | Fix Target | Max Resolution |
|----------|----------------|------------|----------------|
| **Critical** | 24 hours | 7 days | 14 days |
| **High** | 48 hours | 14 days | 30 days |
| **Medium** | 7 days | 30 days | 60 days |
| **Low** | 7 days | 60 days | 90 days |

### 🎖️ Recognition

Reporters are credited in the CHANGELOG when they consent.

---

## 🛡️ Security Design Principles

NoID Privacy for Linux is designed with security in mind:

### Audit-Only by Design
- ✅ **Non-remediating by default**: normal audit mode intentionally changes no configuration, restarts no services, and never refreshes package metadata; invoked services may still record ordinary operational logs/access metadata
- ⚠️ **Explicit stateful opt-ins**: `NOID_RPM_BASELINE_INIT=1` /
  `NOID_RPM_BASELINE_UPDATE=1` writes
  `/var/lib/noid-privacy/rpm-baseline.txt`; `NOID_AIDE_LIVE=1` creates a
  mode-600 temporary log and preserves it only for drift/errors; the NoID-image-
  only `--refresh-noid-rpm-policy` rewrites its documented trusted-state policy
- ✅ **Pure Bash audit**: no language-package dependency tree or bundled binary;
  it capability-detects common compiled operating-system utilities where needed
- ✅ **No Telemetry or Analytics**: audit results are never uploaded; the documented leak-test requests still expose normal connection metadata to their endpoints
- ⚠️ **Network leak-tests run by default**: Active probes are grouped under two skip flags:
  - Section 5 (`netleaks`): ICMP `ping 1.1.1.1` (Cloudflare) / `9.9.9.9` (Quad9) for connectivity, HTTP fallback `curl cp.cloudflare.com/generate_204` (Cloudflare), `dig whoami.akamai.net` (Akamai), and `curl https://ifconfig.me/ip` (TLS public-IP echo service). With a confirmed active VPN, the flag also guards short pings to learned/common LAN gateways for an optional isolation observation; those packets stay local or VPN-routed. Reachability is INFO because intentional local-device access is a valid VPN policy.
  - Section 22 (`interfaces`): `dig . NS` — a DNS root-server query through the configured resolver (no third-party domain)

  These are inherent to leak-testing. To suppress the audit's outbound probes,
  use:
  ```bash
  sudo bash noid-privacy-linux.sh --offline
  # equivalent to: --skip interfaces --skip netleaks
  ```
  Local VPN configuration remains assessed; no VPN is a valid posture rather
  than a warning by itself. Traffic from other software on the host is outside
  the audit's control.

### Code Transparency
- ✅ **Single downloadable audit**: The executable audit is one script; the
  repository also contains its Action wrapper, tests, helpers, and documentation
- ✅ **Open Source**: Every line is inspectable on GitHub
- ✅ **No Obfuscation**: Plain Bash, no encoded/minified code
- ⚠️ **Time-dependent evidence is explicit**: update caches, logs, active
  processes, network probes, and timeouts can legitimately change between runs

---

## 📊 Supported Versions

| Version line | Security fixes | Notes |
|---|---|---|
| 3.7.x | Current | Update to the newest 3.7.x patch release |
| 3.6.x and older | Ended | No maintained backport branch; upgrade before reporting |

Distribution/desktop validation is a separate question documented in
[Docs/SUPPORT.md](Docs/SUPPORT.md).

---

## 🔐 Security Best Practices for Users

### Before Running

1. ✅ **Review the Code**
   ```bash
   # It's one file in pure Bash — read it!
   less noid-privacy-linux.sh
   ```
   Code review helps establish behavior; it does not by itself establish that
   the downloaded bytes came from the intended release.

2. ✅ **Check the Source**
   - Download only from the official GitHub repository
   - Verify the URL: `https://github.com/NexusOne23/noid-privacy-linux`
   - For CI/CD usage, pin the Action to the reviewed release commit SHA; a
     release tag is preferable to `@main` but is not immutable in Git itself

3. ✅ **Verify provenance against a trusted reference**
   ```bash
   # The script is one file in pure Bash. Verify you're getting it from
   # the official repo and inspect the commit history:
   git log --oneline noid-privacy-linux.sh | head -5
   # Compare the checked-out commit with the intended release page:
   # https://github.com/NexusOne23/noid-privacy-linux/releases
   ```
   A commit hash or checksum is useful only when the expected value came from a
   trusted channel. Review the release history and the exact bytes you execute;
   do not treat a hash copied from the same untrusted download location as
   independent provenance.

### During Execution

- ⚠️ Requires root access (`sudo`) for comprehensive system checks
- ✅ Default audit mode performs no intentional remediation; the explicitly documented baseline/AIDE opt-ins create audit-state files, while invoked daemons may maintain normal operational logs
- ✅ All checks use standard Linux utilities (sysctl, ss, systemctl, etc.)

### After Execution

- ✅ Review the findings and fix issues manually or with AI assistance (`--ai`)
- ✅ Re-run periodically to verify your hardening holds
- ⚠️ Review/redact reports before sharing: output can include hostname, usernames, paths, installed software, and security findings

---

## 🚨 Known Security Considerations

### Root Access

- ⚠️ The script requires `sudo` to read certain system files (e.g., `/etc/shadow` permissions, firewall rules)
- ✅ Root access is used for reading in default mode; only the explicitly selected RPM-baseline/AIDE-live features write audit state
- ✅ Combine provenance verification with review of the one-file audit. Neither
  a trusted hash nor source review alone answers both origin and behavior.

### Output Contains System Information

- ⚠️ The audit output contains details about your system's security posture
- ⚠️ Finding text can originate in untrusted filenames/configuration; control bytes are escaped and the AI prompt explicitly marks findings as data, but users must still review generated remediation
- ✅ Do not share raw output publicly if it reveals sensitive configuration
- ✅ The `--json` output is designed for automated processing, not public sharing

---

## 🔍 Code Quality

### Static Analysis
- **ShellCheck**: clean at `--severity=style` (the strictest level) — see
  `.shellcheckrc` for the project-wide rationale on SC2059 (color-format
  strings) and SC2329 (callback dispatch / signal traps). The CI gate enforces
  the same `--severity=style` level.
- **API-Layer Lint**: `scripts/lint-api-usage.sh` enforces 11
  anti-regression patterns covering bug classes — direct firewalld API
  bypassing capability layer, `systemctl is-masked` (non-existent verb),
  `grep -r`
  on symlinked dirs, bare `pass()/fail()/warn()/info()` reintroductions,
  `chage -l` without `LC_ALL=C`, hardcoded VPN-iface regex, `df -T NR==2`
  wrap-vulnerable patterns, `fwupdmgr`/`bluetoothctl` without `LC_ALL=C`,
  **`((var<op>))` arithmetic-command counters that bomb under `set -e`**
  (Pattern 9, all `++`/`--`/`+=`/`-=`/`*=`/`/=`/`%=` forms),
  **`systemd-analyze`/`virsh`/`resolvectl`/`free` without `LC_ALL=C`**
  (Pattern 10, `free -flag` forms covered), and **unanchored `grep
  nameserver` on resolv.conf** (Pattern 11, catches commented entries
  reported as active DNS servers).
- **BATS unit tests**: `tests/unit/` covers the bug-pattern classes via
  `bats` runner against `tests/fixtures/`.
- **bash -n**: syntax-only container validation spans the maintained package
  families. CI may include extra base images beyond the release-supported
  desktop lines in `Docs/SUPPORT.md`; those parser checks are explicitly not
  desktop validation or additional support claims.
- **Action smoke**: one real Ubuntu runner audit exercises the local composite
  Action, its exit-code handling, full JSON consistency checks, score/coverage
  recomputation, and outputs.
- **Audit-Locale Matrix**: runs the audit under `en_US`, `fr_FR`, `es_ES`
  locales to catch the locale-bug class (`chage`/`fwupdmgr`/`bluetoothctl`
  translatable labels).
- **Manual Review**: Review every PR for security implications before merge.

### Verification

Run checks yourself:
```bash
# Syntax check
bash -n noid-privacy-linux.sh

# ShellCheck (if installed)
shellcheck noid-privacy-linux.sh

# API-layer lint
bash scripts/lint-api-usage.sh noid-privacy-linux.sh

# Compliance mapping IDs, profiles, qualities, duplicates, and denominators
bash scripts/coverage-report.sh

# BATS unit tests
bats tests/unit/
```

---

## 🔗 Related Projects

- **[NoID Privacy](https://github.com/NexusOne23/noid-privacy)** — Windows 11 Security & Privacy Hardening Framework (sister project)
- **[NoID Privacy Workstation 44](https://github.com/NexusOne23/noid-privacy-workstation)** — hardened Fedora 44 / GNOME 50 privacy workstation
- **[NoID Privacy for Android](https://play.google.com/store/apps/details?id=com.noid.privacy)** — current Google Play listing

---

## 📄 License & Legal

- **License**: GNU General Public License v3.0 or later
- **Disclaimer**: Use at your own risk. No warranties provided.
- **Audit-Only**: Default mode does not modify system configuration; explicit baseline/AIDE-live opt-ins write only their documented audit-state files.

For licensing questions, see [LICENSE](LICENSE) or open a [Discussion](https://github.com/NexusOne23/noid-privacy-linux/discussions).

---

**Last Updated**: July 19, 2026

**Policy Version**: 1.8.0
