# Security Policy

## 🔒 Reporting Security Vulnerabilities

We take the security of NoID Privacy for Linux seriously. If you discover a security vulnerability, please follow responsible disclosure practices.

### ✅ How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security issues via one of these methods:

1. **GitHub Security Advisory** (Preferred)
   - Go to: https://github.com/NexusOne23/noid-privacy-linux/security/advisories
   - Click "Report a vulnerability"
   - Fill out the private security advisory form

2. **GitHub Discussions** (Alternative)
   - Create a new discussion in the Security category
   - Mark it as "Private" if possible
   - Provide full details

### 📋 What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What can an attacker achieve?
- **Affected Versions**: Which versions are affected?
- **Steps to Reproduce**: Detailed reproduction steps
- **Proof of Concept**: PoC code if applicable (optional)
- **Suggested Fix**: If you have one (optional)

### ⏱️ Response Timeline (SLA)

| Severity | Acknowledgement | Fix Target | Max Resolution |
|----------|----------------|------------|----------------|
| **Critical** | 24 hours | 7 days | 14 days |
| **High** | 48 hours | 14 days | 30 days |
| **Medium** | 7 days | 30 days | 60 days |
| **Low** | 7 days | 60 days | 90 days |

### 🎖️ Recognition

We appreciate responsible disclosure! Contributors will be:
- Credited in the CHANGELOG (if desired)
- Listed in the Security Hall of Fame (coming soon)

---

## 🛡️ Security Design Principles

NoID Privacy for Linux is designed with security in mind:

### Audit-Only by Design
- ✅ **Read-Only**: The script only **reads** system state — it never modifies your system
- ✅ **No External Dependencies**: Zero third-party binaries, libraries, or package managers
- ✅ **Pure Bash**: No Python, Ruby, Node.js, or compiled binaries
- ✅ **No Network Requests by Default**: The script does not phone home or download anything. The optional DNS leak test (`netleaks` section) contacts external services and can be skipped with `--skip netleaks`.
- ✅ **No Data Collection**: Zero telemetry, zero analytics, zero tracking

### Code Transparency
- ✅ **Single File**: One script, easy to read and audit
- ✅ **Open Source**: Every line is inspectable on GitHub
- ✅ **No Obfuscation**: Plain Bash, no encoded/minified code
- ✅ **Deterministic**: Same system state = same output

---

## 📊 Supported Versions

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 3.2.x   | ✅ Fully Supported | Current release, 300+ checks, 42 sections |
| 3.1.x   | ⚠️ Limited Support  | Upgrade to 3.2.x recommended |
| 2.0.x   | ⚠️ Limited Support  | Upgrade to 3.0.x recommended |
| 1.x     | ❌ Not Supported   | Legacy version |

**Recommendation:** Always use the latest v3.x release.

---

## 🔐 Security Best Practices for Users

### Before Running

1. ✅ **Verify Script Integrity**
   ```bash
   # Compare SHA256 hash against GitHub Release
   sha256sum noid-privacy-linux.sh
   ```

2. ✅ **Review the Code**
   ```bash
   # It's one file — read it!
   less noid-privacy-linux.sh
   ```

3. ✅ **Check the Source**
   - Download only from the official GitHub repository
   - Verify the URL: `https://github.com/NexusOne23/noid-privacy-linux`

### During Execution

- ⚠️ Requires root access (`sudo`) for comprehensive system checks
- ✅ The script only reads — it does not modify any files or settings
- ✅ All checks use standard Linux utilities (sysctl, ss, systemctl, etc.)

### After Execution

- ✅ Review the findings and fix issues manually or with AI assistance (`--ai`)
- ✅ Re-run periodically to verify your hardening holds
- ✅ Share reports with your team (no sensitive data in output by default)

---

## 🚨 Known Security Considerations

### Root Access

- ⚠️ The script requires `sudo` to read certain system files (e.g., `/etc/shadow` permissions, firewall rules)
- ✅ Root access is used for **reading only** — no writes, no modifications
- ✅ You can verify this: `grep -c 'rm \|mv \|cp \|echo.*>\|tee \|sed -i\|install ' noid-privacy-linux.sh` (should be 0 for system files)

### Output Contains System Information

- ⚠️ The audit output contains details about your system's security posture
- ✅ Do not share raw output publicly if it reveals sensitive configuration
- ✅ The `--json` output is designed for automated processing, not public sharing

---

## 🔍 Code Quality

### Static Analysis
- **ShellCheck**: All code passes ShellCheck analysis
- **bash -n**: Syntax validation in CI pipeline
- **Manual Review**: Every PR is reviewed for security implications

### Verification

Run checks yourself:
```bash
# Syntax check
bash -n noid-privacy-linux.sh

# ShellCheck (if installed)
shellcheck noid-privacy-linux.sh
```

### Vulnerability Disclosures
*No security vulnerabilities reported to date.*

---

## 🔗 Related Projects

- **[NoID Privacy](https://github.com/NexusOne23/noid-privacy)** — Windows 11 Security & Privacy Hardening Framework (sister project)

---

## 📄 License & Legal

- **License**: GNU General Public License v3.0
- **Disclaimer**: Use at your own risk. No warranties provided.
- **Audit-Only**: This tool does not modify your system.

For licensing questions, see [LICENSE](LICENSE) or open a [Discussion](https://github.com/NexusOne23/noid-privacy-linux/discussions).

---

**Last Updated**: February 27, 2026
**Policy Version**: 1.2
