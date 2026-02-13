---
name: ✨ Feature Request
about: Suggest a new check, section, or enhancement
title: '[FEATURE] '
labels: 'enhancement'
assignees: ''
---

## 🚀 Feature Request

**Note:** For questions or discussions, please use [GitHub Discussions](https://github.com/NexusOne23/noid-privacy-linux/discussions) instead!

## 🔍 Problem Statement

**Is your feature request related to a problem?**

Describe the problem this feature would solve. Example: "NoID Privacy for Linux doesn't check for [...]"

## 💡 Proposed Solution

Describe the check or feature you'd like to see implemented.

## 🔄 Alternatives Considered

Describe any alternative solutions or workarounds you've considered.

## 📊 Impact Assessment

### Category
- [ ] 🔒 Privacy check (browser, telemetry, network, data)
- [ ] 🛡️ Security check (kernel, firewall, SSH, encryption)
- [ ] 🖥️ Desktop check (session, webcam, Bluetooth, keyring)
- [ ] ⚙️ New flag or CLI option
- [ ] 📚 Documentation improvement
- [ ] 🐧 New distro support
- [ ] 🔧 Code improvement / refactoring

### Compatibility
- [ ] Works on Fedora/RHEL
- [ ] Works on Debian/Ubuntu
- [ ] Distro-specific (specify below)
- [ ] Not sure

**Details:**

## 🎯 Use Cases

1. **Use case 1**: [Description]
2. **Use case 2**: [Description]

## 📚 References

Link to any relevant documentation or similar implementations:

- [Example: CIS Benchmark requirement]
- [Example: Similar check in Lynis]
- [Example: Security advisory / CVE]

## 📝 Implementation Hints (Optional)

If you have an idea how to implement this:

```bash
# Example check logic
if [ -f /etc/some-config ]; then
    grep -q "secure_setting" /etc/some-config && pass "Setting is secure" || fail "Setting is insecure"
fi
```

## ✔️ Checklist

- [ ] I have searched for similar feature requests
- [ ] This check doesn't already exist in the script
- [ ] I have described the problem and proposed solution clearly
- [ ] I have provided use cases
- [ ] This is NOT a security vulnerability (use Security Advisory instead)
