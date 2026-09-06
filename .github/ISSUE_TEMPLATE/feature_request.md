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
- [ ] Exact release/desktop entries from `Docs/SUPPORT.md` are listed below
- [ ] Distro-specific (specify below)
- [ ] Not sure

**Details:**

## 🎯 Use Cases

1. **Use case 1**: [Description]
2. **Use case 2**: [Description]

## 📚 References

Link to any relevant documentation or similar implementations:

- Maintained primary configuration/API documentation
- Exact CIS/STIG/Lynis control or test, including version, when relevant
- Security advisory/CVE and the local evidence that can actually be observed

Explain the desktop threat, expected secure/insecure/unknown states, config
precedence, likely false positives, required privileges/tools, timeout, and any
network disclosure. A check is not accepted solely to increase the count.

## 📝 Implementation Hints (Optional)

If you have an idea how to implement this:

```bash
# Pseudocode: parse the effective value and preserve unknown evidence.
if value=$(read_effective_value 2>/dev/null); then
  case "$value" in
    secure)   _emit_pass "Control: secure effective state" ;;
    insecure) _emit_warn "Control: insecure effective state — bounded impact" ;;
    *)        _emit_info "Control: unrecognized effective state" ;;
  esac
else
  _emit_info "Control: effective state unavailable"
fi
```

## ✔️ Checklist

- [ ] I have searched for similar feature requests
- [ ] This check doesn't already exist in the script
- [ ] I explained why existing layered controls do not already cover the risk
- [ ] I have described the problem and proposed solution clearly
- [ ] I have provided use cases
- [ ] This is NOT a security vulnerability (use Security Advisory instead)
