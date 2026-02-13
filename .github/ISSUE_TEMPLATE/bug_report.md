---
name: 🐛 Bug Report
about: Report a bug or unexpected behavior
title: '[BUG] '
labels: 'bug'
assignees: ''
---

## 🐛 Bug Description

A clear and concise description of what the bug is.

## 📋 Steps to Reproduce

1. Run command: `sudo bash noid-privacy-linux.sh ...`
2. Observe output at section: `...`
3. See error / incorrect result

## ✅ Expected Behavior

A clear description of what you expected to happen.

## ❌ Actual Behavior

A clear description of what actually happened. Include the relevant output.

## 💻 System Information

- **Distro**: [e.g., Fedora 43, Ubuntu 24.04, Debian 12]
- **Kernel**: [e.g., 6.18.9-200.fc43.x86_64]
- **Bash Version**: [e.g., 5.2.37]
- **Desktop Environment**: [e.g., GNOME 48, KDE Plasma 6]
- **Script Version**: [e.g., v3.0.0]
- **Flags Used**: [e.g., --ai, --json, --skip bluetooth]

**Get system info:**
```bash
cat /etc/os-release | head -3
uname -r
bash --version | head -1
echo $XDG_CURRENT_DESKTOP
```

## 📝 Relevant Output

```
[Paste the relevant section output here]
```

## 🔍 Additional Context

- Was this a first run or re-run?
- Did it work on a previous version?
- Any unusual system configuration?
- Running in VM or physical machine?
- Is SELinux/AppArmor enforcing?

## ✔️ Checklist

- [ ] I have searched for similar issues
- [ ] I have verified this is reproducible
- [ ] I have included complete system information
- [ ] I have included the relevant output
- [ ] I ran with `bash -x noid-privacy-linux.sh` for debug output (if applicable)

## 🔒 Security Note

If this is a **security vulnerability**, please **DO NOT** create a public issue!
Instead, report it privately via: https://github.com/NexusOne23/noid-privacy-linux/security/advisories
