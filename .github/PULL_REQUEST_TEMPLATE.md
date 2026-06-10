# Pull Request

## 📝 Description

Please include a summary of the changes and the related issue. Explain the motivation and context.

Fixes #(issue number)

## 🎯 Type of Change

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New check or section (non-breaking addition)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to change)
- [ ] 📚 Documentation update
- [ ] 🔧 Code refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🐧 New distro support

## 🧪 Testing

Please describe the tests you ran to verify your changes:

- [ ] Tested on Fedora (version: ___)
- [ ] Tested on Ubuntu/Debian (version: ___)
- [ ] Tested on other distro (specify: ___)
- [ ] `bash -n noid-privacy-linux.sh` passes (syntax check)
- [ ] `shellcheck noid-privacy-linux.sh` passes (if available)
- [ ] `bash scripts/lint-api-usage.sh noid-privacy-linux.sh` passes (API-layer lint)
- [ ] `bats tests/unit/` passes (if you installed bats locally)
- [ ] Ran full audit with `--ai` flag
- [ ] Ran full audit with `--json` flag
- [ ] Ran full audit with `--verbose` flag (per-item PASS detail)
- [ ] Tested `--skip` for affected sections

**Test Environment:**
- **Distro**: 
- **Kernel**: 
- **Bash Version**: 

## 📋 Checklist

- [ ] My code follows the style guidelines of this project (pure Bash, existing helpers)
- [ ] I have performed a self-review of my code
- [ ] I have tested on at least one supported distro
- [ ] My changes handle missing commands gracefully (`command -v`)
- [ ] New checks use `_emit_pass` / `_emit_fail` / `_emit_warn` / `_emit_info` helpers (or the `_emit_pass_agg_*` aggregator for repetitive PASSes)
- [ ] VPN-interface detection uses `$_VPN_IFACE_REGEX` (never hand-written subsets)
- [ ] firewalld policy queries go through `_fw_get_policies` (capability layer)
- [ ] All variables are quoted
- [ ] Translatable command output (`chage`, `fwupdmgr`, `bluetoothctl`, `journalctl --disk-usage`) is wrapped with `LC_ALL=C`
- [ ] I have updated CHANGELOG.md
- [ ] I have read and agree to the [Code of Conduct](CODE_OF_CONDUCT.md)

## 🔒 Security Considerations

- [ ] This change does not introduce security vulnerabilities
- [ ] No hardcoded credentials or secrets
- [ ] The script remains read-only (no system modifications)

## 🔄 Backwards Compatibility

- [ ] This change is backwards compatible
- [ ] New `--skip` keywords are documented (if adding new sections)
- [ ] Existing check IDs are not changed

## 📝 Additional Notes

Add any additional notes for reviewers here.
