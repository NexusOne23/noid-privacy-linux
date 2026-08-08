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

- [ ] Tested every affected entry in `Docs/SUPPORT.md` (list below)
- [ ] `bash -n noid-privacy-linux.sh` passes (syntax check)
- [ ] ShellCheck passes at style level for scripts and BATS tests
- [ ] `bash scripts/lint-api-usage.sh noid-privacy-linux.sh` passes (API-layer lint)
- [ ] `bash scripts/coverage-report.sh` passes (mapping validation)
- [ ] `bats tests/unit/` passes
- [ ] Ran full audit with `--ai` flag
- [ ] Ran full audit with `--json` flag
- [ ] Ran full audit with `--verbose` flag (per-item PASS detail)
- [ ] Tested `--skip` for affected sections

**Test Environment:**
- **Distro**: 
- **Distro version / image digest**:
- **Desktop and display manager**:
- **Kernel**: 
- **Bash Version**: 
- **Environment**: physical / VM / container
- **Audit duration and exit code**:
- **Score and assessed coverage**:

## 📋 Checklist

- [ ] My code follows the style guidelines of this project (pure Bash, existing helpers)
- [ ] I have performed a self-review of my code
- [ ] I have tested every platform/desktop path affected by this change
- [ ] My changes handle missing commands gracefully (`command -v`)
- [ ] New checks use `_emit_pass` / `_emit_fail` / `_emit_warn` / `_emit_info` helpers (or the `_emit_pass_agg_*` aggregator for repetitive PASSes)
- [ ] VPN-interface detection uses `$_VPN_IFACE_REGEX` (never hand-written subsets)
- [ ] firewalld policy queries go through `_fw_get_policies` (capability layer)
- [ ] All variables are quoted
- [ ] Translatable command output (`chage`, `fwupdmgr`, `bluetoothctl`, `journalctl --disk-usage`) is wrapped with `LC_ALL=C`
- [ ] I have updated CHANGELOG.md
- [ ] I updated `Docs/SCORING.md` and the model identifier if score semantics changed
- [ ] I updated `Docs/CIS_RHEL9_MAPPING.md` only for exact, evidence-backed controls
- [ ] I have read and agree to the [Code of Conduct](../CODE_OF_CONDUCT.md)

## 🔒 Security Considerations

- [ ] This change does not introduce security vulnerabilities
- [ ] No hardcoded credentials or secrets
- [ ] Default audit mode remains non-remediating; any explicit audit-state write is documented and permission-safe
- [ ] Missing tools, denied access, malformed output, and timeouts cannot produce a clean PASS
- [ ] Any new network endpoint is necessary, documented, bounded, and disabled by `--offline`

## 🔄 Backwards Compatibility

- [ ] This change is backwards compatible
- [ ] New `--skip` keywords are documented (if adding new sections)
- [ ] Existing check IDs are not changed

## 📝 Additional Notes

Add any additional notes for reviewers here.
