# NoID Privacy for Linux — Test Suite

This directory contains the BATS (Bash Automated Testing System) test-suite
introduced in v3.6 to prevent regressions of the bug classes documented in
the v3.5.0 → v3.6 audit (5 initial patterns; extended to 11 in v3.6.1).

## Layout

```
tests/
├── README.md                 # this file
├── fixtures/                 # captured command outputs for reproducible tests
│   ├── chage-l-en.txt        # English `chage -l` output
│   ├── chage-l-de.txt        # German `chage -l` output (locale-bug fixture)
│   ├── chage-l-en-expiry-set.txt
│   ├── systemctl-is-enabled-masked.txt
│   ├── systemctl-is-enabled-disabled.txt
│   ├── firewall-cmd-policies-deprecated.txt
│   └── firewall-cmd-policies-new.txt
└── unit/                     # BATS unit tests
    ├── test_emit_functions.bats         # v3.6 _emit_* refactor
    ├── test_chage_locale.bats           # Bug Pattern #1 (locale)
    ├── test_pass_aggregation.bats       # v3.6 PASS-Aggregation helpers
    ├── test_systemctl_masked.bats       # Bug Pattern #4 (API versioning)
    └── test_vpn_regex_consistency.bats  # Bug Pattern #5 (regex globals)
```

## Running locally

Install BATS via your package manager:

```bash
# Fedora
sudo dnf install bats

# Ubuntu/Debian
sudo apt-get install bats

# Arch
sudo pacman -S bats
```

Then run from the repository root:

```bash
bats tests/unit/
```

Or run a single test file:

```bash
bats tests/unit/test_emit_functions.bats
```

## Adding new tests

When fixing a bug, add a fixture (sample command output) under
`fixtures/` and a `.bats` test under `unit/` that exercises the bug
condition. The test should:

1. Demonstrate the broken state without the fix
2. Verify the fixed code handles it correctly
3. Reference the bug-pattern class in a header comment

This prevents future regressions of the same class — see
`feedback_noid_audit_bug_patterns.md` (project memory) for the
five recurring patterns.

## CI integration

Tests run automatically via `.github/workflows/ci.yml` on every push
and PR — see the `bats-tests` job.
