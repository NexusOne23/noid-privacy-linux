# NoID Privacy for Linux — Test Suite

This directory contains the BATS (Bash Automated Testing System) test-suite
that prevents regressions of the 11 documented bug-pattern classes (locale,
name-shadow, grep-r on symlinks, API-versioning, regex-globals, `((var<op>))`
arithmetic-command counters, locale-aware tools missing `LC_ALL=C`, and
unanchored `grep nameserver` on resolv.conf).

## Layout

```
tests/
├── README.md                 # this file
├── fixtures/                 # captured command outputs for reproducible tests
│   ├── chage-l-en.txt                       # English `chage -l` output
│   ├── chage-l-de.txt                       # German `chage -l` output (locale-bug fixture)
│   ├── chage-l-en-expiry-set.txt            # `chage -l` with hardened max-days
│   ├── firewall-cmd-policies-deprecated.txt # firewalld 0.8 --list-policies output
│   ├── firewall-cmd-policies-new.txt        # firewalld 0.9+ --get-policies output
│   ├── pam-no-nullok.txt                    # PAM stack without nullok
│   ├── pam-with-nullok.txt                  # PAM stack with nullok present
│   ├── shadow-np-accounts.txt               # /etc/shadow with NP-status accounts
│   ├── shadow-passworded.txt                # /etc/shadow with regular accounts
│   ├── systemctl-is-enabled-disabled.txt    # systemctl is-enabled output: disabled
│   └── systemctl-is-enabled-masked.txt      # systemctl is-enabled output: masked
└── unit/                     # BATS unit tests
    ├── test_emit_functions.bats             # _emit_* refactor (no name shadowing)
    ├── test_chage_locale.bats               # Bug Pattern #1 (locale)
    ├── test_classification_severity.bats    # F-273/F-274/F-275 severity coupling
    ├── test_pass_aggregation.bats           # PASS-Aggregation helpers
    ├── test_systemctl_masked.bats           # Bug Pattern #4 (API versioning)
    └── test_vpn_regex_consistency.bats      # Bug Pattern #5 (regex globals)
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
recurring patterns.

## CI integration

Tests run automatically via `.github/workflows/ci.yml` on every push
and PR — see the `bats-tests` job.
