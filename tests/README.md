# NoID Privacy for Linux — Test Suite

This directory contains the BATS (Bash Automated Testing System) test-suite
that prevents regressions of the 11 documented bug-pattern classes enforced
by `scripts/lint-api-usage.sh`:

1. Direct firewalld policy API calls bypassing `_fw_get_policies`
2. `systemctl is-masked` (verb does not exist — use `_service_masked_any`)
3. `grep -r` on `/etc/pam.d` (must be `-R` for authselect symlinks)
4. Bare `pass()/fail()/warn()/info()` definitions (use `_emit_*` prefix)
5. `chage -l` without `LC_ALL=C` (locale-translated labels)
6. Hardcoded VPN-iface regex bypassing `$_VPN_IFACE_REGEX`
7. `df -T NR==2` wraps on long device names (use `findmnt -no FSTYPE`)
8. `fwupdmgr` / `bluetoothctl` without `LC_ALL=C`
9. `((var<op>))` arithmetic-command counters (rc=1 when result=0 under `set -e`)
10. `systemd-analyze` / `virsh` / `resolvectl` / `free` without `LC_ALL=C`
11. Unanchored `grep nameserver` on `/etc/resolv.conf` (matches commented entries)

## Layout

```
tests/
├── README.md                 # this file
├── fixtures/                 # captured command outputs for reproducible tests
│   ├── chage-l-en.txt                       # English `chage -l` output
│   ├── chage-l-fr.txt                       # French `chage -l` output (locale-bug fixture)
│   ├── chage-l-en-expiry-set.txt            # `chage -l` with hardened max-days
│   ├── firewall-cmd-policies-deprecated.txt # firewalld 0.8 --list-policies output
│   ├── firewall-cmd-policies-new.txt        # firewalld 0.9+ --get-policies output
│   ├── nm-mac-connection-named.conf         # NM conf.d [connection.<name>] cloned-mac (F-385)
│   ├── nm-mac-connection-bare.conf          # NM conf.d bare [connection] cloned-mac (F-385 regression guard)
│   ├── nm-mac-connection-hyphen.conf        # NM conf.d [connection-<name>] hyphen form (F-386, NM canonical)
│   ├── pam-no-nullok.txt                    # PAM stack without nullok
│   ├── pam-with-nullok.txt                  # PAM stack with nullok present
│   ├── shadow-np-accounts.txt               # /etc/shadow with NP-status accounts
│   ├── shadow-passworded.txt                # /etc/shadow with regular accounts
│   ├── sshd-T-algos-strong.txt              # sshd -T output, modern algorithm set
│   ├── sshd-T-algos-weak.txt                # sshd -T output with weak algorithms (F-383)
│   ├── systemctl-is-enabled-disabled.txt    # systemctl is-enabled output: disabled
│   └── systemctl-is-enabled-masked.txt      # systemctl is-enabled output: masked
└── unit/                     # BATS unit tests
    ├── test_emit_functions.bats             # _emit_* refactor (no name shadowing)
    ├── test_chage_locale.bats               # Bug Pattern #1 (locale)
    ├── test_classification_severity.bats    # F-273/F-274/F-275 severity coupling
    ├── test_mac_randomization.bats          # F-385/F-386 NM [connection*] default-section parser
    ├── test_pass_aggregation.bats           # PASS-Aggregation helpers
    ├── test_ssh_algo_strength.bats          # F-382/F-383 SSH algorithm classifier
    ├── test_systemctl_masked.bats           # Bug Pattern #4 (API versioning)
    ├── test_vpn_regex_consistency.bats      # Bug Pattern #5 (regex globals)
    ├── test_zone_iface_classification.bats  # F-387 firewall zone VPN/VM-iface classifier
    └── test_qemu_detection_anchor.bats      # F-388 standalone-qemu pgrep path-anchor
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

This prevents future regressions of the same class.

## CI integration

Tests run automatically via `.github/workflows/ci.yml` on every push
and PR — see the `bats-tests` job.
