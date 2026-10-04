# NoID Privacy for Linux — Test Suite

This directory contains the BATS (Bash Automated Testing System) suite and
sanitized fixtures. The unit tests cover parsers, severity decisions, scoring,
JSON/Action validation, timeout completeness, distro-policy boundaries, and
the 11 source-pattern classes enforced by `scripts/lint-api-usage.sh`:

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

- `fixtures/` contains small, sanitized configuration or command-output
  samples: secure/insecure values, override precedence, locale variants,
  display-manager formats, Firefox policy/profile data, and failure states.
- `unit/` contains the BATS tests. Test filenames identify the subsystem; use
  `find tests/unit -maxdepth 1 -name '*.bats' -printf '%f\n' | sort` for the
  authoritative current inventory instead of maintaining a duplicate tree.

Fixtures must contain no real usernames, addresses, hostnames, identifiers,
tokens, or machine-specific paths.

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
shellcheck --severity=style --shell=bash noid-privacy-linux.sh entrypoint.sh scripts/*.sh tests/test_helper.bash tests/unit/*.bats
bats tests/unit/
```

The ShellCheck command intentionally includes Bats files. ShellCheck 0.9 may
otherwise report `SC2317` for callbacks, traps, setup functions, and mocks that
are invoked indirectly. Exceptions are kept function- or Bats-file-scoped and
document why the call is indirect; production-wide suppression is forbidden so
genuinely dead helpers remain detectable.

The suite includes a per-test temporary-directory compatibility shim for the
Bats 1.2.1 package shipped by Ubuntu 22.04. Newer Bats releases use their native
`BATS_TEST_TMPDIR`; older releases are isolated below their run directory.
Every test file that uses `BATS_TEST_TMPDIR` must source `tests/test_helper.bash`
and call `_noid_ensure_test_tmpdir` at the start of `setup()`; root test runs
must not be allowed to mask a missing compatibility call.

Or run a single test file:

```bash
bats tests/unit/test_emit_functions.bats
```

## Adding new tests

When fixing a bug, add a fixture under `fixtures/` and a `.bats` test under
`unit/` that exercises the decision boundary. As applicable, test:

1. secure and insecure effective states;
2. missing, malformed, permission-denied, and timed-out evidence;
3. vendor/local/user override precedence;
4. translated output when parsing cannot use a machine format;
5. PASS/WARN/FAIL/INFO classification, not merely matching source text; and
6. score/coverage invariance when display detail or repeated findings change.

Source-shape assertions are useful guards, but should not replace a semantic
fixture test when the parser can be isolated.

## CI integration

Tests run automatically via `.github/workflows/ci.yml` on every push
and PR — see the `bats-tests` job.
