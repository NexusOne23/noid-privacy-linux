# NoID Privacy for Linux — CIS RHEL 9 / STIG Compliance Mapping

This document maps NoID checks to the **CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0** and applicable **DISA STIG** controls. It enables compliance-conscious users to:

1. See which CIS Level 1 / Level 2 / STIG controls NoID covers
2. Use `--cis-l1`, `--cis-l2`, `--stig` flags to filter output
3. Generate a coverage report comparing NoID checks against the benchmark

> **Scope note**: NoID is a **hardening posture audit** for Linux desktops. It covers a subset of CIS — primarily the configuration-state controls. Server-stack-specific CIS controls (databases, mail, webservers) are **out of scope** and listed as "N/A — server" below.

> **Compliance level**: NoID does NOT make NoID an officially CIS-certified tool. It maps NoID's findings to CIS control IDs for transparency and lets compliance-conscious users cross-reference. Official CIS audits should still use `cis-cat-pro` or equivalent.

## Coverage summary (v3.6.2)

| Tier | Controls in CIS RHEL 9 | NoID-mapped | Coverage |
|------|------------------------|-------------|----------|
| Level 1 (server + workstation)  | ~232 | ~95  | ~41% |
| Level 2 (defense in depth)      | ~64  | ~25  | ~39% |
| STIG (DISA mandate)             | ~250 | ~80  | ~32% |

## Mapping table

| NoID Section | NoID Check | CIS L1 | CIS L2 | STIG ID |
|--------------|------------|--------|--------|---------|
| 01 Kernel    | Secure Boot enabled                  | 1.1.1  | —      | RHEL-09-211015 |
| 01 Kernel    | Kernel lockdown active               | —      | 1.4.4  | — |
| 01 Kernel    | LUKS encryption                      | —      | 1.1.2  | RHEL-09-231010 |
| 01 Kernel    | `noapic` not set                     | 1.6.1  | —      | — |
| 01 Kernel    | `init_on_alloc=1`                    | —      | 1.1.5  | — |
| 01 Kernel    | `init_on_free=1`                     | —      | 1.1.5  | — |
| 01 Kernel    | `slab_nomerge`                       | —      | 1.5.1  | — |
| 01 Kernel    | `pti=on`                             | —      | 1.5.2  | RHEL-09-213065 |
| 01 Kernel    | `randomize_kstack_offset=on`         | —      | 1.5.3  | — |
| 02 SELinux   | SELinux state = Enforcing            | 1.6.1.4| —      | RHEL-09-431010 |
| 02 SELinux   | SELinux policy = targeted+           | —      | 1.6.1.5| — |
| 03 Firewall  | firewalld / nftables active          | 3.4.2.1| —      | RHEL-09-251010 |
| 03 Firewall  | Default policy = DROP / REJECT       | 3.4.2.4| —      | RHEL-09-251015 |
| 04 nftables  | Counters / logging on default chains | 3.4.3.5| —      | — |
| 06 sysctl    | `kernel.randomize_va_space=2`        | 1.5.3  | —      | RHEL-09-213045 |
| 06 sysctl    | `kernel.kptr_restrict=2`             | —      | 1.5.4  | — |
| 06 sysctl    | `kernel.dmesg_restrict=1`            | 1.5.5  | —      | RHEL-09-213050 |
| 06 sysctl    | `kernel.unprivileged_bpf_disabled=1` | —      | 1.5.6  | — |
| 06 sysctl    | `net.core.bpf_jit_harden=2`          | —      | 1.5.7  | — |
| 06 sysctl    | `net.ipv4.conf.all.accept_redirects=0` | 3.3.3| —      | RHEL-09-253015 |
| 06 sysctl    | `net.ipv4.conf.all.send_redirects=0` | 3.3.4  | —      | RHEL-09-253020 |
| 06 sysctl    | `net.ipv4.conf.all.rp_filter=1`      | 3.3.7  | —      | — |
| 06 sysctl    | `net.ipv4.tcp_syncookies=1`          | 3.3.8  | —      | RHEL-09-253030 |
| 06 sysctl    | `net.ipv4.icmp_echo_ignore_broadcasts=1` | 3.3.5 | — | — |
| 06 sysctl    | `kernel.yama.ptrace_scope>=2`        | —      | 1.5.4  | — |
| 09 SSH       | Root login disabled                  | 5.2.7  | —      | RHEL-09-255045 |
| 09 SSH       | Password auth disabled (key-only)    | —      | 5.2.10 | RHEL-09-255030 |
| 09 SSH       | PermitEmptyPasswords=no              | 5.2.9  | —      | RHEL-09-255035 |
| 09 SSH       | LoginGraceTime ≤ 60                  | 5.2.17 | —      | — |
| 09 SSH       | MaxAuthTries ≤ 4                     | 5.2.6  | —      | RHEL-09-255040 |
| 09 SSH       | Strong Ciphers/MACs/KexAlgorithms    | 5.2.13–15| —    | RHEL-09-255055 |
| 10 audit     | auditd enabled                       | 4.1.1.1| —      | RHEL-09-651005 |
| 10 audit     | Immutable mode (`-e 2`)              | —      | 4.1.3.20| RHEL-09-651010 |
| 11 users     | Password aging max ≤ 365             | 5.5.1.1| —      | RHEL-09-611025 |
| 11 users     | PAM pwquality minlen / minclass      | 5.4.1  | —      | RHEL-09-611070 |
| 11 users     | No legacy `+` entries in passwd      | 6.2.1  | —      | — |
| 12 filesystem| /tmp partition / mount opts          | 1.1.2.1–3| —    | RHEL-09-231030 |
| 12 filesystem| /home noexec or 1777 perms           | 1.1.6.1| —      | — |
| 12 filesystem| World-writable files                 | 6.1.10 | —      | — |
| 12 filesystem| Unowned files                        | 6.1.11 | —      | — |
| 13 crypto    | Crypto policy = DEFAULT or stricter  | 1.6.1  | —      | — |
| 14 updates   | Updates configured (auto / manual)   | 1.2.4  | —      | RHEL-09-211020 |
| 14 updates   | GPG signature verification           | 1.2.2  | —      | RHEL-09-211025 |
| 28 ntp       | chronyd enabled                      | 2.1.1.1| —      | RHEL-09-252005 |
| 30 integrity | AIDE installed                       | —      | 6.1.4  | RHEL-09-651055 |
| 30 integrity | AIDE database / scheduled check      | —      | 6.1.5  | RHEL-09-651060 |
| 32 modules   | Disabled `cramfs` / `freevxfs` / etc | 1.1.1.1| —      | RHEL-09-213020 |
| 32 modules   | usbcore.authorized_default=0         | —      | 3.5.1  | — |
| 33 permissions| /etc/passwd 644                     | 6.1.2  | —      | — |
| 33 permissions| /etc/shadow 0000 / 600              | 6.1.3  | —      | RHEL-09-232030 |
| 34 integrity | rpm -V (RPM-based)                   | —      | 6.1.10 | — |
| 35 browser   | Firefox telemetry disabled           | —      | —      | (out of scope: CIS doesn't cover desktop browser) |
| ... | ... | ... | ... | ... |

## Out-of-scope CIS controls (NoID does NOT cover)

These belong to the server-stack domain that NoID intentionally excludes (use **Lynis** or **OpenSCAP** for server compliance):

- `2.2.x`  — Server services (NIS, telnet, rsh, talk, finger, tftp, nis, ypbind, ypserv)
- `3.4.1.x` — DNS server (named.conf hardening)
- `5.6.x`  — User shell timeouts (TMOUT)
- `6.1.5–9` — System file integrity (mostly server-binary checks)

## Generating coverage report

```bash
sudo bash noid-privacy-linux.sh --cis-l1
# → "CIS Level 1 Coverage: 38/95 (40%) — 38 PASS / 7 FAIL / 5 WARN"

sudo bash noid-privacy-linux.sh --cis-l2
# → "CIS Level 2 Coverage: 12/25 (48%) — 12 PASS / 0 FAIL / 1 WARN"

sudo bash noid-privacy-linux.sh --stig
# → "STIG Coverage: 28/80 (35%) — 28 PASS / 3 FAIL / 2 WARN"
```

## Maintenance

This mapping is updated for each major NoID release. Issues / PRs welcome — see [CONTRIBUTING.md](../CONTRIBUTING.md). When adding a new check to NoID, add a corresponding row here with the closest matching CIS / STIG ID.

## References

- [CIS Red Hat Enterprise Linux 9 Benchmark](https://www.cisecurity.org/benchmark/red_hat_linux) (CIS, free-tier)
- [DISA STIG for Red Hat Enterprise Linux 9](https://public.cyber.mil/stigs/) (US DoD, public)
- [SCAP Security Guide RHEL9 profiles](https://github.com/ComplianceAsCode/content) (upstream OpenSCAP content)
