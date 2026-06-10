# NoID Privacy for Linux — CIS RHEL 9 / STIG Compliance Mapping

This document maps NoID Privacy checks to the **CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0** and applicable **DISA STIG** controls. It enables compliance-conscious users to:

1. See which CIS Level 1 / Level 2 / STIG controls NoID Privacy covers
2. Use `--cis-l1`, `--cis-l2`, `--stig` flags to filter output
3. Generate a coverage report comparing NoID Privacy checks against the benchmark

> **Scope note**: NoID Privacy is a **hardening posture audit** for Linux desktops. It covers a subset of CIS — primarily the configuration-state controls. Server-stack-specific CIS controls (databases, mail, webservers) are **out of scope** and listed as "N/A — server" below.

> **Compliance level**: This mapping does NOT make NoID Privacy an officially CIS-certified tool. It maps NoID Privacy's findings to CIS control IDs for transparency and lets compliance-conscious users cross-reference. Official CIS audits should still use `cis-cat-pro` or equivalent.

## Coverage summary (v3.7.0)

| Tier | Controls in CIS RHEL 9 | NoID Privacy-mapped | Coverage |
|------|------------------------|-------------|----------|
| Level 1 (server + workstation)  | ~232 | 30  | 12% |
| Level 2 (defense in depth)      | ~64  | 16  | 25% |
| STIG (DISA mandate)             | ~250 | 29  | 11% |

> `NoID Privacy-mapped` = the control-ID rows actually present in the mapping table
> below (47 total: 30 L1 + 16 L2 + 29 STIG); `scripts/coverage-report.sh`
> reports these same counts. Benchmark totals (~232/~64/~250) are approximate
> CIS RHEL 9 v2.0.0 ToC sizes. Coverage % = mapped / total.
> Every row corresponds to a check the script actually performs — rows are
> audited against the script source, and any row without a backing check is
> removed rather than kept as aspirational coverage.

## Mapping table

| NoID Privacy Section | NoID Privacy Check | CIS L1 | CIS L2 | STIG ID |
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
| 03 Firewall  | firewalld / nftables active          | 3.4.2.1| —      | RHEL-09-251010 |
| 03 Firewall  | Default policy = DROP / REJECT       | 3.4.2.4| —      | RHEL-09-251015 |
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
| 09 SSH       | No weak Ciphers/MACs/Kex (sha1/md5/cbc) | 5.2.13–15| — | RHEL-09-255055 |
| 09 SSH       | LoginGraceTime ≤ 60                  | 5.2.17 | —      | — |
| 09 SSH       | MaxAuthTries ≤ 4                     | 5.2.6  | —      | RHEL-09-255040 |
| 10 audit     | auditd enabled                       | 4.1.1.1| —      | RHEL-09-651005 |
| 10 audit     | Immutable mode (`-e 2`)              | —      | 4.1.3.20| RHEL-09-651010 |
| 11 users     | Password aging policy + expiry check | 5.5.1.1| —      | RHEL-09-611025 |
| 11 users     | PAM pwquality/cracklib present       | 5.4.1  | —      | RHEL-09-611070 |
| 12 filesystem| /tmp partition / mount opts          | 1.1.2.1–3| —    | RHEL-09-231030 |
| 12 filesystem| World-writable files                 | 6.1.10 | —      | — |
| 12 filesystem| Unowned files                        | 6.1.11 | —      | — |
| 12 filesystem| /etc/passwd 644                     | 6.1.2  | —      | — |
| 12 filesystem| /etc/shadow ≤640                    | 6.1.3  | —      | RHEL-09-232030 |
| 13 crypto    | Crypto policy not LEGACY (DEFAULT+)  | 1.6.1  | —      | — |
| 14 updates   | Updates configured (auto / manual)   | 1.2.4  | —      | RHEL-09-211020 |
| 14 updates   | GPG signature verification           | 1.2.2  | —      | RHEL-09-211025 |
| 27 ntp       | chronyd enabled                      | 2.1.1.1| —      | RHEL-09-252005 |
| 30 hardening | AIDE installed                       | —      | 6.1.4  | RHEL-09-651055 |
| 30 hardening | AIDE database / scheduled check      | —      | 6.1.5  | RHEL-09-651060 |
| 31 modules   | Disabled `cramfs` / `freevxfs` / etc | 1.1.1.1| —      | RHEL-09-213020 |
| 34 integrity | rpm -V (RPM-based)                   | —      | 6.1.10 | — |
| 35 browser   | Firefox telemetry disabled           | —      | —      | (out of scope: CIS doesn't cover desktop browser) |
| ... | ... | ... | ... | ... |

## Out-of-scope CIS controls (NoID Privacy does NOT cover)

These belong to the server-stack domain that NoID Privacy intentionally excludes (use **Lynis** or **OpenSCAP** for server compliance):

- `2.2.x`  — Server services (NIS, telnet, rsh, talk, finger, tftp, nis, ypbind, ypserv)
- `3.4.1.x` — DNS server (named.conf hardening)
- `5.6.x`  — User shell timeouts (TMOUT)
- `6.1.5–9` — System file integrity (mostly server-binary checks)

## Generating coverage report

```bash
# Append a CIS/STIG coverage block to the audit (or run the parser standalone):
sudo bash noid-privacy-linux.sh --cis-l1     # CIS RHEL 9 Level 1 block
sudo bash noid-privacy-linux.sh --cis-l2     # CIS RHEL 9 Level 2 block
sudo bash noid-privacy-linux.sh --stig       # DISA STIG block
bash scripts/coverage-report.sh              # all three, standalone
```

Output format — one line per tier:

```
CIS RHEL 9 Level 1:         <mapped> / 232 controls mapped  (<pct>%)
```

> This is a **static doc-based mapping count** derived from the table above (how
> many CIS/STIG control IDs NoID Privacy cross-references) — NOT a per-control runtime
> PASS/FAIL result. The count reflects the rows present in this file. For an
> official audit use `cis-cat-pro` or OpenSCAP.

## Maintenance

This mapping is updated for each major NoID Privacy release. Issues / PRs welcome — see [CONTRIBUTING.md](../CONTRIBUTING.md). When adding a new check to NoID Privacy, add a corresponding row here with the closest matching CIS / STIG ID.

## References

- [CIS Red Hat Enterprise Linux 9 Benchmark](https://www.cisecurity.org/benchmark/red_hat_linux) (CIS, free-tier)
- [DISA STIG for Red Hat Enterprise Linux 9](https://public.cyber.mil/stigs/) (US DoD, public)
- [SCAP Security Guide RHEL9 profiles](https://github.com/ComplianceAsCode/content) (upstream OpenSCAP content)
