# CIS RHEL 9 and DISA STIG cross-reference

NoID Privacy for Linux is a desktop security and privacy posture audit. It is
not CIS-certified, is not a SCAP scanner, and does not produce an official
compliance verdict. This document records which runtime findings can be
cross-referenced to the current RHEL 9 benchmark controls without pretending
that a Linux-desktop audit replaces CIS-CAT Pro or OpenSCAP.

The mapping was reviewed on 2026-07-18 against:

- CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0, workstation profiles;
- ComplianceAsCode RHEL 9 profile content at commit
  `c17b74bbbb0cd39316d8986880e2e47a73aa2ec5` (content 0.1.82);
- DISA Red Hat Enterprise Linux 9 STIG V2R6, which contains 447 rules.

The CIS profile selectors contain 227 Level 1 Workstation recommendations and
293 cumulative Level 2 Workstation recommendations. “Cumulative” matters:
Level 2 includes the Level 1 controls; it is not a separate 66-control
denominator.

## Meaning of the mapping quality

- **Direct**: the audit reads the state or inventory needed by that control.
  It may use a stricter desktop threshold. This is what the coverage report
  counts.
- **Partial**: the audit provides related evidence, but does not test every
  benchmark condition, enforcement lock, path, architecture, or RHEL-specific
  exception. Partial rows are deliberately excluded from coverage totals.
- An `INFO` finding remains observational and does not become a compliance
  PASS merely because an ID is listed here.

## Direct mappings

Each CIS ID appears once. Multiple STIG IDs in one cell are separate rules
covered by the same effective-state check.

| Section | Audit evidence | CIS profile | CIS control | STIG control | Quality |
|---|---|---|---|---|---|
| 01 Kernel | GRUB superuser password | L1 | 1.4.1 | RHEL-09-212010 | Direct |
| 02 MAC | SELinux is not disabled | L1 | 1.3.1.4 | RHEL-09-431010 | Direct |
| 02 MAC | SELinux is enforcing | L2 | 1.3.1.5 | — | Direct |
| 06 sysctl | IPv4 redirect sending disabled for all/default | L1 | 3.3.2 | RHEL-09-253065, RHEL-09-253070 | Direct |
| 06 sysctl | Bogus ICMP responses ignored | L1 | 3.3.3 | RHEL-09-253060 | Direct |
| 06 sysctl | Broadcast ICMP requests ignored | L1 | 3.3.4 | RHEL-09-253055 | Direct |
| 06 sysctl | Reverse-path filtering for all/default | L1 | 3.3.7 | RHEL-09-253035, RHEL-09-253050 | Direct |
| 06 sysctl | Martian packets logged for all/default | L1 | 3.3.9 | RHEL-09-253025, RHEL-09-253030 | Direct |
| 06 sysctl | TCP SYN cookies enabled | L1 | 3.3.10 | RHEL-09-253010 | Direct |
| 06 sysctl | Kernel message buffer restricted | — | — | RHEL-09-213010 | Direct |
| 06 sysctl | Kernel pointer exposure restricted | — | — | RHEL-09-213025 | Direct |
| 06 sysctl | Protected hardlinks enabled | — | — | RHEL-09-213030 | Direct |
| 06 sysctl | Protected symlinks enabled | — | — | RHEL-09-213035 | Direct |
| 06 sysctl | ASLR enabled | — | — | RHEL-09-213070 | Direct |
| 06 sysctl | Unprivileged BPF disabled | — | — | RHEL-09-213075 | Direct |
| 06 sysctl | `ptrace` restricted | — | — | RHEL-09-213080 | Direct |
| 06 sysctl | BPF JIT hardening enabled | — | — | RHEL-09-251045 | Direct |
| 09 SSH | SSH user/group allow-list present | L1 | 5.1.7 | — | Direct |
| 09 SSH | Login grace time bounded | L1 | 5.1.14 | — | Direct |
| 09 SSH | Authentication attempts bounded | L1 | 5.1.16 | — | Direct |
| 09 SSH | Empty SSH passwords disabled | L1 | 5.1.19 | RHEL-09-255040 | Direct |
| 09 SSH | Direct root SSH login disabled | L1 | 5.1.20 | RHEL-09-255045 | Direct |
| 09 SSH | Public-key authentication enabled | — | — | RHEL-09-255035 | Direct |
| 09 SSH | X11 forwarding disabled | — | — | RHEL-09-255155 | Direct |
| 10 Audit | Immutable audit configuration | L2 | 6.3.3.20 | RHEL-09-654275 | Direct |
| 11 Users | `sudo` commands use a pseudo-terminal | L1 | 5.2.2 | — | Direct |
| 11 Users | Password required for privilege escalation | L2 | 5.2.4 | RHEL-09-432020, RHEL-09-611085 | Direct |
| 11 Users | Global `sudo` reauthentication not disabled | L1 | 5.2.5 | RHEL-09-432015, RHEL-09-432025 | Direct |
| 11 Users | `sudo` credential timeout bounded | L1 | 5.2.6 | — | Direct |
| 11 Users | Failed-attempt lockout threshold | L1 | 5.3.3.1.1 | — | Direct |
| 11 Users | Failed-attempt unlock time | L1 | 5.3.3.1.2 | — | Direct |
| 11 Users | Password dictionary screening enabled | L1 | 5.3.3.2.6 | RHEL-09-611105 | Direct |
| 11 Users | PAM `nullok` absent | L1 | 5.3.3.4.1 | RHEL-09-611025 | Direct |
| 11 Users | Strong PAM password hash | L1 | 5.3.3.4.3 | — | Direct |
| 11 Users | Root is the only UID 0 account | L1 | 5.4.2.1 | — | Direct |
| 11 Users | Restrictive default user umask | L1 | 5.4.3.3 | — | Direct |
| 12 Filesystem | Core-dump handler discards data | — | — | RHEL-09-213040 | Direct |
| 12 Filesystem | Core-dump backtrace processing disabled | — | — | RHEL-09-213085 | Direct |
| 12 Filesystem | Core-dump storage disabled | — | — | RHEL-09-213090 | Direct |
| 12 Filesystem | User core-dump hard limit is zero | — | — | RHEL-09-213095 | Direct |
| 12 Filesystem | `/etc/passwd` mode | L1 | 7.1.1 | RHEL-09-232075 | Direct |
| 12 Filesystem | `/etc/group` mode | L1 | 7.1.3 | RHEL-09-232055 | Direct |
| 12 Filesystem | `/etc/shadow` mode, distro-specific | L1 | 7.1.5 | RHEL-09-232270 | Direct |
| 12 Filesystem | `/etc/gshadow` mode, distro-specific | L1 | 7.1.7 | RHEL-09-232065 | Direct |
| 12 Filesystem | SUID/SGID inventory for manual review | L1 | 7.1.13 | — | Direct |
| 12 Filesystem | `/dev/shm` effective mount has `nodev` | L1 | 1.1.2.2.2 | RHEL-09-231110 | Direct |
| 12 Filesystem | `/dev/shm` effective mount has `nosuid` | L1 | 1.1.2.2.3 | RHEL-09-231120 | Direct |
| 12 Filesystem | `/dev/shm` effective mount has `noexec` | L1 | 1.1.2.2.4 | RHEL-09-231115 | Direct |
| 13 Crypto | System-wide crypto policy is not `LEGACY` | L1 | 1.6.1 | — | Direct |
| 14 Updates | Installed RPM package signatures | — | — | RHEL-09-214010 | Direct |
| 17 Network | No unexpected promiscuous interfaces | — | — | RHEL-09-251040 | Direct |
| 27 Time | Time synchronization in use | L1 | 2.3.1 | — | Direct |
| 27 Time | chrony has configured sources | L1 | 2.3.2 | — | Direct |
| 30 Hardening | AIDE installed | L1 | 6.1.1 | RHEL-09-651010 | Direct |
| 30 Hardening | Scheduled AIDE check evidence | L1 | 6.1.2 | RHEL-09-651015 | Direct |
| 30 Hardening | USBGuard installed | — | — | RHEL-09-291015 | Direct |
| 30 Hardening | USBGuard active | — | — | RHEL-09-291020 | Direct |
| 11 Users | Duplicate user names absent | L1 | 7.2.3 | — | Direct |
| 11 Users | Duplicate UIDs absent | L1 | 7.2.4 | — | Direct |
| 11 Users | Duplicate GIDs absent | L1 | 7.2.5 | — | Direct |
| 11 Users | Duplicate group names absent | L1 | 7.2.6 | — | Direct |
| 34 Integrity | RPM vendor file hashes/metadata | — | — | RHEL-09-214030 | Direct |
| 39 Session | Login-screen user list hidden | L1 | 1.8.3 | RHEL-09-271115 | Direct |
| 39 Session | Screen locking enabled | L1 | 1.8.4 | RHEL-09-271055 | Direct |
| 39 Session | Desktop idle timeout | — | — | RHEL-09-271065 | Direct |
| 39 Session | Lock begins without a grace delay | — | — | RHEL-09-271075 | Direct |
| 39 Session | Desktop removable-media automount disabled | L2 | 1.8.6 | RHEL-09-271020 | Direct |
| 39 Session | Desktop removable-media autorun disabled | L1 | 1.8.8 | RHEL-09-271030 | Direct |
| 39 Session | GDM, SDDM, LightDM, and greetd auto-login | — | — | RHEL-09-271040 | Direct |
| 41 Bluetooth | Bluetooth radio/service disabled | — | — | RHEL-09-291035 | Direct |

## Related evidence that is not counted

| Section | Audit evidence | CIS profile | CIS control | STIG control | Quality |
|---|---|---|---|---|---|
| 03 Firewall | Active firewall implementation | L1 | 4.1.2 | RHEL-09-251015 | Partial |
| 03 Firewall | Exposed services/ports and default targets | L1 | 4.2.1 | RHEL-09-251020 | Partial |
| 04 nftables | `nft` availability and active backend | L1 | 4.1.1 | — | Partial |
| 06 sysctl | IPv4 forwarding | L1 | 3.3.1 | RHEL-09-253075 | Partial |
| 06 sysctl | IPv4 redirects accepted state | L1 | 3.3.5 | RHEL-09-253015, RHEL-09-253040 | Partial |
| 06 sysctl | Source-routed IPv4 packets | L1 | 3.3.8 | RHEL-09-253020 | Partial |
| 09 SSH | Effective cipher list excludes generic weak families | L1 | 5.1.4 | RHEL-09-255065 | Partial |
| 09 SSH | Effective key-exchange list excludes generic weak families | L1 | 5.1.5 | — | Partial |
| 09 SSH | Effective MAC list excludes generic weak families | L1 | 5.1.6 | RHEL-09-255075 | Partial |
| 10 Audit | auditd active state | L2 | 6.3.1.4 | RHEL-09-653010, RHEL-09-653015 | Partial |
| 10 Audit | sudoers watches | L2 | 6.3.3.1 | RHEL-09-654215, RHEL-09-654220 | Partial |
| 10 Audit | Time-change rule family | L2 | 6.3.3.4 | — | Partial |
| 10 Audit | User/group database watches | L2 | 6.3.3.8 | RHEL-09-654240, RHEL-09-654245 | Partial |
| 10 Audit | Present session-history database tamper watches (`utmp/wtmp/btmp`) | L2 | 6.3.3.11 | — | Partial |
| 10 Audit | Present login-history database tamper watches (`faillock`, `lastlog`/`lastlog2`) | L2 | 6.3.3.12 | — | Partial |
| 10 Audit | Deletion/rename syscall family | L2 | 6.3.3.13 | RHEL-09-654065 | Partial |
| 10 Audit | Kernel-module syscall family | L2 | 6.3.3.19 | RHEL-09-654075, RHEL-09-654080 | Partial |
| 11 Users | Effective minimum password length | L1 | 5.3.3.2.2 | RHEL-09-611090 | Partial |
| 11 Users | PAM faillock module present in active stacks | L1 | 5.3.3.1.1 | RHEL-09-611030, RHEL-09-611035 | Partial |
| 11 Users | PAM pwquality module present in active stacks | L1 | 5.3.3.2.3 | RHEL-09-611040, RHEL-09-611045 | Partial |
| 11 Users | Invocation PATH compared with root PATH requirements | L1 | 5.4.2.5 | — | Partial |
| 11 Users | Default umask compared with the STIG owner-only requirement | — | — | RHEL-09-412065 | Partial |
| 12 Filesystem | `/tmp` separate mount and remaining mount flags | L1 | 1.1.2.1.1 | RHEL-09-231015, RHEL-09-231125, RHEL-09-231130 | Partial |
| 12 Filesystem | `/tmp` `nosuid` when separately mounted | L1 | 1.1.2.1.3 | RHEL-09-231135 | Partial |
| 12 Filesystem | `/var/tmp` `nosuid` when separately mounted | L1 | 1.1.2.5.3 | RHEL-09-231185 | Partial |
| 12 Filesystem | `/home` separate mount, `nodev`, and `nosuid` | L1 | 1.1.2.3.2 | RHEL-09-231010, RHEL-09-231045, RHEL-09-231050 | Partial |
| 12 Filesystem | World-writable file scan | L1 | 7.1.11 | RHEL-09-232240, RHEL-09-232245 | Partial |
| 12 Filesystem | Unowned/ungrouped path scan | L1 | 7.1.12 | RHEL-09-232250, RHEL-09-232255 | Partial |
| 31 Modules | Legacy filesystem-module availability | L1 | 1.1.1.1 | RHEL-09-231195 | Partial |
| 31 Modules | USB mass-storage module | L2 | 1.1.1.8 | RHEL-09-291010 | Partial |
| 32 Permissions | Password/group database consistency tools | L1 | 7.2.1 | — | Partial |
| 39 Session | dconf policy locks for desktop settings | L1 | 1.8.5 | RHEL-09-271060, RHEL-09-271070, RHEL-09-271080 | Partial |

The partial table is intentionally non-exhaustive. It highlights the most
tempting places to overclaim. For example, seeing one audit syscall is not
proof that every required architecture and success/failure filter is present,
and reading a GNOME value is not proof that dconf prevents user overrides.

## Coverage report

```bash
bash scripts/coverage-report.sh
bash scripts/coverage-report.sh cis-l1
bash scripts/coverage-report.sh cis-l2
bash scripts/coverage-report.sh stig
```

The script validates table syntax, deduplicates exact IDs, counts only Direct
rows, and uses the fixed benchmark denominators above. The `--cis-l1`,
`--cis-l2`, and `--stig` audit options append the same static cross-reference
summary; they do not filter runtime findings or transform the report into a
certification result.

## Desktop-focused use of CIS, STIG, Lynis, and SCAP

NoID adopts benchmark ideas when they materially reduce risk on an interactive
workstation: effective PAM precedence, removable-media behavior, session lock,
auto-login, firewall exposure, audit rule families, file integrity, package
provenance, and core-dump privacy. Server-only service inventories and DoD-only
policy requirements are not copied merely to increase a check count.

Lynis remains useful as a broad second opinion, and OpenSCAP/ComplianceAsCode is
the appropriate machine-readable RHEL control evaluator. Their findings should
be reconciled with desktop context instead of blindly promoted to NoID FAILs.

## Primary references

- [CIS Red Hat Enterprise Linux benchmark](https://www.cisecurity.org/benchmark/red_hat_linux)
- [ComplianceAsCode RHEL 9 CIS Workstation L1 guide](https://complianceascode.github.io/content-pages/guides/ssg-rhel9-guide-cis_workstation_l1.html)
- [DISA STIG downloads](https://www.cyber.mil/stigs/downloads/)
- [ComplianceAsCode source](https://github.com/ComplianceAsCode/content)
- [Lynis source](https://github.com/CISOfy/lynis)
