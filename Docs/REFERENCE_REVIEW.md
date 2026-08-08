# External control review for desktop scope

Reviewed on 2026-07-18 for the v3.7.1 work. The goal was not to maximize the
number of findings. It was to find controls whose local evidence is reliable,
whose risk matters on an interactive workstation, and whose severity can be
explained without pretending that server or organization policy is universal.

## Sources

- [Lynis 3.1.7](https://cisofy.com/downloads/lynis/) test registrations and
  implementation, reviewed locally without executing third-party audit code;
- CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 Workstation profiles;
- [ComplianceAsCode RHEL 9 content](https://complianceascode.github.io/content-pages/guides/ssg-rhel9-guide-cis_workstation_l1.html)
  0.1.82 at commit `c17b74bbbb0cd39316d8986880e2e47a73aa2ec5`;
- [DISA RHEL 9 STIG](https://www.cyber.mil/stigs/downloads/) V2R6; and
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) for
  password policy rather than older composition/rotation folklore; and
- [USBGuard configuration](https://usbguard.github.io/documentation/configuration)
  and [rule-language](https://usbguard.github.io/documentation/rule-language)
  references for effective insertion/implicit targets and unconditional rules;
- the official [Arch arch-audit](https://gitlab.archlinux.org/archlinux/arch-audit)
  client and Arch Security Team advisory feed for package-specific rolling-
  release vulnerability evidence; and
- Linux kernel documentation for [Magic SysRq](https://docs.kernel.org/admin-guide/sysrq.html),
  [IPv4 sysctls](https://docs.kernel.org/networking/ip-sysctl.html),
  [kernel sysctls](https://docs.kernel.org/admin-guide/sysctl/kernel.html), and
  [BPF JIT hardening](https://docs.kernel.org/admin-guide/sysctl/net.html).

Exact benchmark denominators, mapping quality, and IDs live in
[CIS_RHEL9_MAPPING.md](CIS_RHEL9_MAPPING.md). This document records engineering
decisions, not additional compliance credit.

## Adopted or strengthened

| Reference idea | Desktop adaptation in NoID | Why it is meaningful |
|---|---|---|
| Lynis AUTH-9208 / AUTH-9226; CIS 7.2.3 / 7.2.6 | Explicit duplicate user-name and group-name checks, separate from duplicate UID/GID checks | Names and numeric IDs are independent authorization namespaces; ambiguity is actionable and locally provable |
| Lynis AUTH-9252 | Root ownership plus non-writable directory/file modes for `/etc/sudoers` and every `sudoers.d` drop-in | Mode-only checking misses a non-root-owned policy file; safe root-controlled 0400/0440/0600/0640 modes are accepted instead of treating owner-write as authority granted to another principal |
| CIS 1.1.2.2.2–1.1.2.2.4; STIG 231110/231115/231120 | Effective topmost `/dev/shm` `nodev,nosuid,noexec` options | Shared memory is cross-process desktop attack surface, and the normal distro policy is observable without requiring a server-style partition layout |
| Lynis AUTH-9262/9282/9283/9286 and current authentication guidance | Effective `pwquality.conf.d` plus PAM argument precedence, context-dependent length, dictionary/root enforcement, and explicit central-auth uncertainty | Avoids false PASS from reading a shadowed file and avoids treating local `chage` data as central policy |
| Lynis ACCT-9630 and CIS/STIG audit controls | Exact path/directory coverage plus complete compact syscall families instead of a raw rule count; present `utmp/wtmp/btmp`, `faillock`, legacy `lastlog`, and modern `lastlog2` backends receive tamper-watch checks | Ten duplicate or irrelevant rules are not better evidence than one correct family; PAM audit events are distinguished from history-file manipulation, while architecture/filter completeness remains partial unless proven |
| Lynis FINT-4314/4315/4316/4339/4402 | AIDE presence/database/scheduled result, strong hash evidence, and IMA/EVM state without any baseline write | Integrity evidence is useful only when the operator owns the baseline; the audit never initializes, updates, swaps, or accepts it |
| Lynis USB-1000/2000/3000 | USB-storage policy plus effective USBGuard inserted-device/implicit targets and rule evidence | Hostile/removable peripherals are directly relevant to desktops; mere package or service presence is insufficient, and an unconditional allow-all rule cannot earn whitelist credit |
| Lynis TIME-3104/3112/3120/3132 | Bounded, non-resolving chrony source/authentication checks | Time affects TLS and audit evidence, but dead sources must not turn a three-minute desktop audit into a resolver stall |
| CIS/STIG desktop controls | Native GNOME/Cinnamon removable-media policy and GDM/SDDM/LightDM/greetd auto-login evidence | These controls affect an unattended physical workstation and are evaluated through the actual desktop/display-manager format |
| CIS/STIG sysctl controls plus kernel semantics | Core unprivileged boundaries remain FAIL, while recovery-only SysRq masks, dormant redirect sending, reverse-path routing compatibility, packet-log privacy, and BPF privilege context receive distinct severities | A benchmark target is useful evidence, but a disabled code path or documented privacy/compatibility trade-off is not equivalent to an active unprivileged boundary failure |
| Arch Security Team data through `arch-audit` | Machine-formatted affected-package evidence separates a published fixed version from unresolved advisories; the bounded live request obeys offline mode | A rolling-update list is not a security feed, while vendor-tracked affected packages are direct and actionable evidence |

All adopted behavior has local BATS/source-policy coverage and must still pass
the real VM matrix in [SUPPORT.md](SUPPORT.md).

## Kept as partial evidence

- SSH cipher/MAC/KEX parsing identifies generic weak families, but does not
  duplicate every benchmark allow-list and RHEL crypto-policy exception. It is
  therefore partial for CIS 5.1.4–5.1.6.
- Audit rule families show useful coverage, but do not prove every required
  architecture, success/failure selector, key, and immutable load state.
- `/tmp`, `/var/tmp`, and `/home` effective mount observations are useful on a
  desktop. Combined or inherited mounts do not automatically receive direct
  credit for every benchmark partition control.
- Reading a desktop value does not prove that a system policy lock prevents the
  user from overriding it. Lock-dependent CIS/STIG rows remain partial.
- Firewall backend/activity and exposed-port evidence do not establish that
  every zone/policy path matches a benchmark's prescribed implementation.

Partial evidence is visible for review but excluded from the coverage totals.

## Deliberately not copied as a universal FAIL

- Periodic password expiry and character-class composition: NIST's current
  guidance instead emphasizes sufficient length, blocklists, rate limiting,
  and changing a password on evidence of compromise. Organization policy is
  still reported as INFO.
- A fixed 4096-bit minimum for SSH RSA keys: 2048-bit and larger keys are not
  penalized by an invented universal threshold. Organizations can apply a
  stricter overlay.
- Fail2Ban on every desktop: a host with no exposed password-authenticated
  service does not become insecure merely because Fail2Ban is absent.
- Compiler presence, process count, uptime, load, and generic journal error
  volume: these are operational/context evidence, not compromise or hardening
  verdicts. Performance findings are INFO and the performance section has zero
  posture weight; raw interface/connectivity inventory is likewise weight zero.
- SMART failures and thermal pressure: these are urgent availability and data-
  protection signals, but they are not evidence that security/privacy policy is
  weak. They remain operational INFO while CPU mitigation state carries the
  hardware section's security severity.
- Reachable LAN devices while a VPN is active: printer/NAS sharing can be an
  explicit user choice, and a successful ping alone does not establish a route
  leak. Reachability remains INFO; learned route/DNS evidence is graded on its
  own merits.
- Firewall logging as an unconditional PASS: logging can aid response while
  retaining addresses and connection metadata. Enabled and disabled states
  keep the privacy/response trade-off visible without penalizing logging-off.
- Martian-packet logging as an unconditional security verdict: like firewall
  logging, it trades response evidence for retained source-address metadata.
  The state is reported without charging privacy-conscious logging-off as a
  hardening failure.
- A clean rkhunter/chkrootkit result as proof of integrity: signature and
  heuristic scanners cannot establish that the host is clean.
- Separate `/var`, `/var/log`, `/var/log/audit`, and similar server-style
  partitions as desktop requirements. Their value depends on availability,
  recovery, encryption, and deployment design; absence alone is not a desktop
  privacy failure.
- Server inventories for mail, database, web, SNMP, Squid, Kerberos, or LDAP
  services when they are not installed or exposed. Relevant running listeners
  and services are already assessed through generic attack-surface sections.
- Ordinary package backlogs, compiler/browser/tool installation, a specific
  password-manager or content-blocker choice, raw autostart counts, and an
  inactive optional tool are not failures by themselves. Security-only package
  metadata, effective policy, exposed listeners, and unsafe permissions carry
  severity; Arch's general rolling-update list is not mislabeled as a
  security-only feed.
- Generic process names, network-capable cron commands, expired certificate
  files not tied to a service, trash size, and `systemd-analyze security`
  scores are not standalone compromise/hardening evidence. They remain review
  inventory; only an effective listener, unsafe permission, active policy, or
  other direct boundary can carry adverse severity.

These heuristic/operational sections retain full findings but have zero posture
weight. Direct process/listener, authentication, permission, and integrity
evidence is scored in the sections that own those boundaries.

## Deferred pending reliable evidence

- `dm-integrity`, `dm-verity`, and UEFI MemoryOverwriteRequest can be valuable
  on specific immutable or high-assurance systems. They are not scored yet
  because absence is not a general mutable-desktop failure and the audit needs
  cross-distro, stacked-device, firmware, and suspend/hibernate fixtures before
  it can classify them without false confidence.
- Fine-grained per-control score coverage would require stable control IDs and
  denominators for each distro/desktop path. Raw PASS/INFO counts are not used
  as a substitute; the disclosed section-level coverage model remains the
  auditable v1 boundary.

## Review rule for future imports

A candidate from Lynis, CIS, SCAP, STIG, or another tool is accepted only when:

1. the threat and asset are relevant to an interactive Linux workstation;
2. the effective state and precedence can be read without changing the host;
3. secure, insecure, unavailable, malformed, timeout, and override cases can be
   tested;
4. severity reflects both impact and confidence;
5. network disclosure and performance are bounded; and
6. overlap with an existing layered control does not merely add another count.

Reference implementations inform the behavior, but NoID's code and wording are
independently reviewed for its desktop threat model.
