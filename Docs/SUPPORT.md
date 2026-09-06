# Support and release validation

Support is an evidence claim, not a side effect of recognizing an `ID=` value
in `/etc/os-release`. This document records the deliberately bounded v3.7.2
desktop matrix and the source-validation boundary used to accept the current
script bytes.

## Validation levels

| Level | Evidence | What it establishes |
|---|---|---|
| Desktop VM | Booted KVM/QEMU guest with a real local graphical session and native display manager; the audit modes run inside the guest | The named distro, package manager, init system, desktop, and config readers work together |
| Syntax container | `bash -n` in a distribution/base image | Parsing only; it is not runtime or desktop support |
| Parser fixture | Sanitized BATS fixture for a native config format | The represented precedence and classification cases work; it is not a distro run |

Only the rows below are v3.7.2 release-validated desktop lines. Unlisted
distributions and desktop combinations may work through shared code paths, but
this release makes no validation claim for them.

The recorded VM runs predate the current script corrections. They establish
historical desktop compatibility; validation of the exact current bytes is
listed separately under **Source boundary** below.

## v3.7.2 release-validation matrix

The matrix is branch-oriented: two Fedora generations, the oldest and newest
selected Ubuntu LTS boundaries, upstream Debian/APT, Arch rolling/pacman,
openSUSE Leap/zypper, Mint/Cinnamon, Pop!_OS/COSMIC, and the NoID Workstation
image itself.

| Distribution line | Desktop / display manager | Validation | Default result | Duration |
|---|---|---|---|---:|
| Fedora 43 | GNOME / GDM | **Desktop VM passed** | 413 findings; score 56; coverage 89% | 118.91 s |
| Fedora 44 | GNOME / GDM | **Desktop VM passed** | 418 findings; score 56; coverage 89% | 128.46 s |
| Ubuntu 22.04 LTS | GNOME / GDM | **Desktop VM passed** | 380 findings; score 59; coverage 86% | 13.90 s |
| Ubuntu 26.04 LTS | GNOME / GDM | **Desktop VM passed** | 395 findings; score 59; coverage 86% | 18.60 s |
| Debian 13 | GNOME / GDM | **Desktop VM passed** | 381 findings; score 56; coverage 86% | 10.17 s |
| Arch Linux rolling | KDE Plasma / SDDM | **Desktop VM passed** | 368 findings; score 44; coverage 87% | 38.92 s |
| openSUSE Leap 16.0 | KDE Plasma / SDDM | **Desktop VM passed** | 334 findings; score 65; coverage 84% | 23.05 s |
| Linux Mint 22.3 | Cinnamon / LightDM | **Desktop VM passed** | 367 findings; score 50; coverage 86% | 88.98 s |
| Pop!_OS 24.04 LTS | COSMIC / cosmic-greeter (greetd) | **Desktop VM passed** | 368 findings; score 66; coverage 85% | 17.78 s |
| NoID Privacy Workstation 44 | GNOME / GDM | **Desktop VM passed** | 451 findings; score 100; coverage 100% | 89.20 s |

The scores describe the test guests' observed posture, not auditor quality.
Expected exit codes caused by genuine FAIL/WARN findings are successful audit
executions when stderr, structure, completeness, and independent validators
are clean. The NoID Workstation row is the installed, hardened UEFI + Secure
Boot image (LUKS2 root with Argon2id, SELinux enforcing, immutable audit, no
failed units); its higher score reflects that hardened image, not a difference
in auditor behavior.

### Source boundary

The v3.7.2 script in this checkout has SHA-256
`30ce5f49a8d119a8801620c342e146da087210d68aa920d06083571f05d7546c` and is
639310 bytes. Verify what you are running:

```bash
sha256sum noid-privacy-linux.sh
```

Bash syntax, style-level ShellCheck, the API-layer lint, the
compliance-mapping validator, and 874 BATS checks pass on these exact bytes.

The PATH-chain correction was verified on 2026-09-04 against the byte-identical
installed predecessor, using disposable fixtures on the live host. The old
admission check accepted a root-owned command link through a user-replaceable
intermediate link to a root-controlled target. The corrected check rejects
that chain while preserving trusted absolute and relative links. Regression
tests also reject mutable directory aliases and traversal through an unsafe
directory followed by `..`. No installed command or host configuration was
changed by this validation.

The same fixture-only method verified the RPM symlink-fingerprint correction:
four targets differing by ordinary text or trailing newline bytes produced
only two distinct fingerprints before the fix and four afterward. Ordinary
target fingerprints remain unchanged. No actual RPM or AIDE baseline was
created, updated, or accepted.

The RPM verification branch now retains `.pyc` and `__pycache__` discrepancies.
An isolated native Python 3.14.7 import executed changed bytecode while its
source file remained unchanged; the preceding auditor had discarded such
discrepancies by pathname. Native RPM 6.0.2 also returned exit 1 with errors
only on stderr for a synthetic damaged package database. Production-block
fixtures verify that bytecode drift reaches grading and fingerprinting, while
query diagnostics and empty failed results prevent clean or complete findings.
No installed Python file or real package database was changed.

IP validation was compared locally with native `inet_pton` using 3,359
decimal-IPv4 and hexadecimal-IPv6 inputs, including 809 valid addresses. All
verdicts matched. This corpus does not cover IPv4-embedded IPv6 notation or
prove complete special-purpose address classification. Separate resolver
fixtures verify exact DNS-address matching, reject incomplete failed status
queries, and retain the requirement for a confirmed active VPN interface.
These checks use no external network probes.

Firewall fixtures reproduce five failed global queries being misclassified
as blocked ingress by the installed predecessor. The corrected snapshot
keeps failures unassessed, including partial stdout and later cache reads,
while retaining successful open/blocked and native `no zone` cases. Socket
fixtures execute the complete listener section: failed queries cannot earn
absence PASS findings, and successful populated and empty results remain
covered. The native `ss` query forms were checked on the live host. No firewall
rules or host services were changed.

GNOME recent-file fixtures reproduce the signed `-1` sentinel being reported
as a one-day PASS by the installed predecessor. The native schema and full
callback were checked on the live host. Regression cases preserve indefinite
retention, finite boundaries, disabled tracking, and failed-query evidence
without reading or changing users' settings.

Scheduled AIDE fixtures reproduce drift suppression after database timestamp
changes, clean findings from partial failed queries, and clean findings without
a completed execution or with a database changed during the scan. The current
block retains drift warnings and checks termination kind, execution chronology,
and both database mtime and ctime. Native grouped systemd queries were verified;
the host had no usable recorded invocation at that check. These tests use
synthetic metadata and do not initialize, update, or replace an AIDE baseline.
A historical clean service result does not recheck current file state or
cryptographically bind the current database to the earlier invocation.

Report-binding fixtures additionally reproduce a delayed NoID check report
being missed while an overlapping shared log supplies another run's counts.
The current reader requires a unique private report with the selected systemd
invocation ID; legacy/shared files cannot establish that association. Native
file tests reject ambiguous names, unsafe objects, failed inventories and
metadata reads. Journal fallback checks both trusted unit and invocation fields
and discards partial output from failed reads. Service metadata is synthetic;
no host AIDE check or baseline operation was needed for these regressions.

The account-snapshot delta reads `/etc/passwd` once in the main shell before
audit sections start; it changes the evidence-capture timing, not a grading
rule. A functional regression mutates the source after loading and proves that
repeated production-shaped process substitutions retain the first snapshot.

The desktop matrix above was recorded during the 3.7.1 cycle, on the same
release line but before its final correctness passes. Those rows are therefore
not a byte-identical claim for the shipped script. On top of the delta below,
the `[3.7.2]` trust-boundary and account-snapshot work applies: AIDE
`aide.db.new*` handling, the
`/usr/local` ownership gate and the deterministic IPv4 egress comparison.
The current corrections also cover PATH chains, RPM symlink fingerprints,
IP syntax, resolver ownership, firewall/socket evidence, GNOME retention, and
scheduled AIDE evidence. These changes can alter findings,
score, and coverage; the historical guest results cannot predict a rerun. The earlier
delta is the `[3.7.1]` correctness work listed in `CHANGELOG.md`: the
kill-switch self-probe, the
fwupd HSI runtime suffix, listener and inventory accuracy, enabled-service
reporting, local human-account counting, offline evidence classification, the
desktop authentication trade-offs, commented Firefox preferences, and the
batched firewalld control-plane reads. The authentication trade-offs explicitly
change severity, including `pam_faillock deny=6..10` becoming INFO. The
firewalld caching change preserves its listener criteria: zones, sources,
services/includes, policies, rich rules, forward ports and direct rules;
incomplete evidence remains unassessed. That pass is covered by executable
cache and IPv6-source regressions plus a 455-finding NoID Workstation Action
run (102.71 seconds, valid JSON and outputs, no FAIL findings), not by a second
ten-guest cycle.

### Published v3.7.2 artifact

The `v3.7.2` tag carries the exact bytes described under
[Source boundary](#source-boundary):

Published script SHA-256: `30ce5f49a8d119a8801620c342e146da087210d68aa920d06083571f05d7546c`.

Published script size: 639310 bytes.

The README's Quick Start, tag download and tag clone commands all use this one
checksum, so a repository checkout and a tag download verify identically. The
release page records the full immutable commit ID that the tag resolves to;
pin that ID in workflows that require a non-movable reference.

### Native mode and gate coverage

Every full matrix record includes:

1. default text output;
2. `--json --ai` plus independent JSON/counter/score validation;
3. `--offline` or JSON+AI offline coverage;
4. `--verbose`;
5. repeated representative `--skip` handling;
6. separate `--cis-l1`, `--cis-l2`, and `--stig` runs;
7. Bash syntax, API-policy lint, compliance-mapping validation, and applicable
   BATS/ShellCheck gates; and
8. zero unexpected stderr plus review of adverse, unavailable, and timeout
   evidence.

The audit never refreshed package metadata and never wrote trust state during
validation. These variables remained unset for every audit:

```text
NOID_AIDE_LIVE
NOID_RPM_BASELINE_INIT
NOID_RPM_BASELINE_UPDATE
NOID_RPM_BASELINE_MODE
NOID_RPM_BASELINE_REFRESH
```

No AIDE database was initialized, updated, replaced, or accepted. For the NoID
Workstation guest, the temporary GDM auto-login used only to establish a real
local desktop session was removed before the audit, and the original
`/etc/gdm/custom.conf` bytes, mode, owner, and SELinux context were restored
and verified before the run.

## Release procedure

For a future release, each supported row must record the distribution line,
desktop/display manager, tested source hash, guest resources, audit duration,
exit code, score, coverage, stderr state, and any incomplete evidence. The
minimum sequence is the eight native modes and gates listed above.

The normal default audit budget is roughly three to five minutes on the
smallest validation guest. A longer run is investigated rather than silently
accepted. Validation must remain side-effect-safe: package caches are not
refreshed, AIDE trust state is never changed, RPM baselines are never created
or refreshed, and temporary graphical-login overrides are restored exactly.

On a shared host, at most three owned matrix guests may run concurrently. Each
guest is capped at 6 GiB RAM and 3 vCPU. Active foreign guests are identified
before launch and are never stopped, paused, reconfigured, or counted as
matrix capacity. Every owned guest shuts down from inside the guest or through
a normal ACPI request.

## Compatibility without a support claim

Shared family paths can work on other Fedora/RHEL, Ubuntu/Debian, Arch,
openSUSE, or derivative releases. XFCE and MATE readers also have source and
fixture coverage. None of those facts is a release-validation claim for an
unlisted distribution/desktop pair.

CI may use additional official base images for syntax-only portability checks.
Those jobs are explicitly not desktop VM evidence and do not expand this
support matrix.
