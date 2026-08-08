# Support and release validation

Support is an evidence claim, not a side effect of recognizing an `ID=` value
in `/etc/os-release`. This document records the deliberately bounded v3.7.1
desktop matrix and the evidence boundary used to accept it.

## Validation levels

| Level | Evidence | What it establishes |
|---|---|---|
| Desktop VM | Booted KVM/QEMU guest with a real local graphical session and native display manager; the audit modes run inside the guest | The named distro, package manager, init system, desktop, and config readers work together |
| Syntax container | `bash -n` in a distribution/base image | Parsing only; it is not runtime or desktop support |
| Parser fixture | Sanitized BATS fixture for a native config format | The represented precedence and classification cases work; it is not a distro run |

Only the rows below are v3.7.1 release-validated desktop lines. Unlisted
distributions and desktop combinations may work through shared code paths, but
this release makes no validation claim for them.

## v3.7.1 release-validation matrix

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

The shipped v3.7.1 script has SHA-256
`a307f916e91163e399f71a2d83fe4fdcfd39f4dd47bd85b38390599ccb210196` and is
594634 bytes. Verify what you are running:

```bash
sha256sum noid-privacy-linux.sh
```

Bash syntax, style-level ShellCheck, the API-layer lint and the
compliance-mapping validator pass on these exact bytes.

The desktop matrix above ran during the release cycle, on the same release line
but before its final correctness pass. Those rows are therefore not a
byte-identical claim for the shipped script. The delta is the `[3.7.1]`
correctness work listed in `CHANGELOG.md`: the kill-switch self-probe, the
fwupd HSI runtime suffix, listener and inventory accuracy, enabled-service
reporting, local human-account counting, offline evidence classification, the
desktop authentication trade-offs, commented Firefox preferences, and the
batched firewalld control-plane reads. None of it changes a grading rule —
every listener is still evaluated against the same zones, sources,
services/includes, policies, rich rules, forward ports and direct rules, with
incomplete evidence remaining unassessed. That pass is covered by executable
cache and IPv6-source regressions plus a 455-finding NoID Workstation Action
run (102.71 seconds, valid JSON and outputs, no FAIL findings), not by a second
ten-guest cycle.

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
