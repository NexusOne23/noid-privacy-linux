# Scoring model

NoID Privacy for Linux reports two separate values under model identifier
`section-risk-v1`:

- **Desktop posture score**: the result within the assessed security and
  privacy scope, from 0 to 100.
- **Risk-weight coverage**: how much of the fixed model produced an assessed
  result, from 0% to 100%.

Neither value is a certification, a probability of compromise, or a substitute
for reviewing the findings. A high score with limited coverage is explicitly
rated `LIMITED EVIDENCE`.

## Why findings are not counted directly

The number of emitted findings depends on the machine. One host may expose 30
sysctls or hundreds of file-permission entries while another lacks the relevant
tool entirely. A formula based on raw PASS/FAIL/WARN counts therefore lets loops,
optional packages, JSON detail, or a new informational check change the apparent
importance of unrelated controls.

The model instead assigns a fixed weight to each of the 42 sections before the
audit starts. Adding repeated PASS messages cannot inflate a section's
contribution, and `--verbose` cannot change the score.

## Section grades

For each canonical section, the worst assessed severity determines its grade:

| Result within the section | Grade | Meaning |
|---|---:|---|
| At least one FAIL | 0 | A required control in the section failed |
| No FAIL, at least one WARN | 50 | The section needs review or has incomplete protection |
| At least one PASS, no FAIL/WARN | 100 | No adverse result was found in assessed controls |
| INFO only, skipped, or unavailable | unassessed | No score contribution; coverage is reduced |

INFO findings remain visible but never establish that a control passed. A
zero-weight section can be assessed and reported without affecting either score.

## Risk weights

Weights reflect a general-purpose, single-user Linux desktop threat model:
protection of local data and credentials, browser and network privacy, hostile
peripherals, untrusted applications, persistence, and remote exposure. They are
not probabilities, CVSS scores, finding counts, or CIS/STIG control counts.
Those baselines have different scopes and include organization-specific policy.

The tiers use these design rules:

1. Authentication receives the highest weight because a failure can cross most
   per-user desktop boundaries and sudo policy can cross the root boundary.
2. Root trust, filesystem/data exposure, integrity, browser isolation,
   unattended-session controls, and credential storage receive weights five or
   four according to breadth and directness.
3. Mandatory access control, firewall/sysctl enforcement, cryptography,
   updates, privacy policy, and layered hardening receive weight four.
4. Direct but narrower exposures receive weights one through three.
5. Heuristic malware/process names, generic log volume, activity inventories,
   optional Fail2Ban, performance, raw interfaces/certificate files, and generic
   service-sandbox scores receive zero because they do not establish a live
   desktop hardening boundary by themselves.

Equal weights inside a tier are deliberate: the model does not claim enough
empirical precision to distinguish, for example, browser privacy at 4.2 from
data privacy at 3.8. A different threat model may reasonably choose different
weights; it must use a different model identifier if reports are to remain
comparable.

| Weight | Sections |
|---:|---|
| 6 | users/authentication |
| 5 each | kernel/root trust, filesystem, integrity, browser, session, keyring |
| 4 each | SELinux/AppArmor, firewall, sysctl, crypto, updates, hardening, network privacy, data privacy |
| 3 each | exposed ports, SSH, audit, modules, application telemetry/privacy |
| 2 each | VPN, hardware mitigations, environment/secrets, webcam/audio privacy |
| 1 each | nftables/kill-switch, services, advanced network, containers, desktop/display server, NTP, permissions, boot, Bluetooth privacy |
| 0 | rootkit heuristics, process heuristics, generic logs, performance, raw interfaces, certificate-file inventory, generic systemd exposure scores, Fail2Ban, login/activity inventory |

The 42 weights total exactly 100. At full coverage, a FAIL costs its section's
weight and a WARN costs half that amount before integer rounding. This gives the
tiers a direct, reviewable effect rather than hidden precision.

SELinux and AppArmor share the canonical
`selinux` section identifier because they are alternative mandatory-access-
control implementations in this audit.

## Calculation

For every assessed section with a non-zero weight:

```text
posture score = round(sum(section weight × section grade)
                      / sum(assessed section weights))

risk-weight coverage = round(sum(assessed section weights) × 100
                             / sum(all section weights))
```

Example: a weight-6 section at WARN and a weight-4 section at PASS produce
`(6×50 + 4×100) / 10 = 70`, with 100% coverage of that ten-point example
model.

Rounding is integer half-up, and the GitHub Action independently recomputes the
same arithmetic from the section array.

The JSON report exposes the inputs under `scoring.sections`, including every
section's weight, status, grade, and raw severity counts. The summary includes
`score`, `score_coverage`, `assessed_weight`, and `total_weight`. The GitHub
Action validates the model and independently recomputes both percentages before
accepting a report.

For CI policy, set both Action inputs: `min-score` controls posture within the
assessed scope and `min-coverage` controls how much of the fixed model must have
evidence. Both default to zero for backward compatibility. A score threshold
without a coverage threshold is intentionally allowed, but can be satisfied by
a selectively skipped audit and should not be used as a strong gate.

## Ratings

Coverage is evaluated first:

| Condition | Rating |
|---|---|
| Coverage below 50% | `LIMITED EVIDENCE` |
| Score 90–100 with coverage at least 50% | `STRONG POSTURE` |
| Score 75–89 with coverage at least 50% | `MODERATE POSTURE` |
| Score 50–74 with coverage at least 50% | `WEAK POSTURE` |
| Score 0–49 with coverage at least 50% | `HIGH EXPOSURE` |

These labels deliberately avoid “fully hardened” or “compliant.” Passing an
automated check establishes only the condition that the check actually
observed at that time.

## Coverage granularity

Coverage is binary at the section level: a non-zero-weight section normally
contributes its weight once it emits at least one PASS, WARN, or FAIL. INFO-only
and skipped sections contribute none. A check may also mark a section
explicitly incomplete when required evidence failed or timed out; if that
section has no WARN or FAIL, it remains unassessed even when another sub-check
emitted PASS. This prevents partial evidence from being presented as a clean
section. Optional unavailable sub-checks do not trigger that override: for
example, one assessed hardware control can establish hardware-section coverage
while an unavailable optional firmware utility remains visible as INFO.

This limitation is intentional and disclosed in the JSON's per-section raw
counts. A finer-grained coverage claim would require stable control identifiers
and denominators for every distro/desktop combination; deriving it from raw
finding or INFO counts would recreate the distortion this model removes. CI
gates should therefore review adverse and unavailable findings in addition to
setting `min-coverage`.

## Interpretation and limits

- Read every FAIL and WARN; equal section grades do not imply equal remediation
  urgency.
- Compare score trends only when the audit version, options, and assessed
  coverage are also comparable.
- `--skip` always removes the skipped section's weight. Missing utilities,
  permissions, timeouts, hardware absence, and distro capabilities reduce
  coverage when they leave a section without any assessed result. A required
  evidence failure can also explicitly keep an otherwise PASS-only section
  unassessed; optional gaps remain INFO and disclose the narrower evidence.
- Organization-specific threat models may need different weights. The shipped
  weights are intentionally fixed so reports from the same release remain
  comparable; changing them requires a new model identifier.
- Compliance flags report mapping coverage separately. They do not alter the
  desktop posture score.
