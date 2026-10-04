# Check references and desktop scope

NoID Privacy for Linux assesses security and privacy on interactive Linux
desktops. Its checks use effective local state where available and distinguish
confirmed findings from missing or incomplete information.

## Reference material

- [Lynis](https://cisofy.com/downloads/lynis/) for Linux audit coverage.
- CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 Workstation profiles and
  [ComplianceAsCode RHEL 9 content](https://complianceascode.github.io/content-pages/guides/ssg-rhel9-guide-cis_workstation_l1.html).
- [DISA RHEL 9 STIG](https://www.cyber.mil/stigs/downloads/) V2R6.
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) for authentication.
- USBGuard [configuration](https://usbguard.github.io/documentation/configuration)
  and [rule syntax](https://usbguard.github.io/documentation/rule-language).
- [Arch arch-audit](https://gitlab.archlinux.org/archlinux/arch-audit) and the
  Arch Security Team advisory feed for affected packages.
- Linux kernel documentation for [Magic SysRq](https://docs.kernel.org/admin-guide/sysrq.html),
  [IPv4 sysctls](https://docs.kernel.org/networking/ip-sysctl.html),
  [kernel sysctls](https://docs.kernel.org/admin-guide/sysctl/kernel.html) and
  [BPF JIT hardening](https://docs.kernel.org/admin-guide/sysctl/net.html).

Exact benchmark versions, control IDs and coverage denominators are in the
[CIS/STIG cross-reference](CIS_RHEL9_MAPPING.md). NoID is not CIS-certified and
does not replace a benchmark-specific compliance scanner.

## How findings are interpreted

Effective permissions, authentication policy, exposed services, package
integrity and active protection settings can support security findings.
Configuration precedence matters: a shadowed file, installed package or
service name alone does not establish effective protection.

Operational information such as process counts, load, compiler presence,
temperatures and generic journal messages is reported as context. It does not
by itself prove compromise or weaken the posture score. Hardware failures can
still require urgent attention without being security-policy failures.

Desktop choices also need context. A printer reachable over a VPN is not by
itself a routing leak. Absent server-only partitions or an unused optional
service are not universal desktop failures. Logging settings expose both their
diagnostic value and privacy implications.

AIDE databases remain user-owned trust state. The audit does not initialize,
update or accept a baseline. A clean heuristic scanner result does not prove
that a machine is uncompromised.

Partial benchmark matches are labeled and excluded from direct-coverage totals.
For example, an SSH algorithm-family check does not implement every benchmark
allow-list, and reading a GNOME setting does not prove that policy locks prevent
overrides. See [scoring](SCORING.md), [the check reference](CHECKS.md) and
[compatibility tests](SUPPORT.md) for the implemented scope.
