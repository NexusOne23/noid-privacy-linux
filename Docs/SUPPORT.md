# Compatibility and tests

NoID Privacy for Linux supports the package-manager and desktop interfaces
listed below. The test version is stated explicitly: recognizing a distribution
name alone is not a compatibility test.

## Desktop VM results

These compatibility runs used the 3.7.1 development version. All listed desktop
VM runs passed. They are not a claim that the complete VM set was rerun against
v3.7.2; checks of the current script are listed separately below.

| Distribution | Desktop / display manager | Result |
|---|---|---|
| Fedora 43 | GNOME / GDM | Passed |
| Fedora 44 | GNOME / GDM | Passed |
| Ubuntu 22.04 LTS | GNOME / GDM | Passed |
| Ubuntu 26.04 LTS | GNOME / GDM | Passed |
| Debian 13 | GNOME / GDM | Passed |
| Arch Linux rolling | KDE Plasma / SDDM | Passed |
| openSUSE Leap 16.0 | KDE Plasma / SDDM | Passed |
| Linux Mint 22.3 | Cinnamon / LightDM | Passed |
| Pop!_OS 24.04 LTS | COSMIC / cosmic-greeter | Passed |
| NoID Privacy Workstation 44 | GNOME / GDM | Passed |

The runs covered text, JSON/AI, offline and verbose output, section selection,
and the CIS/STIG display options. “Passed” means that the auditor ran correctly;
a security warning or failure reported about the tested system is not itself
a test failure. Scores describe the inspected system and are not a ranking of
distributions or a measure of auditor quality.

## Published v3.7.2 artifact

Published script SHA-256: `30ce5f49a8d119a8801620c342e146da087210d68aa920d06083571f05d7546c`.

Published script size: 639310 bytes.

Bash syntax, style-level ShellCheck, the API-layer lint, the
compliance-mapping validator, and 874 BATS checks pass on these exact bytes.
The tests cover parsers, classification, score/coverage calculations, output
formats and failed or incomplete queries. See [the test suite](../tests/README.md)
for commands and fixtures.

The repository and tagged download contain the same script. Follow the
[download and checksum instructions](../README.md#-installation). The release
page also identifies the commit for workflows that need an immutable source
reference.

## Coverage limits

A syntax check in a container establishes parsing compatibility. A parser
fixture checks the represented input cases. Neither is a complete desktop VM
test. CI labels these checks separately.

Other Fedora/RHEL, Ubuntu/Debian, Arch and openSUSE derivatives may work through
shared interfaces. XFCE and MATE readers have source and fixture coverage;
unlisted distribution/desktop combinations are not included in the VM results
above. Missing tools, denied reads and incomplete queries remain visible in the
audit rather than producing a clean result.
