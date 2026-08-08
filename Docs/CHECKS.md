# 📋 NoID Privacy for Linux — Section Overview

Section-by-section overview of what the audit checks and why it matters.

> **Version:** 3.7.1 | **Sections:** 42 | **Score model:** `section-risk-v1`

> **Platform coverage** — Distribution release, desktop, and test depth are
> separate facts. Consult the release-specific [support matrix](SUPPORT.md)
> instead of inferring support from an `os-release` parser branch. Desktop
> policy readers cover GNOME, KDE Plasma, XFCE, MATE, Cinnamon, and COSMIC;
> unavailable policy backends are reported as unassessed rather than guessed.

> **Output mode**: by default, repetitive PASSes (Boot params, sysctl keys)
> are aggregated into single summary lines (e.g. "Boot hardening: 7/7
> effective controls"). Use `--verbose` for full per-item detail; `--json` always includes
> all findings.

> **Note**: This is a high-level overview. For the full enumeration of every
> individual check, severity-trigger conditions, and pass/fail values, read
> [`noid-privacy-linux.sh`](../noid-privacy-linux.sh) directly — the script
> is intentionally one file in pure Bash, designed to be readable.

---

## 🛡️ Security Sections (01–34)

### Section 01: Kernel & Boot Integrity
Verifies the foundation of system security: Secure Boot status, kernel lockdown mode, root-filesystem block-stack encryption, UEFI firmware, and effective boot hardening. Lockdown `none` is a warning only when Secure Boot is independently verified active; on legacy BIOS or with inactive/unknown Secure Boot it is optional context, not a fabricated contradiction. Command-line options are not required when the exact running-kernel configuration or a direct runtime state proves the control; unavailable evidence remains unassessed. Page-allocator shuffling is INFO because kernel Kconfig describes it primarily as a cache optimization with incidental security benefit and possible workload cost. Root encryption follows only the root mount's block ancestors, so an unrelated encrypted removable disk cannot create a false PASS, and the report gives only the layer count rather than UUID-bearing mapping names. A compromised boot chain means nothing else matters.

### Section 02: SELinux / AppArmor (MAC)
Checks Mandatory Access Control enforcement. SELinux (Fedora/RHEL) or AppArmor (Ubuntu/Debian) — verifies enforcing mode, policy status, and confined processes. MAC prevents privilege escalation even if an app is compromised.

### Section 03: Firewall
Audits firewalld zones (target, allowed service definitions/ports, interface and source bindings, rich rules, forward-ports, masquerading, inter-zone policies), ufw status + default-incoming policy, or iptables INPUT/FORWARD default policies — whichever firewall is active. Firewalld's effective runtime policy and post-reload permanent policy are evaluated separately: runtime-only allowances cannot be missed, persistent additions are labeled post-reload, and absent permanent interface names remain dormant INFO. A firewall allowance is not called a listening service; actual listeners are graded in Section 08. The `default` target is correctly recognized as default-deny; DHCPv6/mDNS/Samba client entries are not mislabeled as server exposure. Denied-packet logging remains an informational response-versus-retained-metadata trade-off. The section fails when no effective firewall is detected.

### Section 04: nftables & Kill-Switch
Identifies standalone or firewalld-managed nftables and inspects nftables plus policy-routing evidence for a VPN kill-switch. A direct physical-interface `drop` must occur in an nftables output hook and must be paired with an independently confirmed active VPN or a clearly VPN-specific table name; ordinary firewalld DROP zones, LAN-block policies, forward-chain drops, and jumps to chains whose names contain `drop` are not VPN evidence. An absent nftables backend is inventory because iptables/ufw can be valid alternatives. A missing kill-switch warns only when a VPN interface is independently confirmed active; without an active VPN it is an optional policy, not an adverse finding.

### Section 05: VPN & Network
Detects active VPN interfaces (WireGuard, OpenVPN, ProtonVPN, etc.), validates route and DNS-link evidence, and conditionally checks for IPv6 bypass and LAN reachability. No VPN and intentional split tunnels are supported postures and are informational by themselves; a VPN full tunnel is inferred only from an effective IPv4/IPv6 default route on a confirmed active VPN device in any routing table. Private DNS address space and a local resolver stub never prove VPN routing. Interface names are only candidates: administrative-UP state is required, bridge-attached TAP devices are treated as virtualization, and ambiguous TUN/TAP devices are reported without a VPN PASS. Connectivity, direct-DNS/HTTPS egress comparison, and full-tunnel LAN probes are all guarded by `netleaks`, so `--offline` emits no intentional packet from this section while preserving local configuration evidence. The egress comparison never prints either public address and does not claim to test the configured recursive resolver; a mismatch is adverse only with independently established VPN full-tunnel routing. Reachable LAN devices are INFO because printer/NAS access may be intentional and reachability alone cannot prove a VPN leak; blocked candidates provide optional isolation evidence. Browser WebRTC configuration is audited in Section 35. These checks validate observable host routing; they do not cryptographically attest the VPN provider or remote endpoint.

### Section 06: Kernel Hardening (sysctl)
Audits critical sysctl parameters: ASLR level, kernel pointer hiding (`kptr_restrict`), dmesg restriction, unprivileged BPF/userns, SYN cookies, redirect sending, anti-spoofing, and core dump limits. Incoming ICMP redirects are graded only in Section 17 so the same sysctl state cannot affect two weighted sections. Severity is effective-state-aware: `ptrace_scope=1` and `kptr_restrict=1` meet the unprivileged desktop boundary; SysRq sync/remount-only masks and redirect sending while forwarding is off are context; martian logging is an explicit visibility-versus-retained-metadata trade-off; and BPF JIT hardening accounts for whether unprivileged BPF is already disabled.

### Section 07: Services & Daemons
Identifies running network services that increase attack surface: SSH, web servers, Samba, NFS, rpcbind, telnet, FTP, and desktop discovery/printing services. Legacy plaintext remote shells are failures; maintained services are review warnings unless a separate listener/firewall check proves exposure. Desktop-default CUPS, Avahi, Bluetooth, and hybrid-GPU helpers receive desktop context. Ordinary failed units are operational INFO and are read from systemd's plain, locale-stable table so the report names the unit rather than a status glyph. On NoID Workstation, a failed `noid-*` image unit is WARN because it proves that an image integration/hardening step did not complete and no generic dedicated section necessarily owns it. Firewall, auditd, and Fail2Ban state is graded only in their dedicated sections to avoid double-charging one condition.

### Section 08: Open Ports & Listeners
Uses `ss` to enumerate all listening TCP/UDP ports and identify the owning process. Bind scope and host-firewall reachability are distinct evidence: loopback, explicit `%iface` scope, VM/container bridge, and confirmed VPN bindings are classified separately; externally bound ports are checked by exact protocol/port against effective firewalld zones, service definitions, source zones and active HOST policies, or against UFW policy. Firewalld runtime views are captured once per audit and reused for each port; this is a point-in-time performance snapshot, not reduced coverage, and any unreadable view remains unassessed. A proven TCP allowance fails, a missing host firewall fails, a proven default-deny block is informational, and complex rules that cannot be reduced safely remain explicitly unassessed. UDP is connectionless, so `ss` also exposes QEMU user-networking reply/NAT sockets in the listener view. Proven ephemeral QEMU NAT sockets without a matching explicit UDP `hostfwd` are collapsed into one contextual finding; real forwards and uncertain sockets retain normal per-port grading. UDP exposure is a warning only when permitted or unfiltered. The report never claims internet reachability from bind address alone.

### Section 09: SSH Hardening
SSH audit (skipped with a PASS when no SSH unit is enabled or running — smallest attack surface): root login, password authentication, empty-password login (`PermitEmptyPasswords`), pubkey authentication, X11 forwarding, max auth tries, login grace time, user/group whitelists, **effective cipher/MAC/key-exchange algorithm strength** (from `sshd -T`, config fallback — sha1/md5/96-bit/CBC/3des/arcfour classes flagged), and per-user SSH key strength across standalone `*.pub` files plus `authorized_keys` (DSA deprecated, RSA ≥2048, ECDSA ≥P-256). Key fingerprints and comments are never emitted. `PermitRootLogin yes` fails; key/forced-command-constrained root login warns; `no` passes.

### Section 10: Audit System
Checks whether auditd is running, validates immutable mode and meaningful rule
families for identity/PAM/SSH/sudo/network configuration, module loading,
system-time changes, and user deletion/rename activity. Every required member
of a compact syscall family must be present in an effective `always,exit` rule;
a `never,exit` exclusion or one similarly named syscall cannot satisfy it.
Session-history (`utmp/wtmp/btmp`) and login-history (`faillock`, legacy
`lastlog`, or modern `lastlog2`) watches are evaluated only for databases that
exist. The faillock backend is derived from `faillock.conf` plus active PAM
`dir=` overrides instead of assuming the transient `/run/faillock`; this
correctly audits reboot-persistent desktop policy such as
`/var/lib/faillock`. Their finding explicitly concerns manual tampering: PAM's `USER_*`
audit events do not depend on these file watches. Directory and exact-file
watches are distinguished, so watching one SSH file is not mislabeled as
coverage of the whole directory. The check does not treat a raw rule count as
evidence of coverage, and benchmark architecture/filter completeness remains
partial rather than certified.

### Section 11: Users & Authentication
Audits user/group name and UID/GID uniqueness, the sole UID-0 account, empty passwords, login
shells, PAM module arguments, effective `pwquality.conf.d` precedence,
dictionary/root enforcement, `faillock`, sudo `use_pty` and timestamp policy,
database integrity by command status, and organization-controlled password
aging. On Ubuntu 26.04, where the active sudo-rs 0.2.x `sudo -V` output is
summary-only, the locally installed `sudo.ws` parser evaluates the same
`visudo`-validated sudoers policy for those shared options; if neither provider
can expose details, the result remains unassessed. Password-length guidance
follows the authentication context and does not reward arbitrary
character-class rules or forced periodic rotation.
Expired-password and recorded-faillock entries are operational account history
and remain INFO; the effective authentication and rate-limit policies carry
severity. A threshold up to five earns PASS; six through ten is an INFO-level
desktop lockout/denial-of-service trade-off, and values above ten remain WARN.
An explicit `NOPASSWD: ALL` directive is WARN, while command-scoped NOPASSWD
text is INFO and explicitly does not claim that an alias expansion or target
helper is safe. Shell umask parsing recognizes direct assignments and
interactive `case` arms while excluding scoped helper subshells.

### Section 12: Filesystem Security
Inventories effective SUID/SGID binaries by package ownership, owner, writability, and the containing mount's `nosuid` flag instead of using distro-dependent count thresholds. The system scan excludes home trees plus generated snapshot/cache/container-image stores; `nosuid` `/tmp` and `/var/tmp` trees are graded through their mount boundary instead of treating unpacked temporary images as host package inventory. One separate `-xdev` home traversal covers privacy/secret filenames, explicitly includes separately mounted user homes, avoids nested remote/FUSE mounts, and reports SUID/SGID bits on `nosuid` homes as inert. Rootless container and Flatpak object stores are excluded as generated image/package data. World-writable descendants of account-private homes (including root-only group traversal) are distinguished from files reachable by non-root accounts. Unowned-path counts are ownership hygiene, not automatically vulnerabilities. When GNOME 49/50 GDM's live DisplayManager userdb is present, its exact per-seat `config`/`state` entries are reported separately as transient-owner state rather than stale UIDs; this narrow exception does not bypass SUID, SGID, or world-write checks. The scan also checks system world-writable files, `/tmp`, `/var/tmp`, `/dev/shm`, and `/home` mount hardening, swappiness (ZRAM-aware), ACL support, core dumps, root ownership plus safe maximum modes for critical files, and login banners. The desktop baseline requires `/tmp` `noexec`; disk-backed `/var/tmp` may remain executable for build/install compatibility while `nosuid,nodev` remain required. Cron permissions are graded only in Section 32 to avoid duplicate score impact.

### Section 13: Encryption & Crypto
Inventories active dm-crypt/LUKS mappings and validates their cipher policy (AES-XTS = pass, legacy AES-CBC = warn), mapping type, key size, backing device, LUKS2 header version, and every enabled keyslot KDF through read-only `cryptsetup status`/`luksDump`. Mapping and backing-device identifiers are used locally but replaced with report-local ordinal labels to avoid disclosing UUID-bearing names. The audit does not claim which keyslot unlocked an already-active mapping because cryptsetup does not expose that fact; PBKDF2 is contextual INFO because it may protect a high-entropy recovery/token key or satisfy FIPS constraints, while all-Argon2id enabled slots earn PASS. It also reports OpenSSL, checks the **system-wide crypto policy** on RHEL-family (`update-crypto-policies`: LEGACY = FAIL, weakening subpolicies = WARN, FUTURE/FIPS = stricter PASS), and follows every ancestor layer when assessing block swap or swapfiles on encrypted filesystems (ZRAM-aware). Root-at-rest coverage is graded separately from the root mount's own stack in Section 01. The section also reports available system entropy and hardware RNG presence.

### Section 14: Updates & Packages
Checks cached package-manager metadata for pending/security updates, automatic or operator-managed update configuration, repository integrity (GPG keys), and package verification. General backlog counts are operational INFO; only a separately supported security classification can create a security-update failure. Arch's `pacman -Qu` has no security-only subset and is not mislabeled as one; exit 1 plus an empty result means zero cached matches only after a separate package-database query succeeds. When the official-repository `arch-audit` client is installed, its machine format provides a live Arch Security Team lookup: affected packages without a published fixed version WARN, while affected packages with a fixed version available FAIL. That vendor request is bounded to 30 seconds and suppressed by `--offline`/`--skip netleaks`. Other package-manager checks never refresh repository metadata: zero cached updates is INFO, not PASS, because freshness cannot be proven without an explicit network/cache update. Refresh metadata with the distro package manager before running the audit when an authoritative current update result is required.

On APT systems, a version marked `local` means only that its exact installed
version is absent from the current cache; installed state cannot prove its
historical authentication. Ordinary local/unavailable packages therefore WARN
for provenance review. Strictly recognized, non-running version-specific
kernel images, modules, headers, and tools are reported separately as INFO:
retaining or staging such packages across a kernel replacement is normal. The
running ABI, kernel meta packages, add-on driver modules, and malformed names
remain in the WARN bucket.

On RPM systems the installed database is checked for retained signature-header
metadata across RSA, DSA/EdDSA, legacy PGP/GPG, and capability-gated modern
`OPENPGP` tags. This prevents an EdDSA header from being mislabeled unsigned.
Installed metadata alone cannot revalidate the original payload or establish
signer-key trust; those require the original RPM artifacts and the intended
keyring.

### Section 15: Rootkit & Malware Scan
Runs **chkrootkit** under a bounded timeout when it is already installed and
labels heuristic/known-false-positive-prone output for review. Network-capable
cron command patterns are inventory only: command names cannot establish
malicious intent. `rkhunter` is
reported as an aging signature source, not as proof of a clean host. Neither
tool covers memory-only threats or establishes system integrity; use signed
package verification, AIDE/IMA, audit evidence, and incident-response tooling
according to the threat model.

### Section 16: Process Security
Process counts, operational zombie inventory, deleted-but-running binaries, and a basic
name-pattern check (annotated as heuristic — real malware renames binaries).
A matching host-namespace listener/tool name warns for review but never proves
compromise; isolated matches and `ps`/`/proc` snapshot deltas remain INFO.
For actual integrity verification, rely on AIDE/IMA (Section 30) and
chkrootkit (Section 15).

### Section 17: Network Security (Advanced)
Anti-spoofing kernel settings (ICMP redirects sysctl), TCP wrapper config
(deprecated on modern systems — informational only), TCP TIME_WAIT connection
counts as operational inventory, and ARP-monitoring tool detection
(arpwatch/arpon/addrwatch).

### Section 18: Containers & Virtualization
Detects Docker (rootless vs rootful daemon), Podman root containers, libvirt-managed VMs, and standalone qemu-system processes invisible to virsh. Reports the `user.max_user_namespaces` ceiling with distro-neutral severity tiers; the same numeric value is not labeled as one distribution's default.

### Section 19: Logs & Monitoring
Counts journal errors (1h) and criticals (24h) with known-benign-noise filters, dmesg errors, OOM kills and segfaults; checks logrotate presence, journal disk usage (cross-referenced with Section 38's filesystem view), journal forwarding configuration, deleted-but-open log files, and empty syslog files when rsyslog/syslog-ng is active. Generic error-volume, OOM, crash, and file-handle counts are operational INFO, never compromise or hardening verdicts; targeted SELinux, audit, service, and integrity checks carry security severity.

### Section 20: Performance & Resources
Reports CPU load, memory pressure, disk space, and process counts as operational
INFO. This section has zero posture weight and cannot create an adverse exit:
resource pressure is not by itself evidence of compromise or weak hardening.

### Section 21: Hardware & Firmware
Checks CPU vulnerability mitigations (Spectre, Meltdown, MDS, retbleed, etc.), SMART disk health (with USB-bridge fallback via `-d sat`/`-d usbjmicron`), CPU temperature via lm_sensors when available, and USB device count (excluding host root hubs). CPU mitigation state carries security severity; SMART and thermal results are urgent operational evidence but do not change the desktop security/privacy score.

> **Note**: The Firmware update status (fwupd) and **HSI (Host Security ID)
> firmware trust tier** (HSI:0–5 from `fwupdmgr security`) are checked in the
> separate "Firmware & Thunderbolt" block at the end of the audit, not in
> Section 21 itself. Firmware freshness is credited only when fwupd inventories
> an update-capable device and its machine-readable update list is empty. A
> host with no update-capable devices remains unassessed.

### Section 22: Network Interfaces (Detail)
Detailed network view: all interfaces with state and addresses, the full routing table, and a DNS-resolution test via a root-nameserver query (`dig . NS` — no third-party domain). This operational/inventory section has zero posture weight; a failed DNS probe is not a hardening warning. Promiscuous-mode detection lives in Section 05.

### Section 23: Crypto & Certificates
Counts system CA certificates (cross-distro: trust / ca-certificates.crt / /etc/ssl/certs), inventories expired certificate files via `openssl x509 -checkend`, and inventories per-user SSH keys and authorized_keys entries. Expiry is INFO unless use by an active service is established; an unused file is not a live TLS failure.

### Section 24: Environment & Secrets
Scans for **world-readable private key files** (content-verified via PEM
magic strings — filename `.key` alone is NOT sufficient since uBlock Origin
IDB and test fixtures use the same extension), `.env` files in user homes
(uses snapshot/cache-aware find), and configuration files in `/etc` containing
credential patterns. Snapshot directories (`.snapshots`, `timeshift-btrfs`)
are excluded to prevent inflated counts on Snapper/Timeshift systems.

### Section 25: Systemd Security
Inventories `systemd-analyze security` exposure scores for selected active units. Low scores can demonstrate broad sandboxing, but high generic scores remain INFO because service requirements differ and the score alone does not establish exploitability; actual listeners, privileges, and policy are graded in their dedicated sections.

### Section 26: Desktop & GUI Security
Checks display server exposure (Wayland vs X11) and provides a non-scoring
screen-lock overview across
**GNOME / KDE Plasma / XFCE / MATE / Cinnamon / COSMIC**. The dispatcher uses
the active local logind session's desktop identifier before a process fallback,
then the desktop's native settings store, including COSMIC's versioned RON config.
Remote SSH sessions cannot establish a desktop family, and long process names
such as Cinnamon's are not truncated into a false unknown result.
Exact desktop process inventory likewise uses executable-token boundaries over
the full command line, so names beyond Linux's 15-byte `comm` limit (including
KDE's `baloo_file_extractor`) remain observable without substring matches.
An unknown desktop is reported as unassessed; it is not silently treated as
GNOME. Canonical screen-lock severity lives in Section 39 to prevent duplicate
penalties.

### Section 27: Time Sync & NTP
Validates NTP configuration, checks for NTS (Network Time Security) support, and ensures time is properly synchronized. Traditional `chronyd`/`chrony`, Fedora's least-privilege `chronyd-restricted.service` (used by NoID Workstation), and systemd-timesyncd are recognized; all chronyc queries are non-resolving, non-interactive, and bounded by the parent audit. Time drift can break TLS, Kerberos, and audit chronology.

### Section 28: Fail2Ban
Checks whether Fail2Ban is active and inventories configured jails. Absence or an inactive installation is informational: a desktop with no exposed password-authenticated service does not require Fail2Ban.

### Section 29: Recent Logins & Activity
Shows the last 5 logins, failed login attempts (source IPs redacted for safe report-sharing), traditional utmp sessions vs unique users (display-manager and root automation/sudo pseudo-sessions annotated), and bucketized sudo activity (exact counts deliberately not exposed — behavioral metadata). The report explicitly notes that modern graphical sessions can exist only in logind and therefore be absent from utmp; Sections 26 and 39 independently assess the active local desktop.

### Section 30: Advanced Hardening
Checks advanced security features: USBGuard runtime insertion policy + effective rules, coredump service state (storage-aware), compiler inventory, AIDE/Tripwire presence without duplicating Section 34's baseline verdict, **IMA/EVM kernel integrity with runtime measurement count** (>100 measurements = actively measuring; 0 = active but policy too narrow), FireWire DMA-attack surface, home directory permissions, shell idle TMOUT inventory, AIDE database existence, and shell history sensitive-pattern scan. USBGuard earns control credit only when the effective inserted-device/implicit targets are restrictive and no unconditional allow-all rule defeats whitelist semantics; service activity alone is insufficient. Compiler presence, shell `TMOUT`, and generic cron/at allow-list policy are informational, not universal desktop vulnerabilities. (Login banner check is in Section 12 / Filesystem.)

**AIDE Integrity Status**: reads `systemctl show aide-check.service -p
ExecMainStatus` (the last scheduled run's exit-code bitmask: 0=clean, 1=added,
2=removed, 4=changed) and exposes its timestamp. If the database is newer than
that check, the old verdict is explicitly stale. For drift, the audit resolves
the timestamp-matched protected report, shows counts, and includes at most five
paths in text mode; journal parsing is a fallback. The audit never initializes,
updates, swaps, or accepts an AIDE database. `NOID_AIDE_LIVE=1` only runs a
fresh check (up to five minutes); its protected temporary log is retained on
drift/errors and removed on clean. On a freshly installed NoID Workstation,
absence of the database before operator acceptance is an intentional trust
boundary and is reported as INFO; an existing empty database, failed check, or
detected drift remains adverse.

### Section 31: Kernel Modules & Integrity
Audits loaded kernel modules, clearly labels the suspicious-name check as a
heuristic, verifies disablement of legacy/unneeded filesystem modules, checks
USB-storage policy, and reports module-loading lockdown. A restrictive
USBGuard insertion policy is accepted as a desktop alternative to blacklisting
`usb-storage`; daemon activity without effective policy evidence is not.
Compliance credit is
assigned only to the exact benchmark controls listed in the mapping, not to the
size of this module list. (Thunderbolt and FireWire live in Sections 21 and 30.)
The `--cis-l1`, `--cis-l2`, and `--stig` runtime profiles are mutually
exclusive because profile-specific severity context must not be silently
overwritten; run separate audits when comparing profiles.

### Section 32: Permissions & Access Control
Audits cron infrastructure permissions and ownership (/etc/crontab + cron.d/hourly/daily/weekly/monthly), securetty TTY allowances, and inventories core-dump limits in /etc/security/limits.conf + limits.d drop-ins. Canonical core-dump severity lives in Section 12 to prevent duplicate penalties. (World-writable and SUID/SGID scans also live in Section 12.)

### Section 33: Boot Security & Integrity
Reports boot mode (UEFI vs legacy BIOS), kernel module signing enforcement (compile-time, runtime sig_enforce, or cmdline), installed kernel count, and rescue/emergency shell sulogin protection. (GRUB password detection lives in Section 01.)

### Section 34: System Integrity Checks
Runs side-effect-safe package verification (`LC_ALL=C rpm -Va --noscripts` / `debsums -ca`), checks all reported package-file discrepancies (including missing files, metadata, capabilities, links, and digests), and validates critical file checksums. Timestamp-only RPM drift is reported separately as provenance metadata; it is not mislabeled as changed content or permissions.

Package verification is completeness-aware: RPM status 0 (clean) and 1
(reported differences) are graded; debsums status 0 (clean) and 2
(changed/missing files) are graded. Timeout or operational-error output is
treated as incomplete and never as a clean scan.
For `debsums`, executable directories, executable files below library trees,
and known code/library formats form the code tier. Arbitrary data below
`/usr/lib` (for example a browser distribution INI) remains non-code; directory
placement alone cannot escalate it to a binary/library finding.
RPM verification uses `--noscripts`: file metadata/digests are checked, while
package-defined `%verifyscript` hooks are deliberately not executed because
they are arbitrary code and can have side effects.
On Arch, `paccheck` from pacutils performs MTREE SHA-256/property verification
when installed. Its status 1 is a completed discrepancy result as well as the
generic error status, so only recognized quiet-mode package/path records are
graded. Missing files and substantive SHA-256 changes are FAIL; regenerated
GHC, GLib, MIME, and icon caches plus type/ownership/mode/size/mtime drift stay
visible as WARN because maintained install/runtime hooks can legitimately
change them. Unexpected or partial output is incomplete and cannot PASS. The
`pacman -Qkk` fallback checks only presence and file properties (permissions,
size, mtime) and is reported as INFO/WARN, never as a cryptographic clean PASS.

**RPM Drift-Detection** (RPM-based distros): set
`NOID_RPM_BASELINE_INIT=1` once to atomically capture the current modified-file
state to `/var/lib/noid-privacy/rpm-baseline.txt`. For each substantive path,
the baseline records a digest of its bytes or link target plus type, mode,
UID/GID, SELinux context, size where stable, and Linux file capabilities.
That complete fingerprint requires `sha256sum`, `stat`, `readlink`, and
`getcap`. A missing optional command is reported as an INFO coverage gap rather
than a hardening defect; current substantive RPM discrepancies remain WARN
until a complete trusted baseline can classify them.
Subsequent runs alert on **new paths and changed states of already-known
paths**. This catches drift in a customized binary even when `rpm -V` continues
to report the same pathname and status class. `NOID_RPM_BASELINE_UPDATE=1`
atomically rewrites the baseline. The directory and file are restricted to
root (0700/0600). Timestamp-only rows are excluded. Legacy, malformed, or
incompatible baselines are not compared; recreate one explicitly with
`NOID_RPM_BASELINE_UPDATE=1` after reviewing current drift.
Without a trusted baseline, substantive non-config differences remain WARN and
are split into content/link/capability, mode/owner/group, and missing classes;
review them before opting into `NOID_RPM_BASELINE_INIT=1`.

**NoID Workstation expected-state policy**: only when `/etc/os-release`
identifies `ID=noid-privacy-workstation`, an independently reviewed operator
workflow may supply `/etc/noid/rpm-expected-drift-v1.tsv`. The image does not
self-generate or accept this trust state; absence is therefore an INFO coverage
boundary, not incomplete image integration. Raw composition differences remain
visible and explicitly unclassified. If a policy is installed, it is not a
pathname allow-list: every
static NoID-managed override must still match its captured content or link
target, type, mode, UID/GID, SELinux context, size where stable, and file
capabilities. The policy file must be a root-owned, non-symlink regular file
that is not group/world writable and has a validated header, unique path
digests, and state records. A mismatch is WARN, or FAIL for privacy/security
activation paths. The explicit refresh command is deliberately NoID-only and
requires a separately reviewed, fixed root-owned path list; ordinary Fedora
cannot consume these
exceptions. Narrow NoID permission overrides additionally require their exact
RPM status, current mode, and root ownership. Missing RPM `%ghost` objects are
reported as expected runtime state, but metadata drift on an existing `%ghost`
object remains substantive. The `fwupd` StateDirectory mode is treated as
runtime metadata only when the installed vendor unit explicitly declares
`StateDirectory=fwupd`. Debian/Ubuntu continue to use the independent
`debsums` path.

---

## 🔒 Privacy Sections (35–38)

### Section 35: Browser Privacy
Firefox-family audit (Firefox, LibreWolf, Tor Browser, Waterfox — native and
Flatpak profiles) with correct `prefs.js` then `user.js` precedence and
enterprise-policy overrides: telemetry, health reports, WebRTC, DNS resolver
mode, tracking protection, cookie policy, Shield Studies, saved-login posture,
and optional uBlock Origin inventory. Primary-password state is left unassessed when it
cannot be proven from local profile data. DoH is informational because native
system/VPN DNS can be the deliberate privacy boundary. Chromium-family browser
installation and extension choice are inventory, not proof that telemetry or
unsafe behavior is active.

### Section 36: Application Telemetry & Privacy
Detects and audits application-level data collection: GNOME Location Services, effective ABRT automatic-reporting configuration (an active local collector alone is INFO), usage statistics, **file indexer (GNOME Tracker / KDE Baloo / Recoll — DE-aware)**, Flatpak sandbox escapes (`filesystem=host`), explicit Snap telemetry state, Fedora `countme`, Ubuntu `popularity-contest`, and captive portal detection. GNOME schemas are graded only for an active GNOME desktop, so unused schema defaults installed on KDE/COSMIC do not create findings. ABRT is assessed only on RHEL-family systems or when its configuration is present; an unknown desktop without a recognized native indexer remains unassessed rather than passing from Recoll's absence. On Ubuntu, local Apport capture, its automatic-report consent marker, Whoopsie's on-demand submission trigger and per-user Ubuntu Report pending state are reported separately; package presence or an armed path unit is never presented as proof of a completed upload. Identifiers and report contents are not read. Unavailable settings remain unassessed instead of becoming a false PASS.

### Section 37: Network Privacy
Audits network-level privacy: WiFi MAC address randomization, Ethernet MAC cloning, Avahi/mDNS hostname broadcasting, LLMNR status, hostname privacy, RFC 4941 temporary IPv6 addressing, DHCP hostname leaking, and cups-browsed discovery state. A GECOS/hostname token match is contextual INFO because a local label can be generic and the match alone proves neither identity nor network exposure; verified mDNS or DHCP hostname publication carries the adverse severity. A stable IPv6 address is described as a cross-session linkability risk on the same network, never as proof of a person's identity. Temporary-address runtime state is unassessed when no physical network connection is active; an inactive link cannot establish current exposure, and a connection manager may apply profile policy only at activation. LLMNR is graded only when systemd-resolved is the active resolver: effective per-link `resolvectl` scopes take precedence over static files, an explicit setting is a fallback when runtime evidence is unavailable, and a missing file never implies an adverse default. An inactive backend is not inferred from its configuration. Likewise, unavailable NetworkManager evidence does not become an assumed DHCP failure. Service presence is not treated as proof of an unpatched historical CVE; package/update and listener/firewall checks own those conclusions.

### Section 38: Data & Disk Privacy
Checks data-at-rest privacy: recently used files size, thumbnail caches (reveal viewed images after deletion), trash inventory, clipboard managers (password leak risk), core dump configuration, bash history size, journald log retention, and /tmp filesystem type (tmpfs vs persistent). Trash volume remains operational INFO because retained files may be intentional and size alone does not prove exposure. Persistent-journal storage uses allocated filesystem blocks. When `SystemMaxUse` is explicitly configured, the check also parses `SystemMaxFileSize` (or systemd's one-eighth default, capped at 128 MiB) and counts active system/user journals. Usage inside that configured cap plus one rotation allowance per active journal is INFO, because journald can delete only archived files; exceeding the configuration-aware bound is WARN. The generic 512 MiB privacy threshold applies only when no explicit size policy can be parsed.

---

## 🖥️ Desktop Sections (39–42)

### Section 39: Desktop Session Security
Audits session policy across **GNOME / KDE Plasma / XFCE / MATE / Cinnamon /
COSMIC**: native lock delay and idle timeout, lock-on-resume where observable,
lock-screen notification exposure, and display-manager auto-login across GDM,
SDDM, LightDM, and greetd/COSMIC Greeter. It also classifies remote-desktop
listeners by bind scope, reports an active desktop-sharing service as inventory
rather than proof of exposure, inventories autostart entries without count-based
severity, and checks applicable user-switching policy. Idle locking at up to
300 seconds passes, 301–900 seconds warns, zero or over 900 seconds fails;
lock activation is immediate/pass, up to 60 seconds/warn, or longer/fail.
Unknown or inaccessible settings remain unassessed. The report distinguishes
an active desktop profile with no explicit/readable value from the absence of
an active desktop session.

### Section 40: Webcam & Audio Privacy
Checks media device security: webcam device detection and permissions, default microphone-source mute status (PipeWire/PulseAudio), network audio modules (TCP exposure), PipeWire remote access, and screen sharing portal status. An unmuted source is inventory and is never described as proof that an application is recording. An unreadable device permission or unavailable user-session query remains unassessed rather than becoming a failure.

### Section 41: Bluetooth Privacy
Audits Bluetooth exposure: service status, discoverable mode (visible to nearby devices), pairable mode without paired devices, and active Bluetooth without usage. A timed-out or failed controller query remains unassessed; only observed exposure carries adverse severity.

### Section 42: Password & Keyring Security
Comprehensive credential audit: informational password-manager detection (17 supported standalone tools; absence cannot rule out browser, remote, or unrecognized workflows), **GNOME Keyring AND KDE KWallet** PAM auto-unlock, SSH `AddKeysToAgent` timeout, GPG agent cache TTL, and potential secret filename patterns in home directories (subdirectory-aware via the shared cached home traversal `_collect_home_scan`). Contents are not classified or printed: a world-accessible filename match warns, while group/private matches remain INFO; this name-based subset never claims that plaintext credentials were verified.

### Firmware & Thunderbolt (post-section block)

A hardware-attributed block after Section 42. It is controlled by `--skip
hardware`, never by the keyring section:

- **Firmware update status** via machine-readable `fwupdmgr get-devices --json`
  and `get-updates --json`. An empty update list passes only when at least one
  update-capable device exists; no update-capable hardware is INFO/unassessed.
- **HSI (Host Security ID) trust tier** via `fwupdmgr security`: HSI:0=FAIL, HSI:1=WARN, HSI:2=PASS (system-protected baseline), HSI:3+=PASS (heavily-hardened)
- **HSI failing-attestation count** via `✘`-marker in `fwupdmgr security` output
- **Thunderbolt device security level** (DMA attack prevention via per-device `/sys/bus/thunderbolt/devices/*/security`)

---

## 📊 Summary

After all 42 sections, NoID reports a **desktop posture score** and a separate
**assessed risk-weight coverage** percentage. `section-risk-v1` assigns fixed
weights to sections and uses each section's worst assessed severity; raw
finding volume cannot inflate the score. A skipped or INFO-only section has no
coverage. Individual optional unavailable/timed-out sub-checks remain visible
even when other evidence makes the section assessed; a required evidence
failure can explicitly keep an otherwise PASS-only section unassessed. See the
documented granularity limit before using coverage as a CI gate.

The ratings are `STRONG POSTURE` (90+), `MODERATE POSTURE` (75–89), `WEAK
POSTURE` (50–74), and `HIGH EXPOSURE` (below 50), provided at least half of the
fixed risk weight was assessed. Lower coverage is always `LIMITED EVIDENCE`.
See [SCORING.md](SCORING.md) for every weight, formula, JSON field, and limit.

## 🎯 Compliance Mapping

Use `--cis-l1`, `--cis-l2`, or `--stig` to append a compliance coverage block at the end of the audit. The flags reference the static doc-based mapping in [`CIS_RHEL9_MAPPING.md`](CIS_RHEL9_MAPPING.md), which currently maps NoID Privacy checks to:

- **CIS RHEL 9 v2.0 Level 1 Workstation**: 43 / 227 direct controls (18%)
- **CIS RHEL 9 v2.0 Level 2 Workstation, cumulative**: 47 / 293 direct controls (16%)
- **DISA RHEL 9 STIG V2R6**: 56 / 447 direct controls (12%)

> These are deduplicated static mappings, not runtime PASS results or a
> certification. Partial evidence receives no direct-coverage credit. Use
> benchmark-authorized content such as CIS-CAT Pro or OpenSCAP for a formal
> assessment.

The desktop-scope decisions behind adopted, partial, rejected, and deferred
external controls are documented in [REFERENCE_REVIEW.md](REFERENCE_REVIEW.md).

---

## 🤖 AI Integration

With `--ai`, findings are compiled into a structured prompt for an assistant to
explain and prioritize. The generated prompt asks for native, reversible,
distribution-aware suggestions and explicit confirmation before changes. Model
output is still untrusted advice: verify commands, paths, support status,
privacy impact, and rollback before applying anything. The audit neither sends
the prompt nor performs remediation.

---

*For the full script, see [noid-privacy-linux.sh](../noid-privacy-linux.sh)*  
*For usage instructions, see [README.md](../README.md)*
