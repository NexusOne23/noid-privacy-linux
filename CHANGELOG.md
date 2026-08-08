# Changelog

All notable changes to NoID Privacy for Linux will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.7.1] - 2026-08-08

Behavior change — read before upgrading: the hardening score is now produced
by the `section-risk-v1` model (see `Docs/SCORING.md`) instead of the old raw
PASS/FAIL count, so a host's numeric score and rating will differ from 3.7.0
even when nothing on the system changed. No options were removed; the GitHub
Action gains a backward-compatible `min-coverage` gate. Despite the
patch-level version, this release re-works scoring, severity, and multi-distro
support broadly.

### 🐛 Fixed — Firefox preference comments and DNS-mode reporting

- The profile parser now accepts only active, line-anchored `user_pref(...)`
  statements. Commented hardening-template examples such as
  `// user_pref("network.trr.mode", 3);` no longer override the real
  `prefs.js` value and falsely report strict browser DoH.
- DNS mode 5 is reported as the explicit native-resolver choice. Mode 0 is
  described as Firefox's default/rollout decision, while a missing profile
  value remains unassessed instead of being silently equated with native DNS.

### 🔧 Fixed — offline evidence classification after NoID Workstation X13 validation

- Section 27 now queries `chronyc -n sources` once, counts server, peer and
  refclock rows, and reports source reachability as unassessed when that query
  returns no sources or fails. A zero-source offline host can no longer
  receive the vacuous PASS "all sources reachable and valid".
- Section 37 compares the current and permanent Ethernet MAC only while the
  selected interface has an active connection. On a never-connected/offline
  interface, `stable` or `random` is reported as configured intent with the
  applied link state explicitly unassessed instead of producing a false
  reconnect/per-profile warning.
- Section 37 also leaves RFC 4941 runtime state unassessed when no physical
  network connection is active. The kernel default alone no longer creates a
  linkability warning before NetworkManager has activated a profile; the same
  disabled value on an active physical connection remains WARN.

### 🔧 Changed — desktop authentication trade-offs

- Section 11 keeps explicit `NOPASSWD: ALL` directives at WARN while reporting
  command-scoped NOPASSWD text as INFO. The INFO wording preserves the
  reauthentication-bypass evidence and does not infer that aliases or target
  helpers are safe.
- `pam_faillock deny` values up to five remain PASS. Values from six through
  ten are now INFO as a desktop brute-force-versus-lockout trade-off; values
  above ten remain WARN and `deny=0` remains FAIL.

### 🔧 Changed — report presentation

- The `--ai` prompt head is split into `UNTRUSTED SYSTEM CONTEXT`
  (host-supplied strings) and `AUDIT RESULT (tool-computed, not
  host-controlled)`, and the summary box aligns the coverage and score values
  in one column. Values, scoring, and the prompt-injection boundary are
  unchanged.

### 🐛 Fixed — local human-account count in the session inventory

- Section 29 loads the `login.defs` UID bounds explicitly before counting
  local human accounts. Those bounds are cached lazily by the human-UID
  helper, so a run that skipped both earlier consumers (`--skip users --skip
  desktop`) compared empty values and reported zero human accounts in the utmp
  session line.

### 🐛 Fixed — finding accuracy in firmware, listener, and inventory output

- **A kill-switch address of the host itself was probed as a LAN gateway.**
  The guard that skips own VPN-stack addresses read the owning interface with
  a `grep -B3` window and an `^\d+:` pattern that captured the trailing colon
  of `8: pvpnksintrf1:`. That name matches no `/sys` entry, no NetworkManager
  device and no route, so every interface-classification path failed, the
  guard never fired, and the address was reported as `LAN blocked` — a PASS
  that describes a probe against the host's own interface rather than LAN
  isolation. The owning interface is now read from `ip -o addr show` by exact
  address comparison.
- **Firmware trust dropped fwupd's runtime suffix.** The level was extracted
  with `HSI:[0-9]`, which cannot match `HSI:2!`, so a host that fwupd itself
  describes as having runtime issues was reported as a clean secure baseline.
  The suffix is preserved in the finding text and raised as its own entry, and
  the tier switch gained a default branch for levels the audit does not know.
- **The HSI attestation counter included historical events.** Crosses were
  counted across the whole `fwupdmgr security` output, so entries under
  `Host Security Events` inflated the number of currently failing
  attestations.
- **Loopback connections were reported as outbound peer ports.** Only pairs
  whose local port is a listener were skipped, which covers the server side of
  a host-internal socket but not the client side; the local service's own port
  (for example `adb` on 5037) therefore appeared under non-standard outbound
  peer ports.
- **The root-process inventory counted kernel-thread names.** Every kernel
  worker variant is a distinct string, so the unique count was dominated by
  kernel threads and overstated the userspace root surface by an order of
  magnitude. Userspace commands and kernel-thread names are reported
  separately.
- **The strict sysctl aggregate counted tunables the kernel does not
  implement.** A key reported as unavailable stayed in the denominator, so the
  total read `4/5` on kernels that simply dropped the tunable.
- **Mode 000 rendered as a bare `0`.** The annotation that keeps that value
  from reading like a failed measurement could never fire on RHEL-family
  hosts, where the expected mode is also `000`. Modes are zero-padded and the
  required-inaccessible case is annotated.
- **A firewalld zone described interfaces without a link as runtime
  bindings**, contradicting the dormant-assignment finding emitted a few lines
  below it. Present links and configured-but-absent names are listed
  separately.
- **`last` and `lastb` footers were rendered as login records.** With fewer
  records than the requested limit, the `<file> begins <date>` trailer
  survived `head` and appeared in the login lists. Both readers filter it and
  run under a fixed locale.
- **An enabled desktop-context service was reported as "off".** The
  desktop-context service loop tested active and masked but never enabled, so
  a unit that is enabled and merely idle — `bluetooth.service` is the common
  case, since disabling it is a no-op for a D-Bus-activated unit — produced
  `Service off` with a PASS while `systemctl is-enabled` returns `enabled`.
  Not running stays a PASS, but the finding now says the unit is enabled and
  starts on demand or at the next boot. The network service loop already made
  that distinction.
- **Swap reported raw sizes without a utilisation ratio**, so a nearly
  exhausted swap read like an idle one while every filesystem and RAM in the
  same section report a ratio.
- Grammar and presentation: the remaining `noun(s)` sites and the
  runtime-object and attestation counters use the shared pluralization helper,
  the VPN default-route finding no longer carries `ip route` trailing
  whitespace, the RPM trust-boundary statement is no longer repeated verbatim
  within one run, and a near-full filesystem is described as operational
  capacity rather than as a critical condition, matching its INFO severity and
  zero risk weight.
- **A cross-reference pointed at the wrong section.** The AIDE notice sent
  the reader to Section 34 for the database verdict, but the database and
  the check evidence are graded further down in Section 30; Section 34
  grades only the configured checksum algorithm.
- Report consistency: journal sources logged without a PID no longer keep a
  trailing colon, the mid-tier `systemd-analyze` verdict carries the same kind
  of annotation as every other tier, a multi-unit service group no longer
  prints its first unit with an explicit `.service` suffix while single-unit
  entries are written bare, a service context note no longer nests
  parentheses inside the surrounding parenthetical, and the SELinux
  top-source list uses the same `name(count)` rendering as the journal
  top-source list instead of a second `name:count` spelling.

### 🔧 Changed — scoring model, severity, and multi-distro support

- **Scoring model → `section-risk-v1`:** 42 fixed section weights summing to
  100, each section graded by its worst assessed severity, plus a separate
  assessed-risk coverage value that exposes skipped/INFO-only scope. JSON and
  the Action independently validate weights, grades, counters, score,
  coverage, and rating.
- **Weight assignment:** authentication 6; root trust, filesystem/integrity,
  browser, session, credential storage 5; inventory/heuristic-only sections
  (rootkit/process heuristics, generic logs, login activity, optional
  Fail2Ban, certificate files, raw interfaces, performance, `systemd-analyze`)
  0 — they establish no live boundary. Audit evidence moves to weight 3.
- **Severity realigned to the desktop threat model:** firewalld `default` is
  recognised as default-deny; firewall logging, Fail2Ban,
  compiler/browser/tool presence, password-manager/content-blocker choice, and
  autostart/log/pressure/backlog volume no longer produce adverse verdicts;
  duplicate GIDs now FAIL.
- **Removed score distortions:** intentional LAN access, expired-password
  state, recorded faillock history, SMART health, and temperature are context,
  not failures; SSH root login separates unrestricted `yes` from
  key/forced-command modes; `/tmp` vs executable `/var/tmp` are graded by
  role; filename-only secret matches never FAIL for unverified content.
- **Heuristic/unavailable evidence reclassified** (network-capable cron lines,
  process names/namespaces, `ps` snapshot races, expired certificate files,
  generic `systemd-analyze` exposure scores, trash size, inactive
  remote-desktop plumbing, failed webcam/Bluetooth queries): no longer scored
  as regressions. Real listeners, unsafe permissions, discoverability, sharing
  policy, and verified content stay adverse.
- **Authentication** reworked around effective `pwquality.conf.d`/PAM
  precedence, NIST context-dependent minimum length, dictionary/root
  enforcement, faillock, sudo reauthentication, and status-based
  `pwck`/`grpck`; arbitrary composition and periodic rotation are no longer
  rewarded.
- **Sysctl** severity follows effective kernel semantics: level-1
  pointer/ptrace protection is accepted, recovery-only SysRq masks and dormant
  redirect-send are context, martian logging surfaces its privacy trade-off,
  and BPF-JIT hardening accounts for disabled unprivileged BPF.
- **Encryption evidence:** root-at-rest follows only the root mount's full
  block-device ancestor stack (an unrelated encrypted USB cannot create a
  PASS) and swap follows every layer; a VPN device is full-tunnel only with a
  real default route (split tunnels stay informational); the read-only report
  adds mapping type/backing device, LUKS2 header version, and every enabled
  keyslot KDF (all-Argon2id earns credit, PBKDF2 stays contextual) without
  emitting UUIDs or claiming which slot unlocked the mapping.
- **Boot hardening** checks runtime state and the running kernel's build
  defaults before warning on an absent command-line token; page-allocator
  shuffling is INFO (documented mainly as a platform/cache optimisation).
- **Firmware** freshness uses fwupd's machine-readable inventories; `fwupdmgr`
  return code 2 / "no updatable devices" no longer yields a false PASS, and
  hardware without updatable devices is unassessed.
- **Kill-switch** requires a direct output-hook DROP verdict plus independent
  VPN evidence; plain firewalld DROP zones, `block-lan-out`, forward drops,
  and jumps to `drop` chains no longer count. Disabling global IPv6 addressing
  does not imply link-local scopes are absent.
- **Listener grading** separates bind scope from host-firewall reachability,
  matching firewalld by exact protocol/port across zones, service definitions,
  source zones, rich rules, and active HOST policies (UFW honoured); proven
  blocks are INFO, proven TCP allowances FAIL, and ambiguous evidence stays
  unassessed.
- **Firewalld** effective runtime plane is separated from the post-reload
  permanent plane (source bindings, exact interface tokens) so runtime-only
  openings are detected without flagging stale permanent entries as open now.
- **RPM signature inventory** also checks `DSAHEADER` and capability-gated
  `OPENPGP` metadata alongside RSA/legacy fields, and describes installed
  metadata precisely rather than claiming artifact/key verification — so
  NoID's signed Mutter packages no longer read as unsigned merely because
  their build key is not globally imported.
- **RPM/Arch integrity:** missing optional fingerprint commands lower coverage
  (INFO) instead of warning; `paccheck` exit 1 is parsed as a completed
  discrepancy result when records are well-formed (missing files and SHA-256
  drift FAIL, regenerated caches / MTREE-only drift WARN); `arch-audit`
  machine output separates unresolved advisories from packages with fixed
  versions.
- **APT** kernel rotation is INFO without weakening provenance review of the
  running ABI, meta packages, driver modules, malformed names, or unrelated
  packages.
- **Faillock** coverage and history derive from the configured backend and PAM
  overrides (persistent `/var/lib/faillock`, not an assumed `/run/faillock`);
  history PASSes only when `pam_faillock` is actually present in the inspected
  PAM policy.
- **Sudoers** accept root-owned 0400/0440/0600/0640 — the boundary is UID-0
  ownership with no group/world write or execute, not one distro's packaging
  mode; conflicting `--cis-l1`/`--cis-l2`/`--stig` flags are now rejected
  instead of silently keeping the last (repeating one profile stays
  idempotent).
- **Critical files & cron:** critical policy files must be UID-0-owned
  (stricter safe modes still pass), a standard read-only
  `/etc/ssh/sshd_config` is accepted, and cron is graded only in its canonical
  section.
- **USBGuard** earns credit only from an effective restrictive runtime target
  with no allow-all rule.
- **Desktop lock** severity consolidated in Section 39 to avoid duplicate
  penalties (idle ≤5 min pass / ≤15 warn / else fail; activation delay ≤1 min
  warn / else fail) across GNOME, KDE, and native COSMIC.
- **ICMP-redirect** acceptance is graded only in the advanced-network section
  instead of being double-charged in sysctl; removable-media output
  distinguishes opening the file manager from autorun/execution.
- **LLMNR/DNS:** LLMNR grading uses systemd-resolved's effective per-link
  scopes before static config (a missing `resolved.conf` no longer invents an
  enabled default); direct-DNS/HTTPS egress observations redact both public
  addresses and no longer mislabel an authoritative-server query as a resolver
  DNS-leak test.
- **Telemetry** grades GNOME schemas only on GNOME and ABRT only on the RHEL
  family; unused defaults on the wrong desktop can no longer manufacture a
  PASS, and unrecognised native indexers stay unassessed.
- **Kernel Lockdown** no longer reports a Secure Boot contradiction on legacy
  BIOS or when Secure Boot is inactive/unknown; `none` is adverse only with
  independently verified active Secure Boot.
- **Audit rules** are scored by rule-family evidence (every exact syscall in
  effective `always,exit` rules, no descendant-watch/directory confusion, PAM
  events distinguished from history-file tamper watches, `lastlog2` supported)
  instead of raw rule counts; coredump controls consolidated and
  distro-specific shadow/gshadow modes corrected.
- **CIS/STIG cross-reference** rebuilt from the current source documents with
  exact-evidence-only counts — 43/227 CIS L1, 47/293 cumulative L2, 56/447
  STIG V2R6; partial evidence is listed but excluded and the validator rejects
  duplicate or malformed mappings.
- **Portability:** the compliance-mapping validator, RPM status parsers, and
  the shell-umask parser avoid interval-regex (`{m,n}`) syntax unsupported by
  the `mawk` builds on Debian and Mint (Mint's mawk 1.3.4 aborts with an
  internal panic); uptime falls back to `/proc/uptime`, missing `login.defs`
  aging directives read as `unset`, and hostname uses the kernel interface
  when Arch omits `inetutils` — none leak command diagnostics.
- **AIDE/RPM state** is treated as an operator-owned trust boundary: the audit
  never creates AIDE trust state, absent NoID RPM policy leaves composition
  drift visible but unclassified (malformed/mismatching policy stays adverse),
  and a documented `deny=10` is not called a defect — the `deny<=5` note now
  names the lockout/DoS trade-off.
- **Public docs** rewritten around desktop scope, dependencies, stateful
  opt-ins, outbound probes, score limits, support evidence, AI trust
  boundaries, and complementary Lynis/OpenSCAP/AIDE use; fixed check-count and
  support claims that runtime evidence could not justify were removed.
- **Release validation** is deliberately branch-oriented rather than a claimed
  universal distro sweep: Fedora 43/44, Ubuntu 22.04/26.04, Debian 13, Arch
  rolling, openSUSE Leap 16.0, Mint 22.3, Pop!_OS 24.04, and NoID Workstation
  44 are the documented desktop lines; NoID additionally passed Live,
  installed BIOS, and installed UEFI/Secure-Boot scenarios.

### ✨ Added — desktop, distro, and CI coverage

- Native display-manager and session parsing for GDM, SDDM, LightDM, and
  greetd/COSMIC Greeter, plus COSMIC idle/lock and GNOME/Cinnamon
  removable-media policy; unknown desktops stay unassessed instead of falling
  back to GNOME assumptions.
- `logind`-first detection of the sudo caller's local desktop (avoids
  Cinnamon's 15-byte `comm` truncation and excludes remote-only sessions);
  process checks use an executable-token matcher over the full command line,
  removing 15-byte `comm` false negatives such as KDE Baloo.
- Ubuntu 26.04 `sudo-rs` support for `use_pty` and credential-timestamp policy
  via the parallel `sudo.ws` parser (unassessed when neither exposes detail).
- Firefox profile parsing that honours `prefs.js`/`user.js`/enterprise-policy
  precedence; DoH is informational when system/VPN DNS is intentional and the
  primary-password state is not guessed from insufficient data.
- `--offline` suppresses connectivity, leak, LAN, and root-DNS probes while
  preserving local VPN evidence; no-VPN, plain IPv6, alternate firewall
  backends, and raw private-DNS ranges are no longer misgraded as VPN
  pass/fail.
- NoID Workstation 44 coverage against a real encrypted GNOME 50 image:
  recognises `chronyd-restricted.service`, recovers the local graphical
  account when logind leaves `Desktop` empty under a direct root audit, and
  warns on failed `noid-*` integration units.
- GNOME 49/50 GDM transient greeter-user recognition for unowned-path hygiene
  (only per-seat GDM `config`/`state` is excluded and reported explicitly;
  SUID/SGID/world-write checks still apply, and genuine unowned paths
  elsewhere remain graded).
- CI expanded to Ubuntu, Fedora, Debian, Arch, openSUSE, and Red Hat UBI
  syntax images with a blocking style-level ShellCheck gate, mapping
  validation, and an end-to-end local Action smoke test; containers are
  syntax-only and desktop claims require the documented VM matrix.

### 🐛 Fixed — reporting, listeners, and the Action contract

- The final-results and AI-prompt banners share one renderer: fixed rules and
  the title align, dynamic rows stay open on the right so terminal-dependent
  Unicode/emoji widths cannot break the closing edge, and the AI request
  separates confirmed defects from deliberate desktop trade-offs. Removed the
  personal byline (which could be misread as the author of an individual
  report) and the duplicate footer timestamp.
- Listener findings show the full `systemd-resolved` service name instead of
  the kernel's 15-byte `systemd-resolve` task-name truncation, keeping the
  precise scoped loopback address (`127.0.0.53%lo:53`).
- Ephemeral QEMU user-networking UDP NAT/reply sockets collapse into one
  contextual finding (explicit `hostfwd` ports are still graded individually)
  and `%virbr*` scope is honoured, so bridge-only DHCP binds are not
  mislabelled externally bound.
- Interactive case-arm umask policy is recognised without accepting a scoped
  helper subshell as global session policy.
- Non-interactive `chronyc` queries close inherited stdin, ending three
  self-generated `chronyc_t`→`sshd_session_t` AVC denials per SSH-launched run
  that surfaced as a false SELinux warning.
- `debsums` changes are classified by executable/code-library semantics
  instead of flagging every `/usr/lib` data file as a changed binary.
- On native COSMIC, inventory semantics are corrected: namespace ceilings no
  longer name the wrong distro family, RAM `available` is not reported as
  `free`, utmp is not presented as complete logind session state, and an
  unmuted microphone source is not described as active recording.
- Failed-systemd-unit inventory uses systemd's plain table and accepts legacy
  status markers, so `*` is no longer reported as a unit name.
- Removed seven dead legacy dispatch/formatting helpers surfaced by ShellCheck
  (keeping the style gate portable across 0.9–0.11) instead of suppressing
  `SC2317` repository-wide.
- The compliance coverage helper resolves its default mapping document
  relative to its own `BASH_SOURCE` location, so invoking the audit by
  absolute path outside the repository no longer loses the report; an explicit
  `--doc PATH` remains caller-controlled.
- Listener reachability snapshots firewalld's runtime zone, policy,
  direct-rule, and referenced-service views once per audit instead of
  launching the same Python/D-Bus queries for every observed port. Every
  TCP/UDP listener still receives the same exact-port, source-zone,
  service/include, rich-rule, forward-port, and HOST-policy evaluation;
  unreadable or irreducible evidence remains unassessed. This brings a
  455-finding high-listener Action run back to 102.71 seconds without
  weakening verdicts.
- Firewalld zone and policy inventory is read through the native complete
  views instead of starting one Python/D-Bus client per field of every object.
  The audit keeps the same zone targets, services, ports, interfaces, sources
  and policy targets, preserves the older-policy-API fallback, and reports an
  incomplete snapshot explicitly.
- The composite Action now declares values for every advertised output and
  accepts a producer-marked `unassessed` section with positive PASS
  observations, matching the completeness-aware score model; score/coverage
  arithmetic is still recomputed independently and malformed clean-looking
  reports are rejected.
- README and repository metadata now use the source's actual
  `GPL-3.0-or-later` grant, pin the documented checkout example to the peeled
  action commit, disclose the unpublished-tag boundary, and include NoID
  Privacy Workstation in the ecosystem without hard-coding changing
  commercial/app feature counts.

### 🔒 Security & Privacy

- The hostname value is withheld from findings and JSON metadata (the stable
  field is retained as `[redacted]` for schema compatibility); a display-name
  token match is contextual INFO, while verified mDNS/DHCP hostname exposure
  stays adverse.
- Text banners and the slow-boot unit inventory redact the hostname and
  `/dev/disk/by-uuid`/`by-id` values; encryption reporting drops UUID-bearing
  identifiers.
- IPv6 privacy wording states the observable same-network linkability risk
  instead of claiming that a stable address proves identity.
- SSH strength checks cover authorized keys as well as standalone `.pub` files
  without printing fingerprints or key comments.

### 🧪 Tests

- Fixtures and BATS coverage for scoring invariants, Action coverage
  thresholds, authentication/PAM precedence, display-manager precedence,
  Firefox policy precedence, COSMIC/offline behaviour, compliance mapping,
  critical-file ownership/modes, USBGuard policy semantics, and severity
  boundaries.
- Native Mint regression coverage for local logind desktop selection and
  `debsums` code/data classification, including `/usr/lib` configuration data.
- Every temporary-fixture suite explicitly initialises the Bats 1.2.1
  compatibility directory; unprivileged Ubuntu 22.04 now catches a missing
  helper call that root-run gates could hide by making `/root` writable.
- Regression coverage includes caller-CWD-independent compliance mapping,
  weakest-effective PAM aggregation across active stacks, completeness-aware
  Action scoring, Arch update exit semantics, listener token boundaries,
  cached firewalld views (including IPv6 sources), and final exit-code/banner
  contracts.

## [3.7.0] - 2026-06-10

### 🔧 Fixed — additional post-release correctness pass

- **Filesystem scan utility/runtime balance (Section 12)**: prune generated,
  snapshot, cache, container-image and temporary stores at the directory root
  instead of entering one level before pruning. Rootless Podman/Docker and
  Flatpak object stores in user homes no longer create phantom host SUID/SGID
  inventory. The home collector now uses `-xdev` to avoid nested remote/FUSE
  mounts while explicitly adding separately mounted user homes as scan roots.
  `/tmp` and `/var/tmp` are skipped only when their effective mount is `nosuid`;
  unhardened temporary trees remain fully scanned.
- **Test quality**: added regression coverage for the exact `find` arguments
  and directory-boundary pruning; fixed the BATS negation footgun and all
  strict ShellCheck notes. The suite now contains 154 tests.
- **LAN isolation evidence**: a host without `ping` now reports the check as
  unavailable instead of turning command-not-found failures into false
  "LAN blocked" PASS findings.
- **Output grammar**: plural SSH `authorized_keys` counts now retain the noun
  ("2 authorized keys" instead of "2 authorized").
- **Webcam device permissions (Section 40)**: implemented the check already
  promised by the documentation. Static world read/write bits now FAIL;
  disappearing or unreadable nodes produce WARN instead of a clean PASS.
- **Documentation accuracy**: WebRTC configuration is correctly assigned to
  Browser Privacy (Section 35), not the VPN/LAN checks in Section 05.
- **Journal disk-usage accuracy (Sections 19/38)**: sparse/preallocated journal
  files are now graded by allocated filesystem blocks instead of apparent file
  length, eliminating false warnings when sparse holes inflate apparent size.
  Measurement failures are reported as unknown rather than silently becoming
  a zero-byte result. Section 38 also evaluates explicit `SystemMaxUse` and
  `SystemMaxFileSize` settings with journald's documented active-file rotation
  allowance, so a correctly capped journal is not warned merely for sitting
  slightly above a generic 512 MiB threshold.
- **Stacked-mount accuracy (Section 12)**: mount-option checks and temporary
  directory labels now use the effective topmost `findmnt` row. Shadowed mount
  options can no longer mislabel `/tmp` or `/var/tmp`, or incorrectly suppress
  effective SUID/SGID findings.
- **NoID Workstation RPM policy (Section 34)**: NoID-managed static RPM
  overrides are now accepted only when their exact content/link/metadata state
  matches a trusted root-owned image policy. Explicit permission overrides use
  narrow status/mode/ownership predicates, missing runtime `%ghost` objects
  are separated from payload drift, and every other discrepancy retains
  normal WARN/FAIL grading. The generic Fedora path cannot consume NoID
  exceptions; Ubuntu's Debian-package verification is unchanged. The generic
  host baseline remains available for local administrator changes, but is
  fail-closed on NoID while the image policy is missing or invalid so image
  overrides cannot be accidentally legitimized as generic local drift.

### ✨ Added — 5 new checks

- **F-382 — SSH `PermitEmptyPasswords`** (Section 09): explicit or default
  `no` = PASS, `yes` = FAIL. (CIS 5.1.19 / STIG RHEL-09-255040)
- **F-383 — SSH algorithm strength** (Section 09): effective Ciphers, MACs
  and KexAlgorithms from `sshd -T` (config-grep fallback), checked against
  the weak classes sha1 / md5 / 96-bit / CBC / 3des / arcfour / blowfish /
  cast128 / umac-64 — offending algorithms are listed by name.
  (related evidence for CIS 5.1.4–5.1.6; later coverage review correctly
  classifies the generic-family test as partial rather than direct)
- **F-384 — System-wide crypto policy** (Section 13, RHEL-family):
  `update-crypto-policies --show` — LEGACY = FAIL, weakening subpolicies
  (`:SHA1`, `:AD-SUPPORT-LEGACY`) = WARN, DEFAULT = PASS, FUTURE/FIPS = PASS.
  (CIS 1.6.1)
- **World-writable files in user homes** (Section 12): `find / -xdev` never
  crosses mount boundaries, and on Fedora-default btrfs every subvolume
  (incl. /home) is its own mount — world-writable files in homes were
  invisible to the system scan while it passed "0". Separate user-home
  scan, WARN severity with file list.
- **/home mount hardening** (Section 12): a separate /home (partition or
  btrfs subvolume) should carry nosuid,nodev — without them SUID/device
  files in user dirs stay armed. INFO when /home is not a separate mount.
- CIS coverage with the matching mapping rows: **30 L1 / 16 L2 / 29 STIG**.
- BATS regression tests: `sshd -T` fixtures (F-383), chronyc state-marker +
  authdata-column classifiers, AIDE staleness gate. With the correctness pass
  below the regression suite totals 118 tests.

### 🔧 Fixed — Section 27 (NTP): speed + two dead checks

- Both `chronyc sources` calls ran without `-n`, reverse-DNS-resolving every
  source IP although hostnames are never parsed — a dead source's lame PTR
  delegation stalled the section for minutes per call (live-measured: two
  dead sources = 511 s of a 601 s run). All chronyc calls now use `-n`;
  the section completes in milliseconds.
- NTS source count read authdata column 3 (numeric KeyID) instead of
  column 2 (Mode) — always 0, silently falling back to the chrony.conf
  grep. Hosts with active NTS now report "N active sources using NTS".
- Unreachable/falseticker detection matched `^?`/`^x` at line start, but
  the state marker is character 2 of the mode column — it could never
  fire: hosts with dead sources got a false "all sources reachable" PASS.

### 🔧 Fixed — output accuracy

- **AIDE stale WARN after baseline replacement**: the status check reads the
  last scheduled run's exit code; when an operator had replaced the database,
  that verdict graded an older baseline yet the WARN stuck until the next timer run (up to
  24 h). Now gated on db-mtime vs check-end-time → INFO "rebaselined
  after the last check"; unparseable timestamps fail-safe into WARN. The
  WARN message also carries the check timestamp.
- **"Active timers"** used `list-timers --all`, counting inactive and
  masked units — `--all` dropped to match the label.
- **squashfs rationale**: was keyed on Flatpak, but Flatpak deploys via
  OSTree and never loads squashfs — now keys on snapd, the actual hard
  squashfs dependency.
- **"GPG keys: N"** now states whose keyring it counts (root's under sudo).
- **Firmware & Thunderbolt** block got its visible separator — it rendered
  under the Section-42 "PASSWORD & KEYRING SECURITY" banner.
- Deleted-log INFO names normal journald/logrotate rotation instead of
  claiming "logrotate pending restart"; the logged-in-sessions note also
  names root automation/sudo sessions (not only display-manager); port
  4070 annotated as Spotify AP.

### 🔧 Fixed — repo-wide accuracy pass

- **GitHub Action: deprecated `fail-threshold` alias was dead code** —
  `min-score`'s `'0'` default always shadowed the fallback chain; workflows
  using only `fail-threshold` ran with threshold 0. The alias works again.
- **CIS mapping audited row-by-row against the script**: 8 rows without a
  backing check removed (three of them return in this release as real
  checks, see above), section labels corrected, counts re-synced
  (table = `coverage-report.sh` = `Docs/CHECKS.md`).
- **Privacy disclosure synced to the real endpoints** (README + SECURITY.md):
  connectivity = ICMP `1.1.1.1`/`9.9.9.9` + `cp.cloudflare.com/generate_204`
  fallback; Section 22 = DNS root query. `--offline` documented.
- **Docs/CHECKS.md**: 12 section descriptions re-synced to actual behavior;
  distro line aligned (Fedora 39+ / Ubuntu 22.04+).
- **Lint/CI**: ShellCheck style-level clean again (21 `_plural` args quoted);
  `actions/checkout` v4.3.1 → v6.0.3 (SHA-pinned, Node 24 runtime); stale
  `bc` CI dependency dropped; 4 stale code comments cleaned.

### 🔧 Fixed — post-release correctness pass

- **Timeout / exit-status integrity**: preserved exact command exit status for RPM, debsums, chkrootkit, firmware, HSI, Bluetooth and thumbnail checks — partial output from a timeout is never graded as a complete scan; RPM (rc=1) / debsums (rc=2) differences stay valid findings.
- **chkrootkit**: stopped suppressing broad `INFECTED` classes as clean — FP-prone lines stay WARN, all other hits FAIL.
- **Integrity baseline v4**: removed allowlists that hid changed D-Bus activation files, launchers, policy files and executable Python (only derived bytecode/cache stays excluded); atomic, root-private baseline writes that report failures instead of claiming success; v4 fingerprints the actual bytes / link target + security-relevant metadata, so a second change to an already-customized file can't evade a path-only compare; malformed/legacy baselines are never trusted after upgrade.
- **Filesystem traversal**: consolidated four root + four home traversals into one cached, NUL-safe pass per scope, each with a five-minute ceiling; split `/usr` `/var` `/opt` `/srv` `/boot` / EFI devices included, deduped by device. On a clean timeout the trees reached before the ceiling are now surfaced as a **PARTIAL** result (labeled incomplete — the found SUID/SGID/world-writable/unowned items are shown, a "0" downgraded to INFO, never a silent clean PASS) instead of the whole scan being discarded, so a slow/large host still gets actionable findings; high-inode / low-value trees (flatpak OSTree store, `/var/cache`, per-user tool caches `.venvs`/`.gradle`/`.rustup`/`.cargo/registry`/flatpak app caches) are pruned so the scan usually completes inside the ceiling; a graded path that vanished between scan and report (TOCTOU) or a record truncated by the timeout is skipped rather than mis-graded as group/other-writable.
- **AIDE**: separated drift bitmasks (1–7) from operational errors (14–25); resolves the timestamp-matched scheduled report instead of the often-empty service journal; drift WARNs carry added/removed/changed counts + the actual paths.
- **SELinux**: correlate AVC output by ausearch event instead of counting repeated `comm=` fields; only an explicit `<no matches>` result yields a zero-denial PASS.
- **Package verification (cache-only)**: update checks never refresh metadata on any supported package manager (a cached zero is INFO, not a false-current PASS); RPM `--noscripts`; GPG never creates a missing keyring/trustdb; APT/Pacman/Zypper marked checked only after valid queries; RPM signature metadata is status-checked; Debian provenance reworded to the evidence actually available; Arch `paccheck` does bounded MTREE SHA-256 with the `pacman -Qkk` fallback limited to presence/perms/size/mtime.
- **VPN detection**: replaced prefix-only matching with a shared semantic classifier — a tunnel must be administratively up; generic TUN/TAP needs route or active NetworkManager VPN evidence; bridge-attached TAP is virtualization; private-address DNS alone is not VPN-DNS proof; a dummy interface can't PASS from its name.
- **SUID/SGID**: effective-risk classification (package/root ownership, group/other writability, `nosuid` enforcement) replaces distro-dependent count thresholds; home trees are split out and privilege bits on `nosuid` homes treated as inert.
- **Injection / robustness**: control-byte escaping in all structured findings + AI-prompt findings marked as untrusted data (terminal/prompt-injection); GitHub Action summaries context-escape untrusted values for Markdown/HTML; lexical numeric gates before root-context arithmetic; injection-safe indexed lists (Bash 4.3); PATH sanitized before every privileged external command.
- **GitHub Action fail-closed**: rejects unknown `--skip` names, invalid `min-score`, structurally incomplete JSON, counter/finding mismatches, unknown severities, and report/exit-code contradictions.
- **RPM under localized hosts**: forced `LC_ALL=C`; timestamp-only rows separated from substantive content/permission drift; unbaselined vendor deviations are WARN, not a compromise verdict.
- **Misc**: fixed the plaintext-secret contradictory PASS, an empty-journal miscount, suspicious-process wrapper dedup + namespace-aware listeners; tightened public-IP parsing to valid IPv4/IPv6 via the TLS endpoint `https://ifconfig.me/ip`; `coverage-report.sh --doc` argument safety; the pull-request template's Code-of-Conduct link; **scoped-IPv6 listener addresses** (`[fe80::1%wg0]:3702` / `[fe80::1]%wg0:3702`) now extract the bare address before classification — a link-local or VPN-tunnel listener on a scoped socket no longer mis-reads as internet-facing "external"; the integrity RPM baseline reads the SELinux label tolerantly so non-SELinux hosts (Ubuntu/tmpfs) fingerprint without failing.

---

## [3.6.5] - 2026-05-18

### 🐛 ARP math, cosmetic polish + Audit Round-2 (detection + display)

- **F-361** — ARP state-breakdown math (supersedes F-352).
- **F-362** — pluralization helper + subject-verb agreement sweep (F-328).
- **F-363–F-365** — NEEDS WORK rating space-alignment, README sample-output banner sync (with F-351), pluralization-helper sweep extended.
- **Audit Round-2** — 3 detection-accuracy + 9 cosmetic fixes (post-release follow-up) across classification, display polish and AI output.
- **F-378** — fixed F-368 over-aggressive VPN detection (Section 05 LAN-block); **F-379** — fixed F-370 type-aware unit-name decode (Section 01 boot units).

---

## [3.6.4] - 2026-05-18

### 🐛 Live-Audit Self-Review: 10 detection-accuracy fixes

A second-pass review of full v3.6.3 audit output across a multi-interface
laptop (ethernet+wifi, ethernet unplugged) surfaced **one real detection
bug**, **five orphaned sub-headers**, **three message-accuracy issues**, and
**one banner-clarification opportunity**. None affect scoring math; all
improve detection accuracy and report readability.

#### Fixed — Detection Accuracy

- **F-350 — `PRIMARY_IFACE` fallback prefers UP physical interfaces**.
  Previously `ip -o link show | ... | head -1` picked the first non-VPN
  interface alphabetically regardless of state. On multi-interface laptops
  with ethernet+wifi where ethernet was unplugged (DOWN) and wifi connected
  (UP), the DOWN ethernet was selected. Kill-switch validation in Section
  04 then ran against the unused interface, masking missing rules on the
  actually-active one. Two-pass detection: try UP first, fall back to DOWN
  only if no UP physical exists.

- **F-360 — Microphone detection: distinguish "no hardware" from "default
  unusable"** (Section 40 Webcam & Audio Privacy). Previously claimed
  "no microphone hardware" on any wpctl-get-volume error — false-positive
  when actual mic sources exist but PipeWire's `@DEFAULT_AUDIO_SOURCE@`
  was set to a non-mic (e.g. camera UVC pseudo-source on dual-sensor
  laptops). Now counts sources via `wpctl status` to differentiate:
  zero sources = "no microphone hardware", non-zero = "default source
  unusable (N sources exist)". Mirror fix applied to the pactl branch.

#### Fixed — Orphaned Sub-headers (F-285-class — keep section anchored)

Five sub-headers could emit with no findings beneath them on systems where
the underlying state was empty. Same regression-class as F-285 (Boot
Security Analysis). All five now emit a fallback line when zero items
matched, keeping the report visually consistent:

- **F-353** — Section 08 TCP listeners (`No TCP listeners — minimal attack surface` when ss returns empty)
- **F-354** — Section 08 UDP listeners (same fallback)
- **F-355** — Section 09 SSH Key Strength (`No SSH public keys found` when SSH active but no users have keys)
- **F-356** — Section 11 History File Permissions (`No shell or app history files found for any user` on shell-history-disabled systems)
- **F-357** — Section 23 SSH Keys (`No SSH keys found for any user` when no `~/.ssh` exists)

#### Fixed — Message Accuracy

- **F-352 — ARP "other" bucket expanded to named NUD states** (Section 05).
  Previous `_emit_info "ARP entries: $N total ($R reachable, $S stale, $F
  failed, $O other)"` lumped PERMANENT/NOARP/INCOMPLETE/PROBE/DELAY/NONE
  into opaque "other". Users couldn't tell if entries were benign (e.g.
  PERMANENT for static anti-spoof gateway ARP) vs unusual (INCOMPLETE/PROBE
  on a quiescent host). Now enumerates each non-zero state by name in the
  message.

- **F-358 — squashfs / Flatpak: distinguish binary-present from
  apps-installed** (Section 31). Previously "Module squashfs: not disabled
  but not loaded (Flatpak installed)" — the `command -v flatpak` check
  detects the binary, not whether apps are present. Now reports the actual
  app count: `(N Flatpak app(s) present)` or `(flatpak binary present, 0 apps)`.
  squashfs is dynamically loaded only when apps with squashfs-compressed
  runtimes execute, so the distinction matters.

- **F-359 — Webcam name dedup with count-prefix** (Section 40). Modern UVC
  cameras expose multiple `/dev/video*` nodes per physical camera (raw +
  metadata, RGB + IR on dual-sensor laptops). Listing each node verbatim
  produced "Camera A, Camera A, Camera B, Camera B" duplicates. Now
  aggregates with insertion-order-preserving count-prefix:
  `2× Camera A, 2× Camera B`.

#### Fixed — Banner Clarification

- **F-351 — Banner: qualify the "420+" check claim** (line 999). Banner
  says `Checks: 420+ across 42 sections` but Final-Results consistently
  shows ~414 on a typical hardened system (some checks skip when tools
  like chkrootkit/fail2ban/bluetoothctl/lm_sensors aren't installed).
  Both numbers are correct — "420+" is upper-bound — but the gap
  confused users. Banner now reads `Checks: 420+ across 42 sections
  (actual count: see summary)`.

### Verification

- `bash -n` CLEAN
- `lint-api-usage.sh` 11/11 patterns pass
- Live-verified against a multi-interface Fedora 44 system: all 10 fixes
  produce the expected output

---

## [3.6.3] - 2026-05-17

### 🐛 ausearch Hang-Fix + Anaconda WebUI RPM-Verify Exclusion

Two targeted fixes addressing a runtime hang in the SELinux AVC check on
Fedora 44 plus a remaining RPM-verify false-positive class surfaced after
the v3.6.2 ship-cycle.

#### F-349 — `ausearch --input-logs` hang-fix (Section 02 SELinux & MAC)

- Previously: `noid-privacy-linux.sh` hung ~20 minutes at the SELinux AVC
  check on Fedora 44.
- Root-cause: `ausearch -m avc --start recent` WITHOUT `--input-logs` hangs
  indefinitely on Fedora 44 (audit-userspace 4.1.4, kernel 7.0.6) — it goes
  through the blocking auditd interface instead of reading the log file
  directly.
- Fix: added `--input-logs` flag. Tool now parses `/var/log/audit/` directly
  and returns immediately.
- Result: full audit completes in ~166 s on a hardened Fedora 44 system
  (was: infinite hang).

#### F-348 — Anaconda WebUI Firefox profile templates RPM-verify exclusion (Section 34)

- Previously: 2 binary-counted files from Anaconda WebUI Firefox profile
  templates (`firefox-theme/{default,extlink,live}/user.js`) modified by
  privacy hardening (telemetry-off, search.* off, etc.) were FP'd as binary
  tampering.
- Fix: extended F-345 exclusion regex to cover these `user.js` files.
- Same exclusion-class as os-release / pixmaps — config-like prefs shipped
  via the `anaconda-webui` RPM, not executable code.

### Verification

- `bash -n` CLEAN.
- Version bumped 3.6.2 → 3.6.3 across script + all docs.

---

## [3.6.2] - 2026-05-05

### 🐛 Hardened-distro Live-VM False-Positives (5 fixes)

Five context-aware false-positive fixes surfaced by running v3.6.1 against
a Fedora 44 derivative hardened-distro (`ID=noid-privacy-workstation` in
`/etc/os-release`) that masks GNOME-default services and ships intentional
RPM modifications for branding and privacy hardening. All are
semantically-incorrect findings that were always-bugs but only became
visible when audited against this system type rather than a long-running
hardened workstation install.

#### F-343 — DISTRO_FAMILY recognition: `noid-privacy-workstation` → rhel
- Previously: `unknown distro` warning emitted for NoID Privacy's `ID=noid-privacy-workstation`
- Fix: case branch maps to `DISTRO_FAMILY=rhel` (downstream of Fedora 44)
- All package-manager / systemd / SELinux checks now apply correctly

#### F-344 — Automated update detection: `noid-update-reminder.timer`
- Previously: WARN "No automated security update mechanism detected" because
  NoID Privacy deliberately ships a manual user-update workflow (privacy-by-design:
  no auto-fetch to avoid bandwidth fingerprinting + MITM exposure)
- Fix: detect `/etc/systemd/user/noid-update-reminder.timer` → emit PASS
  "Automated updates: noid-update-reminder weekly (privacy-by-design — manual user upgrade)"

#### F-345 — RPM verify exclusion list extended for hardened-distro modified files
- Previously: 18 binaries flagged as "changed checksums" → FAIL severity
- Fix: extended F-281/F-315 exclusion regex to cover hardened-distro
  legitimately-modified files (Anaconda branding, GNOME privacy disables,
  Plymouth/desktop branding, Anaconda transaction-progress patch, Firefox
  profile + Tracker3 service overrides)
- Result: 18 false-positive binaries → 0 → RPM verify FAIL eliminated

#### F-346 — Journal err filter: dbus-broker activation-request failures
- Previously: 19 "errors" in 1h on a clean privacy-distro install (false WARN)
- Root cause: dbus-broker logs ERR each time a still-installed app pokes a
  masked bus name (ColorManager, nm_dispatcher, home1, Avahi, ModemManager1,
  GeoClue2 — all NoID Privacy-masked for privacy hardening). Mask IS the security
  guarantee — these errors confirm it works as intended.
- Fix: extended `_journal_filter` to include
  `dbus-broker-launch\[[0-9]+\]: Activation request for '[^']+' failed`

#### F-347 — Journal err filter: gnome-keyring init noise
- Pattern: `gkr-pam: unable to locate daemon control file` — race during
  PAM init. Harmless: keyring functions correctly post-init.
- Fix: added to `_journal_filter`

### Verification

Live-tested 2026-05-05 on a Fedora 44 derivative hardened-distro VM.
v3.6.1 → v3.6.2 score progression:
- v3.6.1: 93% 🛡️ WELL-HARDENED (255 PASS, 3 FAIL, 13 WARN)
- v3.6.2: **95% 🏰 FULLY HARDENED** (263 PASS, 2 FAIL, 11 WARN)

Tier upgraded WELL-HARDENED → FULLY HARDENED. Remaining FAIL/WARN are
expected on a test VM (no VPN configured, transient SSH fix-phase state) or
design choices (switcheroo-control 7.6 — F-336 known good).

---

## [3.6.1] - 2026-04-30 / 2026-05-01 / 2026-05-02

### 🐛 Live-ISO false-positives + reporting-quality + engineering/self/live audit + polish (64 fixes)

Multi-day correctness and reporting-quality pass. Highlights:

- **Classification** — removed live-ISO false-positives across integrity, update and service checks.
- **Reporting quality** — consistent severity wording, accurate counts, no contradictory PASS-after-WARN.
- **Engineering + self-audit** — bug-pattern re-pass, deterministic output, find-performance fixes.
- **Live-audit self-review** — findings verified against a real run; cosmetic + display polish.
- **Output transparency** + AIDE drift-breakdown UX; sticky-WARN logic bug fixed.
- **Repo-wide documentation sync** + final code-review polish.

---

## [3.6.0] - 2026-04-30

### 🎯 Posture-communication, detection-depth, engineering-discipline & compliance

- **Added** — posture-communication (score framed as hardening posture, not compromise resistance); detection-depth across integrity/updates/network; CIS/STIG compliance groundwork.
- **Changed** — function-naming refactor; `--verbose` flag added to the argument parser.
- **Fixed** — Bug-Pattern #5 reintroductions (5 sites, found by audit re-pass) + other audit findings.
- **Internal** — engineering-discipline pass.

---

## [3.5.0] - 2026-04-27

### 🎯 Phase-8 audit closure + post-audit polish — DE dispatcher, cross-distro, ShellCheck-clean, 15 final fixes

- **Added** — DE dispatcher (Sections 26, 36, 38, 39, 42); cross-distro path normalization; architecture & lifecycle.
- **Changed** — MEDIUM findings addressed.
- **Fixed** — code-quality pass; disk-output regression (post-v3.4.1).
- **Architecture** — F-013 refactor (done in v3.5.0, not deferred).
- **Post-audit polish** — 15 second-pass fixes: display bugs, consistency refactors, help-text/docs, style/cleanup, behavior refinements.

---

## [3.4.1] - 2026-04-27

### 🐛 Post-Release Fixup (after v3.4.0 user testing)

Live test on Snapper+Podman+bootc-build system revealed remaining FPs that
v3.4.0 didn't catch:

- **`_safe_find_root` extended**: Excludes `/var/lib/containers/storage/*`
  (Podman default), `/var/lib/docker/*`, `/var/lib/lxd/*`, `/var/lib/lxc/*`,
  `/var/lib/machines/*`, and OSTree object stores (`*/ostree/repo/objects/*`).
  Container/image-build systems had 60+ phantom SUIDs from layer overlays
  containing complete /usr/bin trees with sudo/mount/passwd binaries.
- **`_safe_find_home` extended**: Also excludes `__pycache__/*` and `target/*`
  (Rust builds).
- **Section 20 (Disk Usage)**: Now skips read-only image filesystems by both
  type (iso9660, squashfs, erofs, cramfs, romfs) and mount-flag (`ro,`).
  Previously FAILed on Fedora ISO loopback mounts (always 100% full by design).
- **Section 39 (VNC/RDP detection)**: Distinguishes localhost-only (INFO —
  qemu SPICE/VNC console, normal for VM development) from externally-bound
  (WARN). Previously WARNed on every system running qemu-system with SPICE.
- **Section 42 (Plaintext secrets)**: Severity-tiered by permissions:
  - World-accessible (007 bits): FAIL
  - Group-accessible (070 bits): WARN
  - Private (600/400): INFO with "consider encrypting" hint

  Previously FAILed on private dev `.env` files which is normal workflow.

Verified on auditor's system: SUID count 81 → 15 (matches actual rootfs count).

---

## [3.4.0] - 2026-04-27

### 🔥 Critical Bug Fixes (False-FAIL elimination)

These fixes eliminate false-FAILs on Snapper/Timeshift systems (openSUSE
default, Mint default, many Fedora/Ubuntu setups).

- **Section 12**: SUID/SGID/world-writable/unowned file scans now exclude
  `*/.snapshots/*`, `*/timeshift-*/*`, `*/.btrfs-snapshots/*`, `*/.snapper/*`.
  Previously inflated counts massively on btrfs+snapshot systems (real example:
  81 → 15 SUID files on Snapper-installed Fedora).
- **Section 24**: Private-key detection now uses content magic-string
  verification (PEM headers) instead of filename matching. Eliminates FPs
  from uBlock Origin IDB (`key_*.key`), test fixtures, API config files.
  Permission threshold tightened from 077 to 007 (group-readable is often
  intentional for service accounts like libvirt's `kvm:kvm`).
- **Section 15**: rkhunter (last release 2018-02-24) is now reported as INFO
  with deprecation warning. Signatures haven't been updated for 8 years and
  miss XZ Backdoor, Bootkitty, BPFDoor, Kovid. chkrootkit (last release
  2025-05-12) remains the recommended scanner.

### 🛡️ Honesty in Documentation

- **README**: Distro support claim narrowed from "Tested on 8 distros" to
  "Optimized for Fedora/RHEL · Tested on Ubuntu/Debian · Best-effort on
  Arch/openSUSE/Mint/Pop!_OS"
- **README + SECURITY.md**: "no network requests" claim made honest. Tool
  now clearly documents that `vpn`/`interfaces`/`netleaks` sections issue
  3rd-party requests (Mozilla, Akamai, Cloudflare, Google) by default.
- **SECURITY.md**: Removed theatrical SHA256 verification step (no published
  hashes) and broken "verify read-only" grep command. Recommends human code
  review as the meaningful integrity check.
- **CHECKS.md**: Section descriptions corrected to match actual code (Sec 16
  process check is heuristic, Sec 17 is sysctl-based not deep-analysis,
  Sec 24 scans key files not env vars).

### ✨ New Helpers + Flags

- `_safe_find_root` / `_safe_find_home` — Snapshot-aware find wrappers
- `_is_real_private_key` — Content-based crypto-key detection
- `has_firewall_block_on_phys` — Generalized firewall-block (nft + iptables + ufw)
- `_grub_main_cfg` / `_grub_password_paths` — Cross-distro GRUB paths
- `_service_active_any` / `_service_masked_any` / `_service_enabled_any` —
  Cross-distro service-name normalization (httpd|apache2, smb|smbd)
- `--offline` flag: shorthand for `--skip vpn --skip interfaces --skip netleaks`

### 🐛 Bug Fixes (28 medium findings)

- **Sec 1 (Kernel)**: Secure Boot check now correctly classifies legacy BIOS
  as N/A (was reporting DISABLED). Adds efivars-based fallback when mokutil
  missing.
- **Sec 3 (Firewall)**: Default-zone false-positive fixed when no interfaces
  assigned but services declared
- **Sec 5 (VPN)**: Connectivity check ICMP-first (no Mozilla tracking);
  Cloudflare's `cp.cloudflare.com/generate_204` as HTTP fallback
- **Sec 5 (VPN)**: Promiscuous-mode check excludes virtualization bridges
  (virbr/docker/br-/veth/lxcbr/cni-/podman/tap)
- **Sec 7 (Services)**: cups/avahi-daemon/bluetooth severity now context-aware
  (INFO on desktop with explanation, WARN on server). Service names
  generalized for cross-distro: httpd|apache2, smb|smbd, nmb|nmbd
- **Sec 8 (Ports)**: Externally-bound port firewall-block check generalized
  to cover iptables-only systems and ufw (not just nftables)
- **Sec 11 (Users)**: NOPASSWD detection regex correctly skips tab-indented
  comments
- **Sec 14 (Updates)**: dnf5-automatic upgrade_type parser uses parameter
  expansion (no more `cut -d= -f2` truncation)
- **Sec 15 (Rootkit)**: chkrootkit now `timeout 120s`-wrapped; FP filter
  surfaces filtered findings as INFO (transparency)
- **Sec 16 (Process)**: Suspicious-process name-pattern check annotates PASS
  ("real malware renames — see AIDE/IMA") to prevent false reassurance
- **Sec 18 (Containers)**: Docker daemon distinguishes rootless (INFO) from
  rootful (WARN)
- **Sec 19 (Logs)**: dmesg error count limited to last 1 hour. Empty-log
  check only runs when rsyslog/syslog-ng active.
- **Sec 20 (Performance)**: RAM threshold uses `available` instead of `used`.
  I/O-wait read directly from `/proc/stat` (instant, no 2-second blocking).
- **Sec 21 (Hardware)**: lm_sensors detection distinguishes "not installed"
  from "installed but unconfigured"
- **Sec 22 (Interfaces)**: DNS resolution test queries root nameservers
  (`. NS`) instead of `google.com`
- **Sec 23 (Certs)**: CA-cert count cross-distro (trust / ca-certificates.crt
  / /etc/ssl/certs/)
- **Sec 29 (Logins)**: Failed-login display redacts source IPs
- **Sec 30 (Hardening)**: Home-directory permissions tier-aware. Suspicious
  history shows first 3 examples instead of just count.
- **Sec 31 (Modules)**: Suspicious-module name-pattern check annotates PASS
  to prevent false reassurance
- **Sec 33 (Boot)**: Module signing detection now covers compile-time, runtime
  sig_enforce, and kernel cmdline enforcement
- **Sec 34 (Integrity)**: `rpm -Va` wrapped in `timeout 90s`. PATH security
  detects `.`, empty entries, and relative entries (privesc vectors).
- **Sec 35 (Browser)**: LibreWolf, Tor Browser, Waterfox profile detection
- **Sec 37 (NetPriv)**: Hostname-real-name detection raised to 5-char minimum
  + word-boundary match (eliminates "fox" matching "firefox-test")
- **Sec 38 (DataPriv)**: Bash-history scan replaced size-threshold with
  sensitive-content pattern scan; covers .zsh/.fish/.python/.psql/.mysql
  histories. Klipper detection KDE-aware (INFO on Plasma).
- **Sec 42 (Keyring)**: Plaintext-secret-files check now searches
  subdirectories (most `.env` files live in dev project subdirs)

### 🏗️ Architecture

- **`--ai` and `--json` no longer mutually exclusive**: JSON output now
  includes `ai_prompt` field when both flags set. Eliminates the
  entrypoint.sh double-run problem in CI/CD.
- **entrypoint.sh refactored**: Single audit run instead of double,
  `badge_color` and `badge_url` outputs added (Shields.io integration),
  grouped redirects (SC2129 clean), variable name clarity
- **AI prompt hardened**: Now includes "Verify each command against current
  system state before suggesting. If you cannot verify a fact, say so." to
  reduce LLM hallucination risk

### 🚀 CI Improvements

- CI now triggers on develop/release branches and version tags (was main-only)
- Distro-test matrix renamed to "Bash Syntax Compat" (honest scope — was
  pretending to be cross-distro logic test)
- New "Audit Smoke Test" job actually runs the audit on Ubuntu in offline
  mode and validates JSON parses cleanly
- ShellCheck job split into blocking warnings and non-blocking style/info
- Example workflow pinned to `@v3.4.0` instead of `@main` (supply-chain
  best practice — example documentation should model good security)

### 🎨 Style/Cosmetic

- 7 ShellCheck issues fixed (SC2086 unquoted vars, SC2126 grep|wc-l → grep -c,
  SC2004 ${} in arithmetic, SC2129 multiple redirects)
- entrypoint.sh: `xargs` replaced with `${var// /}` parameter expansion (no fork)

---

## [3.3.0] - 2026-04-09

### ✨ New Checks (32 additions from Lynis comparison)

**Kernel & Boot (Section 01)**
- Running latest installed kernel vs. installed kernel packages

**Firewall (Section 03)**
- Firewall logging status (firewalld/ufw/iptables — denied packet logging)

**VPN & Network (Section 05)**
- DNSSEC validation status via systemd-resolved

**Users & Authentication (Section 11)**
- Password hashing method detection (YESCRYPT > SHA512 > SHA256 > MD5)
- Password hashing rounds/cost factor from login.defs
- PAM password quality enforcement (pam_pwquality/pam_cracklib)
- Password expiry check for all human accounts
- Duplicate UID detection
- Duplicate GID detection

**Filesystem Security (Section 12)**
- Swappiness level (vm.swappiness)
- ACL support verification on root filesystem

**Encryption & Crypto (Section 13)**
- Hardware RNG detection (/dev/hwrng, hw_random, RDRAND/RDSEED)

**Process Security (Section 16)**
- Zombie/dead process count

**Network Security (Section 17)**
- TCP TIME_WAIT connection monitoring
- ARP monitoring software detection (arpwatch/arpon/addrwatch)

**Logs & Monitoring (Section 19)**
- Deleted log files still held open by processes

**Systemd Security (Section 25)**
- Expanded to 13 services across 3 tiers: security (sshd, firewalld, auditd, usbguard, chronyd), hardware (gdm, thermald), user-facing (NetworkManager, colord, fwupd, etc.)

**Advanced Hardening (Section 30)**
- IMA (Integrity Measurement Architecture) status, policy, and violation count
- EVM (Extended Verification Module) status
- binfmt_misc non-native binary format registration check
- FireWire/IEEE 1394 DMA attack surface (module blacklist check)
- Home directory permissions and ownership for all human users
- Shell idle timeout (TMOUT) across profile configs
- AIDE database existence and size
- Shell history analysis for suspicious commands (curl|bash, /dev/tcp, nc -e)

**System Integrity (Section 34)**
- /etc/hosts duplicate entry detection
- /etc/hosts localhost entry verification
- AIDE checksum algorithm strength
- Valid shells in /etc/shells count

### 🐛 Bug Fixes

- **Bluetooth "not available" logic**: `&&` changed to `||` — now correctly detects BT absence when either bluetoothctl OR bluetooth.service is missing (was requiring BOTH)
- **Double sysrq reporting**: Magic SysRq standalone check downgraded from `warn` to `info` (the sysctl loop already issues `fail` for non-zero values)
- **squashfs false message**: "loaded (required by Flatpak)" now only shows when the module is actually loaded; otherwise shows "not disabled but not loaded"
- **gsettings integer guard**: Screen lock delay and idle timeout callbacks now validate numeric input before integer comparison (prevents bash errors on malformed gsettings output)
- **FINAL RESULTS box**: Added missing right `║` border on title line
- **Score formula comment**: Fixed example result from 90% to correct 91%
- **printf format-string safety**: Kernel, uptime, and duration values in summary now use `%s` format specifier instead of embedded variables (prevents `%` characters from corrupting output)
- **Home directory stat fallback**: Empty `stat` result now skips the check instead of falling back to `777` (which caused spurious warnings)
- **TCP Wrappers false positive**: Downgraded "no deny rules" from `warn` to `info` (TCP wrappers are deprecated on modern systemd-based systems)
- **CPU vulnerability "Unknown"**: Changed from `pass` to `warn` for unrecognized vulnerability status (only "Not affected" and "Mitigation" now get `pass`)
- **auditctl "No rules" counted as 1**: Now filters the "No rules" message before counting
- **Double Bluetooth warning**: "active with no paired devices" now only fires when `pairable != yes` (avoids duplicate with "pairable but no devices" warning)
- **HISTSIZE regex**: Now also matches `export HISTSIZE=` form (was only matching bare `HISTSIZE=`)
- **Dead RPM_NOSIG code**: Removed redundant first `rpm -qa` query that was immediately overwritten
- **Hostname privacy check**: Now checks both first AND last name from GECOS field against hostname
- **Umask check**: Added `/etc/profile.d/*.sh` to search paths (Fedora sets umask there)
- **Skip keywords count**: Corrected from 43 back to 44 (42 sections + `netleaks` + `summary` sub-skip targets — the v3.2.5 "correction" was itself wrong)

### ✨ Additional Checks (5 — closing final Lynis gaps)

- **Password file consistency** (`pwck -rq`) — detects corrupted /etc/passwd entries (Section 11)
- **Locked user accounts** (`passwd -S`) — reports locked accounts, handles Fedora `LK` and Debian `L` status (Section 11)
- **Sudoers security audit** — permissions check (440), sudoers.d drop-in permissions, NOPASSWD scan, `visudo -c` syntax validation (Section 11)
- **Empty log files** — checks /var/log/messages, syslog, auth.log, secure, kern.log for zero-byte files indicating broken logging (Section 19)
- **NTP source quality** — chronyc sources analysis for unreachable/falseticker peers (Section 27)

### 🔧 Improvements

- **binfmt_misc.mount filtered** from failed services (expected failure on hardened systems)
- **Journal error threshold** raised from 10 to 15 (reduces false warnings on desktop with NVIDIA/SELinux)
- **ps self-reference filtered** from Top 5 CPU/Memory output
- **4× useless `cat`** replaced with `$(< /proc/...)` on procfs/sysfs reads
- **4× redundant `2>&1`** removed after `&>/dev/null`
- **Debian/Ubuntu compatibility**: Added `/etc/bash.bashrc` to umask and TMOUT checks, `gdm3` to systemd-analyze hardware services
- Check count updated: 300+ → 390+

---

## [3.2.5] - 2026-04-09

### 🔴 High Fixes

- **IPv6 false positive on VPN interfaces**: Global unicast addresses on VPN tunnel interfaces (e.g. a VPN tunnel's global IPv6) were counted as "IPv6 active — leak risk". These addresses are internal to the WireGuard tunnel and not internet-facing. Script now skips addresses on VPN interfaces (`tun*`, `wg*`, `proton*`, `pvpn*`) when counting global IPv6.

- **Audit watch detection missed `-F path=` syntax**: Script only matched short-form watches (`-w /etc/passwd`) but not the equivalent long-form (`-a always,exit -F path=/etc/passwd`). Systems using syscall-based audit rules (standard on modern Fedora/RHEL) showed 5 false "Audit watch missing" warnings. Now matches `-w`, `-F path=`, and `-F dir=` syntax, including sub-path matches.

- **Faillock counted header lines as failed attempts**: `grep -c "^[a-zA-Z]"` matched username headers (e.g. `user:`) and table headers (`When  Type  Source`) — not actual failures. Systems with zero failed attempts showed "4 account(s) with failed login attempts". Now counts only actual failure entries (lines starting with `YYYY-MM-DD`).

### 🟡 Medium Fixes

- **RPM unsigned: kmod packages indistinguishable from real issues**: Locally-built kernel modules (akmods/dkms) inherently cannot carry RPM GPG signatures — they are compiled on the user's machine. Previously lumped together with genuinely unsigned third-party packages. Now reported separately: `1 unsigned RPM packages (+ 2 locally-built kmod)`.

- **Journal critical: Intel watchdog false positive**: `watchdog: watchdog0: watchdog did not stop!` is logged at every shutdown on virtually all Intel systems with iTCO watchdog. Not a security or stability event. Added to benign-process filter alongside sudo, systemd-coredump, and auth messages.

- **os-release parsing used `eval`**: `eval "$(grep ... /etc/os-release)"` could theoretically execute injected code from a compromised os-release file. Replaced with explicit `while IFS='=' read` loop with key whitelist. Zero practical risk (root-owned file), but cleaner for a security audit tool.

### 🟢 Low Fixes

- **HTTP connectivity check undocumented**: `curl http://detectportal.firefox.com` uses unencrypted HTTP in a privacy tool. This is intentional (captive portal detection requires HTTP to detect redirects). Added explanatory comment.

- **CI: Fedora 39 (EOL) in test matrix**: Replaced with Fedora 42. Matrix now tests Ubuntu 22.04/24.04, Fedora 42/43, Debian 12.

- **CI: Docs/CHECKS.md not validated**: `validate-structure` job checked 7 required files but missed `Docs/CHECKS.md`. Added to the check list.

- **README: "44 skip keywords" incorrect**: Actual count is 43. Corrected.

- **Footer branding**: Removed co-author credit from scan output footer. Now shows `by NexusOne23` only.

### ✨ Improvements

- **GPL v3 copyright header**: Added full copyright notice with license text to the main script header, as recommended by GPL v3 for source files.

---

## [3.2.4] - 2026-03-30

### 🔴 Critical Fixes

- **RPM signature check was completely broken**: `grep -c "not signed"` never matched — RPM outputs `(none)` for unsigned packages, not "not signed". Every system falsely reported "All RPM packages signed". Fixed to check all three signature headers (RSAHEADER for modern Fedora, SIGPGP/SIGGPG for legacy RHEL). Also excludes `gpg-pubkey` meta-packages from the count.

- **NetworkManager connectivity check ignored conf.d drop-ins**: Only parsed `/etc/NetworkManager/NetworkManager.conf`. Fedora configures connectivity in `/etc/NetworkManager/conf.d/` drop-in files. Systems with connectivity disabled via drop-in (standard Fedora hardening) were falsely flagged as "may phone home". Now iterates all config files.

- **DNS resolution test leaked IP to Cloudflare**: `dig +short google.com @1.1.1.1` bypassed VPN/DoH setup and sent a query directly to Cloudflare in a privacy audit tool. Replaced with system-resolver query (`dig +short google.com`). Connectivity test now uses `curl detectportal.firefox.com` with ICMP fallback.

### 🔴 High Fixes

- **aes-cbc classified as "strong"**: LUKS with aes-cbc-essiv has known watermarking weaknesses. Now correctly warns and recommends migration to aes-xts.

- **SSH PubkeyAuthentication false positive**: When PubkeyAuthentication was not explicitly set (OpenSSH default = yes), script warned "not explicitly yes". Now recognizes the default as correct and shows PASS.

- **Kernel-UDP sockets all labeled "likely WireGuard"**: Any kernel-owned UDP socket (IPVS, conntrack, etc.) was assumed to be WireGuard. Now checks if WireGuard interfaces actually exist before labeling.

- **LLMNR/MulticastDNS: `head -1` instead of `tail -1`**: systemd uses last-value-wins semantics for duplicate keys. Script took the first value, potentially returning the wrong setting. Fixed to `tail -1` in both main config and drop-in parsing.

- **IPv6 manual/link-local falsely treated as "disabled"**: `ipv6.method=manual` with configured addresses means IPv6 IS active. Now checks if addresses are actually configured before classifying as disabled.

- **IPv6 ULA misclassified as "link-local"**: `fdxx::` addresses (Unique Local) were counted as link-local in the summary message. Now correctly distinguished.

- **Kernel Lockdown: empty value = PASS**: If `/sys/kernel/security/lockdown` existed but couldn't be parsed, the empty result fell through to PASS. Now explicitly warns on parse failure.

- **AppArmor ignored when getenforce exists but SELinux=Disabled**: `HAS_SELINUX` was set based on `getenforce` binary existence, not actual SELinux status. On systems with SELinux disabled but AppArmor enforcing, AppArmor was silently skipped. MAC detection now checks actual enforcement status.

### 🟡 Medium Fixes

- **Faillock counted login attempts, reported "accounts"**: `grep -c "When"` counted individual failed attempts, but the message said "X accounts". Fixed to count unique usernames.

- **Core dump check missed systemd-coredump Storage=none**: `ulimit -c` and `core_pattern` were checked, but `systemd-coredump` with `Storage=none` (the Fedora standard) was not recognized. Now checks all three mechanisms. Also fixed relative path bug in `_systemd_conf_val` call.

- **net.ipv4.conf.default.rp_filter never checked**: Was in `SYSCTL_MIN_OK` but missing from `SYSCTL_CHECKS` — dead code. Now included in the check loop.

- **cups-browsed: FAIL even when patched**: CVE-2024-47176 was fixed in cups-filters >= 2.0.1. Downgraded from FAIL to WARN with version note.

- **Flatpak: `filesystems=home` not detected**: Only `host` and `host-os` were flagged. Apps with `home` access (full user data) were silently passed. Now detected.

- **Snap telemetry: wrong config key**: `system.telemetry.enabled` doesn't exist. Changed to `experimental.telemetry`.

- **DHCP hostname: last connection file won in global check**: If one connection had `dhcp-send-hostname=true` and a later one had `false`, only `false` was seen. Now flags any single connection with hostname leaking.

- **Journal error count inflated by continuation lines**: Multi-line log entries (stack traces) were counted as separate errors. Now filters to timestamp-prefixed lines only (consistent with critical-level check).

- **chkrootkit FP filter missing `linux_ldiscs` and `suckit`**: Known false positives on modern kernels not filtered. Added to pattern.

- **Suspicious process regex issues**: `reverse.shell` unescaped dot, `nc -l` didn't match with flags (`-lvnp`), `socat`/`cobalt` too broad. Tightened all patterns.

- **Cron file permissions too strict**: Any group/other bit triggered WARN — standard Fedora `/etc/crontab` (644) was always flagged. Now allows read-only for group/other, warns only on write/execute.

- **Coredump check duplicated in two sections**: Section 12 (Filesystem) and Section 38 (Data Privacy) both produced pass/warn for the same coredump check, inflating the score. Section 38 now shows INFO only with reference to Section 12.

- **AutomaticLogin grep matched AutomaticLoginEnable**: `grep AutomaticLogin` also matched `AutomaticLoginEnable=true`, extracting "true" as the username. Fixed with negative lookahead. Also fixed duplicate check in Section 26.

- **`_for_each_user` processed UID 65534 (nobody)**: Missing upper bound caused unnecessary checks on system accounts. Now filters `uid < 65534` consistently.

- **Firmware findings in wrong JSON section**: `CURRENT_SECTION` was still set to "PASSWORD & KEYRING" when firmware checks ran. Added explicit section assignment.

- **bluetooth.socket not checked**: Only `bluetooth.service` was in the disabled-services list. Bluetooth could start via socket activation. Added `bluetooth.socket`.

- **Fedora countme default text incorrect**: Warned about countme being "enabled per-repo" on unset systems. Since Fedora 36+, the default is disabled. Changed to INFO with correct text.

- **IPv6 privacy extensions: false positive on VPN interfaces**: VPN killswitch interfaces with internal ULA addresses triggered "IPv6 privacy extensions disabled" warning. VPN-internal interfaces are now skipped in the privacy check.

### 🟢 Low Fixes

- **Section comment numbers off-by-one**: Comments said "Section 36-43" but headers showed 35-42. All 8 comments corrected.

- **`rpm -Va` no progress indicator**: Full package verification can take 5-15 minutes with no output. Added progress message.

- **iptables rule count wrong**: Counted chain headers (`^[A-Z]`) instead of actual rules. Fixed to exclude headers and empty lines.

- **`cat /proc/loadavg | awk`**: Useless use of cat. Changed to `awk ... /proc/loadavg`.

- **`ip_forward` empty value error**: Missing default caused bash integer comparison error on stderr. Added `|| echo "0"` fallback.

- **systemd-analyze dead else branch**: `if [[ "$SVC" == "sshd" || ... ]]` was always true because the for-loop only contained those 4 values. Removed dead code.

- **`HAS_SELINUX`/`HAS_APPARMOR` undefined with `--skip selinux`**: MAC detection moved before the skip check so AI context always has correct values.

- **`txtf` dead code removed**: Never called anywhere in the script.

- **policies.json `"Value".*true` global match**: `EnableTrackingProtection` check matched any `"Value": true` in the entire file. Now scoped to the specific JSON block via `sed`.

- **vmstat column 16 hardcoded**: I/O wait column position varies across distros. Now dynamically parsed from header.

- **Score integer division truncation**: Always rounded down. Added `+ DENOM/2` for proper rounding.

- **`_human_size` crash on empty input**: No validation for non-numeric or empty arguments. Added regex guard.

- **PipeWire TCP check matched inline comments**: `grep -vE '^\s*#'` only filtered full-line comments. Strings like `value # tcp:4713` still matched. Added second grep to re-validate match after comment removal.

- **ANSI escapes in AI copy markers**: `echo -e "${GRN}..."` in copy markers included terminal color codes when copied. Changed to plain `echo`.

- **Suspicious module check label**: Added "(basic name-based heuristic)" caveat — real rootkits use innocuous names.

- **os-release sourcing**: `. /etc/os-release` could execute arbitrary code on compromised systems. Changed to `eval "$(grep ...)"` with restricted key whitelist.

- **`grep -qw "$GW"` regex wildcard**: Dots in IP addresses interpreted as regex "any character". Changed to `grep -qwF` (fixed string).

- **`ip route show default` missing `2>/dev/null`**: Inconsistent with other `ip` commands. Added error suppression.

---

## [3.2.3] - 2026-03-25

### 🔴 High Fixes

- **Unusual destination ports check was completely dead**: `ss -tnp state established | awk '{print $5}'` grabbed the Process column instead of Peer Address:Port (`$4`). The check always reported "All connections on standard ports" regardless of actual connections. Fixed to `awk '{print $4}'`.

- **Firefox DoH Mode 2/3 descriptions swapped**: Mode 2 was labeled "strict" and Mode 3 was labeled "fallback". In reality, Mode 2 = "DoH first, fallback to native DNS" and Mode 3 = "DoH only, no fallback" (the strictest setting). Both labels and severity corrected (Mode 3 now PASS instead of INFO).

### 🟡 Medium Fixes

- **Flatpak dangerous permissions: triple pattern failure**: (1) `talk-name=org.freedesktop.Flatpak` never matched — actual format is `org.freedesktop.Flatpak=talk`. (2) `filesystems=host` only matched when `host` was the first element; `filesystems=xdg-run;host;` was missed. (3) `\bhost\b` false-positived on `host-etc` (Brave Browser). Rewritten with precise delimiter-aware pattern.

- **Failed services: printed LOAD status instead of unit name**: `awk '{print $2}'` extracted the LOAD column, not the unit name (`$1`). Also added Unicode bullet (`●`/`×`) handling for newer systemd versions.

- **Kernel Taint: exact match instead of bitmask**: Checked `== 4096` (out-of-tree module only). NVIDIA sets both Bit 0 (proprietary) and Bit 12 (out-of-tree), producing 4097. Fixed to `(TAINT & 4096) || (TAINT & 1)` with corrected label.

- **AppArmor profile count wrong (Debian/Ubuntu)**: `grep -c "enforce"` counted all lines containing "enforce" including summary lines ("37 profiles are in enforce mode" + "15 processes are in enforce mode" = 2 instead of 37). Fixed with precise regex extracting the number from the summary line.

- **Umask 4-digit values not recognized**: `0027` and `0077` (common in CIS benchmarks and login.defs) were flagged as insecure. Initial strip-one-zero fix was incomplete (`0027` → `027` ≠ `27`). Fixed with regex `^0*27$` / `^0*77$` matching any number of leading zeros.

- **Hidden processes: inflated count from sort incompatibility**: `sort -n` (numeric) + `comm` (requires lexicographic sort) produced false positives. PIDs like `9, 10` sorted as `9, 10` numerically but `10, 9` lexicographically, causing `comm` to report phantom differences. Fixed to `sort -u` (lexicographic).

- **Cron directory 777 reported as PASS**: A directory with permissions 777 fell through all check branches to the default PASS. Restructured into explicit file/directory branches with proper warnings.

- **GNOME Tracker checked system scope instead of user scope**: `systemctl is-active tracker-miner-fs-3.service` (without `--user`) always returned inactive because Tracker runs as a user service. Now checks per-user via `sudo -u USER systemctl --user`. Added `localsearch-3.service` for Ubuntu 24.04+ (GNOME 46 rebranding).

- **Filesystem module checks missed `blacklist` directive**: Only `install cramfs /bin/false` was detected. `blacklist cramfs` (the common method) was ignored, causing false "not explicitly disabled" messages. USB-storage check already had `blacklist` — now consistent.

- **PipeWire TCP check: false negative then false positive**: Original pattern `module-protocol-pulse.*tcp` never matched real configs. Replaced with `tcp:[0-9]`, which then matched commented-out examples (`#"tcp:4713"`). Final fix: grep for pattern + filter comment lines.

- **GRUB password check: false positive from comments**: `grep -q "password"` matched `# password_pbkdf2 is recommended`. Fixed to `grep -rqE '^\s*(password_pbkdf2|password)\s+'`. Also expanded from `40_custom` only to all files in `/etc/grub.d/`.

- **DHCP hostname check: wrong INI section**: Searched for `[ipv4]` in `NetworkManager.conf`, but global config uses `[connection]` with `ipv4.dhcp-send-hostname`. Now checks both global config (`[connection]` section) and per-connection `.nmconnection` files (`[ipv4]` section). Also accepts `0` as disabled.

- **SSH key type extraction broke on comments with spaces**: `awk '{print $4}'` assumed fixed field position. Comments like `user@host generated 2026` shifted the type field. Fixed to `awk '{print $NF}'` (always last field).

- **auditctl status parsing not portable**: Newer auditd outputs `enabled 1` (multiline), older versions output `AUDIT_STATUS: enabled=1 flag=2` (single line). Fixed with dual-format regex matching both.

- **fwupdmgr false positive from `||` short-circuit**: `[[ $fw_exit -eq 2 ]] || echo "$fw_output" | grep -qi 'no updates'` — the grep ran unconditionally. If exit code was 1 (error) and error text contained "no updates", it falsely reported "up to date". Split into separate `elif` branches.

### 🟢 Low Fixes

- **lock-enabled fallback mislabeled as "Lock on suspend"**: On non-Ubuntu GNOME (Fedora, Arch), the `ubuntu-lock-on-suspend` key doesn't exist. Fallback to `lock-enabled` used the same callback, displaying "Lock on suspend enabled" instead of "Screen locking enabled". Now uses separate callback with correct text.

- **.netrc false positive as "Plaintext secret file"**: `.netrc` is a legitimate credentials file. Removed from secret_patterns list; separate permissions check (must be 600/400) retained.

- **Firmware/Thunderbolt checks skipped by `--skip keyring`**: fwupdmgr and Thunderbolt DMA checks were inside `check_keyring_security()`. Moved to independent block after all function calls.

- **link-local falsely classified as DHCP**: `ipv4.method=link-local` (RFC 3927 zeroconf) does not send DHCP requests. No longer triggers DHCP hostname warnings.

- **NM Connectivity: missing `uri=` key treated as "disabled"**: A `[connectivity]` section without explicit `uri=` key uses NetworkManager's default URI (phones home). Only an explicitly empty `uri=` disables it. Now distinguishes both cases.

- **Root excluded from empty-password check**: `$1 != "root"` filter removed. Root with empty password is the most critical finding and must be reported.

- **Faillock: inconsistent terminology**: WARN said "failed login attempts" but PASS said "no locked accounts". Now consistently uses "failed login attempts" in both cases.

- **modprobe.d pattern missed `/usr/bin/false`**: Only `/bin/false` was matched. Fedora and modern distros use `/usr/bin/false`. Pattern expanded to `/(usr/)?s?bin/(false|true)`.

- **rescue/emergency always reported as "enabled"**: These are static systemd units — `is-enabled` always returns 0. Now checks `ExecStart` for `sulogin` (password-protected rescue shell) and only warns if sulogin is absent.

- **dpkg -l exit 0 for removed packages (Debian/Ubuntu)**: `dpkg -l package` returns 0 even for status "rc" (removed, config remaining). Now checks for `^ii` (actually installed).

- **xclip in clipboard manager daemon list**: xclip is a CLI tool, not a persistent daemon. Removed from detection list.

- **`local` outside function (2 locations)**: `local` keyword in rescue/emergency check and AI prompt block caused Bash warnings. Removed.

### 🔧 Calibration Fixes

- **User list on login screen: WARN → INFO with LUKS**: On LUKS-encrypted systems, physical access requires the encryption passphrase before reaching the login screen. User enumeration is not a meaningful risk. Now INFO with explanation instead of WARN.

- **DoH Mode 3 corrected**: v3.2.2 miscalibrated Mode 3 as INFO ("fallback"). Mode 3 is actually the strictest DoH setting (no fallback). Now correctly PASS.

### ✨ Improvements

- **AI Prompt redesigned**: Added tool URL (`github.com/NexusOne23/noid-privacy-linux`), score with counts, and auto-detected system context (LUKS, VPN, Flatpak, SELinux/AppArmor). Visual upgrade with colored box and clear copy markers.

---

## [3.2.2] - 2026-03-02

### 🔴 High Fixes

- **Permissions: numeric comparison instead of bitwise**: `stat -c %a` returns octal strings that were compared as decimal integers (`555 < 600` → false PASS, but `555 = r-xr-xr-x` = world-readable). Fixed at 5 locations (history files, system file permissions, private keys, cron dirs/files) using proper octal bitmask comparison: `(( (8#${PERMS} & 8#077) != 0 ))`.

- **Firewalld: hardcoded zone list + default zone logic**: Zone enumeration used a hardcoded list missing `trusted`, `home`, `internal`, `work`, `FedoraServer`, `nm-shared`, and custom zones. Replaced with dynamic `firewall-cmd --get-zones`. Additionally, the default zone without explicit interfaces was skipped entirely — but it applies to ALL unassigned interfaces. Now evaluates services/ports on the default zone as exposed.

- **openssl x509 -checkend: grep substring match**: `grep -q "will expire"` matched both "Certificate will expire" AND "Certificate will **not** expire" (substring). Every valid cert was falsely flagged. Fixed by using `openssl x509 -checkend` exit code (0 = valid, 1 = expired) instead of text parsing. Also added multi-distro cert paths (`/etc/pki/tls/certs` + `/etc/ssl/certs`).

### 🟡 Medium Fixes

- **IPv6 NetworkManager: break on first disabled connection**: `break` after first `disabled` result caused false PASS when multiple connections were active (e.g. eth0=disabled, wg0=auto). Now checks ALL active connections; breaks only on first NOT disabled.

- **ICMP Redirect: only conf.all checked**: Missing `net.ipv4.conf.default.accept_redirects` check. New interfaces inherit from `conf.default`, so `conf.all=0` alone is insufficient. Now checks both and warns if only `conf.all` is disabled.

- **Unowned files find without timeout**: `find / -xdev -nouser -o -nogroup` could hang on slow/remote filesystems. Added `timeout 30`.

- **SSH service name: Debian/Ubuntu uses `ssh.service`**: Only `sshd.service` was checked. Debian/Ubuntu uses `ssh.service` (alias). Added `ssh` to service detection and SSH hardening section.

- **RDP remote_found set before value check**: `remote_found=1` was set unconditionally when the gsettings key existed, before checking if RDP was actually enabled (`true`). Now only sets flag when value is `true`.

- **APT security updates: locale-dependent parsing**: `apt-check --human-readable` output depends on system locale. Switched to raw `apt-check` (outputs `UPDATES;SECURITY` to stderr, locale-independent).

- **World-writable detail find without timeout**: Added `timeout 30` to prevent hangs on slow filesystems.

### 🟢 Low Fixes

- **ssh-keygen double execution**: `ssh-keygen -l -f` was called twice per key (once for bits, once for type). Cached result in variable.

- **Podman user/root identical scope**: Both `podman ps -q` calls ran as root, producing identical results. Removed misleading "user" count, kept only root container count.

- **Audit watch sub-path matching**: Grep for `-w /etc/ssh ` (trailing space) didn't match more specific rules like `-w /etc/ssh/sshd_config`. Fixed to match sub-paths.

- **systemctl --user portal check removed**: `systemctl --user` as root returns root's user session, not the desktop user's. Removed redundant portal check (already covered by device enumeration).

- **Chrony status message**: `"chronyd: active"` → `"chrony: active"` for consistency with service naming.

### 🔧 Calibration Fixes

- **SUID files threshold**: Pass ≤25 → Pass ≤30, Warn 31-45, Fail >45. Fedora Workstation with GNOME + NVIDIA has ~23 SUID binaries; ≤30 is normal for a desktop install.

- **SGID files threshold**: Pass ≤15 → Pass ≤10, Warn 11-20, Fail >20. Typical systems have 5-8 SGID files.

- **Unowned files threshold**: Pass ≤10 → Pass =0, Warn 1-5, Fail >5. Hardened systems should have zero unowned files; 10 was too permissive.

- **Btrfs snapshot exclusion**: All `find` commands in Section 12 (SUID, SGID, World-Writable, Unowned) now exclude `/.snapshots/*` to prevent false positives from Btrfs snapshots with stale UIDs/permissions.

- **GDM runtime files exclusion**: Unowned files check now excludes `/var/lib/gdm/*` — GDM creates runtime files (ibus, PulseAudio, dconf, WirePlumber) in a user namespace that appear as unowned to `find -nouser/-nogroup`.

- **`recent-files-max-age=0` logic bug**: Was reported as WARN "kept forever" — but GNOME defines `max-age=0` as "list always empty" (disabled). Now correctly reported as PASS.

- **DoH mode 3 severity**: Was PASS like mode 2 (strict). Mode 3 is fallback-only (falls back to plain DNS on failure). Now INFO to distinguish from strict DoH.

- **IPv6 privacy extensions false positive**: NM check was too strict — `ipv6.method=manual` and `link-local` (functionally equivalent to disabled without configured addresses) were not accepted. Loopback interface was also checked unnecessarily. Now accepts `manual`/`link-local` as IPv6-off and skips `lo`.

- **sshd systemd-security severity**: Was WARN at score 9.6. sshd inherently needs root/PAM/filesystem access — a high exposure score is expected and unavoidable. Now INFO (same as firewalld, fail2ban, auditd).

- **openssl checkend stdout leak**: `openssl x509 -checkend -noout` still prints "Certificate will not expire" to stdout in some OpenSSL versions. Only stderr was suppressed (`2>/dev/null`), causing raw text to leak into the report. Fixed with `&>/dev/null`.

- **at.allow/deny false positive**: Check warned "Neither at.allow nor at.deny exists" even when `at` was not installed. Now skips entirely if `at` command is not available.

---

## [3.2.1] - 2026-02-27

### 🐛 Bug Fixes

- **wsdd gvfsd child process false positive**: `pgrep -x wsdd` also matches the wsdd child process spawned by GNOME's `gvfsd-wsdd` (network browsing). That child always runs with `--no-host`, meaning it does **not** announce the machine on the LAN. The script now reads each matching process's cmdline and only warns if a wsdd process lacks `--no-host` (i.e. is a true standalone broadcast daemon). Systems with GNOME running correctly show PASS.

- **SELinux AVC false positive (aide/usbguard/logind)**: AVC denials from `aide`, `usbguard-daemon`, and `systemd-logind` are normal MAC operation — AIDE reads restricted paths during integrity checks, USBGuard interacts with udev/systemd, logind does session-management accesses at boot. Script now inspects the `comm=` field of each AVC denial and only warns if processes *other than* these expected ones generate denials. Systems with AVC activity from these daemons only now show INFO instead of WARN.

- **Journal critical count inflated by coredump stack traces**: `journalctl -p crit` in short format outputs multi-line entries: one coredump event generates hundreds of continuation lines (stack frames + loaded module list), each counted as a separate "critical" message. The script now only counts lines that start with a timestamp prefix (actual journal entries) and ignores indented continuation lines. One crash = one event, not 700+.

- **Journal errors inflated by sudo-without-TTY messages**: `sudo` logs an error for each invocation without a TTY (e.g. from CI tools or IDE integrations). These are operational noise, not security events. Script now filters `sudo[` lines from the 1-hour error count.

- **RPM verify: `/usr/lib/issue` and `/usr/lib/issue.net` counted as binaries**: These login-banner files (owned by the `setup` package) are plain text, not binaries. They are commonly cleared during system hardening (removing OS identification from login prompts). RPM flags them as modified because they lack the `c` (config) marker in the RPM database. Script now excludes `/usr/lib/issue*` from the binary-changed count. `.pyc` / `__pycache__` exclusion (Python bytecode, previously added) retained.

---

## [3.2.0] - 2026-02-27

### 🐛 False Positive Fixes (Real-World Hardened Systems)

These fixes were identified by running NoID Privacy on a fully-hardened Fedora 43 workstation.
Every single fix removes a genuine false positive from a correctly-secured system.

#### nftables & Firewall
- **nftables false positive**: `nftables.service` is correctly `inactive` when firewalld manages it as its backend (default on Fedora 31+, RHEL 8+). Script now detects `FirewallBackend=nftables` in `/etc/firewalld/firewalld.conf` and reports PASS instead of WARN.
- **Firewall policies**: Added detection of `firewall-cmd --list-policies` (firewalld 0.9+). Inter-zone policies (e.g. `block-lan-out` blocking RFC1918) are now reported and evaluated.

#### Kernel & sysctl
- **`net.ipv4.conf.all.rp_filter = 2` false positive**: Value `2` (loose mode) is required for WireGuard and other VPN setups. Script now accepts `>= 1` as valid for rp_filter (both strict and loose modes are secure; strict mode breaks multi-homed VPN routing).
- **`kernel.unprivileged_bpf_disabled = 2` false positive**: Value `2` is stricter than `1`. Script now accepts `>= 1` for this parameter. General `SYSCTL_MIN_OK` mechanism introduced for params where "higher = more hardened".

#### Swap / Memory
- **ZRAM false positive**: ZRAM (`/dev/zram*`) is in-memory compression, not a persistent disk device. It cannot leak data after reboot and needs no encryption. Previously flagged as "Swap: NOT encrypted". Now correctly reported as PASS with explanation.

#### Core Dumps
- **Coredump drop-in override ignored**: Script only read `/etc/systemd/coredump.conf` and missed drop-in overrides in `/etc/systemd/coredump.conf.d/`. A system with `Storage=external` in the main file but `Storage=none` in a drop-in was incorrectly flagged as WARN. Added `_systemd_conf_val()` helper that reads main config + all drop-ins (last wins), mirroring actual systemd behavior. Applied to both Section 30 and Section 38.

#### Network Privacy
- **Avahi config false positive**: `publish-hostname` config was flagged even when `avahi-daemon` was masked or disabled. Config file contents are irrelevant if the service cannot run. Check now skipped for masked/disabled services.
- **DHCP hostname false positive**: DHCP hostname leak warning was shown for systems with static IP where no DHCP is ever sent. Script now checks if any active NM connection uses `ipv4.method=auto` before checking `dhcp-send-hostname`.
- **Ethernet MAC `stable` vs `random`**: `stable` and `random` were both reported as PASS. `stable` generates a consistent MAC per connection-UUID (not truly random). With a static IP, it provides no privacy benefit. Now correctly reported as INFO with explanation.

#### Automated Updates
- **`dnf5-automatic.timer` not detected**: Fedora 41+ uses `dnf5-automatic` (not `dnf-automatic`). The old timer was not found → false WARN. Script now checks `dnf5-automatic.timer` first and reports the configured `upgrade_type` (security vs. default).

### ✨ New Checks

- **WireGuard/ProtonVPN ip-rule killswitch**: Kill-switch implemented via `ip rule` policy routing (ProtonVPN, NetworkManager WireGuard plugin) was not detected — only nftables DROP rules were checked. Script now also detects `suppress_prefixlength` and `fwmark`-based routing rules.
- **NTS-secured NTP (reliable detection)**: Fixed NTS detection: `chronyc sources` does not output "NTS" literally. Now uses `chronyc authdata` (chrony 4.0+) which shows active NTS sessions, with fallback to checking `nts` keyword on `server`/`pool` lines in chrony.conf.

### 🔧 Internal

- Added `_systemd_conf_val()` helper: reads systemd unit config with full drop-in support (mirrors actual systemd override behavior). Reusable for any systemd config file.
- Added `SYSCTL_MIN_OK` associative array: allows specifying minimum-acceptable values for sysctl params where "higher = stricter". Eliminates per-param special-casing.

---

## [3.1.0] - 2026-02-22

### 🔧 Quality & Correctness Release

**27 issues fixed from comprehensive code review. Zero new features — pure quality improvement.**

### 🔴 Critical Fix

- **Network requests now documented and skippable**: DNS leak test (`dig whoami.akamai.net`) and IP check (`curl ifconfig.me`) are wrapped in `--skip netleaks`. README and SECURITY.md updated to reflect actual behavior.

### 🟠 High Fixes

- **Pipe-to-while counter bug**: 22 instances of `cmd | while` refactored to `while ... done < <(cmd)` using process substitution. Prevents counter loss in subshells — score calculation is now accurate.
- **JSON schema mismatch**: Changed `"status":"pass"` to `"severity":"PASS"` (uppercase) to match entrypoint.sh's `jq` selectors. JSON output now works correctly in GitHub Actions.
- **Documentation accuracy**: Removed "zero network requests" claims from README and SECURITY.md.
- **Temperature parsing false positive**: `sensors` output now filters threshold values (`high`, `crit`, `low`, `hyst`) — only actual readings are compared. Previously `high = +65261.8°C` was parsed as a real temperature.
- **IPv4-mapped IPv6 localhost false positive**: Port check now recognizes `::ffff:127.0.0.1` as localhost. Previously flagged as "EXTERNALLY REACHABLE".

### 🟡 Medium Fixes

- Replaced all 78 `echo -e` with `printf` for POSIX portability, with proper `%%` escaping for literal percent signs
- Fixed unquoted `$0` in root check error message
- IPv6 check now filters link-local (`fe80::`) and multicast (`ff`) addresses to avoid false positives
- GitHub Actions pinned to specific versions (`@v4.2.2`)
- CI now tests on Ubuntu 22.04/24.04, Fedora 39/43, Debian 12 via Docker matrix
- ShellCheck is now enforced in CI (no longer `continue-on-error`)
- Version consistency across script, README, and SECURITY.md
- Hardened 19 `|| echo 0` patterns to `|| true` with `${VAR:-0}` defaults — prevents double-output in command substitutions
- **Flatpak Firefox support**: Browser privacy checks now scan both `~/.mozilla/firefox` and `~/.var/app/org.mozilla.firefox/.mozilla/firefox`
- **`rpm -Va` performance**: Cached output to avoid redundant second scan (saves ~60-120s on large systems)
- Fixed literal `\n` in firewall zone output — multi-line zones now display correctly

### 🧠 Desktop Intelligence (False-Positive Reduction)

- **TCP port check**: Externally bound TCP ports now check for VPN kill-switch before flagging as FAIL (same logic UDP already had)
- **Swap on LUKS**: Swapfiles on LUKS-encrypted volumes are now correctly recognized as encrypted at rest
- **IPv6 ULA filter**: Private `fd00::/8` (ULA) addresses and `::` loopback are no longer counted as global/leak-risk
- **Flatpak permissions**: Only `host`/`host-os` filesystem access triggers a warning — `xdg-download` etc. no longer false-positive
- **Compiler check**: Compilers on desktop systems show INFO instead of WARN (detected via `$XDG_CURRENT_DESKTOP`)
- **squashfs module**: Loaded squashfs is now INFO when Flatpak is installed (Flatpak requires squashfs)
- **Kill-switch duplicates**: VPN-managed duplicate rules downgraded from WARN to INFO (temporary, harmless)
- **Boot params**: `iommu=force` and `lockdown=confidentiality` are now INFO (optional — can break NVIDIA/hardware)
- **Journal criticals**: sudo auth retries are filtered before counting critical journal entries

### 🌍 Multi-Distro Support (Arch + openSUSE)

- **Arch Linux support**: pacman updates, security updates (rolling), package count, SigLevel verification, file integrity via `pacman -Qkk`
- **openSUSE support**: zypper updates, zypper security patches, PackageKit auto-updates detection
- **MAC framework fix**: SELinux/AppArmor detection is now tool-based instead of distro-based — openSUSE correctly uses AppArmor
- **Distro detection expanded**: Arch, Manjaro, EndeavourOS, Garuda, Artix, openSUSE, SLES, Linux Mint, Pop!_OS now recognized
- **False PASS eliminated**: Security updates on unsupported distros now show INFO instead of false PASS
- **Silent skips fixed**: Package count and signature checks now show INFO when package manager is unsupported

### 🐧 Debian/Ubuntu Feature Parity

- **Security updates detection**: apt systems now check for pending security updates via `apt-check` / `apt-get -s`
- **APT package authentication**: Check for unauthenticated/local packages (Debian equivalent of RPM GPG check)
- **debsums hint**: Debian systems without `debsums` now get an installation recommendation

### 🔧 Additional Bugfixes (Post-Review)

- **JSON mode clean output**: ~48 unguarded `printf` sub-headers and raw-dump blocks now suppressed in `--json` mode. Introduced `sub_header()` helper. `--json | jq .` now produces valid JSON.
- **Firewall zone REJECT**: `firewall-cmd --get-target` returns `REJECT` on modern firewalld (not `%%REJECT%%`). Both variants now matched.
- **USB storage pattern**: `usb-storage` (hyphen) and `usb_storage` (underscore) both matched via `usb[-_]storage`
- **ABRT service count**: `systemctl list-units | ccount` was extracting random digits from text output. Fixed to `| wc -l | ccount`.
- **PipeWire socket check**: `grep -rqs` (quiet) piped to `grep -v` always returned empty. Fixed: `-q` moved to second grep.
- **Empty password false positive**: `!` and `!!` in `/etc/shadow` mean "locked" (secure default for system accounts), not "empty". No longer counted as empty passwords. Fixes false positives on Debian/Ubuntu.
- **Screen lock check**: Now uses per-user DBUS session bus (`_gsettings_for_users`) instead of running `gsettings` as root (which returns system defaults, not actual user settings).
- **Compiler desktop detection**: Uses script's own `$DESKTOP_ENV` (set via `/proc`) instead of `$XDG_CURRENT_DESKTOP` (stripped by `sudo`).
- **AI marker in entrypoint.sh**: GitHub Action now correctly finds AI prompt block (`AI ASSISTANT PROMPT` instead of old `AI-READY PROMPT`).
- **SSH config parsing**: `sshd_cfg_val()` now uses `sshd -T` (OpenSSH's own parser) as primary method, with `head -1` fallback. Previously `tail -1` violated OpenSSH's first-match-wins semantics.
- **SUID/SGID find -xdev**: Added `-xdev` to SUID and SGID file searches. Prevents script from hanging on NFS/CIFS/FUSE mounts.
- **Shadow permissions false positive**: `/etc/shadow` and `/etc/gshadow` expected permissions relaxed from `000` to `640`. Debian/Ubuntu use `640` (root:shadow) for PAM password validation — no longer triggers false WARN.
- **VPN DNS range expansion**: DNS-over-VPN check now recognizes all RFC1918 (`10.x`, `172.16-31.x`, `192.168.x`) and CGNAT (`100.64-127.x`) ranges. Fixes false "DNS leak" warnings for Tailscale, WireGuard, and other VPNs.
- **User switching GNOME key**: Changed from `disable-lock-screen` to `disable-user-switching` with corrected logic. Lock screen is already checked via `org.gnome.desktop.screensaver lock-enabled`.

### 🟢 Low & Nitpick Fixes

- Fixed `local i` used outside function scope in JSON output
- Added `.editorconfig` for consistent formatting
- Expanded `.gitignore` (already covered in previous commit)
- Documented score formula: `PASS×100 / (PASS + FAIL×2 + WARN)`
- Documented SSH key strength thresholds (NIST guidelines)
- Documented `ccount()` helper function purpose
- Fixed credits: "Clawde" → "Claude"
- Added Troubleshooting section to README
- Clarified comparison table: "Zero compiled dependencies"
- Expanded AI flag description in `action.yml`
- Added ShellCheck requirement to CONTRIBUTING.md
- Fixed counter variable names in CONTRIBUTING.md docs
- Improved Security Policy SLAs with precise timelines
- Added `netleaks` to skip keywords list in `--help`

---

## [3.0.0] - 2026-02-13

### 🚀 Major Release — Privacy & Security Audit for Linux Desktops

**Complete repositioning: From server security tool to the first desktop privacy & security auditor for Linux.**

### 🌟 Release Highlights

✅ **300+ Checks** — Expanded from 250+ with 8 new privacy & desktop sections  
✅ **42 Sections** — Up from 34 (8 new privacy/desktop sections)  
✅ **AI-Ready Prompt** — `--ai` flag generates copy-paste prompts for ChatGPT/Claude/Gemini  
✅ **JSON Output** — `--json` flag for machine-readable results  
✅ **Desktop-First** — Browser privacy, app telemetry, webcam, Bluetooth, keyring auditing  
✅ **Zero Dependencies** — Still pure Bash, still zero external requirements  

### ✅ Added — Privacy Audit (8 New Sections, 60+ New Checks)

#### 🔒 Browser Privacy (Section 35)
- Firefox telemetry, health reports, WebRTC IP leaks
- DNS-over-HTTPS configuration
- Tracking protection level, third-party cookie policy
- Shield Studies, password saving
- uBlock Origin detection
- Chrome/Chromium presence warning

#### 🔒 Application Telemetry (Section 36)
- GNOME Location Services, problem reporting, usage stats
- GNOME Tracker/file indexer detection
- Recent files tracking configuration
- Flatpak dangerous permissions (filesystem=host, portal escape)
- Snap telemetry
- ABRT crash reporter
- Fedora countme / Ubuntu popularity-contest
- NetworkManager captive portal detection

#### 🔒 Network Privacy (Section 37)
- WiFi MAC address randomization
- Ethernet MAC cloning configuration
- Avahi/mDNS hostname broadcasting
- LLMNR status
- Hostname privacy (real name detection)
- IPv6 privacy extensions
- DHCP hostname leaking
- cups-browsed RCE risk (CVE-2024-47176)

#### 🔒 Data & Disk Privacy (Section 38)
- Recently used files size per user
- Thumbnail cache (reveals viewed images after deletion)
- Trash size monitoring
- Clipboard manager detection (password leak risk)
- Core dump configuration (may contain secrets)
- Bash history size audit
- Journald persistent log size
- /tmp filesystem type (tmpfs vs persistent)

#### 🖥️ Desktop Session Security (Section 39)
- Screen lock delay, idle timeout
- Lock on suspend
- Notification previews on lock screen
- GDM auto-login, guest account, timed login
- Remote desktop/VNC/RDP detection
- Autostart programs audit
- User list visibility on login screen

#### 🖥️ Webcam & Audio Privacy (Section 40)
- Webcam device detection
- Microphone mute status (PipeWire/PulseAudio)
- Network audio modules (TCP exposure)
- PipeWire remote access
- Screen sharing portal status

#### 🖥️ Bluetooth Privacy (Section 41)
- Bluetooth service status
- Discoverable mode (visible to nearby devices)
- Pairable mode without paired devices
- Active Bluetooth without usage

#### 🖥️ Password & Keyring Security (Section 42)
- Password manager detection (keepassxc, bitwarden, pass, etc.)
- GNOME Keyring PAM auto-unlock
- SSH AddKeysToAgent timeout
- GPG agent cache TTL
- Plaintext secret files in home directories
- Firmware update status (fwupdmgr)
- Thunderbolt security level (DMA attack prevention)

### ✅ Added — New Features

- `--ai` flag: Generates AI-ready prompt with all findings for ChatGPT/Claude/Gemini
- `--json` flag: Machine-readable JSON output for scripts and dashboards
- `--skip` support for all new sections: browser, telemetry, netprivacy, dataprivacy, session, media, btprivacy, keyring
- Summary now shows "Security & Privacy Score" (not just "Security Score")

### 🔧 Changed

- Repositioned as "Privacy & Security Audit for Linux Desktops"
- Total sections: 34 → 42
- Total checks: 250+ → 300+
- README completely rewritten with new positioning
- 5 new helper functions for multi-user gsettings/Firefox profile iteration
- All desktop checks iterate over all human users (UID ≥ 1000)

### 🔧 Technical

- gsettings checks use proper DBUS_SESSION_BUS_ADDRESS
- bluetoothctl calls use timeout to prevent hangs
- Fedora 43 + Ubuntu 24.04 compatible
