# Changelog

All notable changes to NoID Privacy for Linux will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

- **IPv6 false positive on VPN interfaces**: Global unicast addresses on VPN tunnel interfaces (e.g. `2a07:b944::2:2` on `proton0`) were counted as "IPv6 active — leak risk". These addresses are internal to the WireGuard tunnel and not internet-facing. Script now skips addresses on VPN interfaces (`tun*`, `wg*`, `proton*`, `pvpn*`) when counting global IPv6.

- **Audit watch detection missed `-F path=` syntax**: Script only matched short-form watches (`-w /etc/passwd`) but not the equivalent long-form (`-a always,exit -F path=/etc/passwd`). Systems using syscall-based audit rules (standard on modern Fedora/RHEL) showed 5 false "Audit watch missing" warnings. Now matches `-w`, `-F path=`, and `-F dir=` syntax, including sub-path matches.

- **Faillock counted header lines as failed attempts**: `grep -c "^[a-zA-Z]"` matched username headers (`nexus:`) and table headers (`When  Type  Source`) — not actual failures. Systems with zero failed attempts showed "4 account(s) with failed login attempts". Now counts only actual failure entries (lines starting with `YYYY-MM-DD`).

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

- **IPv6 privacy extensions: false positive on VPN interfaces**: VPN killswitch interfaces (pvpnksintrf1) with internal ULA addresses triggered "IPv6 privacy extensions disabled" warning. VPN-internal interfaces are now skipped in the privacy check.

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

These fixes were identified by running NoID on a fully-hardened Fedora 43 workstation.
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

---

## [2.0.1] - 2026-02-13

### 🔨 Bugfix Release

### Fixed
- `VERSION` variable collision with `/etc/os-release` → renamed to `FORTIFY_VERSION`
- Subshell counter bug in pipe loops → process substitution
- nftables kill-switch parsing (3-field output)
- `--skip` without argument → clean error message
- Duplicate entropy section removed
- Section name mismatches fixed
- CPU vulnerability glob guard added
- Swap disabled detection
- RPM verify: config vs binary changes distinguished
- DNS leak false positive for systemd-resolved (127.0.0.53)
- PATH world-writable false positive for Fedora symlinks
- chkrootkit Linux.Xor.DDoS false positive filtered
- Cron directory 755 on Fedora recognized as normal

---

## [2.0.0] - 2026-02-13

### 🚀 Major Release — Full Security Audit

### Added
- AppArmor support (Debian/Ubuntu)
- NTS (Network Time Security) check
- USB Guard detection
- Compiler presence check
- AIDE/Tripwire detection
- Cron/At permission audit
- Swap encryption check
- History file permissions
- Login banner check
- Boot security analysis
- PATH security audit
- Entropy check
- 35 sections total, 250+ checks
- 2283 lines

### Changed
- Dual distro support: Fedora/RHEL + Debian/Ubuntu
- Comprehensive kernel hardening section
- Advanced network security checks
- Container and virtualization detection

---

## [1.2.0] - 2026-02-12

### 🎉 Initial Public Release

- 212+ checks across 30 sections
- Fedora/RHEL primary support
- Pure Bash, zero dependencies
- Basic reporting with PASS/FAIL/WARN/INFO

---

**NoID Privacy for Linux** — *Know your system. Harden your privacy.*
