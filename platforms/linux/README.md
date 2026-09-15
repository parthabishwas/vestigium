# Vestigium — Linux collector

Live-response evidence collection for Ubuntu 24.04 LTS (and other systemd-based
Debian derivatives). This is the Linux half of **Vestigium**: the same operating
model as the Windows collector — a modular collector, a hashed evidence tree, a
JSON manifest and a single archive — expressed in the artifacts that matter on
Linux.

Everything runs from Bash with standard system utilities. Helper tools are
staged into the kit itself by the setup step, so the collector is ready to run
on an evidence host that has no internet access.

## Entry points

Run everything from the kit root. `vestigium.sh` detects the platform and
forwards to `platforms/linux/vestigium-linux.sh`, which can also be run
directly:

```bash
sudo ./vestigium.sh --case-id IR-2026-014                          # primary
sudo ./platforms/linux/vestigium-linux.sh --case-id IR-2026-014    # equivalent
./vestigium.sh setup [options]                                     # stage the toolkit
./vestigium.sh verify output/<host>_<timestamp>.tar.zst            # check a package
```

## Root requirement

The collector must run as root and exits immediately otherwise.

**No account name is ever hardcoded.** The operator identity is resolved at
runtime (`SUDO_USER` → `logname` → `id -un`) and recorded in the manifest, and
every user-scoped artifact path is resolved through NSS (`getent passwd`), so
the tool behaves identically whichever administrator account performs the
collection — local, domain, LDAP or SSSD-backed.

## Preparing the kit

Run once on a staging workstation with internet access:

```bash
sudo ./vestigium.sh setup        # = platforms/linux/tools/setup-tools.sh
```

This will:

1. Resolve the full dependency closure of every helper tool the collector uses
   (yara, lsof, dmidecode, debsums, chkrootkit, ...), skipping only packages
   that every Ubuntu installation already has.
2. Download them into `platforms/linux/tools/deb/` — **regardless of what this
   workstation has installed**, so the kit is complete for a target host that
   has none of them. Downloads go to a private temporary directory first; the
   cache itself stays `root:root 755`, because it is later unpacked (and, with
   `--install`, installed) as root.
3. Unpack them into `tools/portable/` (setuid/setgid bits stripped) and
   generate wrappers in `tools/bin/`, so the collector uses kit-local copies
   **without installing anything on the host under investigation**.
4. Download the AVML static memory-acquisition binary into `tools/bin/avml`
   and log its SHA256. Pin a release with `AVML_SHA256=<hash>` (a mismatch is
   rejected); override the source with `AVML_URL`.
5. Clone the YARA rule repositories into the **shared** rules directory
   `shared/yara-rules/` (used by both platforms) and build `active-rules.yar`
   plus a pre-compiled `active-rules.compiled`. The build fails loudly when the
   final bundle does not compile, and a stale compiled bundle is never kept.
6. Write `tools/TOOLS.md` recording every tool, version, commit and SHA256.

Then copy the whole kit to removable media. On the evidence host:

```bash
sudo ./vestigium.sh setup --offline --verify    # confirm readiness, change nothing
sudo ./vestigium.sh --case-id IR-2026-014 --verbose
```

Setup options:

| Option | Effect |
|---|---|
| `--install` | Also install the staged packages system-wide (modifies the host) |
| `--offline` | No network: use `tools/deb/` and the rules already present |
| `--skip-apt` | Do not fetch or unpack Debian packages |
| `--no-yara-rules` | Do not clone or rebuild the rule bundle |
| `--no-avml` | Do not download AVML |
| `--with-clamav` | Also stage ClamAV (large: engine plus signatures) |
| `--no-rootkit` | Do not stage chkrootkit / rkhunter / unhide |
| `--only-missing` | Stage only what this workstation lacks (smaller kit, not portable) |
| `--regen-wrappers` | Offline: rebuild `tools/bin` wrappers from `tools/portable` and rewrite `TOOLS.md` |
| `--verify` | Report readiness only |

The rules location can be overridden with `VESTIGIUM_RULES_DIR`.

Every staged tool gets a wrapper in `tools/bin/`, and the wrapper prefers the
host's own copy at run time — the kit binary is used only on a machine that
does not provide that tool, so system binaries are never shadowed. Tools that
must be patched at run time (chkrootkit, rkhunter) are rewritten into a private
`mktemp` directory, never a predictable path in `/tmp`.

If a collection warns that `yara` (or any other tool) is unavailable, the kit
was staged with `--only-missing` or without network access. Re-stage it with
`sudo ./vestigium.sh setup`; nothing needs to be downloaded or copied by hand.

## Running a collection

No option is mandatory — a bare run performs a full collection:

```bash
sudo ./vestigium.sh
sudo ./vestigium.sh --case-id IR-2026-014 --verbose
```

If `--case-id` is omitted, one is generated as `AUTO-<hostname>-<timestamp>`
and the manifest records that it was auto-generated. At start-up the collector
reports any helper tool it cannot find, so you know up front which artifacts
will be missing.

Investigating one specific profile from any admin account:

```bash
sudo ./vestigium.sh --case-id IR-2026-014 --target-user j.doe
sudo ./vestigium.sh --case-id IR-2026-014 --target-user 1001
sudo ./vestigium.sh --case-id IR-2026-014 --target-user /home/j.doe
```

`--target-user` accepts a username, a UID or a home-directory path, and may be
repeated. Without it, the collector examines root plus every account with UID
1000–64999 that has a real home directory.

Triage and tuning:

```bash
sudo ./vestigium.sh --quick                    # fast triage, no bulk copies
sudo ./vestigium.sh --skip-yara                # skip scanning entirely
sudo ./vestigium.sh --yara-quick               # scan high-signal paths only
sudo ./vestigium.sh --yara-threads 4           # YARA scanner threads (default 2)
sudo ./vestigium.sh --max-journal-mb 4096      # cap for copying /var/log/journal
sudo ./vestigium.sh --modules Processes,Network,Browser
sudo ./vestigium.sh --no-browser-history       # omit history/bookmarks
sudo ./vestigium.sh --browser-sessions         # also copy browser session stores
sudo ./vestigium.sh --memory                   # capture physical RAM (AVML) first
sudo ./vestigium.sh --rootkit-scan             # run chkrootkit / rkhunter
sudo ./vestigium.sh --trusted-tools            # force kit binaries; cross-check the host
sudo ./vestigium.sh --list-modules
```

Full option list: `./vestigium.sh --help`. Modules run volatile-first
(System, Processes, Network, Persistence, ...); with `--memory` the memory
image is taken before anything else.

Output is written to `output/<hostname>_<YYYYmmdd_HHMMSS>/` under the kit root
(or `--output DIR`) and archived to `<hostname>_<YYYYmmdd_HHMMSS>.tar.zst` (or
`.tar.gz` when zstd is unavailable), together with a `.sha256` sidecar.

A physical memory image captured with `--memory` is deliberately **left out of
the archive** — it is already compressed, usually several GB, and normally
transferred on its own. It stays at `17_Memory/memory.avml` with its own
`.sha256`, and the archive is accompanied by a `.memory-image-location.txt`
note pointing at it.

### Interrupting a collection

- **Ctrl+C once** stops collecting and **finalises** what was gathered: hashes,
  manifest (`collection.status: "interrupted"`) and archive, which is named
  `<hostname>_<timestamp>_INCOMPLETE.tar.*`; `19_CollectionLogs/INCOMPLETE.txt`
  records the interruption.
- **Ctrl+C twice** aborts immediately without finalising.

## Folder structure

```text
Vestigium/
  vestigium.sh / .ps1 / .cmd   unified entry points
  VERSION
  shared/
    verify-evidence.sh          integrity check + triage overview for a package
    yara-rules/                 sources.conf, exclusions.conf, custom/, rules.lock
                                (versioned); signature-base/ (incl. iocs/), rules/,
                                active-rules.yar, active-rules.compiled,
                                rule-build-report.csv (generated)
  platforms/linux/
    vestigium-linux.sh         collector
    modules/
      00-lib.sh                 framework: logging, provenance, hashing, manifest
      10-system.sh       20-processes.sh   30-persistence.sh  35-startup.sh
      40-config.sh       45-scheduled.sh   50-services.sh     55-network.sh
      60-browser.sh      65-logs.sh        70-security.sh     75-packages.sh
      80-users.sh        85-filesystem.sh  90-containers.sh   93-memory.sh
      95-yara.sh         97-ioc.sh
    tools/
      setup-tools.sh            toolkit bootstrap
      build-yara-rules.py       compile-validated rule bundle builder
      browser-json.py           extension inventory / preference parsing
      ioc-match.py              signature-base IOC cross-reference
      make-manifest.py          JSON manifest writer
      bin/                      kit-local binaries and wrappers (incl. avml)
      deb/                      cached .deb packages for offline deployment
      portable/                 unpacked package contents
  platforms/windows/            Windows collector
  output/                       default evidence base
```

Each run creates this evidence tree:

```text
01_System           09_Browser         17_Memory
02_Processes        10_Logs            18_Yara
03_Persistence      11_Hosts           19_CollectionLogs
04_Startup          12_Security        20_Hashes
05_Config           13_SystemInfo      21_Manifest
06_ScheduledTasks   14_Users
07_Services         15_Filesystem
08_Network          16_Containers
```

## Collected artifacts

**01_System** — hostname, machine-id, boot-id, OS release, kernel, uptime,
timezone and NTP sync state, virtualisation, DMI data (vendor, model, serials,
BIOS, chassis), CPU/RAM, disks and partitions, PCI/USB inventory, UEFI and
Secure Boot state, boot history. `AssetInfo.txt` is the one-page asset summary.

**02_Processes** — `ps` full and wide views, process tree, `top`, namespaces,
IPC, kernel ring buffer, and a `/proc` walk producing `process_details.csv`
(PID, PPID, user, **start time in UTC from `/proc/PID/stat`**, state, executable
path, **SHA256 of the running binary**, owning package, command line). Anomaly
views: processes executing deleted binaries, execution from `/tmp` `/var/tmp`
`/dev/shm` `/home`, memfd and anonymous executable mappings,
`LD_PRELOAD`-injected processes, orphans. Open files and sockets via `lsof`,
including deleted-but-open files.

**03_Persistence** — the Linux equivalent of the Windows Run-key/Autoruns sweep:
systemd units, timers, sockets, generators and drop-ins (with copies of
everything under `/etc/systemd`), units and udev rules **not owned by any
package**, suspicious `ExecStart` lines, cron in every form, SysV init and
`rc.local`, system shell profiles, `/etc/ld.so.preload` and loader
configuration, PAM and NSS (including unpackaged PAM modules), kernel modules
(unsigned/out-of-tree detection, taint decoding), APT hooks, XDG autostart,
polkit and D-Bus. `SUMMARY.txt` rolls up the high-signal findings.

**04_Startup** — per-profile session startup: shell rc and login files, XDG
autostart entries, user systemd units and timers, per-user crontabs, desktop
environment autostart, GNOME Shell extensions, flatpak overrides.

**05_Config** — account and authorisation databases, sudoers (with a NOPASSWD
review), SSH server configuration and host key fingerprints, `sysctl -a` plus a
security-tunable review, fstab/crypttab/GRUB defaults, APT sources, preferences
and signing keys, **trusted CA review** (locally added and unpackaged
certificates — the TLS-interception indicator), and browser/system policy files.

**06_ScheduledTasks** — systemd timers with the units they trigger, all cron
sources including every user's crontab, anacron and the `at` queue, plus a
filtered view of jobs referencing interpreters, downloads or temp paths.

**07_Services** — all/running/failed units, unit files, boot performance,
`services_inventory.csv` (unit, states, main PID, user, ExecStart, fragment
path, owning package) and the full definition of every loaded unit including
drop-ins.

**08_Network** — addressing, routes (all tables), neighbours, sockets with
owning processes, `listening_sockets.csv` (port → PID → binary → **SHA256** →
package) and `established_connections.csv` (`PeerHost` is intentionally empty:
**no DNS lookups** are made from the evidence host), iptables/nftables/ufw
rulesets, NetworkManager devices and profiles (**secrets redacted**), netplan,
wpa_supplicant, WireGuard/OpenVPN, proxy configuration (system, per-user GNOME,
snap), NFS/RPC/SMB exposure, promiscuous-interface detection.

**09_Browser** — Chrome, Chromium, Edge, Brave, Opera, Vivaldi, Firefox and
Thunderbird, across native, **snap and flatpak** paths, for every profile of
every user:

- `extensions_inventory.csv` — browser, user, profile, extension ID, version,
  name, description, permissions, host permissions, update URL, signing state,
  install date;
- copies of every extension `manifest.json`, Firefox `extensions.json`,
  add-on packages and unpacked extension directories;
- `Preferences` / `Secure Preferences` plus a parsed highlights view: bound
  accounts, startup URLs, homepage, default search provider, proxy mode,
  download directory, Safe Browsing state, per-extension install location;
- Firefox `prefs.js` highlights, `user.js`, policies, `cert9.db`;
- **native messaging hosts** — the browser-to-local-binary bridge used by
  infostealers;
- **credential stores** (`Login Data`, `Cookies`/`Network/Cookies`, `Web Data`,
  `logins.json`, `key4.db`, `cookies.sqlite`, ...) and the raw `Local State`,
  copied into `credential-stores/` by default. `--credential-stores metadata`
  records metadata only;
- a readable `Local State` with the credential-decryption keys
  (`encrypted_key`, `app_bound_encrypted_key`) redacted;
- `credential_store_metadata.txt` and `session_store_metadata.txt` —
  size, timestamps and SHA256 of credential and session stores (see below);
- `SUMMARY.txt` stating the history and session-collection settings and
  flagging extensions with high-risk permissions (`<all_urls>`, `webRequest`,
  `cookies`, `nativeMessaging`, `debugger`, `proxy`, `clipboardRead`,
  `management`, capture APIs) and extensions not installed from an official
  store.

**10_Logs** — journal boots, integrity verification, current-boot and 30-day
text exports, error-priority and kernel views, per-unit exports for ssh, sudo,
cron, logind, display managers, polkit, AppArmor, auditd, snapd, PackageKit,
unattended-upgrades and NetworkManager, a 7-day JSON export, and (in full mode,
capped by `--max-journal-mb`) the native `/var/log/journal` tree. Copies of
`auth.log`, `syslog`, `kern.log`, `dpkg.log`, `apt/`, `ufw.log`, installer logs
and more; `wtmp`, `btmp`, `lastlog` and `utmp` with decoded
`last`/`lastb`/`lastlog`/`utmpdump` views; an authentication-event extract
(sudo, su, SSH accepted and failed, account and group changes); auditd reports
when auditd is installed; and log-tampering indicators (zero-length logs, logs
older than last boot; timestamps in UTC). Records **systemd journal
Forward Secure Sealing (FSS)** status in `journal/journal_sealing.txt`; a
journal with no seal (`journal_fss=disabled`) is flagged, since a sealed
journal would detect after-the-fact tampering.

**11_Hosts** — `/etc/hosts`, `hosts.allow`/`hosts.deny`, `resolv.conf`,
systemd-resolved status and statistics, and a review of non-default host entries.

**12_Security** — AppArmor status, profiles, local overrides, complain-mode
profiles and kernel denials; SELinux status where present; ufw and fail2ban;
auditd rules and status; **integrity verification** via `dpkg --verify` and
`debsums`, unpackaged system binaries, immutable-attribute files; installed
security products; ClamAV, Microsoft Defender for Endpoint and CrowdStrike
sensor state when deployed; recent security-agent logs; and chkrootkit /
rkhunter / unhide output with `--rootkit-scan`. `antirootkit/` holds the
host-vs-kernel cross-checks (see **AntiRootkit** below).

**12_Security/antirootkit** (module **AntiRootkit**, runs every collection) —
host-vs-kernel cross-checks that do not trust the host's tools: processes in
`/proc` hidden from `ps`, live modules in `/sys/module` / `/proc/modules`
hidden from `lsmod` (also cross-referenced against `/proc/kallsyms` symbol
tags, as review context rather than an auto-flag to avoid built-in-subsystem
noise), listening sockets in `/proc/net` hidden from `ss`/`netstat`,
and directory link-count / `ls`-vs-busybox-vs-glob mismatches. `discrepancies.txt`
lists each hit; they become `critical`/`high` findings. `--trusted-tools`
additionally forces the kit's own binaries and records the trust basis in
`tool-provenance.csv`. See [../../docs/TRUSTED-MODE.md](../../docs/TRUSTED-MODE.md).

**13_SystemInfo** — full package inventory (`installed_packages.csv`), manual
and held packages, apt policy, the **install timeline** from `dpkg.log` and apt
history, packages installed in the last 30 days, snap, flatpak, AppImages,
pip/npm/gem including per-user pip, kernel and module inventory, hardware
drivers, environment and limits, plus a `systeminfo`-style overview that
highlights third-party repositories.

**14_Users** — passwd/group/shadow databases and an account analysis (UID 0
accounts, interactive shells, empty passwords, hash algorithms, locked accounts,
administrative group membership, password aging, duplicate UIDs); per profile:
shell and application histories, SSH keys (public keys and `authorized_keys`
collected, private key material recorded as fingerprint and metadata only),
credential-location inventory (`.aws`, `.config/gcloud`, `.kube`, `.docker`,
`.netrc`, `.git-credentials`, keyrings, password managers — **metadata only**),
recently-used files, Trash contents, Downloads/Desktop listings, **SHA256 of
everything in Downloads**, hidden entries, and detection of history files
symlinked to `/dev/null`. When an interactive shell has its history disabled
(HISTFILE unset or pointed at `/dev/null`), `live-shell-history/` **carves
recent commands from the running shell's memory** - covering tty-less reverse
shells too - and flags each such session (`recover-shell-history.py`).

**15_Filesystem** — mounts and filesystem layout; SUID/SGID inventory and the
unpackaged subset with hashes, world-writable and unowned files, and file
capabilities — all taken from **every local on-disk filesystem** (separate
`/home`, `/var`, `/tmp`, `/opt` partitions included) in a single pass that
excludes the evidence output and the Vestigium kit; listings of `/tmp`
`/var/tmp` `/dev/shm` `/run/user` `/opt` `/usr/local` `/srv` `/var/www`,
executables in temporary directories (with type and hash) and copies of the
small ones, 30-day modification and ctime timelines for system paths and home
directories, a full MAC timeline CSV (UTC) in full mode, deleted-but-open
files, and ext filesystem superblock data. Extended attributes are collected from home,
temp and opt paths (`extended_attributes.txt`), with `user.*` attributes - an
uncommon data-hiding technique - listed separately in `extended_attributes_user.txt`.

**16_Containers** — Docker (containers, images, volumes, networks, full
inspect, per-container processes and logs, daemon config, **socket exposure and
privileged containers**), Podman, LXD, Kubernetes contexts, libvirt,
VirtualBox, systemd machines, namespaces and container cgroup membership. Records
**writable-layer drift** for running Docker/Podman containers (`docker diff` /
`podman diff` in `*/container_diffs.txt`); changes under system paths
(`/bin`, `/etc`, `/usr`, ...) are flagged as possible in-container tampering.

**17_Memory** — always: memory summary, slab, vmstat, iomem, swap, per-process
memory, kernel symbol exposure and kernel integrity indicators. With
`--memory`: a full physical memory image via AVML, with a free-space
pre-check, SHA256, and notes on converting it for Volatility 3.

**18_Yara** — YARA scanning of user homes and system paths (or high-signal paths
only with `--yara-quick`), run at low CPU and IO priority with per-target
timeouts and `--yara-threads` scanner threads, plus opt-in process-memory
scanning (`--yara-procs`, capped at 200 processes). Scanning works from an
explicit, de-duplicated target list (nested targets removed) and never scans
the evidence tree, **the Vestigium kit itself**, pseudo-filesystems or
oversized files; when the kit sits inside a scan target this is logged and
noted in `yara_matches.txt`. The pre-compiled bundle is used only when it loads
with the yara actually in use and is newer than `active-rules.yar`; otherwise
the source bundle is used and the reason logged. `ioc-matches/`
cross-references collected hashes, paths, globally routable IPv4/IPv6 addresses
and hostnames against the `signature-base` hash, filename and C2 IOC lists —
entirely offline.

**19_CollectionLogs** — `collection.log` (every step, warning and error),
`command-log.csv` (every command with exit code, duration and output file),
`provenance.csv` (**source path, original mtime/atime/ctime, mode, owner and
source SHA256 for every acquired file**), `module-results.csv`,
`target-users.tsv`, `tool-provenance.csv` (**which binary - kit or host - and
SHA256 produced the evidence**), `run-parameters.txt`, and `INCOMPLETE.txt`
after an interrupted run.

**20_Hashes** — `SHA256SUMS.txt` (verifiable with `sha256sum -c`) and
`SHA256SUMS.csv` for every file in the evidence tree.

**21_Manifest** — `manifest.json` (schema `vestigium/linux-manifest/1`: case,
collector, operator, invocation, completion status, toolkit root and rule-set
hash, host identity, timings, module results, failed commands, acquired-file
provenance and the full hash inventory) and `summary.txt` for the case file.

## Credential stores and data handling

Like the Windows collector, the Linux collector **copies browser credential
stores by default**. That means saved passwords, cookies, autofill and payment
data (`Login Data`, `Cookies` / `Network/Cookies`, `Trust Tokens`, `Web Data`,
`logins.json`, `key4.db`, `cookies.sqlite` and friends), plus the raw Chromium
`Local State`.

They land in `09_Browser/<user>/<browser>/<profile>/credential-stores/`, with
provenance and SHA256. Their size, timestamps and SHA256 are also listed in
`credential_store_metadata.txt`.

A default package therefore contains **live credential material**:

- Firefox logins decrypt offline without a Primary Password.
- Firefox cookies are stored in plaintext.
- Chromium `v10` values (no keyring) use a fixed key.

Use `--credential-stores metadata` when engagement rules forbid handling
credentials. See [docs/DATA-HANDLING.md](../../docs/DATA-HANDLING.md).

What is deliberately **not** collected:

- browser **session stores** — Chromium `Current Session`, `Current Tabs`,
  `Last Session`, `Last Tabs` and `Sessions/`, Firefox `sessionstore.jsonlz4`
  and `sessionstore-backups/` — embed session cookies and form data, so by
  default they are **metadata only** too. `--browser-sessions` copies them into
  `*/sessions/` when open tabs matter to the case; `SUMMARY.txt` and the
  manifest record which way the run went. Treat such a package as credential
  material;
- private SSH key material — fingerprint and metadata only;
- GNOME keyring and password-store contents — presence and metadata only;
- Wi-Fi PSKs and VPN secrets in NetworkManager profiles — redacted in place.

Browsing history, downloads and bookmarks **are** collected by default, since
they carry no credentials and are central to most investigations. Suppress them
with `--no-browser-history` when engagement rules require it.

`/etc/shadow` and `/etc/gshadow` **are** collected, because account tampering is
in scope. The evidence directory is created mode 700 and the archive mode 600.
If your engagement rules forbid handling password hashes, remove those two
entries from `modules/40-config.sh` before running.

## Triage starting points

| Question | Where to look |
|---|---|
| Which accounts were signed into the browsers? | `09_Browser/*/*/*/preferences_highlights.txt`, `09_Browser/*/*/Local_State.redacted.json` |
| Was a malicious or sideloaded extension installed? | `09_Browser/extensions_inventory.csv`, `09_Browser/SUMMARY.txt` |
| Did an extension talk to a local binary? | `09_Browser/*/native-messaging/` |
| Were credential or session stores read or modified? | `09_Browser/*/*/*/credential_store_metadata.txt`, `session_store_metadata.txt` |
| Was traffic being intercepted? | `05_Config/trusted_ca_review.txt`, `08_Network/proxy_configuration.txt`, browser proxy keys |
| What ran, from where, and since when? | `02_Processes/process_details.csv`, `02_Processes/anomaly_*.txt` |
| What persists across reboot? | `03_Persistence/SUMMARY.txt`, `04_Startup/SUMMARY.txt` |
| What connected out, and which binary owned it? | `08_Network/established_connections.csv`, `08_Network/listening_sockets.csv` |
| What arrived on the machine? | `14_Users/profiles/*/downloads_hashes.txt`, `14_Users/profiles/*/listing_Downloads.txt` |
| Who logged in, when, and how? | `10_Logs/logins/`, `10_Logs/SUMMARY.txt` |
| Were system files tampered with? | `12_Security/integrity/`, `15_Filesystem/suid_unpackaged.txt` |
| Do any artifacts match known-bad indicators? | `18_Yara/SUMMARY.txt`, `18_Yara/ioc-matches/ioc_matches.txt` |

## Forensic notes

- This is **live-response collection on a running system**. Volatile state
  reflects the moment of acquisition and cannot be reproduced exactly. Where a
  full disk image is required, image the disk separately.
- Reading files updates access times on filesystems with atime semantics
  (Ubuntu mounts `relatime` by default). Original timestamps are captured in
  `provenance.csv` **before** each copy; copies keep their timestamps, are
  never setuid/setgid, and symlinks are copied as links.
- Running the collector loads its own process, writes to the output directory
  and touches the journal. Prefer running the kit from, and writing evidence
  to, removable media (`--output /media/evidence`) so the system disk is
  modified as little as possible — and so the kit never sits inside a YARA
  scan target.
- The collector makes no DNS lookups and sends nothing over the network.
- Installing packages on the evidence host modifies it. The default setup mode
  avoids this by unpacking tools into the kit; use `--install` only when you
  have accepted that trade-off.
- Every module is isolated: a failure in one is logged and recorded in
  `module-results.csv`, and collection continues.

## Verifying an evidence package

`./vestigium.sh verify` (`shared/verify-evidence.sh`) checks the archive hash,
re-verifies every file against the recorded SHA256 inventory, prints the
manifest and module results, and summarises the high-signal findings:

```bash
./vestigium.sh verify output/<hostname>_<timestamp>.tar.zst   # archive
./vestigium.sh verify output/<hostname>_<timestamp>           # extracted tree
```

Manually, the same checks are:

```bash
sha256sum -c <hostname>_<timestamp>.tar.zst.sha256
tar -xf <hostname>_<timestamp>.tar.zst
cd <hostname>_<timestamp>
sha256sum -c 20_Hashes/SHA256SUMS.txt
jq '.collection.status, (.collection.modules[] | select(.Status != "OK"))' 21_Manifest/manifest.json
```

## Supported platforms

- Ubuntu 24.04 LTS (primary target), 22.04 LTS
- Debian 12 and other systemd-based derivatives (best effort)
- Bash 4.4+, coreutils, systemd; Python 3 for the inventory, manifest, IOC and
  rule-builder helpers

No third-party Python packages are required. Every module degrades gracefully
when an optional tool is missing: the gap is logged and collection continues.

## Licensing

The YARA rule repositories cloned by setup (`Neo23x0/signature-base`,
`Yara-Rules/rules`) are licensed separately by their authors; each clone
contains its own licence file. Review them before redistributing this kit
inside an enterprise. AVML is published by Microsoft under the MIT licence.
