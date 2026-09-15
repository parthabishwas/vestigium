# Changelog

## 2.0.0 - 2026-09-11 - Vestigium

The Ubuntu DFIR collector (Bash, 1.0.0) and DFIRCollector (PowerShell, v1.1)
are merged into one project, **Vestigium**, with a shared entry point, a
shared YARA rule store and a shared verification toolchain. The history of
the Windows collector up to v1.1 is kept in [docs/history](docs/history/).

### Name and publication

- **Name.** *Vestigium* is Latin for footprint or trace, and the root of
  *investigate*. It was chosen after checking GitHub for collisions: the
  working name CrossTrace, and the Vestigo alternative, are both existing
  projects there.
- **Licence and policies.** Released under the MIT licence, with
  `SECURITY.md` (private vulnerability reporting) and `CONTRIBUTING.md`.
- **CI.** Offline tests, plus real collection and verification smoke tests on
  Ubuntu and on Windows PowerShell 5.1 runners. A weekly workflow refreshes
  the YARA rules and proposes the change as a pull request.
- **Redaction.** Engagement identifiers (endpoint user names and the admin
  account) were redacted from `docs/history`. The unredacted originals are
  kept outside the repository.
- **Third-party content.** The YARA rule repositories (DRL 1.1, GPL-2.0), the
  built bundles and the staged binaries are git-ignored and rebuilt by
  `setup`. They are never redistributed from this repository.

### YARA rule maintenance

Both the Linux (`setup-tools.sh` + `build-yara-rules.py`) and the Windows
(`Update-YaraRules.ps1`) builders now support the following, all in
`shared/yara-rules/`:

- **`sources.conf`** declares the rule repositories: name, URL and optional
  ref. Every value is validated before git runs.
- **`custom/`** holds in-house rules. They are included first and win
  identifier clashes.
- **`exclusions.conf`** takes two directives. `file:<glob>` drops whole files.
  `rule:<name>` silences a rule by making it `private`, so rules that depend on
  it keep working. The noisy capability rules are listed there as commented-out
  suggestions.
- **`rules.lock`** records the upstream commits, the rule count and the bundle
  SHA256. It is rewritten only when something meaningful changes.

New commands:

- `setup --rules-only` tracks the latest upstream commits.
- `setup --rules-locked` (Windows: `-Locked`) rebuilds exactly the locked
  commits and reports whether the bundle matches the lock.
- `--fp-corpus DIR` scans a known-clean directory and writes
  `rule-fp-report.txt`.
- `setup --verify` now shows the sources, the lock status and the bundle's age.

Build behaviour:

- Builds are atomic: the old bundle is replaced only by one that compiles.
- Builds are deterministic: no timestamps, and relative paths in the bundle.
- Exit codes: 0 built, 1 build failed, 2 configuration error.

Automation and docs:

- The weekly `.github/workflows/yara-rules.yml` rebuilds and validates the
  bundle, runs a false-positive check, and opens a pull request when
  `rules.lock` changes. The bundle itself is never committed.
- The full lifecycle is in [docs/YARA-RULES.md](docs/YARA-RULES.md).
- Linux source order now follows `sources.conf` (signature-base first, like
  the Windows builder). As a result, Yara-Rules' `crypto_signatures.yar` is
  dropped, because its rule names clash with signature-base. That also removes
  most crypto-constant false positives.

### Project structure

- New layout: `platforms/linux`, `platforms/windows`, `shared/`, `docs/`,
  `tests/`, `output/`. Every file was moved, and none was deleted. Kit binaries,
  the offline package cache and the cloned rule repositories are unchanged.
- The two earlier Linux collections moved from `Ubuntu_DFIR_Script/output/`
  to `output/`. They were moved, not modified: their content digest was
  checked before and after.
- `VERSION` is the single version source for both collectors, the launchers
  and the manifests.
- One rule store, `shared/yara-rules/`, is used by both platforms. The Windows
  collector still reads the legacy `Tools\YaraRules\` when the shared store is
  absent.
- Renamed: `dfir-collect.sh` became `platforms/linux/vestigium-linux.sh`,
  `DFIRCollector.ps1` became `platforms/windows/vestigium-windows.ps1`, and
  `verify-evidence.sh` became `shared/verify-evidence.sh`. Internal function
  names (`dfir_*`, `*-DFIR*`) are unchanged. The Windows YARA and memory code
  now lives in `Modules/Yara.ps1` and `Modules/Memory.ps1`.

### Unified entry point

- `vestigium.sh` (POSIX sh; also works when invoked through a symlink),
  `vestigium.ps1` (PowerShell 5.1/7) and `vestigium.cmd` (cmd.exe/Explorer).
  Each detects the platform: Linux, WSL, Git Bash/MSYS2/Cygwin, Windows or
  macOS.
- Commands `collect`, `verify`, `setup`, `info`, `version`, `help`, plus
  `--platform` and `--dry-run`.
- One option vocabulary with both spellings accepted (`--case-id` /
  `-CaseId`, ...). Options are translated per collector and anything else is
  passed through by name. Mistyped commands and stray words are rejected
  before anything is elevated or collected.
- The Linux launcher re-executes through `sudo` when needed (`--no-elevate`
  disables this). The PowerShell launcher can relaunch elevated (`-Elevate`),
  making relative paths absolute first.
- `vestigium.cmd` pauses only when double-clicked (never under remote shells
  or schedulers; `CT_NOPAUSE=1` disables it entirely).

### Findings report (both platforms)

- The report UI was rebuilt for a modern, professional look: a sticky header
  with a derived risk banner (highest severity present), an executive summary
  line, an SVG severity donut with a clickable legend, a category breakdown
  bar chart coloured by worst severity, a collection-metadata card, and
  severity filter chips alongside the text search. Finding cards gained count
  badges, evidence shown as monospace chips, and a callout style for caveats.
  Still a single self-contained offline file, same JSON schema and safe
  embedding contract, dark-mode and print styles, and the same template token.

- Every collection now writes a **unified findings report** at the evidence
  root: `findings.json` (schema `vestigium/findings/1`) and a self-contained,
  offline `findings.html`. Both platforms feed one shared report UI
  (`shared/report/findings-template.html`), so a package reads the same way
  whichever produced it.
- Findings are severity-ranked triage leads (critical to info), each linked to
  the raw artifact, with collection gaps that weaken negative conclusions.
- Produced during finalisation before hashing, so both files are covered by
  the SHA256 inventory. `vestigium verify` prints the critical and high
  findings for either platform's package.
- Schema and rendering are documented in [docs/FINDINGS-SCHEMA.md](docs/FINDINGS-SCHEMA.md).

### Trusted-binary mode and anti-rootkit (Linux)

- **`--trusted-tools`** forces the kit's own staged binaries instead of the
  host's (whose `ps`, `ss`, `ls`, `netstat`, `lsmod` may be trojaned) by making
  the kit wrappers skip their host-preference. A static **busybox** is staged
  by `setup` as an independent second opinion.
- **`tool-provenance.csv`** (every run) records, for each investigative and
  core tool, whether it resolved to the `kit` or the `host` and its SHA256 -
  documenting exactly which binaries produced the evidence. Trusted mode warns
  about any investigative tool that still fell back to the host.
- New **AntiRootkit** module (runs on every collection, `12_Security/antirootkit/`)
  reads process, module, listening-port and directory truth straight from
  `/proc` and `/sys` with bash and diffs it against `ps`/`lsmod`/`ss`/`netstat`/`ls`
  (and busybox). Hidden processes and modules are `critical` findings, hidden
  ports and directory link mismatches `high`, listing disagreements `medium`.
- Documented in [docs/TRUSTED-MODE.md](docs/TRUSTED-MODE.md). Honest limits:
  base-system utilities cannot be shipped and still run from the host (recorded
  as such), and no live-host check defeats a consistent kernel-mode rootkit -
  capture memory and image the disk for that.

### Deeper artifact coverage

**Windows** (new `Forensics` step; see [docs/WINDOWS-ARTIFACTS.md](docs/WINDOWS-ARTIFACTS.md)):
- `$MFT`, `$LogFile` and the USN journal acquired through a Volume Shadow Copy
  (with a live `fsutil usn readjournal` fallback) into `21_FileSystem/` for
  offline deleted-file timelining.
- `NTUSER.DAT` / `UsrClass.dat` (with transaction logs) copied from the shadow
  copy into `05_Registry/Hives_VSS/` - no `reg load`, so ShellBags, UserAssist
  and RecentDocs are recoverable offline.
- LNK shortcuts and Jump Lists (`17_Execution/UserArtifacts/`), `$Recycle.Bin`
  `$I` metadata (`21_FileSystem/RecycleBin/`), Defender MPLog
  (`12_Defender/MPLog/`) and the w32tm clock offset (`01_System/ClockOffset.txt`).
- The 'no MFT/USN' triage gap now reflects whether acquisition actually
  succeeded.
- `-ScanDrives D:,E:` extends the YARA scan and NTFS-metadata acquisition
  ($MFT, $LogFile, USN journal via `esentutl /vss`) to non-system volumes,
  written to `21_FileSystem\<letter>\`. **This module is unvalidated on real Windows** (no Windows CI) -
  the doc carries a validation checklist.

**Linux:**
- systemd journal Forward Secure Sealing status (`10_Logs/journal/journal_sealing.txt`);
  an unsealed journal is flagged (`linux.integrity.journal_unsealed`).
- Container writable-layer drift via `docker diff` / `podman diff`
  (`16_Containers/*/container_diffs.txt`); drift under system paths is flagged
  (`linux.integrity.container_drift`).
- In-memory shell-history recovery for interactive shells (including tty-less
  reverse shells) whose on-disk history is disabled
  (`14_Users/live-shell-history/`, `recover-shell-history.py`); flagged as
  `linux.account.history_disabled`.
- Anti-rootkit hidden-module detection also consults `/proc/kallsyms` symbol
  tags (as review context, not an auto-flag, to avoid built-in-subsystem noise).

### Verification

- `shared/verify-evidence.sh` and the new `shared/Verify-Evidence.ps1` both
  verify **Linux and Windows** packages: folders, `.tar.zst`/`.tar.gz` and
  `.zip`. Each checks:
  - the archive sidecar
  - every recorded hash
  - missing and unrecorded files
  - memory-image sidecars

  Each also prints the collection summary and module results.
- An empty or malformed hash inventory is reported as a failure.
- Archive extraction refuses path-traversal entries and drops ownership and
  special mode bits.
- The YARA match counter no longer counts the report's header lines as
  matches.
- Windows packages made before 2.0 hashed `Collection.log` while it was still
  being written. That file is reported as expected drift, not tampering.

### Linux collector

Correctness and forensic fixes:

- **Interrupted runs are finalised.** The two preserved collections were
  Ctrl+C'd runs left without hashes or a manifest. Modules now run in a
  supervised subshell. The first SIGINT/SIGTERM/SIGHUP terminates the running
  module's whole process tree, records it `INTERRUPTED` and the rest `NOT RUN`,
  writes `INCOMPLETE.txt`, and still hashes, writes the manifest (status
  `interrupted`) and archives (`*_INCOMPLETE.tar.*`). Exit 130/143/129. A
  second signal aborts immediately.
- **Process start times were wrong.** `process_details.csv` used the mtime of
  `/proc/<pid>`, which is when procfs created the inode. It now computes the
  start time from `/proc/<pid>/stat` and the boot time, in UTC.
- **Filesystem sweeps missed separate partitions.** SUID/SGID, world-writable,
  unowned and file-capability sweeps used `find / -xdev`, which covers only the
  root filesystem. They now walk every local on-disk mount, so separate
  `/home`, `/var`, `/tmp` or `/opt` partitions are included. `getcap -r /` no
  longer descends into `/proc` and `/sys`.
- **YARA scanned its own kit.** The kit's rule sources and IOC lists were
  scanned whenever the kit sat under a scanned path such as `/root`, which
  produced thousands of false positives. The kit and the output folder are now
  excluded, and a warning is logged.
- **Stale or incompatible compiled YARA rules produced silently empty scans.**
  A compiled bundle built by a different libyara version made every scan fail.
  The compiled bundle is now probed and used only when it loads and is newer
  than the source bundle.
- **`established_connections.csv` columns were shifted.** The local address
  column held the peer. The parser is fixed.
- **Timestamps labelled UTC were local time**:
  - in `provenance.csv` and `SHA256SUMS.csv`
  - in the MAC timeline
  - in the log-tampering report
- **False "UNPACKAGED" findings on merged-/usr systems:** some packages list
  `/bin/...` paths while candidates were canonicalised to `/usr/bin/...`.
- **Numeric options are validated** before they reach bash arithmetic. A value
  such as `a[$(cmd)]` was previously executed as root.
- **Symlinks are evidence.** Dangling links were reported as "not present",
  and tree copies skipped every link (for example `/etc/cron.d/x -> /tmp/evil`).
  Links are now copied as links, with their target recorded.
- Two runs in the same second no longer share an evidence directory.
- Module selection is case-insensitive, runs in registry order and rejects an
  all-unknown selection. The invocation is recorded shell-quoted.

Security fixes:

- **Copied setuid/setgid binaries are neutralised.** `cp --preserve=all` carried
  setuid-root bits into the evidence tree, and onto the analyst's machine after
  extraction. The copy's s-bits are stripped. The original mode stays in
  `provenance.csv`.
- **Browser session stores are no longer collected by default.** Firefox
  `sessionstore*` was copied even though the policy says session tokens are
  never collected. Chromium `Current/Last Session`, `Sessions/` and
  `Network/Cookies` were not covered at all. They are now metadata-only; pass
  `--browser-sessions` to collect them.
- **Kit wrappers used predictable temp file names as root.** Wrappers wrote
  `/tmp/.dfirkit-<tool>-<pid>`, a symlink-attack target on a compromised host.
  They now use private `mktemp` directories, and patched scripts run through
  their own interpreter so a `noexec` `/tmp` works. `setup --regen-wrappers`
  rebuilds them offline.
- **The `.deb` cache was owned by `_apt` or world-writable.** It is then
  unpacked, or `dpkg -i`'d, as root. Downloads now go to a private temporary
  directory and are copied in as root. Untrusted cache files are skipped.
  setuid bits are stripped from unpacked tools (openssh-client's
  `ssh-keysign`).
- AVML can be pinned with `AVML_SHA256` and downloads are https-only.
- `umask 077` for everything the collector creates.

Improvements:

- **Browser credential stores are copied, as on Windows.** This covers saved
  passwords, cookies, autofill (`Login Data`, `Network/Cookies`, `Web Data`,
  `logins.json`, `key4.db`, `cookies.sqlite`, ...) and the raw `Local State`.
  They go to `credential-stores/`, with provenance and SHA256.
  `--credential-stores metadata` records metadata only. The policy is recorded
  in `run-parameters.txt`, in the manifest (`browser_credential_stores`), in
  `summary.txt` and in the browser summary. Both launchers translate the
  option. See [docs/DATA-HANDLING.md](docs/DATA-HANDLING.md).
- Order of volatility: Processes and Network now run right after System. With
  `--memory`, RAM is imaged before anything else.
- Warnings when the output is on the filesystem under investigation, or when
  less than 2 GiB is free.
- New options: `--yara-threads`, `--max-journal-mb`, `--browser-sessions`, and
  the `--opt=value` form.
- Performance:
  - `dpkg --verify` and `debsums` now run concurrently. Both re-read every
    packaged file. On the test host the Security module dropped from 531 s to
    280 s.
  - One merged permission walk instead of four.
  - A mostly fork-free `/proc` walk with per-executable caches.
  - One `stat` per provenance record.
  - Batched `realpath`.
  - Prefiltered package-ownership lookups.
  - Hash inventory built without per-file forks.
  - Filename-IOC matching pre-filtered: 17.5 s down to 3.9 s on 25k paths.
- IOC matching:
  - uses `ipaddress` to recognise external IPs (it previously missed CGNAT and
    benchmark ranges)
  - extracts IPv6
  - excludes kit and output paths
  - honours signature-base false-positive exclusions
- The YARA rule builder:
  - exits non-zero when the bundle cannot be made to compile
  - deletes stale compiled bundles
  - maps compiler errors to the offending file for yarac 4.x's error format

### Windows collector

Fixes:

- **The YARA step always reported success.** A leaked `$true` hid failures. A
  static leak scanner is now part of the test suite.
- **YARA broke on paths with spaces.** `Start-Process -ArgumentList` does not
  quote arguments on PowerShell 5.1, so profiles such as `C:\Users\John Doe`
  failed. Arguments are now quoted properly. A per-target timeout kills a hung
  scan, and there is a per-file timeout too.
- **The hash inventory included `Collection.log`,** which changes after hashing,
  so verification always failed on it. It is now excluded, and
  `15_Hashes\README.txt` explains why.
- **Logged-on users lost their registry persistence keys.** `reg load` fails
  for a logged-on user; the keys are now read from `HKU\<SID>`.
- **The version was reported as 1.0.0 in v1.1 collections.** It now comes from
  `VERSION`.
- **`robocopy` fallback copies could be misattributed.** A pre-existing file
  of the same name could be picked up. It now copies into a private temporary
  folder.
- Profiles are also read from the `ProfileList` registry key, which covers
  relocated profiles and gives each profile a SID.

New:

- `-CaseId` (auto-generated when absent), `-OutputPath`, `-Modules`,
  `-ListModules`, `-NoArchive`, `-Version`, `-YaraTimeoutSeconds`.
- `-CaptureMemory` (winpmem, run first, SHA256 sidecar, kept beside the ZIP).
- `-BrowserCredentialStores MetadataOnly`. It records credential stores as
  size, timestamps and SHA256, and writes `Local State` with its decryption keys
  redacted.
- `14_Logs\CommandLog.csv` (exit codes and durations) and `14_Logs\Provenance.csv`
  (source metadata captured before each copy, copy method, SHA256).
- The ZIP is built with `System.IO.Compression`. That is faster, and it handles
  files larger than 2 GB. The ZIP gets a `.sha256` sidecar compatible with
  `sha256sum -c`.
- `Update-YaraRules.ps1` builds into the shared rule store and can
  compile-validate with `yarac64.exe`. It only replaces the bundle when the new
  one builds.
- The documentation now states that Firefox `logins.json` and `key4.db` are
  **not** DPAPI-protected. v1.1 claimed they were.

### Upgrade notes

- Default output is now `output/` in the kit root for both platforms.
- Linux: browser credential stores are copied by default (`--credential-stores
  metadata` for metadata only). Browser session stores are metadata-only unless
  `--browser-sessions`.
  Module order changed (see above). Output folder names and file formats are
  unchanged; new files are `session_store_metadata.txt` and `INCOMPLETE.txt`
  (interrupted runs only).
- Windows: ZIP entries now sit under the collection folder name, where v1.1
  put them at the ZIP root. Both verifiers read both layouts. New folder
  `20_Memory`.
- Manifest schema identifiers are now `vestigium/linux-manifest/1` and
  `vestigium/windows-manifest/1`. Collector names and banners say Vestigium.
