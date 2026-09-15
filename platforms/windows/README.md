# Vestigium Windows Collector

The Windows half of Vestigium: live-response evidence collection for Windows 10/11 on Windows PowerShell 5.1+, using built-in commands and cmdlets, with optional tools in `platforms\windows\Tools\`. (Formerly DFIRCollector v1.1; see `docs/history/`.)

## Running

Run from an elevated prompt. A non-elevated session prints `This tool requires Administrator privileges.` and exits 1.

```powershell
# Primary: from the kit root
.\vestigium.cmd -CaseId IR-2026-014
.\vestigium.ps1 -CaseId IR-2026-014 -TargetUser alice -YaraQuickScan

# Direct
powershell.exe -ExecutionPolicy Bypass -File .\platforms\windows\vestigium-windows.ps1 -CaseId IR-2026-014 -TargetUser "alice,CORP\bob"
```

| Parameter | Meaning |
|---|---|
| `-CaseId <id>` | Recorded in manifest, triage and log. Default `AUTO-<COMPUTERNAME>-<timestamp>` (`CaseIdSource` records which). |
| `-TargetUser <list>` | Name, `DOMAIN\name`, SID, or full profile path; comma-separated accepted. Default: every profile under `%SystemDrive%\Users` plus relocated profiles from the `ProfileList` registry key (SYSTEM/LocalService/NetworkService skipped). |
| `-OutputPath <dir>` | Evidence base. Default `<KitRoot>\output`. |
| `-Modules <list>` / `-ListModules` | Run a subset of steps (case-insensitive); list step names. |
| `-CaptureMemory` | Acquire physical memory first (see below). |
| `-BrowserCredentialStores Copy\|MetadataOnly` | Default `Copy` (v1.1 behaviour). See *Credential stores*. |
| `-SkipYara`, `-YaraQuickScan` | Skip YARA; or scan only Downloads, Desktop and Temp. |
| `-YaraThreads 1-8` | Default **8**. Use `1` on low-resource hosts. |
| `-YaraTimeoutSeconds <n>` | Per target folder, default 1800; yara64 is killed and a `TIMED OUT` line written. Each file also has a 120 s limit (`-a 120`). |
| `-NoArchive`, `-Version` | Leave the tree unzipped; print the kit version. |

Exit codes: `0` success, `1` a step failed or not elevated, `2` usage error.

Output: `<OutputPath>\COMPUTERNAME_USERNAME_YYYYMMDD_HHMMSS\` and `<OutputPath>\COMPUTERNAME_YYYYMMDD_HHMMSS.zip` plus `.zip.sha256`.

## Evidence layout

`01_System` `02_Processes` `03_Autoruns` `04_Startup` `05_Registry` `06_ScheduledTasks` `07_Services` `08_Network` `09_Browser` `10_EventLogs` `11_Hosts` `12_Defender` `13_SystemInfo` `14_Logs` `15_Hashes` `16_Manifest` `17_Execution` `18_Devices` `19_Triage`, and `20_Memory` when memory is captured.

- `14_Logs\Collection.log`: the run log. `Transcript.txt` is the PowerShell transcript.
- `14_Logs\CommandLog.csv`: every native command and cmdlet export (Timestamp, Name, Command, ExitCode, DurationSeconds, OutputFile). Non-zero exit codes are also logged as WARN.
- `14_Logs\Provenance.csv`: every copied file (Timestamp, SourcePath, EvidencePath, SizeBytes, source Creation/LastWrite/LastAccess times captured *before* copying, Attributes, SHA256 of the copy, CopyMethod `CopyItem`/`SharedRead`/`RobocopyBackup`). Shared-read copies get the source creation and last-write times restored.
- `15_Hashes\SHA256.csv`: covers every file except itself, `Collection.log` (still written after hashing), `Manifest.json` (written after hashing) and the memory image. `README.txt` explains the exclusions; the archive's `.sha256` covers everything.
- `16_Manifest\Manifest.json`: schema `vestigium/windows-manifest/1`. Holds case, operator, invocation, status, kit root, YARA rules path and SHA256, memory details, CommandLog and Provenance record counts, results, and hashes.
- `19_Triage\Findings.md`: read it first. It lists AV detections, unsigned autostarts in user-writable paths, listeners, remote-access software, non-Microsoft SYSTEM tasks, and collection gaps. It points you at what to check; it is not a verdict.

## Verification

```powershell
.\vestigium.ps1 verify .\output\HOST_20260911_101500.zip
```

The ZIP stores entries under the collection folder name. It is built with `System.IO.Compression` (Zip64, no 2 GB limit), with `Compress-Archive` as a fallback. The `.sha256` sidecar is in `sha256sum -c` format.

## Memory capture

`-CaptureMemory` runs `Tools\winpmem_mini_x64*.exe <image.raw>` before anything else (order of volatility). First it checks that the evidence volume has RAM + 1 GB free. The image goes to `20_Memory\memory_<HOST>_<timestamp>.raw` with a `.sha256` sidecar and a README. It is **not** put in the ZIP: it stays in the evidence folder beside the archive, and `<zip base>.memory-image-location.txt` records where it is. Transfer it separately. If WinPmem is missing, the step logs a warning and fails, and the collection continues. Without a memory image the triage summary records that gap.

## YARA rules (shared with Linux)

Rules are read from `<KitRoot>\shared\yara-rules\active-rules.yar`, falling back to the legacy `Tools\YaraRules\active-rules.yar`. The scanner is `Tools\yara64.exe`. Build or refresh the shared bundle with:

```powershell
.\vestigium.ps1 setup                                  # kit-level setup
.\vestigium.ps1 setup -Locked                          # rebuild exactly the commits in rules.lock
powershell.exe -ExecutionPolicy Bypass -File .\platforms\windows\Tools\Update-YaraRules.ps1 [-Locked] [-SkipGitUpdate] [-RulesRoot <dir>] [-YaracPath <yarac>]
```

The builder:
- fetches the sources in `shared\yara-rules\sources.conf` (default: `signature-base` and Yara-Rules in folder `rules`) and puts `custom\` first;
- skips external-variable rules, include wrappers, tests and duplicate rule names, and applies `exclusions.conf` (`file:` drops files, `rule:` makes rules private);
- compile-checks the bundle with `Tools\yarac64.exe` (or `-YaracPath`), dropping files that fail (logged in `RuleBuildReport.csv`);
- replaces `active-rules.yar` only after a successful build, then records commits and the bundle SHA256 in `rules.lock` (`-Locked` rebuilds those commits and reports whether the SHA256 matches).

See [docs/YARA-RULES.md](../../docs/YARA-RULES.md).

Matches inside the kit root and the output base are suppressed (`Suppressed-Self-Matches` in `01_System\YaraResults.txt`). The results header records the rules path and SHA256. Run the kit from outside `C:\Users` (removable media or `D:\IR\Vestigium`) and point `-OutputPath` outside scanned profiles. Defender has been seen deleting `active-rules.yar` mid-collection, so add an AV exclusion for the kit path where policy allows. Upstream rule licences apply to redistribution.


## NTFS and filesystem artifacts (Forensics step)

The `Forensics` step acquires artifacts a live collection otherwise cannot:

- **$MFT, $LogFile, USN journal** via a Volume Shadow Copy -> `21_FileSystem\`
  (fallback: `fsutil usn readjournal`). Parse offline with MFTECmd.
- **NTUSER.DAT / UsrClass.dat** copied from the shadow copy -> `05_Registry\Hives_VSS\`
  (ShellBags, UserAssist, RecentDocs; no `reg load` needed).
- **LNK shortcuts and Jump Lists** -> `17_Execution\UserArtifacts\`.
- **$Recycle.Bin** `$I` metadata -> `21_FileSystem\RecycleBin\`.
- **Defender MPLog** -> `12_Defender\MPLog\`.
- **Clock offset** (`w32tm`) -> `01_System\ClockOffset.txt`.
- **Machine hives** `SAM` / `SECURITY` / `SYSTEM` / `SOFTWARE` -> `05_Registry\Hives_VSS\_MACHINE\`
  (offline local hashes, LSA secrets, cached domain creds).

The shadow copy Vestigium creates is deleted afterwards.

**Other drives.** By default only the system drive is deep-collected. Pass
`-ScanDrives D:,E:` to also YARA-scan those volumes and acquire their NTFS
metadata (`$MFT`, `$LogFile`, USN journal) into `21_FileSystem\<letter>\`.
Accepts `D:`, `D`, or a list; the system drive and non-local volumes are
ignored. Whole-drive YARA scans can be slow. Requires an elevated
session; when VSS is unavailable the step degrades and logs the gap. This
module is **not yet validated on real Windows** - see
[../../docs/WINDOWS-ARTIFACTS.md](../../docs/WINDOWS-ARTIFACTS.md) for the
validation checklist.

## Credential stores: what is actually collected

The Linux collector follows the same default. [docs/DATA-HANDLING.md](../../docs/DATA-HANDLING.md) covers both platforms.

With the default `-BrowserCredentialStores Copy`, the collector copies these stores:
- Chromium: `Login Data`, `Login Data For Account`, `Web Data`, `Network\Cookies`, `Network\Trust Tokens`, plus `Local State`.
- Firefox: `logins.json`, `key4.db`, `cookies.sqlite`, `formhistory.sqlite`.

They are not safe just because they are encrypted:

- **Firefox**: `logins.json` + `key4.db` are **not** DPAPI-protected. Unless the user set a Primary Password, the saved passwords can be decrypted offline from the evidence alone.
- **Chromium**: values are encrypted with a key held in `Local State`. That key is protected by the user's DPAPI master key and, in recent Chrome/Edge, by app-bound encryption. Whoever also holds that user's DPAPI material (password, domain backup key, or a live session) can decrypt them.

Treat a `Copy` collection as containing live credentials. Where the rules of engagement forbid handling credentials, use `-BrowserCredentialStores MetadataOnly`. It records size, timestamps and SHA256 (read with shared access) of those stores in `09_Browser\CredentialStoreMetadata.csv` instead of copying them. That is usually enough to show whether a stealer touched them. History, preferences and extension data are still collected.

## Collected artifacts (summary)

- Asset and system information.
- Processes and services.
- Installed applications (registry only, no `wmic product`).
- Registry persistence, including target-user `NTUSER.DAT` keys. A logged-on user's hive is exported from `HKU\<SID>`.
- Startup folders.
- Scheduled tasks: schtasks text and XML, `Get-ScheduledTask`, raw `System32\Tasks` XML.
- Autoruns (`Autorunsc64.exe -a * -c -s -h -t`) and WMI subscription persistence.
- Network state and the hosts file.
- Event logs: EVTX plus the last 500 events per channel; absent channels are recorded.
- Defender status, detections, preferences and exclusions; Malwarebytes and ESET logs, with binary logs carved to `.strings.txt`.
- Execution history: Prefetch, Amcache, SRUM, ShimCache, PSReadLine history.
- USB/volume/MountPoints2 history.
- Browser extensions and profile data.
- Optional YARA and optional memory.

Files locked by running programs are copied with shared read, then robocopy backup mode.

## Platforms

Windows 10/11, Windows PowerShell 5.1 or later. No third-party PowerShell modules required. The toolkit continues when optional tools are missing.
