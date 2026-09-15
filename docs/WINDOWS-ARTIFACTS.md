# Windows NTFS and filesystem artifacts

Vestigium 2.x adds a `Forensics` collection step (module
`platforms/windows/Modules/Forensics.ps1`, evidence in `21_FileSystem/`, with
hives under `05_Registry/Hives_VSS/` and shell artifacts under
`17_Execution/UserArtifacts/`). It closes the biggest gaps in a live Windows
collection: the locked NTFS metadata and the locked registry hives.

> **Status:** this module is written for Windows PowerShell 5.1 and has been
> parse-checked and leak-checked, but it was authored on a machine with no
> Windows host, so its runtime behaviour is **unvalidated**. Use the checklist
> below on Windows 10/11 before relying on it. Please report results.

## What it collects

| Artifact | How | Output | Offline parse |
|---|---|---|---|
| `$MFT`, `$LogFile` | Volume Shadow Copy, backup-semantics raw read | `21_FileSystem/MFT`, `LogFile` | MFTECmd |
| USN journal (`$UsnJrnl:$J`) | allocated-range copy of the sparse ADS, plus an independent `fsutil usn readjournal` | `21_FileSystem/UsnJrnl_J` or `UsnJrnl_readjournal.csv` | MFTECmd / fsutil |
| `NTUSER.DAT`, `UsrClass.dat` (+ `.LOG1/.LOG2`) | copied from the shadow copy (no `reg load`) | `05_Registry/Hives_VSS/<user>/` | Registry Explorer / RECmd -> ShellBags, UserAssist, RecentDocs |
| `SAM`, `SECURITY`, `SYSTEM`, `SOFTWARE` (+ logs) | copied from the shadow copy | `05_Registry/Hives_VSS/_MACHINE/` | secretsdump.py / samdump2 -> local hashes, LSA secrets, cached domain creds |
| Host firewall profiles + rules | `netsh advfirewall` | `08_Network/FirewallProfiles.txt`, `FirewallRules.txt` | disabled profile flagged as a finding |
| BITS transfer jobs | `Get-BitsTransfer -AllUsers` | `08_Network/BitsTransfers.csv` | raw-IP or user-writable-path jobs flagged as a finding |
| Alternate data streams | `Get-Item -Stream *` over user-writable dirs | `21_FileSystem/AlternateDataStreams.csv` | Zone.Identifier download provenance, ADS-hidden payloads |
| Staging archives | recursive listing | `21_FileSystem/StagingArchives.csv` | zip/rar/7z/... in Temp/AppData/Users\Public |
| Windows Error Reporting | `Report.wer` copy | `21_FileSystem/WER/` | crash/injection evidence (no dumps) |
| Certificate stores | `Cert:` provider | `01_System/CertificateStores.csv` | rogue root CAs |
| Named pipes | `\\.\pipe\` listing | `02_Processes/NamedPipes.txt` | C2 / lateral-movement pipes |
| WinRM state | `winrm get/enumerate` | `08_Network/WinRM.txt` | remote-management surface |
| Office macro trust records | per-user Office hive export | `05_Registry/TargetUser_*_Office.reg` | TrustRecords, VBAWarnings, MRU |
| LNK shortcuts, Jump Lists | per-profile `Recent`, `AutomaticDestinations`, `CustomDestinations` | `17_Execution/UserArtifacts/<user>/` + `index.csv` | LECmd / JLECmd |
| `$Recycle.Bin` | `$I` index files + `$I`/`$R` listing (no `$R` blobs) | `21_FileSystem/RecycleBin/<SID>/` + `index.csv` | RBCmd |
| Defender MPLog | most recent `MPLog-*` / `MPDetection-*` | `12_Defender/MPLog/` | text |
| Clock offset | `w32tm /query /status` + `/configuration` + local/UTC | `01_System/ClockOffset.txt` | text |

Non-system volumes are only inventoried and shallow-listed by default. Pass
`-ScanDrives D:,E:` to also YARA-scan them and acquire their `$MFT`, `$LogFile`
and USN journal (via `esentutl /vss`) into `21_FileSystem/<letter>/`.

The shadow copy Vestigium creates is deleted at the end of the step (in a
`finally`). Pre-existing shadow copies are never touched. `21_FileSystem/_ACQUISITION.txt`
records what was obtained, what fell back and what failed. When VSS is
unavailable (non-elevated, or the service is disabled) the step logs it, tries
the live `fsutil` USN read, and continues; the triage/findings gap wording
adjusts to say whether `$MFT`/`$UsnJrnl` were actually acquired.

## Validation checklist (run on Windows 10 and 11, elevated)

1. **VSS acquisition**
   ```powershell
   .\vestigium.ps1 -CaseId TEST -Modules FileSystem,Forensics -SkipYara -NoArchive -OutputPath C:\ev
   ```
   Actually run the whole thing, or just: `.\vestigium.ps1 -Modules Forensics ...`.
   - Confirm a `HarddiskVolumeShadowCopy` was created and then removed:
     `vssadmin list shadows` before/after (the count returns to baseline).
   - `21_FileSystem\_ACQUISITION.txt` lists `OK`/`FAIL`/`FALLBACK` per artifact.
   - `21_FileSystem\MFT` exists and is non-trivial (hundreds of MB on a real
     disk), and `LogFile` is present. These NTFS metadata files are acquired
     with a backup-semantics raw read (`CreateFileW` + `FILE_FLAG_BACKUP_SEMANTICS`,
     which uses the elevated token's SeBackupPrivilege) - `Copy-Item`, `Test-Path`
     and a plain `FileStream` all fail 'Access is denied' on them. If the raw
     read still fails, the step logs `FAIL` and continues.
     Report which happened.
   - Either `UsnJrnl_J` (stream copy) or `UsnJrnl_readjournal.csv` (fallback)
     exists and has content.
2. **Hives** `05_Registry\Hives_VSS\<user>\NTUSER.DAT` exists for each profile
   and loads in Registry Explorer; ShellBags/UserAssist resolve. Confirm the
   collector did **not** need `reg load` for these.
3. **LNK / Jump Lists** `17_Execution\UserArtifacts\<user>\` has `lnk\` and
   `jumplist\` files and `index.csv`; LECmd/JLECmd parse them.
4. **Recycle Bin** delete a test file, empty nothing, run the step, confirm a
   `$I...` file appears under `21_FileSystem\RecycleBin\<SID>\` and RBCmd shows
   the original path.
5. **Defender MPLog** `12_Defender\MPLog\` has recent `MPLog-*.log` files.
6. **Clock** `01_System\ClockOffset.txt` shows local vs UTC and the w32tm
   status; on a domain host the source and phase offset are populated.
7. **Non-elevated / VSS-off** run without admin: the step must not throw, must
   log the gap, and the collection must still finish and verify.
8. **Verify** `.\vestigium.ps1 verify C:\ev\<pkg>.zip` passes and lists the new
   files in the hash inventory.

## PowerShell 5.1 risks to watch

- `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN` path handling by
  `Copy-Item`/`.NET` file APIs. Regular files use `Copy-DFIRLockedFile`
  (shared-read stream, then robocopy `/b`); NTFS metadata files use
  `Copy-DFIRRawFile` (backup-semantics `CreateFileW`), the only path that
  opens `$MFT`/`$LogFile`/`$UsnJrnl:$J` on a live host.
- `$UsnJrnl:$J` is a sparse ADS with a huge logical size; it is copied by
  querying allocated byte ranges (FSCTL_QUERY_ALLOCATED_RANGES) into a sparse
  output, never a naive stream copy from offset zero. A live `fsutil usn
  readjournal` is always taken as well.
- Reserved `$`-prefixed names in paths (handled with single-quoted literals and
  string concatenation, never double-quoted interpolation).
