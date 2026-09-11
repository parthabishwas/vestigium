# DFIRCollector v1.1 — changes

Derived from v1.0 after the July 2026 credential-exposure engagement (5 endpoints).
Every change below traces to evidence that was lost, buried, or misleading in that collection.

## Fixes — evidence that was lost or misleading in v1.0

| # | Change | Why |
|---|--------|-----|
| 1 | `Autorunsc64.exe` now runs with `-s -h -t -nobanner` | v1.0 used `-a * -c` only. The Signer column was empty across all ~1,700 entries on every host, so autostarts could only be judged by publisher strings — the field an attacker controls. |
| 2 | YARA self-matches suppressed; toolkit root recorded in the output header | The collector ran from `C:\Users\<admin>\Downloads\DFIR`, inside a scanned profile, so YARA matched its own rule corpus. Every `APT1_*`, `Agenttesla` and `RAT_Adzok` "hit" in v1.0 output was the scanner reading its own rules. 3,242 lines on one host. |
| 3 | Warning when the collector sits inside a YARA target | Root cause of #2 and of AV quarantining the toolkit mid-collection. |
| 4 | `Get-MpPreference` exported as JSON + registry fallback for exclusions and tamper protection | `MpPreference.csv` was empty on all five hosts because WinDefend is stopped when ESET owns Security Center. Defender exclusions — a standard persistence hiding place — were unverifiable. CSV also renders `ExclusionPath` as the literal `System.String[]`. |
| 5 | Vendor binary logs carved to `.strings.txt` | ESET stores detections in proprietary `.dat`. A confirmed `Worm.MSIL/Agent.LG`, a Windows activation toolkit, and an adware browser extension were all invisible until carved by hand. |
| 6 | Malwarebytes paths corrected; "installed but no logs" distinguished from "not installed" | v1.0 logged an ambiguous "paths not found" on three hosts, so a reported scan could not be corroborated or ruled out. |
| 7 | Locked files copied via shared read, then robocopy `/b` | Seven Edge extensions on one host were never inspected — `manifest.json` was write-locked by the running browser. Browser extensions are the most direct route to stored credentials. |

## Coverage added

| Area | Detail |
|------|--------|
| `17_Execution` | Prefetch + listing, `Amcache.hve` and transaction logs, SRUM, ShimCache, per-profile PSReadLine `ConsoleHost_history.txt`. Three of five endpoints were re-imaged, leaving only 2–3 weeks of event log — nothing covered the actual exposure window. |
| `18_Devices` | `USBSTOR`, `USB`, `SCSI`, `MountedDevices`, portable devices, per-user `MountPoints2`, volume/disk inventory, shallow listing of non-system volumes. An attached personal backup drive carrying a worm was only ever visible indirectly through third-party scan logs. |
| `19_Triage` | `Findings.md` — carved AV detections, unsigned autostarts in user-writable paths, non-ephemeral listeners with known-port annotations, remote-access software, non-Microsoft SYSTEM tasks, and collection gaps. |
| WMI persistence | `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`. Autoruns does not enumerate these. |
| Scheduled task XML | `schtasks /query /xml ONE` plus raw `System32\Tasks` definitions. Carries registration timestamp and author SID, which `schtasks /v` omits. |
| Browser profile data | Chromium `Preferences`, `Secure Preferences`, `Local State`, `History`, `Web Data`, `Login Data`, `Network\Cookies`; Firefox `logins.json`, `key4.db`, `places.sqlite`, `cookies.sqlite`, `prefs.js`. Values stay DPAPI-encrypted — presence and timestamps are the evidence. |
| Event channels | Terminal Services (local session / remote connection / RDP client), DriverFrameworks, WMI-Activity, BITS, CodeIntegrity, SMB client security, AppLocker, Sysmon. Absent channels are recorded, not treated as failure. |

## Defects found and fixed during verification

- **UTF-16LE carve missed odd-offset strings.** Decoding only at byte offset 0 silently dropped every string starting at an odd offset. The ESET adware detection sits at offset 1579 and was not recovered until both alignments were decoded.
- **`Export-DFIRBinaryStrings` did not create its destination directory**, failing silently when the parent did not yet exist.
- **`Mandatory` parameter binding rejects an empty `ArrayList`**, so the triage helpers would break if called before any header line was added. Fixed with `[AllowEmptyCollection()]`.

## Verification

All checks run against the five real evidence packages from the engagement:

- Every `.ps1` parses clean via the PowerShell AST parser; no undefined or orphaned function calls (69 DFIR functions, all reachable).
- String carve reproduces **every** detection found manually — Host A `KingSoft.Z`; Host B `Worm.MSIL/Agent.LG`, `WinActivator.J/.N`, `Yandex.K`, `Object.Suspicious`; Host C `Adware.Chromex.Agent.W` — and correctly returns zero on the two clean hosts.
- YARA suppression drops 3,242 self-match lines on the real Host A output while retaining every match on genuine user files.
- Locked-file copy verified byte-identical against a file held open by an active writer handle.
- Triage summary verified to surface all four Host B detections plus the collection-gap escalations.

## Operational note

Run from outside `C:\Users` — removable media or e.g. `D:\IR\DFIRCollector` — and add an AV exclusion for the toolkit path. In this engagement Microsoft Defender deleted `active-rules.yar` and an `.eml` rule sample from the toolkit during a live collection.
