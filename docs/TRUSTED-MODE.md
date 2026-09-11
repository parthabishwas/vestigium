# Trusted-binary mode (Linux)

On a compromised host, the tools you run are part of the crime scene. A
userland rootkit ships trojaned `ps`, `ss`, `ls`, `netstat` or `lsmod`, or
hooks libc's `readdir`, so a normal collection faithfully records the lie.
Trusted-binary mode is Vestigium's answer: **run the kit's own binaries, and
cross-check the host's tools against the kernel's own view.**

Enable it with `--trusted-tools` (`sudo ./vestigium.sh --trusted-tools ...`).
It has two independent halves.

## 1. Force the kit's binaries

Normally each kit wrapper in `tools/bin/` prefers the host's copy of a tool and
only falls back to the kit's. With `--trusted-tools` that preference is
reversed: the wrapper always runs the kit's own statically-staged copy and
never the host's. The investigative tools the kit carries — `yara`, `lsof`,
`netstat`, `dmidecode`, `debsums`, `sqlite3`, `file`, `chkrootkit`, `rkhunter`,
`unhide`, and the rest — are therefore taken from media you control.

**What it records.** Every run (trusted or not) writes
`19_CollectionLogs/tool-provenance.csv`: for each investigative tool and each
core shell utility, the resolved path, whether it came from the `kit` or the
`host`, and its SHA256. This documents exactly which binaries produced the
evidence. In trusted mode a warning also names any investigative tool that
still had to fall back to the host.

**Honest limitation.** Vestigium cannot ship a whole trusted userland. Base
system utilities — `bash`, `grep`, `awk`, `sed`, `find`, `stat`, `ls`, `ps`,
`ss`, coreutils — come from `util-linux`, `coreutils`, `iproute2` and similar
essential packages that are impractical to stage and would break the modules'
GNU-specific options. Those still run from the host, and `tool-provenance.csv`
marks them `host`. That is exactly why the second half exists.

## 2. Cross-check the host against the kernel

The `AntiRootkit` module (evidence in `12_Security/antirootkit/`) never trusts
those host utilities. It reads the kernel's own view from `/proc` and `/sys`
with plain bash, then diffs it against what the tools report. When the kit's
static **busybox** is staged (by `setup`), it is used as an independent third
opinion. A resource the kernel knows about that a host tool denies is a strong
compromise indicator.

| Check | Kernel truth | Compared against | Flag |
|---|---|---|---|
| Hidden processes | `/proc/<pid>` | `ps -e`, `ps -p`, busybox `ps` | `HIDDEN-PROC` |
| Hidden kernel modules | `/sys/module/*` (live), `/proc/modules` | `lsmod` | `HIDDEN-MODULE` |
| Hidden listening ports | `/proc/net/{tcp,tcp6,udp,udp6}` | `ss`, `netstat` | `HIDDEN-PORT` |
| Hidden directories | directory link count | visible sub-directories | `DIR-NLINK-MISMATCH` |
| Hidden files | `ls`, busybox `ls`, bash glob | each other | `HIDDEN-DIR-ENTRY` |

Outputs in `12_Security/antirootkit/`:

- `discrepancies.txt` — one machine-readable line per finding, each with one of
  the prefixes above. The findings report keys on these.
- `SUMMARY.txt` — the tools used, per-check detail counts, and guidance.
- `processes_proc_vs_ps.txt`, `modules_sys_vs_lsmod.txt`,
  `ports_procnet_vs_tools.txt`, `dirs_link_and_readdir.txt` — the full detail.

Discrepancies become triage findings
(`linux.integrity.hidden_process` and friends, see
[FINDINGS-SCHEMA.md](FINDINGS-SCHEMA.md)): hidden processes and modules are
`critical`, hidden ports and directory link mismatches `high`, listing
disagreements `medium`. They appear in `findings.html` and are printed by
`vestigium verify`.

The `AntiRootkit` module runs on **every** collection, because the checks are
cheap and high-value. `--trusted-tools` strengthens them by forcing the kit's
`netstat` for the port comparison and recording the trust basis; the busybox
third opinion is used whenever it is staged.

## What it does not do

- It does not defend against a **kernel-mode** rootkit that lies consistently
  to both `/proc`/`/sys` and userland — nothing running on the live host fully
  can. For that, capture memory (`--memory`) and image the disk for offline
  analysis.
- It does not replace the host's core shell utilities (see the limitation
  above).
- No check is a verdict. A process that exits mid-scan, or an unusual
  filesystem, can produce a benign discrepancy. Confirm each against the raw
  artifact.

## Preparing the kit

`--trusted-tools` needs a prepared kit. `sudo ./vestigium.sh setup` stages the
static busybox (`tools/bin/busybox`) and the investigative tools. Verify with
`./vestigium.sh setup --verify` (the "busybox (trusted tools)" line) or
`./vestigium.sh info`. Run the kit from read-only removable media so the staged
binaries themselves cannot be tampered with on the host.

## Recommended usage

```bash
sudo ./vestigium.sh --case-id IR-2026-014 --trusted-tools \
     --rootkit-scan --memory --output /media/evidence
```

`--rootkit-scan` adds chkrootkit / rkhunter / unhide (from the kit), `--memory`
captures RAM first for offline kernel-rootkit analysis, and `--trusted-tools`
forces the kit binaries and records the trust basis. The anti-rootkit
cross-checks run regardless.
