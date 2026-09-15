# Offline (air-gapped) deployment and updating the kit

Vestigium is built to run on a host with **no network access**. Collection
makes zero outbound connections and no DNS lookups. Everything a run needs is
staged into the kit ahead of time by `setup`, on a separate machine that does
have internet.

## The model

```
staging box (online)              evidence host (offline)
-------------------               -----------------------
setup  --------------> copy kit to removable media -------> collect / verify
(stage tools + rules)                                       (no network at all)
```

1. On the staging box, run `setup` once (and whenever you want to refresh).
2. Copy the whole kit folder to removable media.
3. On the evidence host, run a collection. Nothing reaches the network.

## What `setup` stages

**Linux** (`./vestigium.sh setup`):

- The APT dependency `.deb` cache in `tools/deb/`, unpacked into a portable
  tree in `tools/portable/` (so the kit runs without installing anything).
- **AVML** static memory-acquisition binary in `tools/bin/` (optional RAM capture).
- A static **busybox** in `tools/bin/` (second opinion for `--trusted-tools`).
- The **YARA rule bundle** built into `shared/yara-rules/` from the pinned
  sources, with `rules.lock`.
- `tools/TOOLS.md` recording every staged tool, its version and SHA256.

`./vestigium.sh setup --offline` rebuilds the portable tree from the on-disk
cache without touching the network. `./vestigium.sh setup --verify` reports
readiness (tools, rule sources, lock status, bundle age).

**Windows** (`vestigium.cmd setup`): builds the YARA rule bundle **and**
downloads the three helper binaries below from their official vendors into
`platforms\windows\Tools\`, each verified against the SHA256 in
`tools.manifest.json` (a mismatch is rejected). The binaries are **not**
redistributed in Git - licences forbid it for Sysinternals - so they are
fetched at setup time and git-ignored. On a fully air-gapped staging box (no
internet at all) place them in `platforms\windows\Tools\` by hand instead:

| Binary | Purpose | Source |
|---|---|---|
| `yara64.exe` | YARA scanning | VirusTotal/YARA releases |
| `Autorunsc64.exe` | Autoruns persistence | Microsoft Sysinternals |
| `winpmem_mini_x64*.exe` | RAM capture (`-CaptureMemory`) | Velocidex WinPmem releases |

Every step that uses one of these **degrades gracefully**: if the binary is
absent the step is skipped with a logged warning and the collection continues.
So the kit is functional without them; it is just more complete with them.

By default `tools.manifest.json` tracks each tool's **latest GitHub release**
(via `repo` + `asset_pattern`; Sysinternals uses its always-current URL), so a
fresh `setup` stages current builds. Latest builds cannot carry a fixed hash, so
they stage **unpinned**: the downloaded SHA256 is recorded in
`Tools\STAGED-TOOLS.md` and a warning is printed. To **freeze** a reproducible
kit, replace a tool's `repo`/`asset_pattern` with an explicit `url` and set its
`sha256`; the download is then rejected on any mismatch. `setup --no-tools`
builds rules only; `setup --verify` reports what is staged without changing it.

## Host prerequisites (cannot be shipped)

These must already exist on the evidence host:

- **Linux:** `bash` 4.4+, plus core system utilities. `python3` is needed for the
  HTML findings report, the IOC matcher and the full manifest; without it the
  collection still completes and writes a minimal, valid `findings.json` and a
  reduced manifest.
- **Windows:** Windows PowerShell 5.1 or PowerShell 7, run elevated.

`./vestigium.sh info` (or `vestigium.cmd info`) reports the detected platform,
the presence of these prerequisites and the staged tools, and free space.

## Updating the kit

There is deliberately **no runtime auto-updater**: an offline collector must not
reach the network, and a background updater would break that guarantee and add
risk. Updates are handled by re-staging on the online box, not on the host under
investigation.

To refresh:

- **Everything:** re-run `setup` on the staging box, then redeploy the kit.
  `tools/TOOLS.md` shows what changed (versions and SHA256).
- **YARA rules only:** `setup --rules-only` tracks the latest upstream commits;
  `setup --rules-locked` rebuilds the exact commits in `rules.lock`. The weekly
  `yara-rules` GitHub workflow proposes rule updates as a pull request. Full
  lifecycle in [YARA-RULES.md](YARA-RULES.md).
- **AVML:** pin a known-good build by exporting `AVML_SHA256` before `setup`; the
  download is rejected if it does not match. Override the URL with `AVML_URL`.
- **Windows binaries:** bump the `url` (and `sha256`) in
  `platforms\windows\Tools\tools.manifest.json` and re-run `setup`, or replace
  the files in `Tools\` by hand. `Tools\STAGED-TOOLS.md` records the staged hashes.

For a reproducible field kit, pin the rules (`rules.lock` / `--rules-locked`) and
`AVML_SHA256`, and keep `tools/TOOLS.md` with the kit so the exact toolset that
produced any evidence is documented.
