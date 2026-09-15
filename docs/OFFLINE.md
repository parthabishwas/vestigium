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

**Windows** (`vestigium.cmd setup`): builds the YARA rule bundle only. Three
third-party binaries are **not** redistributed and must be placed in
`platforms\windows\Tools\` by hand (licences forbid bundling them):

| Binary | Purpose | Source |
|---|---|---|
| `yara64.exe` | YARA scanning | VirusTotal/YARA releases |
| `Autorunsc64.exe` | Autoruns persistence | Microsoft Sysinternals |
| `winpmem_mini_x64*.exe` | RAM capture (`-CaptureMemory`) | Velocidex WinPmem releases |

Every step that uses one of these **degrades gracefully**: if the binary is
absent the step is skipped with a logged warning and the collection continues.
So the kit is functional without them; it is just more complete with them.

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
- **Windows binaries:** replace the files in `platforms\windows\Tools\` with the
  newer releases; record the versions you deployed alongside the kit.

For a reproducible field kit, pin the rules (`rules.lock` / `--rules-locked`) and
`AVML_SHA256`, and keep `tools/TOOLS.md` with the kit so the exact toolset that
produced any evidence is documented.
