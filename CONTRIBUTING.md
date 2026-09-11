# Contributing to Vestigium

Thanks for helping. Vestigium collects evidence that may end up in reports,
disciplinary processes or court. Correctness and predictability matter more
than features, so every change should keep collections reproducible,
verifiable and safe to run on a compromised host.

## Ground rules

- **Never commit evidence, and never commit third-party rules.** `output/`,
  the cloned rule repositories and the built bundles are git-ignored on
  purpose. Only `shared/yara-rules/{sources.conf,exclusions.conf,rules.lock,custom/}`
  are versioned.
- **No outbound network activity during a collection.** No DNS lookups, no
  telemetry, no update checks. Only `setup` may use the network.
- **Never copy credential material** that the data-handling policy excludes.
  If a new artifact might contain secrets, record its metadata instead, or put
  it behind an explicit opt-in flag.
- **Record, then copy.** Capture source metadata before touching a file, and
  go through the provenance helpers (`dfir_copy` on Linux, `Copy-DFIRFile` /
  `Copy-DFIRLockedFile` on Windows).

## Development setup

```bash
git clone https://github.com/parthabishwas/vestigium.git
cd vestigium
tests/run-tests.sh            # offline: lint, launcher dry-runs, verifiers
sudo ./vestigium.sh setup     # optional: stage helper tools and build the YARA bundle
```

The suite uses `shellcheck`, `pwsh`, `python3`, `zstd` and `yara` when they are
present and reports what it skipped. CI runs it on every push, together with
live collection smoke tests on Linux and on Windows PowerShell 5.1.

## Code style

| Area | Requirements |
|---|---|
| `vestigium.sh` | POSIX `sh` (dash/busybox compatible), `shellcheck -s sh` clean |
| Linux collector | Bash 4.4+, `set -uo pipefail`, `shellcheck -S warning` clean, stdlib-only Python 3 |
| Windows collector | **Windows PowerShell 5.1 compatible** (no ternaries, `??`, `&&`), `Set-StrictMode -Version 2.0` safe, **ASCII-only** source files |
| All | Match the surrounding style and comment density; keep output file names and CSV columns stable, since downstream tooling parses them |

On Windows, functions that return `$true`/`$false` must not leak into the
caller's output. Assign the result, return it, or pipe it to `Out-Null`.
`tests/ast-leaks.ps1` enforces this.

## Adding a collection module

- **Linux**: add `platforms/linux/modules/NN-name.sh` with a
  `dfir_module_<name>` function, register it in `DFIR_MODULE_REGISTRY` (in
  `vestigium-linux.sh`, ordered by volatility), and write into an existing
  `DFIR_DIR[...]` folder.
- **Windows**: add `platforms/windows/Modules/Name.ps1`, list it in the module
  loader, and add a step to the launcher's step table.

Every command goes through the logging wrappers (`dfir_cmd` / `dfir_sh` or
`Invoke-DFIRSafeCommand`), so it lands in the command log with an exit code and
duration.

## Pull requests

1. One logical change per pull request, with a clear description of the
   forensic reason.
2. `tests/run-tests.sh` passes. Add tests for new behaviour.
3. Update `CHANGELOG.md` and the relevant README.
4. For YARA rule changes, see [docs/YARA-RULES.md](docs/YARA-RULES.md).

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening a
public issue.
