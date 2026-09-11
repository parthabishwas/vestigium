# YARA rules: sources, builds and maintenance

Vestigium scans with one YARA bundle, `shared/yara-rules/active-rules.yar`,
shared by the Linux and Windows collectors. The bundle is never committed. It
is built locally from upstream rule repositories and your own rules, it is
validated, and it is pinned in `rules.lock` so that every kit can rebuild the
same rule set and every collection can be traced back to it.

## Lifecycle

```text
sources.conf ──► fetch (git, shallow) ──► validate ──► exclude / suppress ──► build
  custom/ ─────────────────────────────────┘          (exclusions.conf)        │
                                                                                ▼
 manifest records bundle SHA256 ◄── collect ◄── field kit ◄── rules.lock ◄── active-rules.yar
                                               (--rules-locked)              (+ .compiled, reports)
```

1. **Sources.** `sources.conf` lists the rule repositories, in precedence
   order. `custom/` holds your own rules and always comes first.
2. **Fetch.** Each source is fetched shallowly (`git fetch --depth 1`) at its
   configured ref, or at its locked commit, and checked out detached.
3. **Validate.** Every candidate file is checked. The following are skipped
   and recorded:
   - include wrappers
   - files with duplicate identifiers
   - identifiers already accepted from an earlier file
   - signature-base rules that need LOKI/THOR external variables
   - files that do not compile on their own (Linux builder)
4. **Exclude / suppress.** `exclusions.conf` drops whole files and turns
   individual rules private.
5. **Build.** The accepted files are concatenated into a temporary bundle,
   which is compiled. A file that breaks the compile is dropped and the bundle
   rebuilt. The temporary bundle replaces `active-rules.yar` (and
   `active-rules.compiled`) only when everything succeeded.
6. **Lock.** `rules.lock` records the builder, the yara version, each source's
   commit, and the bundle's SHA256 and counts.
7. **Collect.** The collectors scan with the bundle and record its path and
   SHA256 in the results header and the manifest. The SHA256 ties a finding
   back to a lock, and so to exact upstream commits.

## What lives in `shared/yara-rules/`

| Path | Versioned | Written by |
|---|---|---|
| `sources.conf` | yes | you |
| `exclusions.conf` | yes | you |
| `custom/` | yes | you |
| `rules.lock` | yes | the builder (review and commit it) |
| `README.md` | yes | - |
| `signature-base/`, `rules/`, other source checkouts | no | setup (git) |
| `active-rules.yar`, `active-rules.compiled` | no | the builder |
| `rule-build-report.csv` (Linux), `RuleBuildReport.csv` (Windows) | no | the builder |
| `rule-fp-report.txt` | no | the builder (`--fp-corpus`) |

## Updating the rules

| Goal | Linux | Windows |
|---|---|---|
| Latest upstream, rebuild, rewrite lock | `sudo ./vestigium.sh setup --rules-only` | `.\vestigium.ps1 setup` |
| Rebuild exactly the locked commits | `sudo ./vestigium.sh setup --rules-locked` | `.\vestigium.ps1 setup -Locked` |
| Rebuild from the checkouts on disk (no network) | `sudo ./vestigium.sh setup --rules-only --offline` | `.\vestigium.ps1 setup -SkipGitUpdate` |
| Also check for false positives | add `--fp-corpus /usr/bin` | (Linux only) |
| Status: sources, lock, bundle age | `./vestigium.sh setup --verify` | - |

- **`--rules-only`** fetches the latest commit of each source (or its pinned
  ref) and rebuilds, then rewrites `rules.lock`. It skips apt, AVML and
  wrapper regeneration. It does not need root when the rules directory is
  writable; `vestigium.sh` still elevates by default, but
  `platforms/linux/tools/setup-tools.sh --rules-only` can be run directly.
- **`--rules-locked`** (implies `--rules-only`) and **`-Locked`** read the
  sources from `rules.lock`, not from `sources.conf`. For each source:
  - a checkout already at the locked commit is used as it is, which works
    offline;
  - otherwise the commit is fetched (`git fetch --depth 1 origin <sha>`) and
    checked out.

  The build stops, leaving the existing bundle in place, when a commit cannot
  be obtained: rewritten upstream history, no network, `--offline` /
  `-SkipGitUpdate`, or local changes in the checkout. The new bundle's SHA256
  is then compared with the lock and reported as `MATCH` or `MISMATCH`, with
  the inputs that differ. Locked builds never rewrite the lock.
- A full `sudo ./vestigium.sh setup` also runs the rule stage, in "latest"
  mode.

The Linux builder can also be run directly:

```bash
python3 platforms/linux/tools/build-yara-rules.py --rules-dir shared/yara-rules \
    --compiled shared/yara-rules/active-rules.compiled --yarac "$(command -v yarac)" \
    [--locked] [--fp-corpus DIR ...] [--fp-timeout 900] [--no-lock]
```

Exit codes: `0` built; `1` build failed (existing bundle unchanged); `2`
configuration or usage error.

## Sources: `sources.conf`

```text
# <name>        <git-url>                                        [<ref>]
signature-base  https://github.com/Neo23x0/signature-base.git
rules           https://github.com/Yara-Rules/rules.git
acme-intel      git@github.com:acme/yara-intel.git               main
```

The fields:

- `name` is the folder under `shared/yara-rules/`. It may contain
  `[A-Za-z0-9._-]`, must not start with `.` or `-`, and `custom` is
  reserved.
- `url` must be `https://…` or `git@host:path`. Any other scheme, including
  `file://`, `ssh://` and `ext::`, is rejected.
- `ref` is a branch, a tag or a full 40-character commit SHA. When it is
  omitted, the repository's default branch is used.

Invalid lines stop the build before git is invoked. Both builders apply the
same checks to `sources.conf` and to `rules.lock`.

Order is precedence. When two files declare the same rule identifier, the
later **file** is skipped as a whole ("identifier already accepted" in the
report). With the default order (signature-base first), a handful of
Yara-Rules files are skipped this way, including
`rules/crypto/crypto_signatures.yar`. When `sources.conf` is missing, the
built-in list (signature-base, rules) is used.

**Private or in-house repositories.** Add a line with an SSH or HTTPS URL.
Authentication uses the staging workstation's own git setup, such as an SSH
agent, a deploy key or a credential helper. Nothing secret goes into the
kit. Pin a tag or commit if the repository moves fast. For CI access, see
[the weekly workflow](#weekly-ci-loop).

Where rule files are searched for:

| Repository | Search roots |
|---|---|
| signature-base | `yara/` |
| any other | the first-level folders named `yara`, `rules`, `malware`, `maldocs`, `webshells`, `exploit_kits`, `packers`, `email`, `mobile_malware`, `crypto`, `cve_rules`, `antidebug_antivm` and `capabilities`, or the repository root when none exists |

In both cases, `.git`, `test`, `tests` and `deprecated` folders and files
starting with `.`, `~` or `_` are ignored.

## In-house rules: `custom/`

Rules you write go in `shared/yara-rules/custom/` (`*.yar`, `*.yara`, any
sub-folder). They are versioned with the kit and always built first, so their
identifiers win clashes. They are validated like every other file. A custom
file that fails validation is left out and logged as a warning, so test before
committing. Conventions are in [custom/README.md](../shared/yara-rules/custom/README.md):
one family per file, an organisation prefix, and the required `meta:` fields
`author`, `description`, `date` and `reference`.

## Tuning false positives: `exclusions.conf`

```text
file:rules/capabilities/*        # drop whole files: glob on the path relative to shared/yara-rules
rule:Big_Numbers*                # suppress rules: exact identifier or glob
```

- **`file:<glob>`** is matched case-insensitively against the path with `/`
  separators, and `*` also crosses `/`. A matching file is not built and is
  reported as `excluded`.
- **`rule:<name>`** is case-sensitive; `*` and `?` are supported. The rule's
  declaration is rewritten in the bundle from `rule X` to `private rule X`
  (`global` is kept, and already-private rules are untouched). A private rule
  still evaluates, so rules that reference it keep working, but it never
  reports a match. Each suppression is reported as `suppressed`.
- A pattern that matches nothing is reported as `unmatched`, with a warning.
- An unknown directive stops the build.

The shipped file suggests the noisiest capability and crypto-constant rules
seen on clean hosts, all commented out: `Big_Numbers*`, `BASE64_table`,
`Chacha_256_constant`, `possible_includes_base64_packed_functions` and
`with_sqlite`. Detection stays complete until you enable them.

**Finding candidates.** Scan a known-clean corpus with the new bundle:

```bash
sudo ./vestigium.sh setup --rules-only --fp-corpus /usr/bin --fp-corpus /opt/app
```

This writes `rule-fp-report.txt`:
- the rules that fired, ranked by count, each with its source file and up to
  three sample paths;
- a block of commented `#rule:<name>` lines ready to copy.

Files over 50 MB, symlinks and special files are skipped. The scan runs with a
per-file timeout of 60 s and a wall-clock limit (`--fp-timeout`, default
900 s). A scan that runs out of time is marked partial. Review each hit
before silencing it; a hit on a clean corpus is a candidate, not a verdict.

**Build report** (`rule-build-report.csv`). Its columns are `Repository`,
`File` (relative path), `Status`, `Reason`, `RuleCount` and `Rules`. The
`Status` values are:

| Status | Meaning |
|---|---|
| `accepted` | built into the bundle |
| `skipped` | left out by validation; `Reason` says why |
| `excluded` | dropped by a `file:` exclusion |
| `suppressed` | one row per rule made private by a `rule:` exclusion |
| `unmatched` | an exclusion pattern that matched nothing |

The Windows report uses capitalised statuses and has no `RuleCount` column.

## `rules.lock`

The lock is an INI-like text file: `key = value` lines under sections. It is
diff-friendly and parsed identically by bash, Python and PowerShell.

```ini
[lock]
format = 1
generated = 2026-09-11T04:25:16Z
builder = build-yara-rules.py (Linux)
yara = 4.5.0

[source signature-base]            ; one section per source, in precedence order
url = https://github.com/Neo23x0/signature-base.git
ref =                              ; requested ref (empty = default branch)
commit = 43b2b2faafdaeb7f00102673f62555a2feb04c1b
commit_date = 2026-06-17T12:05:58+02:00

[custom]
files = 0
sha256 = e3b0…                     ; digest over custom/ (line endings normalised)

[exclusions]
sha256 = d97d…                     ; exclusions.conf digest (none = absent)
files_excluded = 0
rules_suppressed = 0

[bundle]
file = active-rules.yar
sha256 = 8b63…                     ; SHA256 of active-rules.yar
rules = 15683                      ; all rule declarations
rules_reporting = 15660            ; excluding private rules
files_accepted = 1090
files_skipped = 140
```

- The bundle is **deterministic**. It contains no timestamps, and file markers
  use paths relative to the rules directory. The same sources, `custom/`,
  exclusions, builder and yara version therefore give the same SHA256 on any
  machine and in any directory.
- A build that would change only the `generated` line leaves the lock file
  untouched, so the weekly job opens a pull request only when something real
  changed.
- **Linux and Windows builders** follow the same rules and emit the same
  bundle format. One difference remains: the Linux builder also compiles each
  file on its own. A few Yara-Rules files reference private rules defined in
  another file (for example `is__elf` from `malware/000_common_rules.yar`).
  The Linux builder drops them, while the Windows builder, which checks only
  the whole bundle, keeps them. A lock produced on one platform can therefore
  report `MISMATCH` on the other; the report lists the differing inputs.
  Treat the Linux/CI lock as the reference.

## Weekly CI loop

[`.github/workflows/yara-rules.yml`](../.github/workflows/yara-rules.yml)
runs every Monday and on demand:

1. On `ubuntu-latest`, it installs `yara` and `git` and runs
   `setup-tools.sh --rules-only --fp-corpus /usr/bin`, which fetches the
   latest upstream commits, validates, builds, writes the lock and runs the
   false-positive scan.
2. It fails when the bundle does not compile. It then compiles
   `active-rules.yar` again with `yarac` as an independent check.
3. It uploads `rule-build-report.csv`, `rule-fp-report.txt` and `rules.lock`
   as artifacts.
4. When `rules.lock` changed, it opens or updates a pull request from branch
   `automation/yara-rules`. The PR body lists old and new commits per source
   and the rule-count delta. Only `rules.lock` is committed; the bundle never
   is.

**Maintainer loop:**
1. Open the PR and download the artifacts.
2. Compare the build report and the FP report with the previous run's.
3. Adjust `exclusions.conf` on the PR branch if needed.
4. Merge.
5. Field kits pull the repository and run `setup --rules-locked`, which
   rebuilds exactly the reviewed commits and confirms the SHA256.

**Workflow notes:**
- Pull requests created with the default `GITHUB_TOKEN` do not trigger other
  workflows. To run `tests.yml` on them, store a fine-grained token with
  *contents* and *pull-requests* write access as the repository secret
  `RULES_PR_TOKEN`.
- A private source needs credentials in CI too, for example a deploy key
  loaded with `webfactory/ssh-agent` before the build step.

## Offline and air-gapped kits

- Stage on a connected workstation with `sudo ./vestigium.sh setup` (or
  `--rules-locked` for the reviewed set), then copy the whole kit, including
  the source checkouts, to removable media.
- On the air-gapped side, `setup --rules-only --offline` rebuilds from the
  checkouts present. It is useful after editing `custom/` or
  `exclusions.conf`, and it rewrites the lock.
- `setup --rules-locked --offline` succeeds only when every checkout is
  already at its locked commit. It fails clearly otherwise, and reports
  whether the rebuilt bundle matches the lock.
- `--verify` needs no network. It shows each source's checkout commit against
  the lock, whether the bundle's SHA256 matches the lock, and the bundle's age.
- Without git on the host, commits are read from `.git/HEAD`.

## The compiled bundle and yara versions

`active-rules.compiled` is written by `yarac` and loads only with a
compatible libyara version. The Linux collector's kit wrapper prefers the
host's own `yara`, which may be a different version. The collector therefore
uses the compiled bundle only when:
- it is newer than `active-rules.yar`, and
- it loads in a probe scan.

Otherwise it falls back to the source bundle, which is slower because it is
compiled per scan but always works. The builder replaces `active-rules.yar`
first and the compiled file second, and removes a compiled file it could not
rebuild, so a stale compiled bundle is never used. Rebuild the rules
(`--rules-only --offline`) after changing the yara version on a staging
workstation. The Windows collector always uses the source bundle.

## Licensing

The rule repositories keep their own licences. They are cloned and built on
your machine, never committed to this repository and never shipped in its
releases:

- **signature-base** (Florian Roth / Nextron Systems): Detection Rule
  License (DRL) 1.1. Redistribution and derived works must keep attribution to
  the rule authors; the rules carry `author` / `reference` metadata, and the
  bundle keeps every rule's original text.
- **Yara-Rules** (`rules`): GNU GPL-2.0. A bundle containing these rules is a
  GPL-2.0 work if you distribute it; provide the source (the bundle is its
  own source) and the licence.

Kits handed to third parties (clients, other teams) carry the built bundle
and the checkouts, including each repository's `LICENSE`, so check the
licence terms before handing one over. Your `custom/` rules are yours to
license.
