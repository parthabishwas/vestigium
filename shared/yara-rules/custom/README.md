# In-house YARA rules

Files here (`*.yar`, `*.yara`, any sub-folder) are versioned with the kit and
built into `active-rules.yar` **before** every upstream source, so an
identifier used here wins over the same identifier upstream. The upstream
file that clashes is skipped entirely and listed in the build report, so pick
unique names.

## Conventions

- **One family or behaviour per file**, named after it:
  `acme_webshells_php.yar`, `apt_example_loader.yar`.
- **Prefix identifiers** with your organisation (`ACME_...`) to avoid clashes.
- **Required `meta:` fields** on every rule: `author`, `description`,
  `date` (YYYY-MM-DD) and `reference` (case, report or URL).
- **No `include` statements and no external variables**: the builder emits one
  flat bundle and skips such files.
- **Test before committing**. The builder compile-checks every file and drops
  one that fails (with a warning), so a broken rule silently loses coverage:

  ```bash
  yarac -w custom/acme_webshells_php.yar /tmp/test.compiled   # compiles alone
  yara -w -r custom/acme_webshells_php.yar /path/to/samples   # fires on known-bad
  yara -w -r custom/acme_webshells_php.yar /usr/bin           # quiet on known-clean
  sudo ./vestigium.sh setup --rules-only --offline            # rebuild the bundle
  ```

  Then check `rule-build-report.csv` for your file (`accepted`).

`example.yar.sample` shows the expected layout; it is not built.

See [docs/YARA-RULES.md](../../../docs/YARA-RULES.md) for the full lifecycle.
