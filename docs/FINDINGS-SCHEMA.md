# Findings schema (`vestigium/findings/1`)

Both collectors emit the same two files at the **root of the evidence tree**,
so an analyst opens the same thing whichever platform produced the package:

| File | What it is |
|---|---|
| `findings.json` | Machine-readable triage findings (this schema). Feeds SIEM, ticketing and review tooling. |
| `findings.html` | A self-contained, offline HTML view of the same data. No network, no external files. |

`findings.html` is the shared template `shared/report/findings-template.html`
with the JSON injected (see [Rendering](#rendering)). The report UI therefore
has one source of truth; each platform only produces the JSON.

Findings are **automated observations to prioritise review, not verdicts**.
Every one points at the raw artifact it came from, so it can be confirmed.

## Top-level object

```jsonc
{
  "schema": "vestigium/findings/1",
  "tool": "Vestigium",
  "generated_utc": "2026-09-11T04:12:03Z",
  "case_id": "IR-2026-014",
  "host": {
    "hostname": "web01",
    "platform": "linux",              // "linux" | "windows"
    "os": "Ubuntu 24.04.4 LTS",
    "os_version": "24.04"
  },
  "collection": {
    "status": "completed",            // "completed" | "interrupted"
    "collector_version": "2.0.0",
    "evidence_root": "web01_20260911_101500",
    "started_utc": "2026-09-11T10:15:00Z",
    "ended_utc": "2026-09-11T10:31:07Z",
    "duration_seconds": 967
  },
  "counts": { "critical": 0, "high": 2, "medium": 5, "low": 0, "info": 3, "total": 10 },
  "findings": [ /* Finding objects, see below */ ],
  "gaps": [
    "No memory image was captured; memory-resident implants cannot be excluded."
  ],
  "notes": [
    "Automated observations to prioritise review, not conclusions.",
    "Confirm each item against the underlying artifact before reporting it."
  ]
}
```

## Finding object

```jsonc
{
  "id": "linux.persistence.ld_preload",   // stable, dotted: <platform>.<category>.<name>
  "title": "/etc/ld.so.preload present",
  "severity": "critical",                 // critical | high | medium | low | info
  "category": "persistence",
  "count": 1,                             // number of underlying items
  "summary": "The dynamic-linker preload file exists (classic rootkit persistence).",
  "detail": "",                           // optional, longer context
  "evidence": [                           // evidence-relative paths, forward slashes
    "03_Persistence/dynamic-linker/ld.so.preload.txt"
  ],
  "items": [                              // sample underlying lines, capped at 50
    "/usr/lib/evil.so"
  ],
  "note": ""                              // optional caveat, e.g. "leads, not verdicts"
}
```

### Fields

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Stable across runs. `<platform>.<category>.<name>`, lowercase, dotted. Tools group and de-duplicate on this. |
| `title` | yes | Short human label. |
| `severity` | yes | One of the five levels below. Drives ordering and colour. |
| `category` | yes | See the recommended set below; free-form is allowed. |
| `count` | yes | Underlying item count (e.g. matched lines). `0` is allowed for an informational finding. |
| `summary` | yes | One sentence. |
| `detail` | no | Longer context; may be empty. |
| `evidence` | yes | Zero or more evidence-relative paths (forward slashes), so the reader can open the source. |
| `items` | no | Up to 50 sample lines from the source. Truncation is indicated by `count > len(items)`. |
| `note` | no | Caveat, e.g. that signature hits are leads. |

### Severity

| Level | Meaning |
|---|---|
| `critical` | Strong indicator of compromise that usually warrants immediate action (e.g. `ld.so.preload` present, a confirmed AV detection, a process running a deleted binary). |
| `high` | Likely malicious or high-risk and expected to be reviewed first (unsigned autostart from a user-writable path, LD_PRELOAD injection, non-store browser extension with dangerous permissions). |
| `medium` | Worth review; benign explanations exist (unpackaged system binaries, world-writable files, non-ephemeral listeners). |
| `low` | Minor or contextual. |
| `info` | Context, not suspicion (counts, inventory, "nothing found" confirmations). |

### Recommended categories

`malware`, `persistence`, `process`, `network`, `account`, `integrity`,
`execution`, `filesystem`, `browser`, `memory`, `collection`.

Use `collection` for findings about the collection itself; put shortfalls that
weaken negative conclusions in the top-level `gaps` array instead.

## Rules

- `counts` must equal the number of findings at each severity. `total` is the
  finding count, not the sum of `count` fields.
- Findings are ordered by severity (critical first), then by `count` descending.
- An interrupted collection still emits findings for what was collected, with
  `collection.status` = `interrupted` and a matching `gaps` entry.
- Paths are evidence-relative and use forward slashes on both platforms.

## Rendering

`findings.html` is produced by taking `shared/report/findings-template.html`
and replacing the literal token `__VESTIGIUM_FINDINGS_JSON__` (inside the
`<script id="vestigium-findings" type="application/json">` element) with the
findings JSON.

Before injection the JSON is made safe to embed by replacing `<`, `>` and `&`
with the **JSON unicode escapes** `\u003c`, `\u003e` and `\u0026`. This is
deliberate: the content of a `<script>` element is raw text, so HTML entities
such as `&lt;` are **not** decoded there -- entity escaping would corrupt the
data and would not protect it. Unicode escapes are valid JSON that `JSON.parse`
decodes back to the original characters, and because no literal `<` survives the
data can never close the script element. `findings.json` itself is written
**unescaped** (normal JSON); only the copy embedded in the HTML is escaped.

The page reads the embedded JSON with `textContent` + `JSON.parse` and renders
it entirely client-side, with no network access.

## Producers

| Platform | Producer | Notes |
|---|---|---|
| Linux | `platforms/linux/tools/build-findings.py` | Reads the evidence tree; writes `findings.json` and injects the template. Falls back to a minimal JSON (no HTML) when `python3` is absent. |
| Windows | `platforms/windows/Modules/Findings.ps1` | Built from the same data as the triage summary; writes `findings.json` and `findings.html`. |

Both run during finalisation, **before hashing**, so the two files are covered
by the SHA256 inventory and verified by `vestigium verify`.
