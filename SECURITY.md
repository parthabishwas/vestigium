# Security policy

Vestigium runs with root or Administrator privileges on hosts that may already
be compromised, so defects in it can matter more than in ordinary tooling. Thank
you for reporting them responsibly.

## Supported versions

| Version | Supported |
|---|---|
| 2.x | Yes |
| < 2.0 (Ubuntu DFIR collector 1.0, DFIRCollector 1.x) | No, upgrade to 2.x |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Email: **info@parthabishwas.com**, subject `Vestigium security: <short title>`
- Or use GitHub's private vulnerability reporting on this repository (the
  *Security* tab, then *Report a vulnerability*)

Include the affected version or commit, the platform, reproduction steps or a
proof of concept, and the impact you expect. You can expect an acknowledgement
within **5 business days** and a status update at least every two weeks until
the issue is resolved. Fixes are released as soon as practical, and reporters
are credited in the changelog unless they prefer otherwise.

## In scope

- Code execution, privilege escalation or file overwrite reachable by a local
  user on the host being collected. Examples: temp-file races, `PATH` or
  `LD_LIBRARY_PATH` hijacking of kit wrappers, unsafe handling of attacker-named
  files.
- Evidence integrity failures: tampering that goes undetected by
  `vestigium verify`, or hash inventories that do not cover what they claim to.
- Unsafe archive handling in the verifiers, such as path traversal or special
  file modes.
- Collection of data beyond the configured policy: credential stores in
  metadata mode, session stores without `--browser-sessions`, private keys or
  keyring contents (see [docs/DATA-HANDLING.md](docs/DATA-HANDLING.md)).
- Unexpected outbound network activity during a collection.

## Out of scope

- Findings in the third-party YARA rules, IOC lists or staged binaries. Report
  those to their upstream projects.
- Detection gaps and false positives in rules. Open a normal issue, or tune
  them with `shared/yara-rules/exclusions.conf`.
- Issues that need an already-privileged attacker on the analyst's own
  workstation.
