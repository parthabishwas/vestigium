#!/usr/bin/env python3
"""Emit the JSON manifest for a Vestigium Linux collection.

Reads the evidence tree written by vestigium-linux.sh plus DFIR_MF_*
environment variables and prints the manifest to stdout. Standard library only.
No DNS lookups are made: host identity comes from uname and local files.
"""

from __future__ import annotations

import csv
import json
import os
import platform
import sys
from typing import Any, Dict, List


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def read_csv(path: str) -> List[Dict[str, str]]:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    except OSError:
        return []


def read_os_release() -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if "=" in line:
                    key, _, value = line.partition("=")
                    values[key.strip()] = value.strip().strip('"')
    except OSError:
        pass
    return values


def read_first_line(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.readline().strip()
    except OSError:
        return ""


def read_findings_counts(evidence: str):
    """Severity counts from findings.json, or None when it is absent/unreadable."""
    path = os.path.join(evidence, "findings.json")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    counts = data.get("counts") if isinstance(data, dict) else None
    return counts if isinstance(counts, dict) else None


def main() -> int:
    evidence = env("DFIR_MF_EVID")
    logs = os.path.join(evidence, "19_CollectionLogs")
    hashes_csv = os.path.join(evidence, "20_Hashes", "SHA256SUMS.csv")

    results = read_csv(os.path.join(logs, "module-results.csv"))
    commands = read_csv(os.path.join(logs, "command-log.csv"))
    provenance = read_csv(os.path.join(logs, "provenance.csv"))
    hashes = read_csv(hashes_csv)

    users: List[Dict[str, str]] = []
    users_tsv = os.path.join(logs, "target-users.tsv")
    if os.path.isfile(users_tsv):
        with open(users_tsv, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 5:
                    users.append({
                        "username": parts[0], "uid": parts[1], "gid": parts[2],
                        "home": parts[3], "shell": parts[4],
                    })

    os_release = read_os_release()

    # Exit-code classification matches the collector's own:
    #   0 captured, 1 "nothing found", 127 tool absent (skipped),
    #   141 SIGPIPE from an intentional `| head -n N`, anything else = failure.
    def classify(code: str) -> str:
        if code in ("0", "1"):
            return "ok"
        if code == "127":
            return "skipped"
        if code == "141":
            return "ok"
        return "failed"

    skipped_commands = [
        {"label": row.get("Label", ""), "command": row.get("Command", "")}
        for row in commands if classify(row.get("ExitCode", "")) == "skipped"
    ]
    failed_commands = [
        {
            "label": row.get("Label", ""),
            "command": row.get("Command", ""),
            "exit_code": row.get("ExitCode", ""),
            "output": row.get("OutputFile", ""),
        }
        for row in commands
        if classify(row.get("ExitCode", "")) == "failed"
    ]

    manifest: Dict[str, Any] = {
        "schema": "vestigium/linux-manifest/1",
        "tool": "Vestigium",
        "case_id": env("DFIR_MF_CASE"),
        "collector": {
            "name": "vestigium-linux.sh",
            "version": env("DFIR_MF_VER"),
            "invocation": env("DFIR_MF_ARGS"),
            "operator": env("DFIR_MF_OPER"),
        },
        "host": {
            "hostname": env("DFIR_MF_HOST"),
            "fqdn": platform.node(),            # uname nodename; no resolver query
            "machine_id": read_first_line("/etc/machine-id"),
            "boot_id": read_first_line("/proc/sys/kernel/random/boot_id"),
            "os": os_release.get("PRETTY_NAME", ""),
            "os_id": os_release.get("ID", ""),
            "os_version_id": os_release.get("VERSION_ID", ""),
            "kernel": platform.release(),
            "kernel_version": platform.version(),
            "architecture": platform.machine(),
            "product_name": read_first_line("/sys/class/dmi/id/product_name"),
            "product_serial": read_first_line("/sys/class/dmi/id/product_serial"),
            "sys_vendor": read_first_line("/sys/class/dmi/id/sys_vendor"),
        },
        "collection": {
            # "interrupted" when the operator pressed Ctrl+C once and the
            # collector finalised early (19_CollectionLogs/INCOMPLETE.txt).
            "status": env("DFIR_MF_STATUS", "completed") or "completed",
            # "copy" (default, as on Windows) or "metadata" (--credential-stores).
            "browser_credential_stores": env("DFIR_CREDENTIAL_STORES", "copy") or "copy",
            "start_utc": env("DFIR_MF_START"),
            "end_utc": env("DFIR_MF_END"),
            "duration_seconds": int(env("DFIR_MF_DUR", "0") or 0),
            "evidence_root": evidence,
            "file_count": int(env("DFIR_MF_FILES", "0") or 0),
            "total_bytes": int(env("DFIR_MF_BYTES", "0") or 0),
            "modules": results,
            "command_count": len(commands),
            "skipped_command_count": len(skipped_commands),
            "failed_command_count": len(failed_commands),
        },
        "findings_report": {
            "json": "findings.json",
            "html": "findings.html",
            "counts": read_findings_counts(evidence),
        },
        "toolkit": {
            "root": env("DFIR_MF_KIT"),
            "yara_rules_sha256": env("DFIR_MF_RULES_SHA256"),
        },
        "profiles_examined": users,
        "skipped_commands": skipped_commands[:500],
        "failed_commands": failed_commands[:500],
        "acquired_source_files": [
            {
                "source": row.get("SourcePath", ""),
                "evidence_path": row.get("EvidencePath", ""),
                "size_bytes": row.get("SizeBytes", ""),
                "mtime": row.get("MTimeUTC", ""),
                "source_sha256": row.get("SourceSHA256", ""),
            }
            for row in provenance
        ],
        "evidence_sha256": [
            {
                "path": row.get("RelativePath", ""),
                "sha256": row.get("SHA256", ""),
                "size_bytes": row.get("SizeBytes", ""),
            }
            for row in hashes
        ],
        "notes": [
            "Collected from a live, running system; volatile state reflects the "
            "moment of acquisition and cannot be reproduced exactly.",
            "Reading files updates access times on filesystems mounted with atime "
            "semantics; original timestamps are preserved in provenance.csv.",
            ("Browser credential stores (saved passwords, cookies, autofill) were "
             "copied into 09_Browser/*/credential-stores/ and contain live "
             "credential material; handle this package accordingly."
             if env("DFIR_CREDENTIAL_STORES", "copy") != "metadata" else
             "Browser credential stores were not copied (--credential-stores "
             "metadata); only their size, timestamps and SHA256 are recorded."),
            ("Browser session stores (open tabs, session cookies, form data) were "
             "collected because --browser-sessions was given."
             if env("DFIR_BROWSER_SESSIONS", "0") == "1" else
             "Browser session stores (open tabs, session cookies, form data) were "
             "not collected; only their metadata is recorded."),
        ],
    }

    json.dump(manifest, sys.stdout, indent=2, sort_keys=False)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
