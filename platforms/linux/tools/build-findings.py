#!/usr/bin/env python3
"""Build the cross-platform Vestigium findings report for a Linux collection.

Reads the evidence tree written by vestigium-linux.sh plus DFIR_MF_*
environment variables (the same ones make-manifest.py reads), constructs a
`vestigium/findings/1` object (see docs/FINDINGS-SCHEMA.md), writes it to
findings.json, and produces findings.html by injecting the escaped JSON into the
shared report template.

Findings are automated leads to prioritise review, not verdicts: every one
points at the raw artifact it came from. Standard library only; nothing is sent
anywhere and no lookups are made.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
from typing import Callable, Dict, List

MAX_ITEMS = 50
READ_LIMIT_MB = 64
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
PLACEHOLDER = "__VESTIGIUM_FINDINGS_JSON__"


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def read_text(path: str, limit_mb: int = READ_LIMIT_MB) -> str:
    """File contents, or "" when absent, unreadable or larger than the cap."""
    try:
        if os.path.getsize(path) > limit_mb * 1024 * 1024:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


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


def command_output(text: str) -> List[str]:
    """The real command output from a captured artifact.

    dfir_cmd / dfir_sh wrap output between a "### started:" header (preceded by
    the echoed label/command/script) and a "### exit code:" trailer. Returning
    only the region between them strips both the command-header lines and the
    echoed shell script body, so match rules never see the collector's own text.
    Files with no such header (e.g. a tool that wrote plain output) return whole.
    """
    lines = text.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if line.startswith("### started:"):
            start = i + 1
            break
    end = len(lines)
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].startswith("### exit code:"):
            end = i
            break
    return [line for line in lines[start:end] if not line.startswith("###")]


def nonblank(lines: List[str]) -> List[str]:
    return [line for line in lines if line.strip()]


def count_csv_rows(path: str) -> int:
    """Cheap data-row count for a quoted CSV: lines beginning with a quote, less
    the header. Robust to newlines embedded inside quoted fields (those wrapped
    lines do not start with a quote)."""
    rows = 0
    for line in read_text(path).splitlines():
        if line.startswith('"'):
            rows += 1
    return max(0, rows - 1)


def count_tsv_rows(path: str) -> int:
    return len(nonblank(read_text(path).splitlines()))


# ---------------------------------------------------------------------------
# Finding catalog
# ---------------------------------------------------------------------------
class Finding:
    """One catalog entry. `matcher(output_lines)` returns the matched lines;
    the finding is emitted when that list is non-empty."""

    def __init__(self, fid: str, severity: str, category: str, source: str,
                 title: str, summary: str,
                 matcher: Callable[[List[str]], List[str]],
                 note: str = "") -> None:
        self.fid = fid
        self.severity = severity
        self.category = category
        self.source = source
        self.title = title
        self.summary = summary
        self.matcher = matcher
        self.note = note


def rx(pattern: str) -> Callable[[List[str]], List[str]]:
    compiled = re.compile(pattern)
    return lambda lines: [line for line in lines if compiled.match(line)]


def match_ld_preload(lines: List[str]) -> List[str]:
    """Emit only when the linker actually reports the file PRESENT; the items
    are the stat/content lines that describe it."""
    if not any(line.strip() == "RESULT: ld.so.preload=PRESENT" for line in lines):
        return []
    return nonblank(lines)


def match_world_writable(lines: List[str]) -> List[str]:
    """Data lines under the two "---" section headers."""
    return [line for line in nonblank(lines) if not line.lstrip().startswith("---")]


def match_nonstore_extensions(lines: List[str]) -> List[str]:
    """update_url= lines in the SUMMARY section that lists non-store extensions,
    up to the next blank line."""
    marker = "extensions not installed from an official store"
    collecting = False
    hits: List[str] = []
    for line in lines:
        if not collecting:
            if marker in line:
                collecting = True
            continue
        if not line.strip():
            break
        if "update_url=" in line:
            hits.append(line.strip())
    return hits


def match_journal_unsealed(lines: List[str]) -> List[str]:
    """Emit only when the journal is not tamper-evident."""
    if any(line.strip() == "RESULT: journal_fss=disabled" for line in lines):
        return [line.strip() for line in lines
                if line.startswith("Reason:") or line.startswith("FSS key file")]
    return []


def match_history_disabled(lines: List[str]) -> List[str]:
    return [line.strip() for line in lines if line.startswith("HISTORY-DISABLED ")]


def match_container_drift(lines: List[str]) -> List[str]:
    """Containers whose running writable layer changed under sensitive paths."""
    hits: List[str] = []
    for line in lines:
        if not line.startswith("CONTAINER-DRIFT "):
            continue
        m = re.search(r"sensitive=(\d+)", line)
        if m and int(m.group(1)) > 0:
            hits.append(line.strip())
    return hits


CATALOG: List[Finding] = [
    Finding("linux.persistence.ld_preload", "critical", "persistence",
            "03_Persistence/dynamic-linker/ld.so.preload.txt",
            "/etc/ld.so.preload present",
            "The dynamic-linker preload file exists (classic rootkit persistence).",
            match_ld_preload),
    Finding("linux.process.deleted_binary", "critical", "process",
            "02_Processes/anomaly_deleted_binaries.txt",
            "Process running a deleted binary",
            "A running process is executing a binary that was unlinked from disk.",
            rx(r"^PID ")),
    Finding("linux.malware.ioc", "critical", "malware",
            "18_Yara/ioc-matches/ioc_matches.txt",
            "IOC cross-reference match",
            "Collected evidence matched a known-bad hash, filename or C2 indicator.",
            rx(r"^MATCH ")),
    Finding("linux.integrity.hidden_process", "critical", "integrity",
            "12_Security/antirootkit/discrepancies.txt",
            "Process hidden from ps",
            "A process the kernel exposes in /proc is not reported by ps (or by "
            "busybox ps) - a userland-rootkit indicator.",
            rx(r"^HIDDEN-PROC "),
            note="Confirm against /proc; a process that exited mid-scan is a benign cause."),
    Finding("linux.integrity.hidden_module", "critical", "integrity",
            "12_Security/antirootkit/discrepancies.txt",
            "Kernel module hidden from lsmod",
            "A live module in /sys/module or /proc/modules is not listed by lsmod "
            "- a rootkit-hiding indicator.",
            rx(r"^HIDDEN-MODULE ")),
    Finding("linux.integrity.hidden_port", "high", "network",
            "12_Security/antirootkit/discrepancies.txt",
            "Listening port hidden from ss/netstat",
            "A socket the kernel lists in /proc/net is not shown by ss or netstat.",
            rx(r"^HIDDEN-PORT ")),
    Finding("linux.integrity.dir_link_mismatch", "high", "filesystem",
            "12_Security/antirootkit/discrepancies.txt",
            "Directory link count exceeds visible sub-directories",
            "A directory's link count implies more sub-directories than readdir "
            "returns - a hidden directory indicator.",
            rx(r"^DIR-NLINK-MISMATCH ")),
    Finding("linux.integrity.hidden_dir_entry", "medium", "filesystem",
            "12_Security/antirootkit/discrepancies.txt",
            "Directory listing tools disagree",
            "ls, busybox ls and a bash glob returned different entry counts for a "
            "directory - a tool may be filtering readdir.",
            rx(r"^HIDDEN-DIR-ENTRY ")),
    Finding("linux.process.ld_preload", "high", "process",
            "02_Processes/anomaly_ld_preload.txt",
            "Process with dynamic-linker injection variables set",
            "A process has LD_PRELOAD, LD_LIBRARY_PATH or LD_AUDIT set in its environment.",
            rx(r"^PID ")),
    Finding("linux.process.suspicious_path", "high", "process",
            "02_Processes/anomaly_suspicious_exec_paths.txt",
            "Process executing from a temporary or user-writable path",
            "A process runs from /tmp, /dev/shm, a home or a web directory.",
            rx(r"^PID ")),
    Finding("linux.malware.yara_file", "high", "malware",
            "18_Yara/yara_matches.txt",
            "YARA rule match on a file",
            "A YARA rule matched a collected file.",
            rx(r"^[A-Za-z_][A-Za-z0-9_]* (\[[^]]*\] )?/"),
            note="YARA hits are leads, not verdicts; triage each against the file."),
    Finding("linux.malware.yara_process", "high", "malware",
            "18_Yara/yara_process_matches.txt",
            "YARA rule match on process memory",
            "A YARA rule matched the memory of a running process.",
            rx(r"^=== PID")),
    Finding("linux.integrity.suid_unpackaged", "high", "integrity",
            "15_Filesystem/suid_unpackaged.txt",
            "Setuid binary not owned by any package",
            "A setuid executable exists that no installed package owns.",
            rx(r"^UNPACKAGED")),
    Finding("linux.persistence.unpackaged_pam", "high", "persistence",
            "03_Persistence/pam/unpackaged-pam-modules.txt",
            "PAM module not owned by any package",
            "A PAM module exists that no installed package owns (credential-theft vector).",
            rx(r"^UNPACKAGED")),
    Finding("linux.browser.nonstore_extensions", "high", "browser",
            "09_Browser/SUMMARY.txt",
            "Browser extension not installed from an official store",
            "A browser extension was sideloaded from outside an official store.",
            match_nonstore_extensions),
    Finding("linux.integrity.unpackaged_binaries", "medium", "integrity",
            "12_Security/integrity/unpackaged_binaries.txt",
            "Unpackaged binary in a system directory",
            "An executable in a system binary directory is not owned by any package.",
            rx(r"^UNPACKAGED")),
    Finding("linux.integrity.modified_packaged", "medium", "integrity",
            "12_Security/integrity/dpkg_verify.txt",
            "Packaged file modified from its distribution state",
            "A packaged file differs in checksum, mode or ownership from the package database.",
            rx(r"^(?:..5|\?\?)")),
    Finding("linux.persistence.unpackaged_units", "medium", "persistence",
            "03_Persistence/systemd/unpackaged-units.txt",
            "Systemd unit not owned by any package",
            "A systemd unit file exists that no installed package owns.",
            rx(r"^=== ")),
    Finding("linux.filesystem.temp_executables", "medium", "filesystem",
            "15_Filesystem/executables_in_temp.txt",
            "Executable in a temporary directory",
            "An executable file was found under /tmp, /var/tmp or /dev/shm.",
            rx(r"^/(?:tmp|var/tmp|dev/shm)/")),
    Finding("linux.integrity.container_drift", "high", "integrity",
            "16_Containers/docker/container_diffs.txt",
            "Running container changed system files",
            "A running container's writable layer differs from its image under "
            "binary, library or config paths - a possible in-container implant.",
            match_container_drift,
            note="Benign for build/CI containers; confirm the changed paths."),
    Finding("linux.account.history_disabled", "medium", "account",
            "14_Users/live-shell-history/SUMMARY.txt",
            "Live shell with on-disk history disabled",
            "An interactive shell has its on-disk history switched off "
            "(HISTFILE=/dev/null, HISTSIZE=0 or a /dev/null symlink) - a common "
            "anti-forensic step. In-memory commands were carved best-effort.",
            match_history_disabled,
            note="See 14_Users/live-shell-history/pid<pid>_*.txt for carved commands."),
    Finding("linux.integrity.journal_unsealed", "low", "integrity",
            "10_Logs/journal/journal_sealing.txt",
            "systemd journal is not tamper-evident (no FSS)",
            "Forward Secure Sealing is not active, so the journal can be edited "
            "by root without detection - corroborate journal-based timelines.",
            match_journal_unsealed),
    Finding("linux.filesystem.world_writable", "low", "filesystem",
            "15_Filesystem/world_writable.txt",
            "World-writable file or directory",
            "A world-writable filesystem entry was found.",
            match_world_writable),
]


# ---------------------------------------------------------------------------
def build_catalog_findings(evidence: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for entry in CATALOG:
        path = os.path.join(evidence, entry.source)
        if not os.path.isfile(path):
            continue
        output = command_output(read_text(path))
        matches = entry.matcher(output)
        if not matches:
            continue
        finding: Dict[str, object] = {
            "id": entry.fid,
            "title": entry.title,
            "severity": entry.severity,
            "category": entry.category,
            "count": len(matches),
            "summary": entry.summary,
            "detail": "",
            "evidence": [entry.source],
            "items": [line.rstrip() for line in matches[:MAX_ITEMS]],
        }
        if entry.note:
            finding["note"] = entry.note
        findings.append(finding)
    return findings


def read_module_results(logs: str):
    """Returns (total, not_ok, not_run) module rows from module-results.csv.
    not_ok / not_run are lists of (module, status)."""
    import csv
    path = os.path.join(logs, "module-results.csv")
    total = 0
    not_ok: List[tuple] = []
    not_run: List[tuple] = []
    text = read_text(path)
    if not text:
        return total, not_ok, not_run
    reader = csv.reader(text.splitlines())
    header_seen = False
    for row in reader:
        if not row:
            continue
        if not header_seen:
            header_seen = True
            continue
        module = row[0] if len(row) > 0 else ""
        status = row[1] if len(row) > 1 else ""
        total += 1
        if status != "OK":
            not_ok.append((module, status))
        if status == "NOT RUN":
            not_run.append((module, status))
    return total, not_ok, not_run


def build_collection_findings(evidence: str, logs: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []

    total, not_ok, _ = read_module_results(logs)
    if not_ok:
        names = ", ".join(f"{m} ({s})" for m, s in not_ok)
        modules_summary = f"{total} modules: {total - len(not_ok)} OK, {len(not_ok)} not OK ({names})"
    else:
        modules_summary = f"{total} modules: {total} OK"
    findings.append({
        "id": "linux.collection.modules",
        "title": "Module collection results",
        "severity": "info",
        "category": "collection",
        "count": len(not_ok),
        "summary": modules_summary,
        "detail": "",
        "evidence": ["19_CollectionLogs/module-results.csv"],
        "items": [f"{m}: {s}" for m, s in not_ok[:MAX_ITEMS]],
    })

    processes = count_csv_rows(os.path.join(evidence, "02_Processes/process_details.csv"))
    connections = count_csv_rows(os.path.join(evidence, "08_Network/established_connections.csv"))
    listeners = count_csv_rows(os.path.join(evidence, "08_Network/listening_sockets.csv"))
    profiles = count_tsv_rows(os.path.join(logs, "target-users.tsv"))
    inventory_sources = [
        "02_Processes/process_details.csv",
        "08_Network/established_connections.csv",
        "08_Network/listening_sockets.csv",
        "19_CollectionLogs/target-users.tsv",
    ]
    findings.append({
        "id": "linux.collection.summary",
        "title": "Collection inventory",
        "severity": "info",
        "category": "collection",
        "count": 0,
        "summary": (f"{processes} processes, {connections} connections, "
                    f"{listeners} listeners, {profiles} profiles"),
        "detail": "",
        "evidence": [s for s in inventory_sources
                     if os.path.isfile(os.path.join(evidence, s))],
        "items": [],
    })
    return findings


def build_gaps(evidence: str, logs: str, status: str) -> List[str]:
    gaps: List[str] = []

    if os.path.isfile(os.path.join(evidence, "17_Memory/memory-image-NOT-COLLECTED.txt")):
        gaps.append("No memory image was captured (--memory); memory-resident "
                    "implants cannot be excluded.")

    if os.path.isfile(os.path.join(evidence, "12_Security/integrity/SKIPPED-in-quick-mode.txt")):
        gaps.append("Package integrity verification (dpkg/debsums) was skipped "
                    "in --quick mode.")

    incomplete = os.path.isfile(os.path.join(logs, "INCOMPLETE.txt"))
    if status == "interrupted" or incomplete:
        _, _, not_run = read_module_results(logs)
        message = "Collection was interrupted; findings cover only what was collected."
        if not_run:
            message += " Modules not run: " + ", ".join(m for m, _ in not_run) + "."
        gaps.append(message)

    warnings, errors = count_log_levels(os.path.join(logs, "collection.log"))
    gaps.append(f"collection.log recorded {warnings} warning(s) and {errors} "
                "error(s); review before relying on any negative finding.")
    return gaps


def count_log_levels(path: str) -> tuple:
    warnings = errors = 0
    for line in read_text(path).splitlines():
        if "[WARN]" in line:
            warnings += 1
        elif "[ERROR]" in line:
            errors += 1
    return warnings, errors


def escape_json_for_html(text: str) -> str:
    return (text.replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--template", required=True)
    parser.add_argument("--json-out", required=True, dest="json_out")
    parser.add_argument("--html-out", required=True, dest="html_out")
    args = parser.parse_args()

    evidence = args.evidence.rstrip("/")
    logs = os.path.join(evidence, "19_CollectionLogs")

    os_release = read_os_release()
    status = env("DFIR_MF_STATUS", "completed") or "completed"

    findings = build_catalog_findings(evidence)
    findings += build_collection_findings(evidence, logs)

    order = {name: i for i, name in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: (order.get(str(f["severity"]), 9), -int(str(f["count"]))))

    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        level = str(finding["severity"])
        if level in counts:
            counts[level] += 1
    counts["total"] = len(findings)

    obj: Dict[str, object] = {
        "schema": "vestigium/findings/1",
        "tool": "Vestigium",
        "generated_utc": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "case_id": env("DFIR_MF_CASE"),
        "host": {
            "hostname": env("DFIR_MF_HOST"),
            "platform": "linux",
            "os": os_release.get("PRETTY_NAME", ""),
            "os_version": os_release.get("VERSION_ID", ""),
        },
        "collection": {
            "status": status,
            "collector_version": env("DFIR_MF_VER"),
            "evidence_root": os.path.basename(evidence),
            "started_utc": env("DFIR_MF_START"),
            "ended_utc": env("DFIR_MF_END"),
            "duration_seconds": int(env("DFIR_MF_DUR", "0") or 0),
        },
        "counts": counts,
        "findings": findings,
        "gaps": build_gaps(evidence, logs, status),
        "notes": [
            "Findings are automated leads, not verdicts; confirm each against "
            "the underlying artifact.",
        ],
    }

    serialized = json.dumps(obj, indent=2)

    os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
    with open(args.json_out, "w", encoding="utf-8") as handle:
        handle.write(serialized + "\n")

    template = read_text(args.template, limit_mb=16)
    if template and PLACEHOLDER in template:
        escaped = escape_json_for_html(serialized)
        html = template.replace(PLACEHOLDER, escaped)
        with open(args.html_out, "w", encoding="utf-8") as handle:
            handle.write(html)
    else:
        # No usable template: the JSON still stands on its own.
        print(f"WARNING: template not found or missing {PLACEHOLDER}; "
              f"skipped {args.html_out}")

    print(f"Findings report: {counts['total']} finding(s) written to {args.json_out}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
