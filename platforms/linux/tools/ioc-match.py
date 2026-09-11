#!/usr/bin/env python3
"""Cross-reference collected evidence against signature-base IOC lists.

Reads the hashes, filenames, hostnames and IP addresses that the collector has
already written into the evidence tree and compares them with:

  hash-iocs.txt      md5/sha1/sha256 of known-bad files
  filename-iocs.txt  regular expressions for known-bad file paths
  c2-iocs.txt        command-and-control hosts and IP addresses

Paths under any --exclude-prefix (repeatable; the collector passes the
Vestigium kit root and the evidence output base) are ignored, so the kit's own
rule sources and IOC lists can never match themselves.

Everything is local; nothing is sent anywhere and no DNS lookups are made.
Standard library only.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import warnings
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

HASH_RE = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 candidates (validated by the ipaddress module afterwards). Covers the
# bracketed "[addr]:port" form ss prints and IPv4-mapped "::ffff:a.b.c.d".
IPV6_RE = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3}")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
PATH_TOKEN_RE = re.compile(r"/[\w./ +@-]{4,}")

# Filename patterns that must be matched individually when grouped: numbered
# or named back-references change meaning once patterns are concatenated.
BACKREF_RE = re.compile(r"(?<!\\)(?:\\\\)*\\(?:[1-9]|g<)|\(\?P=")
LEADING_FLAGS_RE = re.compile(r"^\(\?([aiLmsux]+)\)")
GROUP_SIZE = 64

# Evidence files worth mining, relative to the evidence root.
EVIDENCE_HASH_SOURCES = [
    "02_Processes/process_details.csv",
    "08_Network/listening_sockets.csv",
    "12_Security/integrity/unpackaged_binaries.txt",
    "15_Filesystem/suid_unpackaged.txt",
    "15_Filesystem/executables_in_temp.txt",
    "20_Hashes/SHA256SUMS.txt",
]

EVIDENCE_NETWORK_SOURCES = [
    "08_Network/established_connections.csv",
    "08_Network/ss_established.txt",
    "08_Network/ss_all.txt",
    "11_Hosts/etc_hosts",
    "11_Hosts/hosts_review.txt",
    "08_Network/proxy_configuration.txt",
]


def read_text(path: str, limit_mb: int = 64) -> str:
    try:
        if os.path.getsize(path) > limit_mb * 1024 * 1024:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def walk_files(root: str, names: Iterable[str]) -> List[str]:
    found = []
    for name in names:
        candidate = os.path.join(root, name)
        if os.path.isfile(candidate):
            found.append(candidate)
    return found


def make_excluder(prefixes: Iterable[str]) -> Callable[[str], bool]:
    """Predicate: True when a path lies under one of the excluded prefixes."""
    roots: Set[str] = set()
    for prefix in prefixes:
        if not prefix:
            continue
        for variant in (os.path.normpath(prefix), os.path.realpath(prefix)):
            variant = variant.rstrip("/")
            if variant:                      # never let "/" exclude everything
                roots.add(variant)
    ordered = tuple(sorted(roots))

    def excluded(path: str) -> bool:
        return any(path == root or path.startswith(root + "/") for root in ordered)
    return excluded


def external_address(token: str) -> Optional[str]:
    """Canonical text of a globally routable unicast address, else None.

    ipaddress.is_global excludes RFC1918, loopback, link-local, CGNAT
    100.64/10, benchmarking 198.18/15, documentation, ULA fc00::/7 and more.
    """
    try:
        addr = ipaddress.ip_address(token)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not addr.is_global or addr.is_multicast:
        return None
    return str(addr)


# ---------------------------------------------------------------------------
class NamePattern:
    __slots__ = ("raw", "regex", "description", "exclude")

    def __init__(self, raw: str, regex: "re.Pattern[str]", description: str,
                 exclude: "Optional[re.Pattern[str]]") -> None:
        self.raw = raw
        self.regex = regex
        self.description = description
        self.exclude = exclude


def load_hash_iocs(path: str) -> Dict[str, str]:
    """hash-iocs.txt lines look like: <hash>;<description>"""
    table: Dict[str, str] = {}
    for line in read_text(path, limit_mb=128).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(";", 1)
        digest = parts[0].strip().lower()
        if HASH_RE.fullmatch(digest):
            table[digest] = parts[1].strip() if len(parts) > 1 else ""
    return table


def load_filename_iocs(path: str) -> List[NamePattern]:
    """filename-iocs.txt: '# description' comment lines followed by
    REGEX;SCORE[;FALSE-POSITIVE-EXCLUSION-REGEX] entries."""
    patterns: List[NamePattern] = []
    seen: Set[str] = set()
    comment = ""
    for line in read_text(path, limit_mb=64).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            comment = line.lstrip("#").strip()
            continue
        parts = line.split(";")
        raw = parts[0].strip()
        if len(raw) < 6 or raw in seen:   # too short: guaranteed false positives
            continue
        score = parts[1].strip() if len(parts) > 1 else ""
        fp_raw = ";".join(parts[2:]).strip()
        try:
            regex = re.compile(raw)
            exclude = re.compile(fp_raw) if fp_raw else None
        except re.error:
            continue
        seen.add(raw)
        description = comment or ""
        if score:
            description = f"{description} (score {score})" if description else f"score {score}"
        patterns.append(NamePattern(raw, regex, description, exclude))
    return patterns


def scoped(raw: str) -> str:
    """Turn a leading global flag group "(?i)x" into a scoped "(?i:x)" so the
    pattern can sit inside an alternation."""
    match = LEADING_FLAGS_RE.match(raw)
    if match:
        return f"(?{match.group(1)}:{raw[match.end():]})"
    return f"(?:{raw})"


def group_patterns(patterns: List[NamePattern]) -> List[Tuple["re.Pattern[str]", List[NamePattern]]]:
    """Pre-filter groups: one alternation regex per GROUP_SIZE patterns.

    A path is tested against each group once; only when a group matches are
    its members tested individually. That turns O(paths x patterns) Python
    calls into O(paths x groups) with the same results: members are always
    confirmed with their own regex, in file order. A group that fails to
    compile is split until each piece compiles or is a single pattern.
    """
    groups: List[Tuple["re.Pattern[str]", List[NamePattern]]] = []

    def add(members: List[NamePattern]) -> None:
        if len(members) == 1:
            groups.append((members[0].regex, members))
            return
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                combined = re.compile("|".join(scoped(m.raw) for m in members))
        except (re.error, Warning, RecursionError, OverflowError):
            half = len(members) // 2
            add(members[:half])
            add(members[half:])
            return
        groups.append((combined, members))

    batch: List[NamePattern] = []
    for pattern in patterns:
        if BACKREF_RE.search(pattern.raw):
            if batch:
                add(batch)
                batch = []
            add([pattern])
            continue
        batch.append(pattern)
        if len(batch) >= GROUP_SIZE:
            add(batch)
            batch = []
    if batch:
        add(batch)
    return groups


def first_name_match(path: str, groups) -> Optional[NamePattern]:
    for combined, members in groups:
        if not combined.search(path):
            continue
        for member in members:
            if member.regex.search(path) and not (member.exclude and member.exclude.search(path)):
                return member
    return None


def load_c2_iocs(path: str) -> Set[str]:
    entries: Set[str] = set()
    for line in read_text(path, limit_mb=64).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value = line.split(";", 1)[0].strip().lower()
        if not value:
            continue
        try:
            value = str(ipaddress.ip_address(value))   # canonical IPv6 text
        except ValueError:
            pass
        entries.add(value)
    return entries


# ---------------------------------------------------------------------------
def collect_hashes(evidence: str, excluded: Callable[[str], bool]) -> Dict[str, Set[str]]:
    """digest -> set of contexts it appeared in"""
    hashes: Dict[str, Set[str]] = {}
    for path in walk_files(evidence, EVIDENCE_HASH_SOURCES):
        text = read_text(path)
        for line in text.splitlines():
            # The first absolute path on a line is the file the hash belongs to.
            first = PATH_TOKEN_RE.search(line)
            if first and excluded(first.group(0).strip()):
                continue
            for match in HASH_RE.findall(line):
                digest = match.lower()
                hashes.setdefault(digest, set()).add(
                    f"{os.path.relpath(path, evidence)}: {line.strip()[:200]}")
    # Per-user download hashes, written one file per profile.
    users_dir = os.path.join(evidence, "14_Users", "profiles")
    if os.path.isdir(users_dir):
        for user in os.listdir(users_dir):
            candidate = os.path.join(users_dir, user, "downloads_hashes.txt")
            if os.path.isfile(candidate):
                for line in read_text(candidate).splitlines():
                    for match in HASH_RE.findall(line):
                        hashes.setdefault(match.lower(), set()).add(
                            f"14_Users/profiles/{user}/downloads_hashes.txt: {line.strip()[:200]}")
    return hashes


def collect_paths(evidence: str, excluded: Callable[[str], bool]) -> Set[str]:
    paths: Set[str] = set()
    candidates = [
        "02_Processes/process_details.csv",
        "15_Filesystem/executables_in_temp.txt",
        "15_Filesystem/suid_sgid_binaries.txt",
        "15_Filesystem/timeline_system_30d.txt",
        "15_Filesystem/timeline_home_30d.txt",
    ]
    for path in walk_files(evidence, candidates):
        for line in read_text(path).splitlines():
            for token in PATH_TOKEN_RE.findall(line):
                token = token.strip()
                if not excluded(token):
                    paths.add(token)
    return paths


def collect_network(evidence: str) -> Tuple[Set[str], Set[str], Set[str]]:
    ipv4: Set[str] = set()
    ipv6: Set[str] = set()
    domains: Set[str] = set()
    for path in walk_files(evidence, EVIDENCE_NETWORK_SOURCES):
        text = read_text(path)
        for token in IPV4_RE.findall(text):
            addr = external_address(token)
            if addr:
                ipv4.add(addr)
        for token in IPV6_RE.findall(text):
            if token.count(":") < 2:
                continue
            addr = external_address(token)
            if addr:
                (ipv4 if "." in addr else ipv6).add(addr)
        for domain in DOMAIN_RE.findall(text):
            domains.add(domain.lower())
    return ipv4, ipv6, domains


# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ioc-dir", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--exclude-prefix", action="append", default=[], metavar="PATH",
                        help="ignore evidence paths under PATH (repeatable)")
    args = parser.parse_args()

    excluded = make_excluder(args.exclude_prefix)

    hash_iocs = load_hash_iocs(os.path.join(args.ioc_dir, "hash-iocs.txt"))
    name_iocs = load_filename_iocs(os.path.join(args.ioc_dir, "filename-iocs.txt"))
    name_groups = group_patterns(name_iocs)
    c2_iocs = load_c2_iocs(os.path.join(args.ioc_dir, "c2-iocs.txt"))

    evidence_hashes = collect_hashes(args.evidence, excluded)
    evidence_paths = collect_paths(args.evidence, excluded)
    evidence_ipv4, evidence_ipv6, evidence_domains = collect_network(args.evidence)

    lines: List[str] = []
    lines.append("IOC CROSS-REFERENCE REPORT")
    lines.append("==========================")
    lines.append("")
    lines.append(f"IOC source directory : {args.ioc_dir}")
    lines.append(f"Evidence root        : {args.evidence}")
    for prefix in args.exclude_prefix:
        lines.append(f"Excluded prefix      : {prefix}")
    lines.append("")
    lines.append("Loaded indicators")
    lines.append(f"  file hashes        : {len(hash_iocs)}")
    lines.append(f"  filename patterns  : {len(name_iocs)}")
    lines.append(f"  C2 hosts/addresses : {len(c2_iocs)}")
    lines.append("")
    lines.append("Evidence extracted from this collection")
    lines.append(f"  unique hashes      : {len(evidence_hashes)}")
    lines.append(f"  unique paths       : {len(evidence_paths)}")
    lines.append(f"  external IPv4      : {len(evidence_ipv4)}")
    lines.append(f"  external IPv6      : {len(evidence_ipv6)}")
    lines.append(f"  hostnames          : {len(evidence_domains)}")
    lines.append("")

    hits = 0

    lines.append("--- hash matches ---")
    for digest, contexts in sorted(evidence_hashes.items()):
        if digest in hash_iocs:
            hits += 1
            lines.append(f"MATCH hash {digest}")
            lines.append(f"      description: {hash_iocs[digest] or '(none supplied)'}")
            for context in sorted(contexts)[:5]:
                lines.append(f"      seen in: {context}")
    if hits == 0:
        lines.append("(no hash matches)")

    before = hits
    lines.append("")
    lines.append("--- filename pattern matches ---")
    for path in sorted(evidence_paths):
        pattern = first_name_match(path, name_groups)
        if pattern is not None:
            hits += 1
            lines.append(f"MATCH path {path}")
            lines.append(f"      pattern: {pattern.raw}")
            lines.append(f"      description: {pattern.description or '(none supplied)'}")
    if hits == before:
        lines.append("(no filename matches)")

    before = hits
    lines.append("")
    lines.append("--- command-and-control matches ---")
    for value in sorted(evidence_ipv4 | evidence_ipv6 | evidence_domains):
        if value in c2_iocs:
            hits += 1
            lines.append(f"MATCH c2 {value}")
    if hits == before:
        lines.append("(no C2 matches)")

    lines.append("")
    lines.append(f"Total matches: {hits}")
    lines.append("")
    lines.append("Matches are investigative leads. Signature-base IOC lists are broad")
    lines.append("and historical; confirm each hit against the artifact itself before")
    lines.append("drawing conclusions.")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    print(f"IOC cross-reference complete: {hits} match(es) written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
