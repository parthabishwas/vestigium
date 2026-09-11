#!/usr/bin/env python3
"""Build a single, compilable YARA rule bundle from the shared rule store.

Inputs (all under --rules-dir, normally <kit>/shared/yara-rules):

  custom/          the organisation's own rules; always included FIRST, so
                   they win identifier clashes
  sources.conf     rule repositories, in precedence order ("<name> <url> [ref]").
                   Without it, every sub-directory is used (legacy behaviour).
  exclusions.conf  "file:<glob>" drops rule files, "rule:<name|glob>" rewrites a
                   rule to `private rule` (still usable by other rules, never
                   reported)
  rules.lock       written after every successful build; with --locked it is
                   the input instead (exact commits) and the result is checked
                   against it

Validation, per candidate file:

  * signature-base rules listed in yara/external-variable-rules.txt are skipped
    (vanilla yara does not populate LOKI/THOR external variables),
  * include-wrapper files are skipped (this builder emits one flat bundle),
  * files with duplicate rule identifiers are skipped after the first use,
  * every candidate file is compiled on its own and dropped if it fails,
  * the assembled bundle is compiled once more and, on failure, the offending
    source file is removed and the bundle rebuilt.

The bundle is assembled in a temporary file next to --out and replaces the
old bundle (and --compiled) only when the whole build succeeded. Its content
is deterministic: the same inputs give the same SHA256. A CSV build report
records what was accepted and why anything was skipped, excluded or
suppressed. --fp-corpus scans known-clean directories with the new bundle and
writes a false-positive report.

Exit codes: 0 built; 1 build failed (existing bundle left unchanged);
2 configuration or usage error.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, NamedTuple, Optional, Tuple

RULE_NAME_RE = re.compile(
    r"^[ \t]*(?:private[ \t]+|global[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
# Same declaration shape, with the parts needed to rewrite it.
RULE_DECL_RE = re.compile(
    r"^([ \t]*)((?:(?:private|global)[ \t]+)*)rule([ \t]+)([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
INCLUDE_RE = re.compile(r'^[ \t]*include[ \t]+"', re.MULTILINE)

SKIP_DIR_NAMES = (".git", "tests", "test", "deprecated")
CUSTOM_DIR = "custom"

# sources.conf validation. Nothing that fails these checks is ever handed to git.
SOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SOURCE_URL_RE = re.compile(r"^(?:https://[^\s]+|git@[^\s:]+:[^\s]+)$")
SOURCE_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RESERVED_NAMES = {CUSTOM_DIR}

# Used only when sources.conf is missing (mirrors setup-tools.sh).
DEFAULT_SOURCES = [
    ("signature-base", "https://github.com/Neo23x0/signature-base.git", ""),
    ("rules", "https://github.com/Yara-Rules/rules.git", ""),
]

LOCK_FORMAT = "1"
FP_MAX_BYTES = 50 * 1024 * 1024


class ConfigError(Exception):
    """A configuration file is invalid; nothing is built."""


class Source(NamedTuple):
    name: str
    url: str
    ref: str
    commit: str = ""          # locked commit (--locked only)


class Exclusion(NamedTuple):
    kind: str                 # "file" or "rule"
    pattern: str
    line: int

    @property
    def label(self) -> str:
        return f"exclusions.conf line {self.line}: {self.kind}:{self.pattern}"


class RuleFile(NamedTuple):
    group: str                # "custom" or the source name
    path: str                 # absolute path
    rel: str                  # path relative to the rules dir, "/" separators
    names: List[str]


def log(message: str) -> None:
    print(f"[build-yara-rules] {message}", file=sys.stderr, flush=True)


def read_text(path: str) -> str:
    """UTF-8 (invalid bytes replaced), BOM stripped, LF line endings."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    return text[1:] if text.startswith("\ufeff") else text


def normalised_bytes(path: str) -> bytes:
    """File bytes with a UTF-8 BOM removed and CRLF/CR folded to LF, so a
    Windows checkout (core.autocrlf) hashes like a Linux one."""
    with open(path, "rb") as handle:
        data = handle.read()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def strip_comment(line: str) -> str:
    """Drops a trailing "# comment" (a # at line start or after whitespace)."""
    return re.sub(r"(^|\s)#.*$", "", line).strip()


# ---------------------------------------------------------------------------
# Configuration files
# ---------------------------------------------------------------------------
def validate_source(name: str, url: str, ref: str) -> str:
    """Returns an error message, or "" when the entry is safe to use."""
    if (not SOURCE_NAME_RE.match(name) or name.startswith((".", "-"))
            or name.lower() in RESERVED_NAMES):
        return (f"invalid source name '{name}' (letters, digits, . _ -; "
                f"must not start with . or -; '{CUSTOM_DIR}' is reserved)")
    if not SOURCE_URL_RE.match(url):
        return f"invalid URL '{url}' for source '{name}' (only https:// or git@host:path)"
    if ref and (not SOURCE_REF_RE.match(ref) or ref.startswith(("-", "/"))
                or ".." in ref or ref.endswith(("/", ".lock"))):
        return f"invalid ref '{ref}' for source '{name}'"
    return ""


def parse_sources(path: str) -> List[Source]:
    sources: List[Source] = []
    seen = set()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for number, raw in enumerate(handle, start=1):
            line = strip_comment(raw)
            if not line:
                continue
            fields = line.split()
            if len(fields) not in (2, 3):
                raise ConfigError(f"{path}:{number}: expected '<name> <git-url> [<ref>]'")
            name, url = fields[0], fields[1]
            ref = fields[2] if len(fields) == 3 else ""
            problem = validate_source(name, url, ref)
            if problem:
                raise ConfigError(f"{path}:{number}: {problem}")
            if name.lower() in seen:
                raise ConfigError(f"{path}:{number}: duplicate source name '{name}'")
            seen.add(name.lower())
            sources.append(Source(name, url, ref))
    return sources


def parse_exclusions(path: str) -> List[Exclusion]:
    entries: List[Exclusion] = []
    if not os.path.isfile(path):
        return entries
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for number, raw in enumerate(handle, start=1):
            line = strip_comment(raw)
            if not line:
                continue
            kind, sep, pattern = line.partition(":")
            kind, pattern = kind.strip().lower(), pattern.strip()
            if not sep or kind not in ("file", "rule") or not pattern or " " in pattern:
                raise ConfigError(f"{path}:{number}: expected 'file:<glob>' or "
                                  f"'rule:<name|glob>', got '{line}'")
            if kind == "file":
                pattern = pattern.replace("\\", "/").lstrip("/")
            elif not re.match(r"^[A-Za-z0-9_*?\[\]]+$", pattern):
                raise ConfigError(f"{path}:{number}: invalid rule name or glob '{pattern}'")
            entries.append(Exclusion(kind, pattern, number))
    return entries


def parse_lock(path: str) -> List[Tuple[str, Dict[str, str]]]:
    """INI-like: [section] headers and "key = value" lines, order preserved."""
    sections: List[Tuple[str, Dict[str, str]]] = []
    current: Optional[Dict[str, str]] = None
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = {}
                sections.append((line[1:-1].strip(), current))
            elif "=" in line and current is not None:
                key, _sep, value = line.partition("=")
                current[key.strip().lower()] = value.strip()
    return sections


def lock_section(sections: List[Tuple[str, Dict[str, str]]], name: str) -> Dict[str, str]:
    for section, values in sections:
        if section == name:
            return values
    return {}


def lock_sources(path: str) -> List[Source]:
    sources: List[Source] = []
    for section, values in parse_lock(path):
        if not section.startswith("source "):
            continue
        name = section[len("source "):].strip()
        url, ref, commit = values.get("url", ""), values.get("ref", ""), values.get("commit", "")
        problem = validate_source(name, url, ref)
        if problem:
            raise ConfigError(f"{path}: {problem}")
        if not COMMIT_RE.match(commit):
            raise ConfigError(f"{path}: source '{name}' has no full commit SHA (got '{commit}')")
        sources.append(Source(name, url, ref, commit))
    if not sources:
        raise ConfigError(f"{path}: no [source <name>] sections")
    return sources


# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------
def git_binary() -> Optional[str]:
    return shutil.which("git")


def git_output(path: str, *args: str) -> str:
    git = git_binary()
    if not git:
        return ""
    try:
        proc = subprocess.run(
            [git, "-c", f"safe.directory={path}", "-C", path, *args],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.decode("utf-8", "replace").strip() if proc.returncode == 0 else ""


def read_head(path: str) -> str:
    """HEAD commit without git (air-gapped kit): .git/HEAD, loose refs, packed-refs."""
    gitdir = os.path.join(path, ".git")
    try:
        head = read_text(os.path.join(gitdir, "HEAD")).strip()
        if COMMIT_RE.match(head):
            return head
        if head.startswith("ref:"):
            ref = head[4:].strip()
            loose = os.path.join(gitdir, *ref.split("/"))
            if os.path.isfile(loose):
                value = read_text(loose).strip()
                return value if COMMIT_RE.match(value) else ""
            packed = os.path.join(gitdir, "packed-refs")
            if os.path.isfile(packed):
                for line in read_text(packed).splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == ref and COMMIT_RE.match(parts[0]):
                        return parts[0]
    except OSError:
        pass
    return ""


def commit_info(path: str) -> Tuple[str, str]:
    """(commit SHA, ISO commit date) of a checkout; "unknown" when unavailable."""
    if not os.path.exists(os.path.join(path, ".git")):
        return "unknown", "unknown"
    out = git_output(path, "log", "-1", "--format=%H %cI")
    if out and len(out.split()) == 2 and COMMIT_RE.match(out.split()[0]):
        sha, date = out.split()
        return sha, date
    return (read_head(path) or "unknown"), "unknown"


def search_roots(repo_path: str) -> List[str]:
    """Directories inside a repository that hold rule files."""
    name = os.path.basename(repo_path.rstrip(os.sep))
    if name == "signature-base":
        candidate = os.path.join(repo_path, "yara")
        return [candidate] if os.path.isdir(candidate) else [repo_path]

    common = ["yara", "malware", "maldocs", "webshells", "exploit_kits", "packers",
              "email", "mobile_malware", "crypto", "cve_rules", "antidebug_antivm",
              "capabilities", "rules"]
    found = [os.path.join(repo_path, part) for part in common
             if os.path.isdir(os.path.join(repo_path, part))]
    return found or [repo_path]


def external_variable_exclusions(repo_path: str) -> set:
    listing = os.path.join(repo_path, "yara", "external-variable-rules.txt")
    excluded = set()
    if os.path.isfile(listing):
        for line in read_text(listing).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                excluded.add(os.path.basename(line).lower())
    return excluded


def rel_path(path: str, rules_dir: str) -> str:
    return os.path.relpath(path, rules_dir).replace(os.sep, "/")


def candidate_files(roots: List[str], repo_path: str, rules_dir: str) -> List[str]:
    """Rule files under roots, sorted by their path relative to the rules dir.
    Skip decisions look only at the part of the path inside the repository, so
    a kit stored under e.g. /home/x/tests/ is not mistaken for a test folder."""
    found: Dict[str, str] = {}
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for filename in filenames:
                if not filename.lower().endswith((".yar", ".yara")):
                    continue
                if filename.startswith((".", "~", "_")):
                    continue
                path = os.path.join(dirpath, filename)
                inner = os.path.relpath(path, repo_path).split(os.sep)[:-1]
                if any(part in SKIP_DIR_NAMES for part in inner):
                    continue
                found.setdefault(rel_path(path, rules_dir), path)
    return [found[key] for key in sorted(found)]


# ---------------------------------------------------------------------------
# Compilation and bundle assembly
# ---------------------------------------------------------------------------
def compiles(yarac: str, path: str) -> Tuple[bool, str]:
    """True when yarac accepts this rule source."""
    with tempfile.NamedTemporaryFile(suffix=".compiled", delete=True) as output:
        try:
            proc = subprocess.run(
                [yarac, "-w", path, output.name],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=600, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"compiler invocation failed: {exc}"
    if proc.returncode == 0:
        return True, ""
    return False, proc.stdout.decode("utf-8", "replace").strip().replace("\n", " | ")[:400]


def suppress_rules(text: str, patterns: List[Exclusion]) -> Tuple[str, List[Tuple[str, Exclusion]]]:
    """Rewrites matching rule declarations to `private rule` (keeps `global`;
    already-private rules are left alone). Returns the text and the
    (rule, exclusion) pairs applied."""
    applied: List[Tuple[str, Exclusion]] = []

    def replace(match: "re.Match[str]") -> str:
        indent, modifiers, space, name = match.groups()
        if "private" in modifiers.split():
            return match.group(0)
        for entry in patterns:
            if fnmatch.fnmatchcase(name, entry.pattern):
                applied.append((name, entry))
                return f"{indent}{modifiers}private rule{space}{name}"
        return match.group(0)

    if not patterns:
        return text, applied
    return RULE_DECL_RE.sub(replace, text), applied


def bundle_header(sources: List[Tuple[str, str]]) -> List[str]:
    """Deterministic header: no timestamps, so the same inputs hash the same."""
    lines = ["/*", "    Vestigium - active YARA rule bundle",
             "    Sources (earlier entries win rule identifier clashes):"]
    for name, commit in sources:
        lines.append(f"      - {name} @ {commit}")
    lines += ["    Excluded: include wrappers, duplicate rule identifiers, external-variable",
              "              rules, exclusions.conf entries and files that do not compile.",
              "    Record: rules.lock (commits, bundle SHA256) and the build report.",
              "*/"]
    return lines


def build_bundle(accepted: List[RuleFile], out_path: str, sources: List[Tuple[str, str]],
                 suppress: List[Exclusion]) -> List[Tuple[RuleFile, str, Exclusion]]:
    """Writes the bundle (UTF-8, LF). Returns the rules that were suppressed."""
    suppressed: List[Tuple[RuleFile, str, Exclusion]] = []
    with open(out_path, "w", encoding="utf-8", errors="replace", newline="\n") as handle:
        for line in bundle_header(sources):
            handle.write(line + "\n")
        for entry in accepted:
            text, applied = suppress_rules(read_text(entry.path), suppress)
            suppressed.extend((entry, name, rule) for name, rule in applied)
            handle.write(f"\n/* BEGIN {entry.rel} */\n")
            handle.write(text)
            if not text.endswith("\n"):
                handle.write("\n")
            handle.write(f"/* END {entry.rel} */\n")
    return suppressed


def offending_source(bundle_path: str, error_text: str) -> Optional[str]:
    """Map a compiler error line number in the bundle back to a source file.

    yarac reports errors as `error: rule "X" in <file>(<line>): <message>`
    (older builds: `<file>(<line>): error: ...`); prefer the line number that
    follows the bundle's own file name.
    """
    name = re.escape(os.path.basename(bundle_path))
    match = (re.search(name + r"\((\d+)\)", error_text)
             or re.search(r"\((\d+)\):", error_text))
    if not match:
        return None
    target_line = int(match.group(1))
    current: Optional[str] = None
    with open(bundle_path, "r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            if line.startswith("/* BEGIN "):
                current = line[len("/* BEGIN "):].rstrip().rstrip("*/").strip()
            if number >= target_line:
                return current
    return current


def count_rules(path: str) -> Tuple[int, int]:
    """(all rule declarations, private ones) in a bundle."""
    total = private = 0
    for match in RULE_DECL_RE.finditer(read_text(path)):
        total += 1
        if "private" in match.group(2).split():
            private += 1
    return total, private


def tool_version(binary: str) -> str:
    try:
        proc = subprocess.run([binary, "--version"], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=30, check=False)
        lines = proc.stdout.decode("utf-8", "replace").strip().splitlines()
        return lines[0].strip() if proc.returncode == 0 and lines else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def tree_digest(files: List[RuleFile]) -> str:
    """SHA256 over "<sha256>  <relative path>" lines of line-ending-normalised files."""
    digest = hashlib.sha256()
    for entry in sorted(files, key=lambda item: item.rel):
        content = hashlib.sha256(normalised_bytes(entry.path)).hexdigest()
        digest.update(f"{content}  {entry.rel}\n".encode("utf-8"))
    return digest.hexdigest()


def write_report(path: str, rows: List[Dict[str, str]]) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".rule-build-report.", suffix=".csv", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=["Repository", "File", "Status", "Reason", "RuleCount", "Rules"],
                quoting=csv.QUOTE_ALL)
            writer.writeheader()
            writer.writerows(rows)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------------------
# rules.lock
# ---------------------------------------------------------------------------
LOCK_HEADER = """\
# Vestigium YARA rule lock (format 1) - generated, but versioned in git.
# Written by the rule builder after every successful build (unless only the
# 'generated' line would change). Reproduce this exact build with:
#   Linux:   sudo ./vestigium.sh setup --rules-locked
#   Windows: .\\vestigium.ps1 setup -Locked
# Format: "key = value" lines under [lock], [source <name>] (in precedence
# order), [custom], [exclusions] and [bundle]. See docs/YARA-RULES.md.
"""


def render_lock(values: Dict[str, object]) -> str:
    out = [LOCK_HEADER]
    out.append("[lock]")
    for key in ("format", "generated", "builder", "yara"):
        out.append(f"{key} = {values[key]}")
    for source in values["sources"]:  # type: ignore[union-attr]
        out.append("")
        out.append(f"[source {source['name']}]")
        for key in ("url", "ref", "commit", "commit_date"):
            value = source[key]
            out.append(f"{key} = {value}" if value else f"{key} =")
    for section, keys in (("custom", ("files", "sha256")),
                          ("exclusions", ("sha256", "files_excluded", "rules_suppressed")),
                          ("bundle", ("file", "sha256", "rules", "rules_reporting",
                                      "files_accepted", "files_skipped"))):
        out.append("")
        out.append(f"[{section}]")
        data = values[section]  # type: ignore[index]
        for key in keys:
            out.append(f"{key} = {data[key]}")
    return "\n".join(out) + "\n"


def write_lock(path: str, text: str) -> bool:
    """Writes the lock unless only its 'generated' line would change.
    Returns True when the file was (re)written."""
    def significant(content: str) -> List[str]:
        return [line for line in content.splitlines()
                if not line.startswith("generated =") and not line.startswith("#")]

    if os.path.isfile(path):
        try:
            if significant(read_text(path)) == significant(text):
                return False
        except OSError:
            pass
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".rules.lock.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return True


def check_against_lock(lock_path: str, built: Dict[str, object]) -> bool:
    sections = parse_lock(lock_path)
    want = lock_section(sections, "bundle").get("sha256", "")
    have = built["bundle"]["sha256"]  # type: ignore[index]
    if want == have:
        log(f"lock check: MATCH - bundle SHA256 {have} equals rules.lock")
        return True
    log(f"lock check: MISMATCH - bundle SHA256 {have}, rules.lock records {want or '(none)'}")
    differences = []
    lock_meta = lock_section(sections, "lock")
    if lock_meta.get("yara", "") != built["yara"]:
        differences.append(f"yara {built['yara']} here, {lock_meta.get('yara', '?')} in lock "
                           f"(built by {lock_meta.get('builder', '?')})")
    for section, key in (("custom", "sha256"), ("exclusions", "sha256"),
                         ("bundle", "rules"), ("bundle", "files_accepted")):
        locked = lock_section(sections, section).get(key, "")
        current = str(built[section][key])  # type: ignore[index]
        if locked != current:
            differences.append(f"{section}.{key}: {current} here, {locked or '(none)'} in lock")
    for item in differences:
        log(f"lock check:   {item}")
    if not differences:
        log("lock check:   inputs match; compare rule-build-report.csv with the one from the locked build")
    return False


# ---------------------------------------------------------------------------
# False-positive check
# ---------------------------------------------------------------------------
def fp_scan(yara: str, rule_args: List[str], corpora: List[str], report_path: str,
            timeout: int, max_bytes: int, rule_sources: Dict[str, str],
            bundle_sha: str) -> bool:
    files: List[str] = []
    skipped_large = skipped_other = 0
    for corpus in corpora:
        for dirpath, dirnames, filenames in os.walk(corpus):
            dirnames.sort()
            for filename in sorted(filenames):
                path = os.path.join(dirpath, filename)
                try:
                    info = os.lstat(path)
                except OSError:
                    skipped_other += 1
                    continue
                if not stat.S_ISREG(info.st_mode) or "\n" in path:
                    skipped_other += 1
                elif info.st_size > max_bytes:
                    skipped_large += 1
                else:
                    files.append(path)

    hits: Dict[str, List[str]] = {}
    status = "completed"
    errors = 0
    if files:
        fd, listing = tempfile.mkstemp(prefix="vestigium-fp.", suffix=".lst")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as handle:
                handle.write("\n".join(files) + "\n")
            command = [yara, "-w", "-N", "-a", "60", "-p", str(min(8, os.cpu_count() or 2)),
                       *rule_args, "--scan-list", listing]
            try:
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError as exc:
                log(f"false-positive check skipped: cannot run {yara}: {exc}")
                return False
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                status = f"TIMED OUT after {timeout}s - results are partial"
            if proc.returncode not in (0, None) and status == "completed" and not out:
                log(f"false-positive scan failed: {err.decode('utf-8', 'replace')[:300]}")
                status = f"FAILED (yara exit {proc.returncode})"
            errors = sum(1 for line in err.decode("utf-8", "replace").splitlines() if line.strip())
            for line in out.decode("utf-8", "replace").splitlines():
                rule, _sep, path = line.partition(" ")
                if rule and path:
                    hits.setdefault(rule, []).append(path)
        finally:
            os.remove(listing)

    ranked = sorted(hits.items(), key=lambda item: (-len(item[1]), item[0]))
    lines = [
        "Vestigium YARA false-positive check",
        f"Generated:   {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"Bundle:      {bundle_sha} ({' '.join(os.path.basename(a) if os.sep in a else a for a in rule_args)})",
        f"Corpus:      {', '.join(corpora)}",
        f"Files:       {len(files)} scanned, {skipped_large} skipped (> {max_bytes // (1024 * 1024)} MB), "
        f"{skipped_other} skipped (not regular files), {errors} scan error line(s)",
        f"Status:      {status}",
        f"Rules fired: {len(ranked)} ({sum(len(p) for _r, p in ranked)} matches)",
        "",
        "The corpus is assumed clean: every match below is a candidate false positive.",
        "Review before silencing; add 'rule:<name>' or 'file:<glob>' to exclusions.conf.",
        "",
    ]
    if ranked:
        lines.append(f"{'COUNT':>7}  {'RULE':<48} SOURCE FILE")
        for rule, paths in ranked:
            lines.append(f"{len(paths):>7}  {rule:<48} {rule_sources.get(rule, '?')}")
            for sample in paths[:3]:
                lines.append(f"{'':>9}e.g. {sample}")
        lines += ["", "# Candidate exclusions.conf lines (commented out; enable only after review):"]
        for rule, paths in ranked:
            lines.append(f"#rule:{rule}    # {len(paths)} hit(s) on the clean corpus")
    else:
        lines.append("No rule fired on the corpus.")
    os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    log(f"false-positive check: {len(ranked)} rule(s) fired on {len(files)} file(s) [{status}]; "
        f"report: {report_path}")
    return status == "completed"


# ---------------------------------------------------------------------------
def default_yara(yarac: str) -> str:
    sibling = os.path.join(os.path.dirname(yarac), "yara") if os.path.dirname(yarac) else ""
    if sibling and os.access(sibling, os.X_OK):
        return sibling
    return shutil.which("yara") or "yara"


def resolve_sources(args: argparse.Namespace, rules_dir: str) -> Tuple[List[Source], str]:
    """Sources in precedence order, and where they came from."""
    if args.locked:
        return lock_sources(args.lock), os.path.basename(args.lock)
    if os.path.isfile(args.sources):
        return parse_sources(args.sources), os.path.basename(args.sources)
    # Legacy layout: no sources.conf. Use the known repositories that are
    # present, then any other checkout (sorted), as older builders did.
    known = {name for name, _url, _ref in DEFAULT_SOURCES}
    sources = [Source(n, u, r) for n, u, r in DEFAULT_SOURCES
               if os.path.isdir(os.path.join(rules_dir, n))]
    for name in sorted(os.listdir(rules_dir)):
        if (name in known or name.startswith((".", "_")) or name == CUSTOM_DIR
                or not os.path.isdir(os.path.join(rules_dir, name))):
            continue
        sources.append(Source(name, git_output(os.path.join(rules_dir, name),
                                                "remote", "get-url", "origin"), ""))
    return sources, "directory scan (no sources.conf)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules-dir", required=True,
                        help="shared rule store (custom/, source checkouts, configuration)")
    parser.add_argument("--out", default="", help="bundle path (default <rules-dir>/active-rules.yar)")
    parser.add_argument("--report", default="",
                        help="CSV build report (default <rules-dir>/rule-build-report.csv)")
    parser.add_argument("--compiled", default="", help="optional compiled bundle output")
    parser.add_argument("--yarac", default="yarac")
    parser.add_argument("--yara", default="", help="yara scanner for --fp-corpus (default: next to yarac)")
    parser.add_argument("--sources", default="", help="default <rules-dir>/sources.conf")
    parser.add_argument("--exclusions", default="", help="default <rules-dir>/exclusions.conf")
    parser.add_argument("--custom-dir", default="", help="default <rules-dir>/custom")
    parser.add_argument("--lock", default="", help="default <rules-dir>/rules.lock")
    parser.add_argument("--no-lock", action="store_true", help="do not write rules.lock")
    parser.add_argument("--locked", action="store_true",
                        help="build the sources recorded in the lock (checkouts must be at the "
                             "locked commits), compare the bundle SHA256 with it, keep the lock")
    parser.add_argument("--builder-name", default="build-yara-rules.py (Linux)",
                        help=argparse.SUPPRESS)
    parser.add_argument("--fp-corpus", action="append", nargs="+", default=[], metavar="DIR",
                        help="known-clean directories to scan with the new bundle")
    parser.add_argument("--fp-report", default="", help="default <rules-dir>/rule-fp-report.txt")
    parser.add_argument("--fp-timeout", type=int, default=900,
                        help="wall-clock limit for the false-positive scan, seconds (default 900)")
    parser.add_argument("--skip-compile-check", action="store_true",
                        help="assemble without validating each rule file (faster, riskier)")
    args = parser.parse_args()

    rules_dir = os.path.abspath(args.rules_dir)
    if not os.path.isdir(rules_dir):
        log(f"rules directory not found: {rules_dir}")
        return 2
    args.out = os.path.abspath(args.out or os.path.join(rules_dir, "active-rules.yar"))
    args.report = args.report or os.path.join(rules_dir, "rule-build-report.csv")
    args.sources = args.sources or os.path.join(rules_dir, "sources.conf")
    args.exclusions = args.exclusions or os.path.join(rules_dir, "exclusions.conf")
    custom_dir = os.path.abspath(args.custom_dir or os.path.join(rules_dir, CUSTOM_DIR))
    args.lock = args.lock or os.path.join(rules_dir, "rules.lock")
    args.fp_report = args.fp_report or os.path.join(rules_dir, "rule-fp-report.txt")
    corpora = [os.path.abspath(d) for group in args.fp_corpus for d in group]
    for corpus in corpora:
        if not os.path.isdir(corpus):
            log(f"--fp-corpus directory not found: {corpus}")
            return 2
    if args.locked and not os.path.isfile(args.lock):
        log(f"--locked: {args.lock} not found")
        return 2

    try:
        exclusions = parse_exclusions(args.exclusions)
        sources, origin = resolve_sources(args, rules_dir)
    except (ConfigError, OSError) as exc:
        log(f"configuration error: {exc}")
        return 2
    file_rules = [e for e in exclusions if e.kind == "file"]
    rule_rules = [e for e in exclusions if e.kind == "rule"]
    log(f"sources ({origin}): " + (", ".join(s.name for s in sources) or "(none)"))
    if exclusions:
        log(f"exclusions.conf: {len(file_rules)} file pattern(s), {len(rule_rules)} rule pattern(s)")

    # Resolve checkouts and their commits.
    groups: List[Tuple[str, str, List[str]]] = []      # (name, path, roots)
    lock_entries: List[Dict[str, str]] = []
    header_sources: List[Tuple[str, str]] = []
    if os.path.isdir(custom_dir):
        groups.append((CUSTOM_DIR, custom_dir, [custom_dir]))
        header_sources.append((CUSTOM_DIR, "kit"))
    for source in sources:
        path = os.path.join(rules_dir, source.name)
        if not os.path.isdir(path):
            if args.locked:
                log(f"FAILED: locked source '{source.name}' has no checkout at {path}")
                return 1
            log(f"WARNING: source '{source.name}' has no checkout at {path}; skipped")
            continue
        commit, date = commit_info(path)
        if args.locked and commit != source.commit:
            log(f"FAILED: {source.name} is at {commit}, rules.lock requires {source.commit} "
                f"(check it out first: setup-tools.sh --rules-locked)")
            return 1
        groups.append((source.name, path, search_roots(path)))
        header_sources.append((source.name, commit))
        lock_entries.append({"name": source.name, "url": source.url, "ref": source.ref,
                             "commit": commit, "commit_date": date})
    if sources and not os.path.isfile(args.sources) and not args.locked:
        log("sources.conf not found: using the directories present (legacy layout)")
    configured = {CUSTOM_DIR} | {s.name for s in sources}
    for name in sorted(os.listdir(rules_dir)):
        path = os.path.join(rules_dir, name)
        if os.path.isdir(path) and not name.startswith((".", "_")) and name not in configured:
            log(f"note: directory '{name}' is not a configured source; ignored")

    if not groups:
        log(f"no rule repositories found under {rules_dir}")
        return 1

    have_yarac = False
    if not args.skip_compile_check:
        try:
            subprocess.run([args.yarac, "--version"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False, timeout=30)
            have_yarac = True
        except (OSError, subprocess.TimeoutExpired):
            log(f"{args.yarac} unavailable: skipping per-file compile validation")

    report_rows: List[Dict[str, str]] = []
    accepted: List[RuleFile] = []
    custom_files: List[RuleFile] = []
    seen_rules: Dict[str, str] = {}
    used_patterns = set()
    total = 0

    for group, repo, roots in groups:
        ext_exclusions = external_variable_exclusions(repo) if group != CUSTOM_DIR else set()
        files = candidate_files(roots, repo, rules_dir)
        log(f"{group}: {len(files)} candidate rule file(s)")

        for path in files:
            total += 1
            rel = rel_path(path, rules_dir)
            status, reason, names = "accepted", "", []
            if group == CUSTOM_DIR:
                custom_files.append(RuleFile(group, path, rel, []))
            try:
                matched = next((e for e in file_rules
                                if fnmatch.fnmatchcase(rel.lower(), e.pattern.lower())), None)
                if matched:
                    status, reason = "excluded", matched.label
                    used_patterns.add(matched)
                elif os.path.basename(path).lower() in ext_exclusions:
                    status, reason = "skipped", "external-variable rule file"
                else:
                    content = read_text(path)
                    if INCLUDE_RE.search(content):
                        status, reason = "skipped", "contains include statement"
                    else:
                        names = RULE_NAME_RE.findall(content)
                        if not names:
                            status, reason = "skipped", "no rule identifiers found"
                        elif len(set(names)) != len(names):
                            status, reason = "skipped", "duplicate identifiers inside file"
                        else:
                            clash = [n for n in names if n in seen_rules]
                            if clash:
                                status = "skipped"
                                reason = "identifier already accepted: " + ",".join(clash[:5])
                            elif have_yarac:
                                ok, error = compiles(args.yarac, path)
                                if not ok:
                                    status, reason = "skipped", f"does not compile: {error}"
            except OSError as exc:
                status, reason = "skipped", f"read failure: {exc}"

            if status == "accepted":
                for name in names:
                    seen_rules[name] = rel
                accepted.append(RuleFile(group, path, rel, names))
            elif group == CUSTOM_DIR and status == "skipped":
                log(f"WARNING: custom rule file {rel} not included: {reason[:200]}")

            report_rows.append({
                "Repository": group,
                "File": rel,
                "Status": status,
                "Reason": reason,
                "RuleCount": str(len(names)),
                "Rules": ";".join(names[:40]),
            })

    if not accepted:
        log("no eligible rule files: bundle not written")
        write_report(args.report, report_rows)
        return 1

    out_dir = os.path.dirname(args.out)
    os.makedirs(out_dir, exist_ok=True)
    fd, tmp_bundle = tempfile.mkstemp(prefix=".active-rules.building.", suffix=".yar", dir=out_dir)
    os.close(fd)
    tmp_compiled = ""
    try:
        suppressed = build_bundle(accepted, tmp_bundle, header_sources, rule_rules)

        # Validate the assembled bundle, dropping offenders until it compiles.
        if have_yarac:
            ok, error = compiles(args.yarac, tmp_bundle)
            attempt = 0
            while not ok and accepted and attempt < 10:
                attempt += 1
                culprit = offending_source(tmp_bundle, error)
                if not culprit:
                    log(f"bundle compile failed and the source could not be identified: {error}")
                    break
                log(f"attempt {attempt}: dropping {culprit} ({error[:120]})")
                accepted = [entry for entry in accepted if entry.rel != culprit]
                for row in report_rows:
                    if row["File"] == culprit:
                        row["Status"] = "skipped"
                        row["Reason"] = f"bundle compile failure: {error[:200]}"
                suppressed = build_bundle(accepted, tmp_bundle, header_sources, rule_rules)
                ok, error = compiles(args.yarac, tmp_bundle)

            if not ok:
                # Returning success here would let setup report a usable kit whose
                # every scan later fails to load its rules.
                write_report(args.report, report_rows)
                log(f"FAILED: bundle still does not compile after {attempt} repair attempt(s): "
                    f"{error[:300]}")
                log(f"existing {args.out} left unchanged")
                return 1

            if args.compiled:
                fd, tmp_compiled = tempfile.mkstemp(prefix=".active-rules.building.",
                                                    suffix=".compiled",
                                                    dir=os.path.dirname(os.path.abspath(args.compiled)))
                os.close(fd)
                try:
                    subprocess.run([args.yarac, "-w", tmp_bundle, tmp_compiled],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   check=True, timeout=900)
                except (OSError, subprocess.SubprocessError) as exc:
                    log(f"pre-compilation failed (collector will use the source bundle): {exc}")
                    os.remove(tmp_compiled)
                    tmp_compiled = ""

        # Commit: bundle first, then the compiled form. The collector uses the
        # compiled bundle only when it is newer than the source bundle, so any
        # interruption between the two renames leaves a consistent kit.
        os.chmod(tmp_bundle, 0o644)
        os.replace(tmp_bundle, args.out)
        tmp_bundle = ""
        if args.compiled:
            if tmp_compiled:
                os.chmod(tmp_compiled, 0o644)
                bundle_mtime = os.stat(args.out).st_mtime
                if os.stat(tmp_compiled).st_mtime <= bundle_mtime:
                    os.utime(tmp_compiled, (bundle_mtime + 1, bundle_mtime + 1))
                os.replace(tmp_compiled, args.compiled)
                tmp_compiled = ""
                log(f"pre-compiled bundle written to {args.compiled}")
            elif os.path.lexists(args.compiled):
                # Never let a compiled bundle outlive the source it was built from.
                os.remove(args.compiled)
                log(f"removed stale compiled bundle {args.compiled}")
    finally:
        for leftover in (tmp_bundle, tmp_compiled):
            if leftover and os.path.exists(leftover):
                os.remove(leftover)

    # Record suppressions and patterns that matched nothing.
    for entry, name, rule in suppressed:
        used_patterns.add(rule)
        report_rows.append({"Repository": entry.group, "File": entry.rel, "Status": "suppressed",
                            "Reason": f"{rule.label} (rewritten to private rule)",
                            "RuleCount": "1", "Rules": name})
    for rule in exclusions:
        if rule not in used_patterns:
            log(f"WARNING: {rule.label} matched nothing")
            report_rows.append({"Repository": "exclusions.conf", "File": "", "Status": "unmatched",
                                "Reason": f"{rule.label} matched nothing", "RuleCount": "0",
                                "Rules": ""})
    write_report(args.report, report_rows)

    counts = {status: sum(1 for row in report_rows if row["Status"] == status)
              for status in ("accepted", "skipped", "excluded", "suppressed")}
    rules_total, rules_private = count_rules(args.out)
    bundle_sha = sha256_file(args.out)
    yara_version = tool_version(args.yarac) if have_yarac else "unknown"
    built: Dict[str, object] = {
        "format": LOCK_FORMAT,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "builder": args.builder_name,
        "yara": yara_version,
        "sources": lock_entries,
        "custom": {"files": len(custom_files), "sha256": tree_digest(custom_files)},
        "exclusions": {
            "sha256": (hashlib.sha256(normalised_bytes(args.exclusions)).hexdigest()
                       if os.path.isfile(args.exclusions) else "none"),
            "files_excluded": counts["excluded"],
            "rules_suppressed": counts["suppressed"],
        },
        "bundle": {
            "file": os.path.basename(args.out), "sha256": bundle_sha, "rules": rules_total,
            "rules_reporting": rules_total - rules_private,
            "files_accepted": counts["accepted"], "files_skipped": counts["skipped"],
        },
    }

    log(f"bundle: {args.out}")
    log(f"files scanned={total} accepted={counts['accepted']} skipped={counts['skipped']} "
        f"excluded={counts['excluded']} rules suppressed={counts['suppressed']} "
        f"rule identifiers={len(seen_rules)}")
    log(f"bundle sha256={bundle_sha} rules={rules_total} (reporting {rules_total - rules_private})")
    log(f"report: {args.report}")

    if args.locked:
        check_against_lock(args.lock, built)
    elif not args.no_lock:
        if write_lock(args.lock, render_lock(built)):
            log(f"lock written: {args.lock}")
        else:
            log(f"lock unchanged: {args.lock}")

    if corpora:
        yara = args.yara or default_yara(args.yarac)
        rule_args = ["-C", args.compiled] if args.compiled and os.path.isfile(args.compiled) \
            else [args.out]
        fp_scan(yara, rule_args, corpora, args.fp_report, max(30, args.fp_timeout),
                FP_MAX_BYTES, seen_rules, bundle_sha)
    return 0


if __name__ == "__main__":
    sys.exit(main())
