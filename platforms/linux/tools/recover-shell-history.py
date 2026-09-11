#!/usr/bin/env python3
"""Best-effort recovery of a live shell's in-memory command history.

Anti-forensic operators disable on-disk history (HISTFILE=/dev/null,
HISTSIZE=0, `unset HISTFILE`, `set +o history`), but an interactive shell that
is still running keeps its history list, readline buffers and recent command
strings in its own heap. This reads those regions through /proc/<pid>/mem and
carves printable strings that look like command lines.

The output is a LEAD, not a transcript: it may include fragments, prompt text,
completions and strings that were never executed. Order is by memory address,
not by time. Standard library only; root is required.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Iterable, List, Tuple

MAX_TOTAL_BYTES = 64 * 1024 * 1024      # never read more than this per process
CHUNK = 4 * 1024 * 1024
STRING_RE = re.compile(rb"[\x20-\x7e\t]{3,300}")

# Regions worth reading: the heap (malloc'd history entries), the main stack
# (the command currently being edited) and anonymous read-write mappings
# (large history lists spill into mmap'd arenas).
WANTED_TAGS = ("[heap]", "[stack]")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def read_maps(pid: int) -> List[Tuple[int, int, str]]:
    regions: List[Tuple[int, int, str]] = []
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 5:
                    continue
                addr, perms = parts[0], parts[1]
                path = parts[5] if len(parts) > 5 else ""
                if "r" not in perms or "w" not in perms:
                    continue                      # history lives in writable data
                if path and path not in WANTED_TAGS:
                    continue                      # skip file-backed mappings
                start_s, end_s = addr.split("-")
                regions.append((int(start_s, 16), int(end_s, 16), path or "[anon]"))
    except OSError as exc:
        print(f"cannot read /proc/{pid}/maps: {exc}", file=sys.stderr)
    # Heap and stack first, then anonymous regions, largest first.
    order = {"[heap]": 0, "[stack]": 1}
    regions.sort(key=lambda r: (order.get(r[2], 2), -(r[1] - r[0])))
    return regions


def read_region(mem, start: int, end: int, budget: int) -> bytes:
    data = bytearray()
    pos = start
    while pos < end and len(data) < budget:
        want = min(CHUNK, end - pos, budget - len(data))
        try:
            chunk = os.pread(mem, want, pos)
        except OSError:
            break                                 # unmapped hole or race; stop this region
        if not chunk:
            break
        data.extend(chunk)
        pos += len(chunk)
    return bytes(data)


def looks_like_command(text: str) -> bool:
    """Conservative filter: keep strings that could plausibly have been typed
    at a prompt; drop obvious binary noise, env dumps and prompt fragments."""
    stripped = text.strip()
    if len(stripped) < 3 or len(stripped) > 300:
        return False
    if not re.match(r"^[A-Za-z0-9_./~$(\[\-]", stripped):
        return False
    letters = sum(ch.isalnum() for ch in stripped)
    if letters < 0.4 * len(stripped):
        return False
    if re.match(r"^[A-Z_][A-Z0-9_]{2,}=", stripped):
        return False                              # environment variable, not a command
    if stripped.startswith(("http://", "https://")):
        return True                               # a bare URL is still a lead
    if " " in stripped or "/" in stripped or "|" in stripped or ";" in stripped:
        return True
    # Single-token lines: keep common interactive commands.
    return stripped in {"ls", "pwd", "id", "w", "who", "history", "exit", "sudo",
                        "clear", "logout", "reboot", "su", "top", "ps"}


def carve(pid: int, budget: int) -> Iterable[str]:
    seen = set()
    try:
        mem = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    except OSError as exc:
        print(f"cannot open /proc/{pid}/mem: {exc}", file=sys.stderr)
        return
    try:
        remaining = budget
        for start, end, _tag in read_maps(pid):
            if remaining <= 0:
                break
            blob = read_region(mem, start, end, remaining)
            remaining -= len(blob)
            for match in STRING_RE.finditer(blob):
                text = match.group(0).decode("ascii", "replace")
                if text in seen:
                    continue
                seen.add(text)
                if looks_like_command(text):
                    yield text
    finally:
        os.close(mem)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--max", type=int, default=500, help="maximum candidate lines")
    parser.add_argument("--budget-mb", type=int, default=MAX_TOTAL_BYTES // (1024 * 1024))
    args = parser.parse_args()

    if not os.path.isdir(f"/proc/{args.pid}"):
        print(f"no such process: {args.pid}", file=sys.stderr)
        return 0
    count = 0
    for line in carve(args.pid, args.budget_mb * 1024 * 1024):
        print(line)
        count += 1
        if count >= args.max:
            print(f"... stopped at {args.max} candidate lines", file=sys.stderr)
            break
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
