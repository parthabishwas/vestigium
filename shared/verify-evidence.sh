#!/usr/bin/env bash
#
# verify-evidence.sh - Integrity-check a Vestigium evidence package and print
# a triage overview. Handles Linux and Windows collections.
#
# Usage:
#   ./vestigium.sh verify <package>                               # via the launcher
#   shared/verify-evidence.sh output/<host>_<timestamp>            # Linux tree
#   shared/verify-evidence.sh output/<host>_<timestamp>.tar.zst    # Linux archive
#   shared/verify-evidence.sh output/<HOST>_<timestamp>.zip        # Windows archive
#
# 1. Archive: checks the <archive>.sha256 sidecar when present, then extracts
#    into a private temporary directory (owners and special mode bits dropped).
# 2. Contents: re-verifies every file against the recorded inventory (Linux
#    20_Hashes/SHA256SUMS.txt, Windows 15_Hashes/SHA256.csv) and lists files
#    that are present but not recorded. An empty or malformed inventory is a
#    failure, never a pass.
# 3. Prints the collection summary, module results and, for Linux
#    collections, the highest-signal findings.
#
# Exit codes: 0 verified, 1 integrity failure, 2 usage error or unreadable
# package. Needs bash, sha256sum (or shasum) and tar; python3 for Windows
# collections (or use vestigium.ps1 verify / shared/Verify-Evidence.ps1).
#
set -uo pipefail

if [[ -t 1 ]]; then
    C_RST=$'\033[0m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_RED=$'\033[31m'; C_CYN=$'\033[36m'
else
    C_RST=""; C_GRN=""; C_YEL=""; C_RED=""; C_CYN=""
fi
ok()   { printf '%s[ OK ]%s %s\n'   "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[WARN]%s %s\n'   "$C_YEL" "$C_RST" "$*"; }
bad()  { printf '%s[FAIL]%s %s\n'   "$C_RED" "$C_RST" "$*"; }
info() { printf '[INFO] %s\n' "$*"; }
head1(){ printf '\n%s=== %s ===%s\n' "$C_CYN" "$*" "$C_RST"; }

usage() {
    printf 'Usage: %s <evidence-directory | .tar.zst | .tar.gz | .zip>\n' "$(basename "$0")" >&2
}

if command -v sha256sum >/dev/null 2>&1; then
    SHA256=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
    SHA256=(shasum -a 256)
else
    printf 'sha256sum or shasum is required\n' >&2
    exit 2
fi

TARGET="${1:-}"
case "$TARGET" in
    -h|--help) usage; exit 0 ;;
    "") usage; exit 2 ;;
esac
if [[ ! -e "$TARGET" ]]; then
    bad "Not found: ${TARGET}"
    exit 2
fi

EVID="$TARGET"
TMPDIR_EXTRACT=""
FAILURES=0
cleanup() { [[ -n "$TMPDIR_EXTRACT" ]] && rm -rf "$TMPDIR_EXTRACT"; }
trap cleanup EXIT

extract_zip() {
    # Refuses entries that would land outside the destination directory.
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$1" "$2" <<'PY'
import os
import sys
import zipfile

src, dest = sys.argv[1], os.path.realpath(sys.argv[2])
with zipfile.ZipFile(src) as archive:
    for info in archive.infolist():
        # Windows PowerShell 5.1 Compress-Archive stores backslash separators.
        name = info.filename.replace("\\", "/")
        target = os.path.realpath(os.path.join(dest, name))
        if target != dest and not target.startswith(dest + os.sep):
            sys.exit(f"unsafe path in archive: {info.filename}")
        if name.endswith("/"):
            os.makedirs(target, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with archive.open(info) as fin, open(target, "wb") as fout:
            while True:
                chunk = fin.read(1 << 20)
                if not chunk:
                    break
                fout.write(chunk)
PY
    elif command -v unzip >/dev/null 2>&1; then
        unzip -q "$1" -d "$2"
    else
        return 1
    fi
}

is_collection_root() {
    [[ -d "$1/20_Hashes" || -d "$1/19_CollectionLogs" || -d "$1/15_Hashes" || -d "$1/14_Logs" ]]
}

# ---------------------------------------------------------------------------
if [[ -f "$TARGET" ]]; then
    head1 "Archive integrity"
    if [[ -f "${TARGET}.sha256" ]]; then
        expected="$(awk 'NR == 1 {print tolower($1)}' "${TARGET}.sha256")"
        actual="$("${SHA256[@]}" "$TARGET" | awk '{print tolower($1)}')"
        if [[ -n "$expected" && "$expected" == "$actual" ]]; then
            ok "Archive SHA256 matches ${TARGET}.sha256"
        else
            bad "Archive SHA256 does NOT match ${TARGET}.sha256"
            exit 1
        fi
    else
        warn "No .sha256 sidecar found next to the archive"
    fi

    TMPDIR_EXTRACT="$(mktemp -d "${TMPDIR:-/tmp}/vestigium-verify.XXXXXX")" || exit 2
    printf 'Extracting to %s ...\n' "$TMPDIR_EXTRACT"
    case "$TARGET" in
        *.zip|*.ZIP)
            extract_zip "$TARGET" "$TMPDIR_EXTRACT" ||
                { bad "Extraction failed or refused (unsafe entry, or neither python3 nor unzip available)"; exit 2; } ;;
        *)
            tar --no-same-owner --no-same-permissions -xf "$TARGET" -C "$TMPDIR_EXTRACT" ||
                { bad "Extraction failed (tar needs zstd for .tar.zst)"; exit 2; } ;;
    esac
    EVID="$TMPDIR_EXTRACT"
fi

if [[ -d "$EVID" ]] && ! is_collection_root "$EVID"; then
    for candidate in "$EVID"/*/; do
        candidate="${candidate%/}"
        if is_collection_root "$candidate"; then EVID="$candidate"; break; fi
    done
fi
[[ -d "$EVID" ]] || { bad "Not an evidence directory: ${EVID}"; exit 2; }

if [[ -f "$EVID/20_Hashes/SHA256SUMS.txt" ]]; then
    FORMAT=linux
elif [[ -f "$EVID/15_Hashes/SHA256.csv" ]]; then
    FORMAT=windows
else
    FORMAT=unknown
fi

# ---------------------------------------------------------------------------
head1 "Evidence tree integrity"
info "Collection format: ${FORMAT}"

verify_linux() {
    local sums="20_Hashes/SHA256SUMS.txt" total malformed out rc failed unrecorded
    total="$(grep -cE '^\\?[0-9a-fA-F]{64} [ *].' "$EVID/$sums")"
    malformed="$(grep -cvE '^(\\?[0-9a-fA-F]{64} [ *].+)?$' "$EVID/$sums")"
    if (( total == 0 )); then
        bad "The hash inventory is empty or unreadable: ${sums}"
        FAILURES=$((FAILURES + 1))
        return
    fi
    if (( malformed > 0 )); then
        bad "${malformed} malformed line(s) in ${sums}"
        FAILURES=$((FAILURES + malformed))
    fi

    # collection.log keeps growing until the run ends, so it is intentionally
    # not part of the inventory; the archive SHA256 covers it.
    out="$(cd "$EVID" && "${SHA256[@]}" -c --quiet "$sums" 2>&1)"
    rc=$?
    failed="$(printf '%s\n' "$out" | grep -c ': FAILED')"
    if (( failed == 0 && rc == 0 )); then
        ok "All ${total} hashed files match"
    elif (( failed > 0 )); then
        bad "${failed} of ${total} recorded files do not match or are missing"
        printf '%s\n' "$out" | grep ': FAILED' | head -n 20 | sed 's/^/         /'
        FAILURES=$((FAILURES + failed))
    elif (( malformed == 0 )); then
        bad "The inventory could not be verified"
        printf '%s\n' "$out" | head -n 10 | sed 's/^/         /'
        FAILURES=$((FAILURES + 1))
    fi

    # Names sha256sum had to escape (backslash, newline) are not compared here.
    unrecorded="$( (cd "$EVID" && find . -type f -print | sed 's|^\./||') |
        awk 'NR == FNR { sub(/^\\?[0-9a-fA-F]+ [ *]\.\//, ""); seen[$0] = 1; next }
             !($0 in seen) && $0 !~ /\\/ &&
             $0 !~ /^(19_CollectionLogs\/collection\.log$|20_Hashes\/|21_Manifest\/)/' \
            "$EVID/$sums" -)"
    if [[ -n "$unrecorded" ]]; then
        warn "$(printf '%s\n' "$unrecorded" | grep -c .) file(s) are present but not in the inventory"
        printf '%s\n' "$unrecorded" | head -n 10 | sed 's/^/         /'
    fi
}

verify_windows() {
    if ! command -v python3 >/dev/null 2>&1; then
        bad "python3 is required to verify Windows collections here (or use vestigium.ps1 verify)"
        FAILURES=$((FAILURES + 1))
        return
    fi
    local report total malformed mismatched missing drift unrecorded
    report="$(python3 - "$EVID" <<'PY'
import csv
import hashlib
import os
import re
import sys

root = sys.argv[1]
inventory = os.path.join(root, "15_Hashes", "SHA256.csv")
post_hash = re.compile(r"^(14_Logs/Collection\.log$|15_Hashes/|16_Manifest/)", re.I)
digest_re = re.compile(r"[0-9a-f]{64}")
recorded, mismatched, missing, drift = set(), [], [], []
malformed = 0
with open(inventory, encoding="utf-8-sig", newline="") as handle:
    rows = list(csv.DictReader(handle))
for row in rows:
    rel = (row.get("RelativePath") or "").replace("\\", "/")
    want = (row.get("SHA256") or "").lower()
    if not rel or not digest_re.fullmatch(want):
        malformed += 1
        continue
    recorded.add(rel.lower())
    path = os.path.join(root, *rel.split("/"))
    if not os.path.isfile(path):
        missing.append(rel)
        continue
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() != want:
        # Collections made before Vestigium 2.0 hashed Collection.log while
        # it was still being written.
        (drift if rel.lower() == "14_logs/collection.log" else mismatched).append(rel)
unrecorded = []
for dirpath, _dirs, files in os.walk(root):
    for name in files:
        full = os.path.join(dirpath, name)
        if os.path.islink(full):
            continue
        rel = os.path.relpath(full, root).replace(os.sep, "/")
        if rel.lower() not in recorded and not post_hash.search(rel):
            unrecorded.append(rel)
print(f"TOTAL {len(rows) - malformed}")
print(f"MALFORMED {malformed}")
for tag, items in (("MISMATCH", mismatched), ("MISSING", missing),
                   ("DRIFT", drift), ("UNRECORDED", unrecorded)):
    for item in items:
        print(f"{tag} {item}")
PY
)" || { bad "Could not read 15_Hashes/SHA256.csv"; FAILURES=$((FAILURES + 1)); return; }

    total="$(sed -n 's/^TOTAL //p' <<<"$report")"
    malformed="$(sed -n 's/^MALFORMED //p' <<<"$report")"
    mismatched="$(grep -c '^MISMATCH ' <<<"$report")"
    missing="$(grep -c '^MISSING ' <<<"$report")"
    drift="$(grep -c '^DRIFT ' <<<"$report")"
    unrecorded="$(grep -c '^UNRECORDED ' <<<"$report")"
    if (( ${total:-0} == 0 )); then
        bad "The hash inventory is empty or unreadable: 15_Hashes/SHA256.csv"
        FAILURES=$((FAILURES + 1))
    fi
    if (( ${malformed:-0} > 0 )); then
        bad "${malformed} malformed row(s) in 15_Hashes/SHA256.csv"
        FAILURES=$((FAILURES + malformed))
    fi
    if (( ${total:-0} > 0 && mismatched == 0 && missing == 0 )); then
        ok "All ${total} recorded files match"
    fi
    if (( mismatched > 0 || missing > 0 )); then
        (( mismatched > 0 )) && bad "${mismatched} file(s) do not match their recorded hash"
        (( missing > 0 )) && bad "${missing} recorded file(s) are missing"
        grep -E '^(MISMATCH|MISSING) ' <<<"$report" | head -n 20 | sed 's/^/         /'
        FAILURES=$((FAILURES + mismatched + missing))
    fi
    (( drift > 0 )) && warn "14_Logs/Collection.log changed after hashing (expected for collections made before Vestigium 2.0)"
    if (( unrecorded > 0 )); then
        warn "${unrecorded} file(s) are present but not in the inventory"
        grep '^UNRECORDED ' <<<"$report" | head -n 10 | sed 's/^UNRECORDED /         /'
    fi
}

case "$FORMAT" in
    linux)   verify_linux ;;
    windows) verify_windows ;;
    *)       bad "Hash inventory missing: 20_Hashes/SHA256SUMS.txt or 15_Hashes/SHA256.csv"
             FAILURES=$((FAILURES + 1)) ;;
esac

# Memory images carry their own SHA256 sidecar and usually travel beside the
# archive rather than inside it.
while IFS= read -r sidecar; do
    [[ -n "$sidecar" ]] || continue
    image="${sidecar%.sha256}"
    expected="$(awk 'NR == 1 {print tolower($1)}' "$sidecar")"
    if [[ -f "$image" ]]; then
        if [[ "$("${SHA256[@]}" "$image" | awk '{print tolower($1)}')" == "$expected" ]]; then
            ok "Memory image matches: ${image#"$EVID"/}"
        else
            bad "Memory image does NOT match: ${image#"$EVID"/}"
            FAILURES=$((FAILURES + 1))
        fi
    else
        info "Memory image $(basename "$image") is stored outside the archive; expected SHA256 ${expected}"
    fi
done < <(find "$EVID" -path '*_Memory/*.sha256' -type f 2>/dev/null)

# ---------------------------------------------------------------------------
head1 "Collection summary"
if [[ "$FORMAT" == linux ]]; then
    [[ -f "${EVID}/21_Manifest/summary.txt" ]] && sed -n '1,28p' "${EVID}/21_Manifest/summary.txt"
    if [[ -f "${EVID}/19_CollectionLogs/INCOMPLETE.txt" ]]; then
        warn "This collection was INTERRUPTED - see 19_CollectionLogs/INCOMPLETE.txt"
    fi

    head1 "Module results"
    if [[ -f "${EVID}/19_CollectionLogs/module-results.csv" ]] && command -v python3 >/dev/null 2>&1; then
        python3 - "${EVID}/19_CollectionLogs/module-results.csv" <<'PY'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8", errors="replace")))
print(f"{'MODULE':<18}{'STATUS':<13}{'ARTIFACTS':>10}{'SKIPPED':>9}{'FAILED':>8}{'SECONDS':>9}")
for r in rows:
    print(f"{r['Module']:<18}{r['Status']:<13}{r['Commands']:>10}{r['Skipped']:>9}{r['Failures']:>8}{r['DurationSeconds']:>9}")
PY
    else
        cat "${EVID}/19_CollectionLogs/module-results.csv" 2>/dev/null
    fi
elif [[ "$FORMAT" == windows ]]; then
    if [[ -f "${EVID}/16_Manifest/Manifest.json" ]] && command -v python3 >/dev/null 2>&1; then
        python3 - "${EVID}/16_Manifest/Manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8-sig"))
for key in ("Hostname", "CaseId", "Operator", "CollectorVersion", "CollectionTime",
            "Status", "NumberOfFiles", "DurationSeconds"):
    if key in manifest:
        print(f"{key:<18}: {manifest[key]}")
results = manifest.get("Results") or []
if isinstance(results, dict):
    results = [results]
if results:
    print(f"\n{'MODULE':<18}{'SUCCESS':<9}MESSAGE")
    for r in results:
        print(f"{str(r.get('Name', '')):<18}{str(r.get('Success', '')):<9}{r.get('Message', '') or ''}")
PY
    fi
fi

# ---------------------------------------------------------------------------
_report() {
    # _report LABEL FILE [GREP_PATTERN]
    local label="$1" file="$2" pattern="${3:-}"
    [[ -f "$file" ]] || return 0
    local count
    if [[ -n "$pattern" ]]; then
        count="$(grep -cE "$pattern" "$file" 2>/dev/null)"
    else
        count="$(grep -cvE '^\s*(#|$)' "$file" 2>/dev/null)"
    fi
    count="${count//[^0-9]/}"; count="${count:-0}"
    if (( count > 0 )); then
        warn "${label}: ${count} line(s) - ${file#"$EVID"/}"
    else
        ok "${label}: nothing recorded"
    fi
}

if [[ "$FORMAT" == linux ]]; then
    head1 "High-signal findings"
    # YARA match lines look like "<rule> [tags] /path"; header lines never do.
    _report "YARA file matches"        "${EVID}/18_Yara/yara_matches.txt"          '^[A-Za-z_][A-Za-z0-9_]* (\[[^]]*\] )?/'
    _report "YARA process matches"     "${EVID}/18_Yara/yara_process_matches.txt"  '^=== PID'
    _report "IOC matches"              "${EVID}/18_Yara/ioc-matches/ioc_matches.txt" '^MATCH'
    _report "Unpackaged setuid binaries" "${EVID}/15_Filesystem/suid_unpackaged.txt" '^UNPACKAGED'
    _report "Unpackaged system binaries" "${EVID}/12_Security/integrity/unpackaged_binaries.txt" '^UNPACKAGED'
    _report "Unpackaged systemd units" "${EVID}/03_Persistence/systemd/unpackaged-units.txt" '^=== '
    _report "Unpackaged PAM modules"   "${EVID}/03_Persistence/pam/unpackaged-pam-modules.txt" '^UNPACKAGED'
    _report "Modified packaged files"  "${EVID}/12_Security/integrity/dpkg_verify.txt" '^\?\?|^..5'
    _report "Processes on deleted binaries" "${EVID}/02_Processes/anomaly_deleted_binaries.txt" '^PID '
    _report "Processes from temp/home paths" "${EVID}/02_Processes/anomaly_suspicious_exec_paths.txt" '^PID '
    _report "LD_PRELOAD injected processes"  "${EVID}/02_Processes/anomaly_ld_preload.txt" '^PID '
    _report "Executables in temp dirs" "${EVID}/15_Filesystem/executables_in_temp.txt" '^/(tmp|var/tmp|dev/shm)'

    ldpre="${EVID}/03_Persistence/dynamic-linker/ld.so.preload.txt"
    if [[ -f "$ldpre" ]] && grep -q '^RESULT: ld.so.preload=PRESENT' "$ldpre" 2>/dev/null; then
        bad "/etc/ld.so.preload exists on the host - review immediately"
    elif [[ -f "$ldpre" ]]; then
        ok "/etc/ld.so.preload: absent"
    fi

    if [[ -f "${EVID}/09_Browser/SUMMARY.txt" ]]; then
        n="$(sed -n '/extensions not installed from an official store/,/^$/p' \
             "${EVID}/09_Browser/SUMMARY.txt" 2>/dev/null | grep -c 'update_url=')"
        n="${n//[^0-9]/}"; n="${n:-0}"
        if (( n > 0 )); then
            warn "Browser extensions from outside an official store: ${n}"
        else
            ok "Browser extensions: all from official stores"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Triage findings (findings.json is written at the evidence root by both
# platforms, so this works whatever produced the package).
if [[ -f "${EVID}/findings.json" ]] && command -v python3 >/dev/null 2>&1; then
    head1 "Triage findings"
    python3 - "${EVID}/findings.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as exc:
    print(f"  (could not read findings.json: {exc})"); sys.exit(0)
c = d.get("counts", {})
print("  {:>3} critical  {:>3} high  {:>3} medium  {:>3} low  {:>3} info  ({} total)".format(
    c.get("critical", 0), c.get("high", 0), c.get("medium", 0),
    c.get("low", 0), c.get("info", 0), c.get("total", 0)))
for f in d.get("findings", []):
    if f.get("severity") in ("critical", "high"):
        print("  [{:<8}] {}  ({})".format(f.get("severity", ""), f.get("title", ""), f.get("count", 0)))
PY
fi

head1 "Next steps"
if [[ -n "$TMPDIR_EXTRACT" ]]; then
    printf '  The archive was extracted to a temporary directory that is removed\n'
    printf '  when this script exits. Extract it yourself to read these files.\n\n'
    prefix=""
else
    prefix="${EVID}/"
fi
[[ -f "${EVID}/findings.html" ]] && printf '  Findings report: %sfindings.html\n' "$prefix"
if [[ "$FORMAT" == windows ]]; then
    printf '  Triage summary : %s19_Triage/Findings.md\n' "$prefix"
    printf '  Collection log : %s14_Logs/Collection.log\n' "$prefix"
    printf '  Full manifest  : %s16_Manifest/Manifest.json\n\n' "$prefix"
else
    printf '  Browser triage : %s09_Browser/SUMMARY.txt\n' "$prefix"
    printf '  Persistence    : %s03_Persistence/SUMMARY.txt\n' "$prefix"
    printf '  Logins         : %s10_Logs/SUMMARY.txt\n' "$prefix"
    printf '  Full manifest  : %s21_Manifest/manifest.json\n\n' "$prefix"
fi

head1 "Result"
if (( FAILURES == 0 )); then
    ok "Evidence package verified"
    exit 0
fi
bad "Integrity problems found: ${FAILURES}"
exit 1
