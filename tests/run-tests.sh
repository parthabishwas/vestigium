#!/usr/bin/env bash
#
# run-tests.sh - Static checks and offline tests for Vestigium.
#
# Nothing is collected from the host: the tests lint every script, exercise
# the launchers in --dry-run mode, run the collectors' argument handling, and
# verify synthetic evidence packages (clean, tampered, corrupted, malformed and
# malicious) with both verifiers. shellcheck, pwsh, zstd and python3 are used
# when present; whatever is missing is reported as skipped.
#
# Usage: tests/run-tests.sh
#
set -uo pipefail

KIT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
PASS=0; FAIL=0; SKIP=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/vestigium-tests.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT

pass()    { PASS=$((PASS + 1)); printf '  ok    %s\n' "$*"; }
fail()    { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$*"; }
skip()    { SKIP=$((SKIP + 1)); printf '  skip  %s\n' "$*"; }
section() { printf '\n== %s\n' "$*"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# expect DESCRIPTION WANT_RC PATTERN COMMAND...
# Passes when COMMAND exits WANT_RC and (if PATTERN is set) prints a line
# matching the extended regex PATTERN.
expect() {
    local desc="$1" want_rc="$2" pattern="$3"; shift 3
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    if [[ "$rc" == "$want_rc" ]] && { [[ -z "$pattern" ]] || grep -qE -- "$pattern" <<<"$out"; }; then
        pass "$desc"
    else
        fail "$desc (rc=${rc}, want ${want_rc}; pattern: ${pattern:-none})"
        printf '%s\n' "$out" | head -n 15 | sed 's/^/          /'
    fi
}

# Vendored content (unpacked packages, cloned rule repositories) is not ours to lint.
VENDORED=(-path "$KIT/platforms/linux/tools/portable" -o -path "$KIT/platforms/linux/tools/deb"
          -o -path "$KIT/shared/yara-rules" -o -path "$KIT/output")
mapfile -t BASH_FILES < <(find "$KIT/platforms/linux" "$KIT/shared" "$KIT/tests" \( "${VENDORED[@]}" \) -prune -o -name '*.sh' -type f -print | sort)
mapfile -t PY_FILES < <(find "$KIT/platforms" "$KIT/shared" \( "${VENDORED[@]}" \) -prune -o -name '*.py' -type f -print | sort)
mapfile -t PS_FILES < <(find "$KIT" \( "${VENDORED[@]}" \) -prune -o -name '*.ps1' -type f -print | sort)

# ---------------------------------------------------------------------------
section "Syntax"
if sh -n "$KIT/vestigium.sh"; then pass "sh -n vestigium.sh"; else fail "sh -n vestigium.sh"; fi
if have dash; then
    if dash -n "$KIT/vestigium.sh"; then pass "dash -n vestigium.sh"; else fail "dash -n vestigium.sh"; fi
fi
for f in "${BASH_FILES[@]}"; do
    if bash -n "$f" 2>"$WORK/err"; then pass "bash -n ${f#"$KIT"/}"; else fail "bash -n ${f#"$KIT"/}: $(head -n 1 "$WORK/err")"; fi
done
if have python3; then
    for f in "${PY_FILES[@]}"; do
        if python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1])' "$f" 2>"$WORK/err"
        then pass "python parse ${f#"$KIT"/}"; else fail "python parse ${f#"$KIT"/}: $(tail -n 1 "$WORK/err")"; fi
    done
else
    skip "python3 not installed"
fi

# ---------------------------------------------------------------------------
section "Lint"
if have shellcheck; then
    if shellcheck -s sh -S warning "$KIT/vestigium.sh" >"$WORK/sc" 2>&1; then pass "shellcheck vestigium.sh"
    else fail "shellcheck vestigium.sh"; head -n 20 "$WORK/sc" | sed 's/^/          /'; fi
    if shellcheck -s bash -S warning "${BASH_FILES[@]}" >"$WORK/sc" 2>&1; then pass "shellcheck bash sources (${#BASH_FILES[@]} files)"
    else fail "shellcheck bash sources"; head -n 40 "$WORK/sc" | sed 's/^/          /'; fi
else
    skip "shellcheck not installed"
fi
if grep -nP '[^\x00-\x7F]' "${PS_FILES[@]}" "$KIT/vestigium.cmd" >"$WORK/ascii" 2>/dev/null; then
    fail "PowerShell/cmd sources must be ASCII (Windows PowerShell 5.1 reads BOM-less files as ANSI)"
    head -n 10 "$WORK/ascii" | sed 's/^/          /'
else
    pass "PowerShell/cmd sources are ASCII-only"
fi
if [[ "$(grep -c $'\r$' "$KIT/vestigium.cmd")" == "$(wc -l <"$KIT/vestigium.cmd")" ]]; then
    pass "vestigium.cmd uses CRLF line endings"
else
    fail "vestigium.cmd must use CRLF line endings"
fi

if have pwsh; then
    pwsh -NoProfile -File "$KIT/tests/ps-parse.ps1" "${PS_FILES[@]}" >"$WORK/psparse" 2>&1
    while IFS= read -r line; do
        case "$line" in
            "OK "*)    pass "PowerShell parse ${line#OK "$KIT"/}" ;;
            "ERROR "*) fail "PowerShell parse ${line#ERROR "$KIT"/}" ;;
        esac
    done <"$WORK/psparse"
    grep -qE '^(OK|ERROR) ' "$WORK/psparse" || { fail "PowerShell parser did not run"; head -n 5 "$WORK/psparse" | sed 's/^/          /'; }
    leaks="$(pwsh -NoProfile -File "$KIT/tests/ast-leaks.ps1" -Root "$KIT/platforms/windows" 2>&1)"
    if [[ -z "$leaks" ]]; then pass "no leaked boolean results in Windows modules"
    else fail "leaked boolean results in Windows modules"; printf '%s\n' "$leaks" | sed 's/^/          /'; fi
else
    skip "pwsh not installed: PowerShell parse and leak checks"
fi

# ---------------------------------------------------------------------------
section "sh launcher (dry run)"
CT="$KIT/vestigium.sh"
if [[ "$(uname -s)" == Linux ]]; then
    expect "version"                 0 '^Vestigium [0-9]'             sh "$CT" version
    expect "help"                    0 'Usage: \./vestigium\.sh'      sh "$CT" help
    expect "linux translation"       0 "'--case-id' 'IR 7' '--target-user' 'alice' '--target-user' 'bob' '--quick'" \
        sh "$CT" --dry-run --no-elevate --case-id 'IR 7' --target-user alice -TargetUser bob -Quick
    expect "option values are never remapped" 0 "'--case-id' '-Verbose'" \
        sh "$CT" --dry-run --no-elevate --case-id -Verbose
    expect "windows translation"     0 "'-CaseId' 'IR 7'.*'-YaraTimeoutSeconds' '60'.*'-TargetUser' 'alice,bob'" \
        sh "$CT" --platform windows --dry-run --case-id 'IR 7' --target-user alice --target-user bob --yara-timeout=60
    expect "windows credential mode" 0 "'-BrowserCredentialStores' 'MetadataOnly'" \
        sh "$CT" --platform windows --dry-run --credential-stores metadata
    expect "windows rejects unknown" 2 'unknown option'                sh "$CT" --platform windows --dry-run --bogus
    expect "linux credential-store policy" 0 "'--credential-stores' 'metadata'" \
        sh "$CT" --dry-run --no-elevate -BrowserCredentialStores MetadataOnly
    expect "credential-store value validated" 2 'copy or metadata'     sh "$CT" --dry-run --credential-stores maybe
    expect "unknown command rejected" 2 "unknown command 'verfiy'"     sh "$CT" verfiy x.zip
    expect "stray argument rejected"  2 "unexpected argument"          sh "$CT" --dry-run --case-id X stray
    expect "verify needs a package"  2 'usage'                         sh "$CT" verify
    expect "unknown platform"        2 'unknown --platform'            sh "$CT" --platform plan9
    ln -s "$CT" "$WORK/ct-link"
    expect "works through a symlink" 0 '^Vestigium [0-9]'             sh "$WORK/ct-link" version
else
    skip "sh launcher tests need Linux"
fi

if have pwsh; then
    section "PowerShell launcher (dry run)"
    PSL=(pwsh -NoProfile -File "$KIT/vestigium.ps1")
    expect "version"                 0 '^Vestigium [0-9]'             "${PSL[@]}" version
    expect "linux translation"       0 "--case-id 'IR 7' --target-user alice --target-user bob --quick" \
        "${PSL[@]}" -DryRun -CaseId 'IR 7' -TargetUser alice,bob -Quick
    expect "GNU options accepted"    0 '--case-id IR-8 --output /tmp/ev --memory' \
        "${PSL[@]}" -DryRun --case-id IR-8 --output=/tmp/ev --memory
    expect "in-process comma list"   0 '--target-user alice --target-user bob' \
        pwsh -NoProfile -Command "& '$KIT/vestigium.ps1' -DryRun --target-user alice,bob"
    expect "windows translation"     0 "-BrowserCredentialStores MetadataOnly -CaseId 'IR 7' -SkipYara -TargetUser alice,bob" \
        "${PSL[@]}" -DryRun -Platform Windows -CaseId 'IR 7' -TargetUser alice,bob -BrowserCredentialStores MetadataOnly --skip-yara
    expect "unknown command"         2 'unknown command'               "${PSL[@]}" bogus
fi

# ---------------------------------------------------------------------------
section "Linux collector argument handling"
LC="$KIT/platforms/linux/vestigium-linux.sh"
expect "--help"                      0 'Vestigium Linux Collector'    bash "$LC" --help
expect "--version"                   0 '^vestigium-linux\.sh [0-9]'   bash "$LC" --version
expect "--list-modules"              0 '^Processes$'                   bash "$LC" --list-modules
# shellcheck disable=SC2016 # the literal is the point: it must be rejected, not evaluated
expect "rejects arithmetic injection" 2 ''                             bash "$LC" --cmd-timeout 'a[$(touch /tmp/ct-pwned)]'
if [[ -e /tmp/ct-pwned ]]; then fail "arithmetic injection executed"; rm -f /tmp/ct-pwned; fi
expect "rejects unknown option"      2 'Unknown option'                bash "$LC" --no-such-option

# ---------------------------------------------------------------------------
section "Evidence verification"
if ! have python3; then
    skip "python3 not installed: verification fixtures"
else
    F="$WORK/fixtures"
    L="$F/lin/web01_20260911_101500"
    mkdir -p "$L/01_System" "$L/19_CollectionLogs" "$L/20_Hashes" "$L/21_Manifest"
    echo hello >"$L/01_System/a.txt"
    printf 'x y\n' >"$L/01_System/space name.txt"
    printf '"Module","Status","Commands","Skipped","Failures","DurationSeconds","Message"\n"System","OK","3","0","0","1",""\n' \
        >"$L/19_CollectionLogs/module-results.csv"
    (cd "$L" && find . -type f ! -path './20_Hashes/*' -print0 | sort -z | xargs -0 sha256sum) >"$L/20_Hashes/SHA256SUMS.txt"
    echo "log line" >"$L/19_CollectionLogs/collection.log"
    printf 'Summary\n' >"$L/21_Manifest/summary.txt"
    (cd "$F/lin" && tar -czf ../web01.tar.gz web01_20260911_101500) && (cd "$F" && sha256sum web01.tar.gz >web01.tar.gz.sha256)
    cp -a "$F/lin" "$F/tampered"
    echo tampered >>"$F/tampered/web01_20260911_101500/01_System/a.txt"
    cp -a "$F/lin" "$F/empty";   : >"$F/empty/web01_20260911_101500/20_Hashes/SHA256SUMS.txt"
    cp -a "$F/lin" "$F/garbage"; echo garbage >"$F/garbage/web01_20260911_101500/20_Hashes/SHA256SUMS.txt"
    cp "$F/web01.tar.gz" "$F/bad.tar.gz"; sed 's/web01.tar.gz/bad.tar.gz/' "$F/web01.tar.gz.sha256" >"$F/bad.tar.gz.sha256"
    printf 'junk' >>"$F/bad.tar.gz"

    W="$F/win/WS01_ADMIN_20260911_101500"
    mkdir -p "$W/01_System" "$W/14_Logs" "$W/15_Hashes" "$W/16_Manifest"
    echo asset >"$W/01_System/AssetInfo.txt"
    python3 - "$W" <<'PY'
import csv, hashlib, os, sys
root = sys.argv[1]
rows = []
for dirpath, _dirs, files in os.walk(root):
    for name in files:
        full = os.path.join(dirpath, name)
        rel = os.path.relpath(full, root).replace("/", "\\")
        rows.append({"RelativePath": rel, "FullPath": "C:\\ev\\" + rel,
                     "SHA256": hashlib.sha256(open(full, "rb").read()).hexdigest().upper(),
                     "Length": os.path.getsize(full), "LastWriteUtc": ""})
with open(os.path.join(root, "15_Hashes", "SHA256.csv"), "w", newline="", encoding="utf-8-sig") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows)
PY
    echo "late log line" >"$W/14_Logs/Collection.log"
    printf '{"Hostname":"WS01","Status":"Completed","Results":[{"Name":"System","Success":true,"Message":""}]}' \
        >"$W/16_Manifest/Manifest.json"
    python3 - "$F/win" "$F/WS01.zip" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
    for dirpath, _dirs, files in os.walk(src):
        for name in files:
            full = os.path.join(dirpath, name)
            archive.write(full, os.path.relpath(full, src))
PY
    (cd "$F" && sha256sum WS01.zip | awk '{print toupper($1) "  WS01.zip"}' >WS01.zip.sha256)
    cp -a "$F/win" "$F/winbad"
    printf '"RelativePath","FullPath","SHA256","Length","LastWriteUtc"\n"01_System\\AssetInfo.txt","","nothex","",""\n' \
        >"$F/winbad/WS01_ADMIN_20260911_101500/15_Hashes/SHA256.csv"
    python3 -c 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1], "w"); z.writestr("../../escape.txt", "x"); z.close()' "$F/evil.zip"

    # Linux fixture: 3 hashed files (two samples + module-results.csv);
    # Windows fixture: 1 (Collection.log is written after hashing, as in 2.0).
    VS=(bash "$KIT/shared/verify-evidence.sh")
    expect "sh: clean Linux tree"          0 'All 3 hashed files match'        "${VS[@]}" "$L"
    expect "sh: Linux archive + sidecar"   0 'Archive SHA256 matches'          "${VS[@]}" "$F/web01.tar.gz"
    expect "sh: tampered Linux tree"       1 'do not match'                    "${VS[@]}" "$F/tampered/web01_20260911_101500"
    expect "sh: empty inventory fails"     1 'empty or unreadable'             "${VS[@]}" "$F/empty/web01_20260911_101500"
    expect "sh: garbage inventory fails"   1 'empty or unreadable'             "${VS[@]}" "$F/garbage/web01_20260911_101500"
    expect "sh: corrupted archive"         1 'does NOT match'                  "${VS[@]}" "$F/bad.tar.gz"
    expect "sh: Windows tree"              0 'All 1 recorded files match'      "${VS[@]}" "$W"
    expect "sh: Windows zip + sidecar"     0 'Archive SHA256 matches'          "${VS[@]}" "$F/WS01.zip"
    expect "sh: malformed Windows CSV"     1 'malformed row'                   "${VS[@]}" "$F/winbad/WS01_ADMIN_20260911_101500"
    expect "sh: zip path traversal"        2 'Extraction failed'               "${VS[@]}" "$F/evil.zip"
    if [[ -e "$WORK/escape.txt" || -e "$F/escape.txt" ]]; then fail "zip traversal wrote outside the extraction dir"; fi
    if have pwsh; then
        VP=(pwsh -NoProfile -File "$KIT/shared/Verify-Evidence.ps1")
        expect "ps: clean Linux tree"      0 'All 3 recorded files match'      "${VP[@]}" "$L"
        expect "ps: Linux archive"         0 'Archive SHA256 matches'          "${VP[@]}" "$F/web01.tar.gz"
        expect "ps: tampered Linux tree"   1 'do not match'                    "${VP[@]}" "$F/tampered/web01_20260911_101500"
        expect "ps: empty inventory fails" 1 'empty or unreadable'             "${VP[@]}" "$F/empty/web01_20260911_101500"
        expect "ps: garbage inventory fails" 1 'malformed line'                "${VP[@]}" "$F/garbage/web01_20260911_101500"
        expect "ps: Windows zip"           0 'Evidence package verified'       "${VP[@]}" "$F/WS01.zip"
        expect "ps: malformed Windows CSV" 1 'malformed line'                  "${VP[@]}" "$F/winbad/WS01_ADMIN_20260911_101500"
        expect "ps: zip path traversal"    2 'Unsafe path'                     "${VP[@]}" "$F/evil.zip"
    fi
fi

# ---------------------------------------------------------------------------
section "Browser credential-store policy (Linux)"
if have python3; then
    B="$WORK/browser"
    mkdir -p "$B/chrome/Default/Network" "$B/firefox/abcd.default"
    echo pw >"$B/chrome/Default/Login Data"
    echo ck >"$B/chrome/Default/Network/Cookies"
    echo '{}' >"$B/chrome/Default/Preferences"
    echo '{"os_crypt":{"encrypted_key":"SECRETKEY"}}' >"$B/chrome/Local State"
    echo lj >"$B/firefox/abcd.default/logins.json"
    echo k4 >"$B/firefox/abcd.default/key4.db"
    for policy in copy metadata; do
        listing="$(DFIR_CREDENTIAL_STORES="$policy" B="$B" EV="$WORK/bev-$policy" bash -c '
            set -uo pipefail
            DFIR_ROOT="$0/platforms/linux"; DFIR_TOOLS="$DFIR_ROOT/tools"; DFIR_MODULES="$DFIR_ROOT/modules"
            DFIR_KIT_ROOT="$0"; DFIR_CMD_TIMEOUT=60; DFIR_MAX_FILE_MB=64; DFIR_MAX_HASH_MB=64
            DFIR_MAX_TREE_FILES=100; DFIR_BROWSER_HISTORY=1; DFIR_BROWSER_SESSIONS=0
            DFIR_TARGET_USERS=(); DFIR_QUIET=1; DFIR_VERBOSE=0; DFIR_MODE=full
            source "$DFIR_MODULES/00-lib.sh"; source "$DFIR_MODULES/60-browser.sh"
            mkdir -p "$EV" && dfir_init "$EV" >/dev/null 2>&1
            base="${DFIR_DIR[Browser]}/tester"
            _dfir_browser_chromium tester Chrome "$B/chrome" "$base" >/dev/null 2>&1
            _dfir_browser_firefox tester Firefox "$B/firefox" "$base" >/dev/null 2>&1
            cd "$base" && find . -type f | sort
            grep -c SECRETKEY Chrome/Local_State.redacted.json' "$KIT" 2>&1)"
        copied="$(grep -c '/credential-stores/' <<<"$listing")"
        if [[ "$policy" == copy ]]; then
            if (( copied == 5 )) && grep -q 'Chrome/Default/credential-stores/Network/Cookies' <<<"$listing" &&
               grep -q 'Firefox/abcd.default/credential-stores/key4.db' <<<"$listing"; then
                pass "copy: Chromium, Firefox and Local State stores copied (5 files)"
            else
                fail "copy: expected 5 copied credential stores, found ${copied}"; printf '%s\n' "$listing" | sed 's/^/          /'
            fi
        else
            if (( copied == 0 )) && [[ "$(grep -c 'credential_store_metadata.txt' <<<"$listing")" == 2 ]]; then
                pass "metadata: no credential store copied, metadata written"
            else
                fail "metadata: ${copied} credential store(s) copied"; printf '%s\n' "$listing" | sed 's/^/          /'
            fi
        fi
        if [[ "$(tail -n 1 <<<"$listing")" == 0 ]]; then pass "${policy}: redacted Local State hides the key"
        else fail "${policy}: redacted Local State still contains the key"; fi
    done
else
    skip "python3 not installed: browser policy test"
fi

section "YARA rule builder"
BYR="$KIT/platforms/linux/tools/build-yara-rules.py"
YARAC=/usr/bin/yarac
# check DESCRIPTION COMMAND...: passes when COMMAND succeeds.
check() { local desc="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi; }
if ! have python3 || [[ ! -x "$YARAC" ]]; then
    skip "python3 or ${YARAC} not available: rule builder tests"
else
    R="$WORK/yara-rules"
    mkdir -p "$R/custom" "$R/alpha/yara" "$R/beta/rules/noisy" "$R/stray/yara" "$WORK/corpus"
    printf '# test sources\nalpha https://example.invalid/alpha.git\nbeta  https://example.invalid/beta.git  v1  # pinned\n' >"$R/sources.conf"
    printf 'file:beta/rules/noisy/*\nrule:Noisy_*    # silence the noisy family\n' >"$R/exclusions.conf"
    printf 'rule Shared_Name { strings: $a = "custom-wins" condition: $a }\n' >"$R/custom/org.yar"
    printf 'rule Shared_Name { strings: $a = "alpha-loses" condition: $a }\nrule Alpha_In_Clash_File { condition: false }\n' \
        >"$R/alpha/yara/clash.yar"
    printf 'rule Noisy_Const { strings: $a = "NOISY-MARKER" condition: $a }\nglobal rule Noisy_Global { condition: true }\nrule Uses_Noisy { condition: Noisy_Const }\n' \
        >"$R/alpha/yara/good.yar"
    printf 'rule Uses_Noisy { condition: true }\n' >"$R/beta/rules/later.yar"
    printf 'rule Beta_Excluded_By_File { condition: true }\n' >"$R/beta/rules/noisy/n.yar"
    printf 'rule Broken_Rule { strings: $a = "x" condition: $a and and }\n' >"$R/beta/rules/broken.yar"
    printf 'rule Beta_Fine { strings: $a = "beta-fine" condition: $a }\n' >"$R/beta/rules/fine.yar"
    printf 'rule Stray_Not_Configured { condition: true }\n' >"$R/stray/yara/s.yar"
    printf 'xx NOISY-MARKER beta-fine xx\n' >"$WORK/corpus/sample.txt"
    GITREPOS=0
    if have git; then
        GITREPOS=1
        for repo in alpha beta; do
            { git -C "$R/$repo" init -q && git -C "$R/$repo" add -A &&
              git -C "$R/$repo" -c user.name=t -c user.email=t@example.invalid commit -qm init; } >/dev/null 2>&1 || GITREPOS=0
        done
    fi
    BUILD=(python3 "$BYR" --rules-dir "$R" --compiled "$R/active-rules.compiled" --yarac "$YARAC")
    B="$R/active-rules.yar"; REP="$R/rule-build-report.csv"; LOCK="$R/rules.lock"

    expect "builder: bundle built, lock written"  0 'lock written'       "${BUILD[@]}"
    check  "custom/ wins an identifier clash"   grep -qF '"alpha","alpha/yara/clash.yar","skipped","identifier already accepted: Shared_Name"' "$REP"
    check  "custom rule text is in the bundle"  grep -qF 'custom-wins' "$B"
    check  "earlier source wins over a later one" grep -qF '"beta","beta/rules/later.yar","skipped","identifier already accepted: Uses_Noisy"' "$REP"
    check  "sources are built in order (custom, alpha, beta)" \
        bash -c 'grep -o "^/\* BEGIN [a-z]*" "$1" | uniq | tr "\n" " " | grep -qx "/\* BEGIN custom /\* BEGIN alpha /\* BEGIN beta "' _ "$B"
    check  "unconfigured checkout is ignored"   bash -c '! grep -q Stray_Not_Configured "$1"' _ "$B"
    check  "file: exclusion drops the file"     grep -qF '"beta","beta/rules/noisy/n.yar","excluded","exclusions.conf line 1: file:beta/rules/noisy/*"' "$REP"
    check  "excluded rule absent from bundle"   bash -c '! grep -q Beta_Excluded_By_File "$1"' _ "$B"
    check  "rule: suppression makes the rule private" grep -qx 'private rule Noisy_Const { strings: $a = "NOISY-MARKER" condition: $a }' "$B"
    check  "rule: suppression keeps global"     grep -qx 'global private rule Noisy_Global { condition: true }' "$B"
    check  "suppressions are reported"          test "$(grep -c '","suppressed","' "$REP")" = 2
    check  "suppressed bundle still compiles"   "$YARAC" -w "$B" "$WORK/check.compiled"
    if [[ -x /usr/bin/yara ]]; then
        /usr/bin/yara -w "$B" "$WORK/corpus/sample.txt" >"$WORK/yara.out" 2>&1
        check "referencing rule still matches"  grep -q '^Uses_Noisy ' "$WORK/yara.out"
        check "suppressed rule never reports"   bash -c '! grep -q "^Noisy_" "$1"' _ "$WORK/yara.out"
        expect "false-positive corpus report"   0 'false-positive check: 2 rule' "${BUILD[@]}" --fp-corpus "$WORK/corpus"
        check  "FP report lists the firing rule" grep -q 'Beta_Fine' "$R/rule-fp-report.txt"
    else
        skip "/usr/bin/yara not available: match and false-positive checks"
    fi
    check  "broken rule file dropped"           grep -qE '"beta","beta/rules/broken.yar","skipped","does not compile' "$REP"
    check  "lock records the bundle SHA256"     grep -qx "sha256 = $(sha256sum "$B" | awk '{print $1}')" "$LOCK"
    check  "lock records requested refs"        grep -qx 'ref = v1' "$LOCK"
    expect "rebuild is deterministic (lock unchanged)" 0 'lock unchanged' "${BUILD[@]}"
    if (( GITREPOS == 1 )); then
        check  "lock records source commits"    grep -qx "commit = $(git -C "$R/alpha" rev-parse HEAD)" "$LOCK"
        expect "--locked rebuild matches the lock" 0 'lock check: MATCH' "${BUILD[@]}" --locked
        printf 'rule Beta_Later { condition: false }\n' >"$R/beta/rules/later2.yar"
        git -C "$R/beta" add -A >/dev/null 2>&1
        git -C "$R/beta" -c user.name=t -c user.email=t@example.invalid commit -qm later >/dev/null 2>&1
        expect "--locked refuses a checkout off the locked commit" 1 'rules.lock requires' "${BUILD[@]}" --locked
    else
        skip "git not available: commit and --locked checks"
    fi

    # Atomic replacement: a yarac that accepts every single file but rejects
    # the assembled temporary bundle must leave the previous bundle intact.
    before="$(sha256sum "$B" "$R/active-rules.compiled")"
    cat >"$WORK/failing-yarac" <<EOF
#!/bin/sh
case "\$(basename -- "\${2:-x}")" in
    .active-rules.building.*) echo "\$2(3): error: simulated compile failure" >&2; exit 1 ;;
esac
exec "$YARAC" "\$@"
EOF
    chmod +x "$WORK/failing-yarac"
    expect "failing bundle compile is reported" 1 'left unchanged' \
        python3 "$BYR" --rules-dir "$R" --compiled "$R/active-rules.compiled" --yarac "$WORK/failing-yarac"
    check  "previous bundle and compiled bundle survive" test "$before" = "$(sha256sum "$B" "$R/active-rules.compiled")"
    check  "no temporary bundle left behind"    bash -c '! compgen -G "$1/.active-rules.building.*"' _ "$R"

    cp "$R/sources.conf" "$WORK/sources.keep"
    printf 'evil file:///etc/passwd\n' >>"$R/sources.conf"
    expect "sources.conf rejects non-https/git@ URLs" 2 'invalid URL' "${BUILD[@]}"
    cp "$WORK/sources.keep" "$R/sources.conf"
    printf 'drop:everything\n' >>"$R/exclusions.conf"
    expect "exclusions.conf rejects unknown directives" 2 "expected 'file:<glob>'" "${BUILD[@]}"
    expect "setup --help lists the rule options" 0 '--rules-locked' bash "$KIT/platforms/linux/tools/setup-tools.sh" --help
fi

# ---------------------------------------------------------------------------
section "Findings report"
# Shared embedding: JSON with < > & and a literal </script> must round-trip
# through the template exactly, with no character able to close the script.
if have node; then
    node - "$KIT/shared/report/findings-template.html" <<'JS'
const fs=require('fs');
function esc(j){return j.replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/&/g,'\\u0026');}
const obj={schema:"vestigium/findings/1",findings:[{title:"a<b & c>d </script> <!-- x -->"}]};
const html=fs.readFileSync(process.argv[2],'utf8').replace('__VESTIGIUM_FINDINGS_JSON__',esc(JSON.stringify(obj)));
const block=html.match(/<script id="vestigium-findings"[^>]*>([\s\S]*?)<\/script>/)[1];
if(/[<>&]/.test(block)) throw new Error("literal < > & survived");
if(JSON.parse(block).findings[0].title!==obj.findings[0].title) throw new Error("fidelity lost");
JS
    if [[ $? -eq 0 ]]; then pass "findings template embeds JSON safely and losslessly"
    else fail "findings template embedding is unsafe or lossy"; fi
else
    skip "node not installed: findings embedding test"
fi

# Linux producer on a synthetic evidence tree.
if have python3; then
    B="$WORK/ev/host_20260101_000000"
    mkdir -p "$B/03_Persistence/dynamic-linker" "$B/18_Yara/ioc-matches" "$B/02_Processes" \
             "$B/19_CollectionLogs" "$B/17_Memory"
    printf 'RESULT: ld.so.preload=PRESENT\nmode=... mtime=...\n/usr/lib/evil.so\n' >"$B/03_Persistence/dynamic-linker/ld.so.preload.txt"
    printf 'MATCH hash deadbeef\n      seen in: x\n' >"$B/18_Yara/ioc-matches/ioc_matches.txt"
    printf 'Evil_Rule [tag] /tmp/x <b>&\n' >"$B/18_Yara/yara_matches.txt"
    printf 'PID 1234  /home/u/.hidden/dropper\n' >"$B/02_Processes/anomaly_suspicious_exec_paths.txt"
    printf '"Module","Status","Commands","Skipped","Failures","DurationSeconds","Message"\n"System","OK","5","0","0","1",""\n' >"$B/19_CollectionLogs/module-results.csv"
    printf 'x [WARN] a\ny [ERROR] b\n' >"$B/19_CollectionLogs/collection.log"
    printf 'Physical memory was not acquired.\n' >"$B/17_Memory/memory-image-NOT-COLLECTED.txt"
    out="$WORK/fj.json"; html="$WORK/fj.html"
    if DFIR_MF_CASE=T DFIR_MF_STATUS=completed DFIR_MF_VER=2.0.0 python3 "$KIT/platforms/linux/tools/build-findings.py" \
         --evidence "$B" --template "$KIT/shared/report/findings-template.html" \
         --json-out "$out" --html-out "$html" >/dev/null 2>&1; then
        check="$(python3 - "$out" "$html" <<'PY2'
import json,re,sys
d=json.load(open(sys.argv[0] if False else sys.argv[1]))
ids={f["id"]:f for f in d["findings"]}
assert ids["linux.persistence.ld_preload"]["severity"]=="critical", "ld_preload severity"
assert ids["linux.malware.ioc"]["severity"]=="critical", "ioc severity"
assert ids["linux.malware.yara_file"]["severity"]=="high", "yara severity"
assert d["counts"]["critical"]==2, "critical count %r"%d["counts"]
assert d["counts"]["total"]==len(d["findings"]), "total mismatch"
assert any("memory image" in g for g in d["gaps"]), "memory gap missing"
assert any("1 warning" in g and "1 error" in g for g in d["gaps"]), "warn/err gap"
h=open(sys.argv[2]).read()
assert "__VESTIGIUM_FINDINGS_JSON__" not in h, "token left"
block=re.search(r'<script id="vestigium-findings"[^>]*>([\s\S]*?)</script>',h).group(1)
assert "</script>" not in block and "<b>" not in block, "unsafe embed"
assert json.loads(block)["findings"], "embedded json parse"
print("ok")
PY2
)"
        if [[ "$check" == ok ]]; then pass "Linux findings: severities, counts, gaps and safe HTML embed"
        else fail "Linux findings check: $check"; fi
    else
        fail "Linux build-findings.py failed on the synthetic tree"
    fi
    # No-op guard: producer must not write inside a read-only-style path it was not given
else
    skip "python3 not installed: Linux findings producer test"
fi

section "Trusted-tools and anti-rootkit"
# Launcher wiring.
expect "trusted-tools in help"  0 'trusted-tools'  bash "$KIT/platforms/linux/vestigium-linux.sh" --help
expect "AntiRootkit registered"  0 '^AntiRootkit$' bash "$KIT/platforms/linux/vestigium-linux.sh" --list-modules

# The anti-rootkit module, driven with stubbed framework helpers so the test
# does not depend on 00-lib internals. A clean run must produce the report
# structure; a run against tools that lie must flag the discrepancy.
ar_run() { # ar_run OUTDIR SHIMDIR  (SHIMDIR may be empty for the honest run)
    local out="$1" shim="$2"
    PATH="${shim:+$shim:}$PATH" bash -c '
        set -uo pipefail
        DFIR_TOOLS="'"$KIT/platforms/linux/tools"'"; DFIR_TRUSTED_TOOLS=1
        declare -A DFIR_DIR=([Security]="'"$out"'")
        DFIR_USER_ROWS=()
        dfir_log(){ :; }; _dfir_record_cmd(){ :; }
        # busybox forced off so proc detection exercises the ps re-verify path.
        dfir_tool(){ case "$1" in busybox) : ;; netstat) command -v netstat 2>/dev/null;; *) command -v "$1";; esac; }
        source "'"$KIT/platforms/linux/modules/72-antirootkit.sh"'"
        dfir_module_antirootkit'
}

honest="$WORK/ar-clean"; mkdir -p "$honest"
ar_run "$honest" ""
if [[ -f "$honest/antirootkit/SUMMARY.txt" && -f "$honest/antirootkit/discrepancies.txt" ]]; then
    pass "anti-rootkit produces SUMMARY and discrepancies files"
else
    fail "anti-rootkit did not produce its report files"
fi
if ! grep -qE '^HIDDEN-PROC|^HIDDEN-MODULE' "$honest/antirootkit/discrepancies.txt" 2>/dev/null; then
    pass "anti-rootkit: clean host shows no hidden process/module"
else
    fail "anti-rootkit: false positive on a clean host"
    sed 's/^/          /' "$honest/antirootkit/discrepancies.txt"
fi

# A lying host: ps hides PID 1, ls hides everything.
shim="$WORK/ar-shim"; mkdir -p "$shim"
cat >"$shim/ps" <<'SH'
#!/bin/bash
case " $* " in *" -p 1 "*) exit 1;; esac
command -p ps "$@" | awk '$1 != 1'
SH
printf '#!/bin/bash\nexit 0\n' >"$shim/ls"
chmod +x "$shim/ps" "$shim/ls"
dirty="$WORK/ar-dirty"; mkdir -p "$dirty"
ar_run "$dirty" "$shim"
disc="$dirty/antirootkit/discrepancies.txt"
if grep -q '^HIDDEN-PROC 1' "$disc" 2>/dev/null; then
    pass "anti-rootkit: detects a process hidden from ps"
else
    fail "anti-rootkit: missed a process hidden from ps"; sed 's/^/          /' "$disc" 2>/dev/null | head
fi
if grep -q '^HIDDEN-DIR-ENTRY ' "$disc" 2>/dev/null; then
    pass "anti-rootkit: detects a directory listing tool that hides entries"
else
    fail "anti-rootkit: missed an ls that hides directory entries"
fi

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
(( FAIL == 0 ))
