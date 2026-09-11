#!/usr/bin/env bash
#
# setup-tools.sh - Prepare the Vestigium Linux collector so it is ready to run.
# Normally invoked as `sudo ./vestigium.sh setup [options]` from the kit root.
#
# What it does
#   1. Works out which helper tools the collector wants and which are missing.
#   2. Downloads the missing Debian packages (with dependencies) into
#      tools/deb/ so the kit can later be deployed offline.
#   3. Unpacks them into tools/portable/ (setuid/setgid bits stripped) and
#      generates wrappers in tools/bin/, so the collector can use them WITHOUT
#      installing anything on the host under investigation. Add --install to
#      install them system-wide instead.
#   4. Downloads the AVML static memory-acquisition binary into tools/bin/.
#   5. Fetches the YARA rule sources listed in the shared rules directory's
#      sources.conf (<kit>/shared/yara-rules) and builds active-rules.yar
#      (plus a pre-compiled bundle when yarac is available), honouring
#      custom/ and exclusions.conf, and records the build in rules.lock.
#      --rules-only does just this step; --rules-locked rebuilds the exact
#      commits recorded in rules.lock. See docs/YARA-RULES.md.
#   6. Writes tools/TOOLS.md recording every tool, version and SHA256.
#
# Run this on a staging workstation with internet access, then copy the whole
# kit to removable media. Running it directly on an evidence host is supported
# but modifies that host - prefer staging.
#
set -uo pipefail

TOOLS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PLATFORM_DIR="$(dirname "$TOOLS_DIR")"
DEB_DIR="${TOOLS_DIR}/deb"
BIN_DIR="${TOOLS_DIR}/bin"
PORTABLE_DIR="${TOOLS_DIR}/portable"
SETUP_LOG="${TOOLS_DIR}/setup.log"

# Kit root: $VESTIGIUM_HOME (exported by vestigium.sh), else three levels up
# (<kit>/platforms/linux/tools) when that looks like a Vestigium kit.
KIT_ROOT=""
if [[ -n "${VESTIGIUM_HOME:-}" && -d "${VESTIGIUM_HOME}/platforms/linux" ]]; then
    KIT_ROOT="$(cd -- "$VESTIGIUM_HOME" && pwd -P)"
else
    _cand="$(cd -- "${TOOLS_DIR}/../../.." 2>/dev/null && pwd -P)"
    [[ -n "$_cand" && -f "${_cand}/VERSION" && -d "${_cand}/platforms/linux" ]] && KIT_ROOT="$_cand"
    unset _cand
fi

# YARA rules are shared between platforms: $VESTIGIUM_RULES_DIR, else
# <kit>/shared/yara-rules, else (standalone copy of this folder) tools/yara-rules.
if [[ -n "${VESTIGIUM_RULES_DIR:-}" ]]; then
    RULES_DIR="$VESTIGIUM_RULES_DIR"
elif [[ -n "$KIT_ROOT" ]]; then
    RULES_DIR="${KIT_ROOT}/shared/yara-rules"
else
    RULES_DIR="${TOOLS_DIR}/yara-rules"
fi

export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

DO_INSTALL=0
DO_OFFLINE=0
DO_APT=1
DO_RULES=1
DO_AVML=1
DO_BUSYBOX=1
WITH_CLAMAV=0
WITH_ROOTKIT=1
VERIFY_ONLY=0
ONLY_MISSING=0
REGEN_ONLY=0
RULES_ONLY=0
RULES_LOCKED=0
FP_CORPUS=()
# Rule sources come from <rules dir>/sources.conf. This list is the fallback
# when that file is missing (older kits); folder = repository name.
YARA_REPOS=(
    "https://github.com/Neo23x0/signature-base.git"
    "https://github.com/Yara-Rules/rules.git"
)
# Filled by read_rule_sources / read_lock_sources: one entry per source.
SRC_NAMES=(); SRC_URLS=(); SRC_REFS=(); SRC_COMMITS=()

# Packages the collector uses. Format "command:package".
CORE_TOOLS=(
    "yara:yara"
    "yarac:yara"
    "lsof:lsof"
    "pstree:psmisc"
    "fuser:psmisc"
    "dmidecode:dmidecode"
    "lspci:pciutils"
    "lsusb:usbutils"
    "lshw:lshw"
    "getcap:libcap2-bin"
    "debsums:debsums"
    "file:file"
    "sqlite3:sqlite3"
    "jq:jq"
    "zstd:zstd"
    "netstat:net-tools"
    "arp:net-tools"
    "utmpdump:util-linux"
    "tune2fs:e2fsprogs"
    "lsattr:e2fsprogs"
    "mokutil:mokutil"
    "efibootmgr:efibootmgr"
    "ssh-keygen:openssh-client"
    "openssl:openssl"
    "acpi:acpi"
)
ROOTKIT_TOOLS=(
    "chkrootkit:chkrootkit"
    "rkhunter:rkhunter"
    "unhide:unhide"
)
CLAMAV_TOOLS=(
    "clamscan:clamav"
    "freshclam:clamav-freshclam"
)

# Needed only while preparing the kit (cloning rule repositories, fetching
# AVML). They are checked for, but never staged into the kit: the evidence host
# does not need them, and staging git would pull perl and binutils along.
STAGING_ONLY_TOOLS=(
    "git:git"
    "curl:curl"
)

# AVML: override the source with AVML_URL; pin a release by exporting
# AVML_SHA256 (the download is rejected when it does not match).
AVML_URL="${AVML_URL:-https://github.com/microsoft/avml/releases/latest/download/avml}"
AVML_SHA256="${AVML_SHA256:-}"
AVML_SHA256="${AVML_SHA256,,}"

# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RST=$'\033[0m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_RED=$'\033[31m'; C_CYN=$'\033[36m'
else
    C_RST=""; C_GRN=""; C_YEL=""; C_RED=""; C_CYN=""
fi

log()  { printf '%s [INFO ] %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$SETUP_LOG"; }
ok()   { printf '%s [ OK  ] %s%s%s\n' "$(date '+%H:%M:%S')" "$C_GRN" "$*" "$C_RST" | tee -a "$SETUP_LOG"; }
warn() { printf '%s [WARN ] %s%s%s\n' "$(date '+%H:%M:%S')" "$C_YEL" "$*" "$C_RST" | tee -a "$SETUP_LOG"; }
err()  { printf '%s [ERROR] %s%s%s\n' "$(date '+%H:%M:%S')" "$C_RED" "$*" "$C_RST" | tee -a "$SETUP_LOG" >&2; }
head1(){ printf '\n%s=== %s ===%s\n' "$C_CYN" "$*" "$C_RST" | tee -a "$SETUP_LOG"; }

usage() {
    cat <<EOF
Usage: sudo ./vestigium.sh setup [options]
       sudo $(basename "$0") [options]

  --install          Also install the downloaded packages system-wide.
                     Without it, tools are unpacked into tools/portable and
                     used from there (leaves the host untouched).
  --offline          Do not use the network: install/unpack from tools/deb
                     and use whatever rules are already in the rules directory.
  --skip-apt         Do not fetch or unpack any Debian packages.
  --no-yara-rules    Do not clone or rebuild the YARA rule bundle.
  --no-avml          Do not download the AVML memory acquisition binary.
  --no-busybox       Do not stage the static busybox used by --trusted-tools.
  --with-clamav      Also stage ClamAV (large: engine plus signatures).
  --no-rootkit       Do not stage chkrootkit/rkhunter/unhide.
  --only-missing     Stage only the packages this workstation lacks. Default
                     is to stage them all, so the kit works on a host that has
                     none of them installed.
  --regen-wrappers   Offline: regenerate the tools/bin wrappers from the
                     existing tools/portable tree and rewrite TOOLS.md. No
                     apt, network or rule changes.
  --rules-only       Update the YARA rules only: fetch the latest commit of each
                     source in sources.conf (or its pinned ref), rebuild the
                     bundle and rewrite rules.lock. No apt, AVML or wrapper
                     changes; root is not required when the rules directory is
                     writable. With --offline: rebuild from the checkouts on disk.
  --rules-locked     Rebuild exactly the commits recorded in rules.lock (shallow
                     fetch of each locked commit that is not checked out yet;
                     fails clearly when one is unavailable) and report whether
                     the bundle SHA256 matches the lock. Implies --rules-only;
                     the lock itself is not rewritten.
  --fp-corpus DIR    After building, scan the known-clean DIR (repeatable) with
                     the new bundle and write rule-fp-report.txt: rules that
                     fired, counts, sample paths. Files over 50 MB are skipped.
  --verify           Report readiness (tools, rule sources, lock status, bundle
                     age) only; change nothing.
  -h, --help         This help.

Environment
  VESTIGIUM_HOME       kit root (set by vestigium.sh)
  VESTIGIUM_RULES_DIR  YARA rules directory (default <kit>/shared/yara-rules)
  AVML_URL              AVML download URL (default: latest GitHub release)
  AVML_SHA256           expected AVML SHA256; the download is rejected if it differs
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --install)        DO_INSTALL=1; shift ;;
        --offline)        DO_OFFLINE=1; shift ;;
        --skip-apt)       DO_APT=0; shift ;;
        --no-yara-rules)  DO_RULES=0; shift ;;
        --no-avml)        DO_AVML=0; shift ;;
        --no-busybox)     DO_BUSYBOX=0; shift ;;
        --with-clamav)    WITH_CLAMAV=1; shift ;;
        --no-rootkit)     WITH_ROOTKIT=0; shift ;;
        --only-missing)   ONLY_MISSING=1; shift ;;
        --regen-wrappers) REGEN_ONLY=1; shift ;;
        --verify)         VERIFY_ONLY=1; shift ;;
        --rules-only)     RULES_ONLY=1; shift ;;
        --rules-locked)   RULES_LOCKED=1; RULES_ONLY=1; shift ;;
        --fp-corpus)
            if (( $# < 2 )) || [[ -z "$2" ]]; then
                printf -- '--fp-corpus needs a directory\n' >&2; exit 2
            fi
            FP_CORPUS+=("$2"); shift 2 ;;
        --fp-corpus=*)    FP_CORPUS+=("${1#*=}"); shift ;;
        -h|--help)        usage; exit 0 ;;
        *) printf 'Unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

if (( RULES_ONLY == 1 )); then
    if (( DO_RULES == 0 || REGEN_ONLY == 1 )); then
        printf -- '--rules-only/--rules-locked cannot be combined with --no-yara-rules or --regen-wrappers\n' >&2
        exit 2
    fi
    DO_APT=0
    DO_AVML=0
fi
for _corpus in "${FP_CORPUS[@]}"; do
    [[ -d "$_corpus" ]] || { printf -- '--fp-corpus: not a directory: %s\n' "$_corpus" >&2; exit 2; }
done
unset _corpus

if (( VERIFY_ONLY == 0 )); then
    mkdir -p "$DEB_DIR" "$BIN_DIR" "$PORTABLE_DIR" "$RULES_DIR"
    # A wrapper-only regeneration keeps the log of the last full setup.
    (( REGEN_ONLY == 1 )) || : >"$SETUP_LOG"
fi

# ---------------------------------------------------------------------------
have_system() { command -v "$1" >/dev/null 2>&1; }
have_kit()    { [[ -x "${BIN_DIR}/$1" ]]; }
have_any()    { have_kit "$1" || have_system "$1"; }

kit_rel() {
    # Path relative to the kit root for reports (absolute when outside it).
    if [[ -n "$KIT_ROOT" && "$1" == "$KIT_ROOT"/* ]]; then
        printf '%s' "${1#"$KIT_ROOT"/}"
    else
        printf '%s' "$1"
    fi
}

count_rules() {
    # Counts rule declarations, including private and global rules.
    grep -cE '^[[:space:]]*((private|global)[[:space:]]+)*rule[[:space:]]+[A-Za-z_]' "$1" 2>/dev/null
}

wanted_tools() {
    # Tools the collector needs on the evidence host: these get staged.
    printf '%s\n' "${CORE_TOOLS[@]}"
    (( WITH_ROOTKIT == 1 )) && printf '%s\n' "${ROOTKIT_TOOLS[@]}"
    (( WITH_CLAMAV == 1 ))  && printf '%s\n' "${CLAMAV_TOOLS[@]}"
    return 0
}

# ---------------------------------------------------------------------------
# YARA rule sources and lock (<rules dir>/sources.conf, rules.lock)
# ---------------------------------------------------------------------------
valid_source() {
    # valid_source NAME URL REF: the checks build-yara-rules.py applies too.
    # Nothing that fails them is ever handed to git.
    local name="$1" url="$2" ref="$3"
    if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ || "$name" == [.-]* || "${name,,}" == custom ]]; then
        err "invalid rule source name '${name}' (letters, digits, . _ -; not starting with . or -; 'custom' is reserved)"
        return 1
    fi
    if [[ ! "$url" =~ ^https://[^[:space:]]+$ && ! "$url" =~ ^git@[^[:space:]:]+:[^[:space:]]+$ ]]; then
        err "invalid URL '${url}' for rule source '${name}' (only https:// or git@host:path)"
        return 1
    fi
    if [[ -n "$ref" ]] && [[ ! "$ref" =~ ^[A-Za-z0-9._/-]+$ || "$ref" == [-/]* || "$ref" == *..* \
                             || "$ref" == */ || "$ref" == *.lock ]]; then
        err "invalid ref '${ref}' for rule source '${name}'"
        return 1
    fi
    return 0
}

read_rule_sources() {
    # Fills SRC_* from sources.conf ("<name> <git-url> [<ref>]", "#" comments),
    # or from YARA_REPOS when the file is missing.
    SRC_NAMES=(); SRC_URLS=(); SRC_REFS=(); SRC_COMMITS=()
    local conf="${RULES_DIR}/sources.conf" line n=0 i url
    local -a fields
    if [[ ! -f "$conf" ]]; then
        warn "$(kit_rel "$conf") not found: using the built-in source list"
        for url in "${YARA_REPOS[@]}"; do
            SRC_NAMES+=("$(basename "$url" .git)"); SRC_URLS+=("$url"); SRC_REFS+=(""); SRC_COMMITS+=("")
        done
        return 0
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1))
        read -r -a fields <<<"${line%$'\r'}"
        for i in "${!fields[@]}"; do
            if [[ "${fields[i]}" == \#* ]]; then fields=("${fields[@]:0:i}"); break; fi
        done
        (( ${#fields[@]} == 0 )) && continue
        if (( ${#fields[@]} > 3 || ${#fields[@]} < 2 )); then
            err "${conf}:${n}: expected '<name> <git-url> [<ref>]'"
            return 1
        fi
        valid_source "${fields[0]}" "${fields[1]}" "${fields[2]:-}" || { err "  in ${conf}:${n}"; return 1; }
        for i in "${!SRC_NAMES[@]}"; do
            if [[ "${SRC_NAMES[i],,}" == "${fields[0],,}" ]]; then
                err "${conf}:${n}: duplicate source name '${fields[0]}'"
                return 1
            fi
        done
        SRC_NAMES+=("${fields[0]}"); SRC_URLS+=("${fields[1]}"); SRC_REFS+=("${fields[2]:-}"); SRC_COMMITS+=("")
    done <"$conf"
    return 0
}

read_lock_sources() {
    # Fills SRC_* from the [source <name>] sections of rules.lock, in order.
    local lock="$1" line section="" key value idx=0 i
    SRC_NAMES=(); SRC_URLS=(); SRC_REFS=(); SRC_COMMITS=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == [\#\;]* ]] && continue
        if [[ "$line" =~ ^\[source[[:space:]]+([^]]+)\]$ ]]; then
            section=source; idx=${#SRC_NAMES[@]}
            SRC_NAMES+=("${BASH_REMATCH[1]%"${BASH_REMATCH[1]##*[![:space:]]}"}")
            SRC_URLS+=(""); SRC_REFS+=(""); SRC_COMMITS+=("")
            continue
        fi
        if [[ "$line" == \[* ]]; then section=""; continue; fi
        [[ "$section" == source && "$line" == *=* ]] || continue
        key="${line%%=*}"; key="${key//[[:space:]]/}"
        value="${line#*=}"; value="${value#"${value%%[![:space:]]*}"}"; value="${value%"${value##*[![:space:]]}"}"
        case "$key" in
            url)    SRC_URLS[idx]="$value" ;;
            ref)    SRC_REFS[idx]="$value" ;;
            commit) SRC_COMMITS[idx]="$value" ;;
        esac
    done <"$lock"
    if (( ${#SRC_NAMES[@]} == 0 )); then
        err "${lock}: no [source <name>] sections"
        return 1
    fi
    for i in "${!SRC_NAMES[@]}"; do
        valid_source "${SRC_NAMES[i]}" "${SRC_URLS[i]}" "${SRC_REFS[i]}" || { err "  in ${lock}"; return 1; }
        if [[ ! "${SRC_COMMITS[i]}" =~ ^[0-9a-f]{40}$ ]]; then
            err "${lock}: source '${SRC_NAMES[i]}' has no full commit SHA"
            return 1
        fi
    done
    return 0
}

lock_get() {
    # lock_get FILE SECTION KEY: prints the value, empty when absent.
    awk -v want="[$2]" -v key="$3" '
        function trim(s) { sub(/^[ \t\r]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
        /^[ \t]*\[/ { section = trim($0); next }
        section == want && index($0, "=") > 0 {
            if (trim(substr($0, 1, index($0, "=") - 1)) == key) { print trim(substr($0, index($0, "=") + 1)); exit }
        }' "$1" 2>/dev/null
}

checkout_commit() {
    # HEAD commit of a rule checkout; "none" without one, "unknown" when unreadable.
    local path="$1" head=""
    [[ -e "${path}/.git" ]] || { printf 'none'; return 0; }
    if command -v git >/dev/null 2>&1; then
        head="$(git -c safe.directory="$path" -C "$path" rev-parse HEAD 2>/dev/null)"
    elif [[ -f "${path}/.git/HEAD" ]]; then
        head="$(head -n 1 "${path}/.git/HEAD" 2>/dev/null)"
    fi
    [[ "$head" =~ ^[0-9a-f]{40}$ ]] || head=unknown
    printf '%s' "$head"
}

rules_git() {
    # rules_git CHECKOUT ARGS...: git inside one rule checkout. safe.directory
    # lets root work on a kit copied from another user or removable media.
    local path="$1"; shift
    "$GIT_BIN" -c safe.directory="$path" -c advice.detachedHead=false -C "$path" "$@"
}

fetch_source() {
    # fetch_source NAME URL REF: shallow fetch of REF (branch, tag or commit;
    # the default branch when empty) and a detached checkout of it. A new
    # source is fetched into a temporary folder first, so a failed clone
    # leaves nothing behind. Local changes in a checkout make this fail.
    local name="$1" url="$2" ref="$3" path="${RULES_DIR}/$1" work
    if [[ -d "${path}/.git" ]]; then
        work="$path"
        if [[ "$(rules_git "$work" remote get-url origin 2>/dev/null)" != "$url" ]]; then
            log "${name}: origin set to ${url}"
            rules_git "$work" remote set-url origin "$url" >>"$SETUP_LOG" 2>&1 \
                || rules_git "$work" remote add origin "$url" >>"$SETUP_LOG" 2>&1 || return 1
        fi
    elif [[ -e "$path" ]]; then
        err "${path} exists but is not a git checkout; move it away to fetch ${name}"
        return 1
    else
        work="$(mktemp -d "${RULES_DIR}/.fetch-${name}.XXXXXXXXXX")" || return 1
        if ! "$GIT_BIN" init -q "$work" >>"$SETUP_LOG" 2>&1 \
           || ! rules_git "$work" remote add origin "$url" >>"$SETUP_LOG" 2>&1; then
            rm -rf -- "$work"
            return 1
        fi
    fi
    if rules_git "$work" fetch -q --depth 1 origin "${ref:-HEAD}" >>"$SETUP_LOG" 2>&1 \
       && rules_git "$work" checkout -q --detach FETCH_HEAD >>"$SETUP_LOG" 2>&1; then
        if [[ "$work" != "$path" ]]; then
            chmod 755 "$work"
            mv -- "$work" "$path" || { rm -rf -- "$work"; return 1; }
        fi
        return 0
    fi
    [[ "$work" != "$path" ]] && rm -rf -- "$work"
    return 1
}

rules_status() {
    # Rule sources, lock status and bundle age for --verify and the summary.
    local conf="${RULES_DIR}/sources.conf" lock="${RULES_DIR}/rules.lock"
    local bundle="${RULES_DIR}/active-rules.yar" i name commit locked note origin
    origin="$([[ -f "$conf" ]] && echo sources.conf || echo 'built-in list; sources.conf missing')"
    printf '\nRule sources (%s, in precedence order after custom/):\n' "$origin"
    if read_rule_sources >/dev/null 2>&1; then
        for i in "${!SRC_NAMES[@]}"; do
            name="${SRC_NAMES[i]}"
            commit="$(checkout_commit "${RULES_DIR}/${name}")"
            locked="$([[ -f "$lock" ]] && lock_get "$lock" "source ${name}" commit)"
            if [[ "$commit" == none ]]; then note="${C_RED}not fetched${C_RST}"
            elif [[ ! -f "$lock" ]]; then note=""
            elif [[ -z "$locked" ]]; then note="${C_YEL}not in rules.lock${C_RST}"
            elif [[ "$locked" == "$commit" ]]; then note="${C_GRN}= lock${C_RST}"
            else note="${C_YEL}lock has ${locked:0:12}${C_RST}"; fi
            printf '  %-18s %-12s %s%s %b\n' "$name" "${commit:0:12}" "${SRC_URLS[i]}" \
                "${SRC_REFS[i]:+ (ref ${SRC_REFS[i]})}" "$note"
        done
    else
        printf '  %sINVALID sources.conf - run setup --rules-only to see the error%s\n' "$C_RED" "$C_RST"
    fi
    local ncustom nexcl
    ncustom="$(find "${RULES_DIR}/custom" -type f \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null | wc -l)"
    nexcl="$(grep -cE '^[[:space:]]*(file|rule):' "${RULES_DIR}/exclusions.conf" 2>/dev/null)"
    printf '%-30s %s\n' "Custom rule files" "${ncustom} in custom/"
    printf '%-30s %s\n' "Active exclusions" "${nexcl:-0} line(s) in exclusions.conf"

    local state="${C_YEL}absent - run setup --rules-only to create it${C_RST}"
    if [[ -f "$lock" ]]; then
        local want have
        want="$(lock_get "$lock" bundle sha256)"
        state="generated $(lock_get "$lock" lock generated) by $(lock_get "$lock" lock builder), yara $(lock_get "$lock" lock yara); "
        if [[ ! -f "$bundle" ]]; then
            state+="${C_RED}bundle missing${C_RST}"
        else
            have="$(sha256sum "$bundle" | awk '{print $1}')"
            if [[ "$have" == "$want" ]]; then
                state+="${C_GRN}bundle SHA256 matches${C_RST}"
            else
                state+="${C_YEL}bundle SHA256 DIFFERS (built from other inputs; run setup --rules-locked to reproduce the lock)${C_RST}"
            fi
        fi
    fi
    printf '%-30s %b\n' "Rule lock" "$state"

    if [[ -f "$bundle" ]]; then
        local built age
        built="$(stat -c %Y "$bundle" 2>/dev/null || echo 0)"
        age=$(( ($(date +%s) - built) / 86400 ))
        printf '%-30s %b\n' "Bundle age" \
            "$( ((age > 30)) && printf '%s' "$C_YEL")${age} day(s) (built $(date -u -d "@${built}" '+%Y-%m-%d %H:%M UTC'))$( ((age > 30)) && printf ' - consider setup --rules-only%s' "$C_RST")"
    fi
    return 0
}

report_status() {
    head1 "Toolkit readiness"
    local entry cmd pkg src
    printf '%-16s %-22s %s\n' "COMMAND" "PACKAGE" "RESOLVED FROM"
    while IFS= read -r entry; do
        cmd="${entry%%:*}"; pkg="${entry#*:}"
        if have_kit "$cmd"; then src="${C_GRN}kit (tools/bin)${C_RST}"
        elif have_system "$cmd"; then src="${C_GRN}system ($(command -v "$cmd"))${C_RST}"
        else src="${C_RED}MISSING${C_RST}"; fi
        printf '%-16s %-22s %b\n' "$cmd" "$pkg" "$src"
    done < <(printf '%s\n' "$(wanted_tools)" "${STAGING_ONLY_TOOLS[@]}")

    printf '\n%-30s %s\n' "Rules directory" "$(kit_rel "$RULES_DIR")"
    printf '%-30s %s\n' "YARA rule bundle" \
        "$([[ -f "${RULES_DIR}/active-rules.yar" ]] && echo "${C_GRN}present ($(count_rules "${RULES_DIR}/active-rules.yar") rules)${C_RST}" || echo "${C_RED}MISSING${C_RST}")"
    local cstate="${C_YEL}absent (optional)${C_RST}"
    if [[ -f "${RULES_DIR}/active-rules.compiled" ]]; then
        if [[ "${RULES_DIR}/active-rules.compiled" -nt "${RULES_DIR}/active-rules.yar" ]]; then
            cstate="${C_GRN}present${C_RST}"
        else
            cstate="${C_YEL}STALE (older than active-rules.yar; collector will use the source bundle)${C_RST}"
        fi
    fi
    printf '%-30s %s\n' "Pre-compiled rule bundle" "$cstate"
    rules_status
    printf '%-30s %s\n' "signature-base IOC lists" \
        "$([[ -d "${RULES_DIR}/signature-base/iocs" ]] && echo "${C_GRN}present${C_RST}" || echo "${C_YEL}absent${C_RST}")"
    printf '%-30s %s\n' "AVML memory acquisition" \
        "$([[ -x "${BIN_DIR}/avml" ]] && echo "${C_GRN}present${C_RST}" || echo "${C_YEL}absent (needed for --memory)${C_RST}")"
    printf '%-30s %s\n' "busybox (trusted tools)" \
        "$([[ -x "${BIN_DIR}/busybox" ]] && echo "${C_GRN}present${C_RST}" || echo "${C_YEL}absent (--trusted-tools cross-checks use /proc only)${C_RST}")"
    printf '%-30s %s\n' "Cached .deb packages" \
        "$(find "$DEB_DIR" -maxdepth 1 -name '*.deb' 2>/dev/null | wc -l)"
    printf '\n'
}

if (( VERIFY_ONLY == 1 )); then
    report_status
    exit 0
fi

if [[ "$(id -u)" != "0" ]] && (( RULES_ONLY == 0 )); then
    err "This script must run as root (package download, unpacking and install all need it)."
    err "(--rules-only / --rules-locked run without root when the rules directory is writable.)"
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Debian packages
# ---------------------------------------------------------------------------
# The .deb cache is unpacked into the kit on every run and, with --install,
# handed to `dpkg -i` - both as root. It must therefore be writable by root
# only: a package planted in a directory owned by _apt or world-writable would
# be root code execution. Downloads happen in a private temporary directory
# (owned by _apt so apt can drop privileges) and are then copied in as root.
secure_deb_cache() {
    chown root:root "$DEB_DIR" 2>/dev/null
    chmod 755 "$DEB_DIR" 2>/dev/null
    rmdir "${DEB_DIR}/partial" 2>/dev/null   # left behind by older versions
    return 0
}

trusted_debs() {
    # Prints cached .deb files that are regular, root-owned and not writable by
    # group or others; warns about (and skips) anything else.
    local deb
    for deb in "$DEB_DIR"/*.deb; do
        [[ -e "$deb" || -L "$deb" ]] || continue
        if [[ -L "$deb" || ! -f "$deb" ]] || [[ "$(stat -c %u "$deb" 2>/dev/null)" != 0 ]] \
           || [[ -n "$(find "$deb" -maxdepth 0 -perm /022 2>/dev/null)" ]]; then
            warn "Skipping untrusted package file (not a root-owned, root-only-writable regular file): ${deb}"
            continue
        fi
        printf '%s\n' "$deb"
    done
}

strip_special_bits() {
    # Staged packages can ship setuid/setgid binaries (openssh-client's
    # ssh-keysign is setuid root). The collector already runs as root, so the
    # bits serve no purpose in the kit and would give anyone who can execute a
    # copied kit an escalation path.
    local -a special=()
    mapfile -t special < <(find "$PORTABLE_DIR" -xdev -type f -perm /6000 -print 2>/dev/null)
    if ((${#special[@]} > 0)); then
        chmod ug-s -- "${special[@]}" 2>>"$SETUP_LOG"
        ok "Removed setuid/setgid bits from ${#special[@]} staged file(s): ${special[*]#"$PORTABLE_DIR"/}"
    fi
    return 0
}

stage_packages() {
    head1 "Debian packages"
    secure_deb_cache

    # The kit has to be self-sufficient on an evidence host that may have none
    # of these tools installed. By default every wanted package is staged, even
    # when the staging workstation already provides it - otherwise the kit only
    # carries what this particular workstation happened to be missing.
    local -a missing_pkgs=()
    local entry cmd pkg
    while IFS= read -r entry; do
        cmd="${entry%%:*}"; pkg="${entry#*:}"
        if (( ONLY_MISSING == 1 )) && have_any "$cmd"; then
            continue
        fi
        missing_pkgs+=("$pkg")
    done < <(wanted_tools)

    # Deduplicate.
    if ((${#missing_pkgs[@]} > 0)); then
        mapfile -t missing_pkgs < <(printf '%s\n' "${missing_pkgs[@]}" | sort -u)
    fi

    if ((${#missing_pkgs[@]} == 0)); then
        ok "Nothing to stage."
    else
        log "Staging packages: ${missing_pkgs[*]}"

        if (( DO_OFFLINE == 0 )); then
            log "Refreshing package lists"
            apt-get update -qq >>"$SETUP_LOG" 2>&1 || warn "apt-get update reported errors; continuing"

            # `apt-get install --download-only` silently skips anything already
            # installed here, which would leave the kit incomplete for a target
            # host that lacks it. Resolve the dependency closure explicitly and
            # fetch every package with `apt-get download`, which does not care
            # about local install state.
            log "Resolving dependency closure"
            local -a closure=()
            mapfile -t closure < <(
                apt-cache depends --recurse --no-recommends --no-suggests \
                    --no-conflicts --no-breaks --no-replaces --no-enhances \
                    "${missing_pkgs[@]}" 2>/dev/null |
                grep -E '^[a-zA-Z0-9]' | sed 's/:.*$//' | sort -u
            )

            # Drop packages that every Ubuntu installation already has. Shipping
            # libc6 and friends would be pointless and mixing them into
            # LD_LIBRARY_PATH could break the host's own binaries.
            local -a fetch=()
            local pkgname prio ess
            for pkgname in "${closure[@]}"; do
                [[ -z "$pkgname" ]] && continue
                prio="$(apt-cache show "$pkgname" 2>/dev/null | awk -F': ' '/^Priority:/{print $2; exit}')"
                ess="$(apt-cache show "$pkgname" 2>/dev/null | awk -F': ' '/^Essential:/{print $2; exit}')"
                [[ "$ess" == "yes" ]] && continue
                case "$prio" in required|important) continue ;; esac
                fetch+=("$pkgname")
            done

            # Private download directory; apt verifies every package against
            # the signed archive indices and drops to _apt when it can write.
            local dl
            if ! dl="$(mktemp -d "${TMPDIR:-/tmp}/vestigium-apt.XXXXXXXXXX")"; then
                err "Cannot create a temporary download directory"
                return 1
            fi
            chown _apt:root "$dl" 2>/dev/null
            chmod 700 "$dl"

            log "Downloading ${#fetch[@]} package file(s)"
            if ! (cd "$dl" && apt-get download -y "${fetch[@]}") >>"$SETUP_LOG" 2>&1; then
                warn "Bulk download failed; retrying package by package"
                local pkg1
                for pkg1 in "${fetch[@]}"; do
                    (cd "$dl" && apt-get download -y "$pkg1") >>"$SETUP_LOG" 2>&1 \
                        || warn "could not download ${pkg1}"
                done
            fi

            # Copy into the root-only cache as root; new files are root:root 644.
            local f moved=0
            for f in "$dl"/*.deb; do
                [[ -f "$f" && ! -L "$f" ]] || continue
                install -m 644 -o root -g root -- "$f" "${DEB_DIR}/" && moved=$((moved + 1))
            done
            rm -rf -- "$dl"
            ok "Downloaded ${moved} package file(s) into ${DEB_DIR}"
        else
            log "Offline mode: using packages already cached in ${DEB_DIR}"
        fi
    fi

    local -a debs=()
    mapfile -t debs < <(trusted_debs)
    ((${#debs[@]} == 0)) && { log "No .deb files staged"; return 0; }

    if (( DO_INSTALL == 1 )); then
        log "Installing staged packages system-wide (this modifies the host)"
        if dpkg -i "${debs[@]}" >>"$SETUP_LOG" 2>&1; then
            ok "Packages installed"
        else
            warn "dpkg reported dependency problems; attempting to resolve"
            apt-get -f install -y >>"$SETUP_LOG" 2>&1 && ok "Dependencies resolved" \
                || err "Dependency resolution failed - see ${SETUP_LOG}"
        fi
    fi

    # Always unpack into the kit so the collector can run without installing.
    log "Unpacking staged packages into ${PORTABLE_DIR}"
    local deb
    for deb in "${debs[@]}"; do
        dpkg-deb -x "$deb" "$PORTABLE_DIR" 2>>"$SETUP_LOG" \
            || warn "could not unpack $(basename "$deb")"
    done
    strip_special_bits
    generate_wrappers
}

generate_wrappers() {
    # A wrapper is created for every tool the kit carries. The wrapper itself
    # prefers the host's own copy at run time, so a kit binary is only used on a
    # machine that does not already provide that tool.
    local created=0 entry cmd target dir
    while IFS= read -r entry; do
        cmd="${entry%%:*}"
        target=""
        for dir in usr/bin usr/sbin bin sbin usr/local/bin; do
            if [[ -x "${PORTABLE_DIR}/${dir}/${cmd}" ]]; then
                target="${dir}/${cmd}"
                break
            fi
        done
        [[ -z "$target" ]] && continue

        cat >"${BIN_DIR}/${cmd}" <<WRAPPER
#!/bin/sh
# Generated by Vestigium setup-tools.sh: run the kit-local copy of ${cmd}
# without installing it on the host under investigation. The kit stays
# relocatable - every path is derived from the wrapper's own location.
SELF_DIR="\$(cd "\$(dirname "\$0")" && pwd)"
PORTABLE="\$(cd "\$SELF_DIR/../portable" && pwd)"
ARCH="\$(uname -m)"

# Prefer whatever this host provides; only fall back to the kit copy when the
# host has none. The kit directory is removed from PATH for the lookup so the
# wrapper cannot find itself. In trusted-tools mode (DFIR_TRUSTED_TOOLS=1) this
# host preference is skipped, so the kit's own copy is always used - the host's
# binaries are not trusted on a possibly compromised machine.
if [ "\${DFIR_TRUSTED_TOOLS:-0}" != 1 ]; then
    HOST_PATH="\$(printf '%s' "\$PATH" | tr ':' '\\n' | grep -vxF "\$SELF_DIR" | paste -sd: -)"
    HOST_COPY="\$(PATH="\$HOST_PATH" command -v ${cmd} 2>/dev/null)"
    if [ -n "\$HOST_COPY" ] && [ "\$HOST_COPY" != "\$SELF_DIR/${cmd}" ]; then
        exec "\$HOST_COPY" "\$@"
    fi
fi

LD_LIBRARY_PATH="\$PORTABLE/usr/lib/\$ARCH-linux-gnu:\$PORTABLE/usr/lib:\$PORTABLE/lib/\$ARCH-linux-gnu:\$PORTABLE/lib:\${LD_LIBRARY_PATH:-}"
PATH="\$PORTABLE/usr/sbin:\$PORTABLE/usr/bin:\$PORTABLE/sbin:\$PORTABLE/bin:\$PATH"
export LD_LIBRARY_PATH PATH

# Perl and Python modules shipped by the staged packages.
for d in "\$PORTABLE"/usr/lib/\$ARCH-linux-gnu/perl5/* "\$PORTABLE"/usr/share/perl5 \\
         "\$PORTABLE"/usr/lib/\$ARCH-linux-gnu/perl/* "\$PORTABLE"/usr/share/perl/*; do
    [ -d "\$d" ] && PERL5LIB="\$d:\${PERL5LIB:-}"
done
d="\$PORTABLE/usr/lib/python3/dist-packages"
[ -d "\$d" ] && PYTHONPATH="\$d:\${PYTHONPATH:-}"
export PERL5LIB PYTHONPATH

TARGET="\$PORTABLE/${target}"

# Some packaged tools (chkrootkit, rkhunter) hardcode /usr/lib/<name>,
# /usr/share/<name>, /etc/<name> or /var/lib/<name>. When the kit carries those
# directories, rewrite the references at run time so the tool works without
# being installed on the host.
if [ -d "\$PORTABLE/usr/lib/${cmd}" ] || [ -d "\$PORTABLE/usr/share/${cmd}" ] ||
   [ -d "\$PORTABLE/var/lib/${cmd}" ] || [ -e "\$PORTABLE/etc/${cmd}.conf" ]; then
    case "\$(head -c 4 "\$TARGET" 2>/dev/null)" in
        "\$(printf '\\177ELF')") ;;
        *)
            # The patched copies live in a private mktemp directory (mode 700,
            # unpredictable name). A fixed name in a shared /tmp would let a
            # local user on the evidence host pre-create or symlink it and get
            # code executed as root.
            WORK="\$(mktemp -d "\${TMPDIR:-/tmp}/.vestigium-${cmd}.XXXXXXXXXX" 2>/dev/null)" || exec "\$TARGET" "\$@"
            trap 'rm -rf "\$WORK"' EXIT
            trap 'exit 129' HUP
            trap 'exit 130' INT
            trap 'exit 143' TERM
            PATCHED="\$WORK/${cmd}"
            REWRITE="s#/usr/lib/${cmd}#\$PORTABLE/usr/lib/${cmd}#g;
                     s#/usr/share/${cmd}#\$PORTABLE/usr/share/${cmd}#g;
                     s#/var/lib/${cmd}#\$PORTABLE/var/lib/${cmd}#g;
                     s#/etc/${cmd}.conf#\$PORTABLE/etc/${cmd}.conf#g;
                     s#/etc/${cmd}/#\$PORTABLE/etc/${cmd}/#g"
            if ! sed -e "\$REWRITE" "\$TARGET" >"\$PATCHED" 2>/dev/null || ! chmod 700 "\$PATCHED"; then
                rm -rf "\$WORK"; trap - EXIT HUP INT TERM
                exec "\$TARGET" "\$@"
            fi

            # The tool's own configuration file also carries absolute paths.
            CONF=""
            if [ -f "\$PORTABLE/etc/${cmd}.conf" ]; then
                CONF="\$WORK/${cmd}.conf"
                sed -e "\$REWRITE" "\$PORTABLE/etc/${cmd}.conf" >"\$CONF" 2>/dev/null || CONF=""
            fi

            case " \$* " in
                *" --configfile "*) CONF="" ;;   # caller supplied its own
            esac

            # Run through the script's own interpreter, so a noexec TMPDIR
            # (CIS-hardened /tmp) does not break the tool.
            INTERP="\$(sed -n '1s/^#![[:space:]]*//p' "\$TARGET")"
            if [ -n "\$CONF" ]; then
                \$INTERP "\$PATCHED" --configfile "\$CONF" "\$@"
            else
                \$INTERP "\$PATCHED" "\$@"
            fi
            exit \$? ;;
    esac
fi

exec "\$TARGET" "\$@"
WRAPPER
        chmod 755 "${BIN_DIR}/${cmd}"
        created=$((created + 1))
        ok "kit wrapper created for ${cmd}"
    done < <(wanted_tools)
    (( created == 0 )) && log "No kit wrappers needed"
    return 0
}

# ---------------------------------------------------------------------------
# 2. AVML static memory acquisition binary
# ---------------------------------------------------------------------------
stage_avml() {
    head1 "AVML memory acquisition"

    local sha
    if [[ -x "${BIN_DIR}/avml" ]]; then
        sha="$(sha256sum "${BIN_DIR}/avml" | awk '{print $1}')"
        if [[ -n "$AVML_SHA256" && "$sha" != "$AVML_SHA256" ]]; then
            err "Staged AVML sha256 ${sha} does not match AVML_SHA256=${AVML_SHA256}; delete ${BIN_DIR}/avml to re-download"
            return 1
        fi
        ok "Already staged: ${BIN_DIR}/avml (sha256 ${sha}${AVML_SHA256:+, matches pin})"
        return 0
    fi
    if (( DO_OFFLINE == 1 )); then
        warn "Offline mode: AVML not staged (memory capture will be unavailable)"
        return 0
    fi
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        err "Neither curl nor wget is available; cannot download AVML"
        return 1
    fi

    log "Downloading AVML from ${AVML_URL}"
    local tmp="${BIN_DIR}/.avml.download"
    rm -f "$tmp"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --retry 3 --connect-timeout 20 -o "$tmp" "$AVML_URL" 2>>"$SETUP_LOG"
    else
        wget -q --https-only --tries=3 --timeout=20 -O "$tmp" "$AVML_URL" 2>>"$SETUP_LOG"
    fi

    if [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"
        err "AVML download failed - memory capture (--memory) will be unavailable"
        return 1
    fi
    if ! head -c 4 "$tmp" | grep -q $'\x7fELF'; then
        rm -f "$tmp"
        err "Downloaded AVML file is not an ELF binary; discarded"
        return 1
    fi
    sha="$(sha256sum "$tmp" | awk '{print $1}')"
    log "AVML download sha256: ${sha}"
    if [[ -n "$AVML_SHA256" && "$sha" != "$AVML_SHA256" ]]; then
        rm -f "$tmp"
        err "AVML sha256 ${sha} does not match AVML_SHA256=${AVML_SHA256}; discarded"
        return 1
    fi
    mv "$tmp" "${BIN_DIR}/avml"
    chmod 755 "${BIN_DIR}/avml"
    ok "AVML staged (sha256 ${sha}${AVML_SHA256:+, matches pin})"
    return 0
}

# ---------------------------------------------------------------------------
# 2b. busybox-static: the trusted second-opinion userland
# ---------------------------------------------------------------------------
# In --trusted-tools mode the collector runs the kit's own binaries and the
# anti-rootkit module cross-checks the host's ps/ls/find against a statically
# linked busybox (and against raw /proc /sys). A single static multicall binary
# with no shared-library dependencies is hard for a userland rootkit to subvert.
stage_busybox() {
    head1 "busybox (trusted-tools second opinion)"

    local sha
    if [[ -x "${BIN_DIR}/busybox" ]]; then
        sha="$(sha256sum "${BIN_DIR}/busybox" | awk '{print $1}')"
        ok "Already staged: ${BIN_DIR}/busybox (sha256 ${sha})"
        return 0
    fi

    # Extract the busybox ELF from a busybox-static .deb, preferring a cached
    # copy so an offline kit works. dpkg-deb -x lays it down under bin/busybox.
    local deb work
    deb="$(find "$DEB_DIR" -maxdepth 1 -name 'busybox-static_*.deb' 2>/dev/null | sort | tail -n 1)"
    if [[ -z "$deb" ]]; then
        if (( DO_OFFLINE == 1 )); then
            warn "Offline mode: no busybox-static .deb cached; trusted-tools cross-checks will use /proc only"
            return 0
        fi
        local dl
        dl="$(mktemp -d "${TMPDIR:-/tmp}/vestigium-bb.XXXXXXXXXX")" || return 1
        chown _apt:root "$dl" 2>/dev/null; chmod 700 "$dl"
        log "Downloading busybox-static"
        if (cd "$dl" && apt-get download -y busybox-static) >>"$SETUP_LOG" 2>&1; then
            local f
            for f in "$dl"/busybox-static_*.deb; do
                [[ -f "$f" && ! -L "$f" ]] && install -m 644 -o root -g root -- "$f" "${DEB_DIR}/"
            done
            deb="$(find "$DEB_DIR" -maxdepth 1 -name 'busybox-static_*.deb' 2>/dev/null | sort | tail -n 1)"
        fi
        rm -rf -- "$dl"
    fi
    if [[ -z "$deb" ]]; then
        warn "busybox-static could not be staged; trusted-tools cross-checks will use /proc only"
        return 0
    fi

    work="$(mktemp -d "${TMPDIR:-/tmp}/vestigium-bbx.XXXXXXXXXX")" || return 1
    if ! dpkg-deb -x "$deb" "$work" 2>>"$SETUP_LOG"; then
        rm -rf -- "$work"; warn "Could not unpack $(basename "$deb")"; return 0
    fi
    local src
    src="$(find "$work" -type f -name busybox -perm -u+x 2>/dev/null | head -n 1)"
    if [[ -z "$src" ]] || ! head -c 4 "$src" | grep -q $'\x7fELF'; then
        rm -rf -- "$work"; warn "No busybox ELF found in $(basename "$deb")"; return 0
    fi
    install -m 755 -- "$src" "${BIN_DIR}/busybox"
    rm -rf -- "$work"
    sha="$(sha256sum "${BIN_DIR}/busybox" | awk '{print $1}')"
    ok "busybox staged (sha256 ${sha})"
    return 0
}

# ---------------------------------------------------------------------------
# 3. YARA rules
# ---------------------------------------------------------------------------
stage_yara_rules() {
    head1 "YARA rules"
    log "Rules directory: ${RULES_DIR}"
    local lock="${RULES_DIR}/rules.lock" i name failed=0
    GIT_BIN="$(command -v git 2>/dev/null || { have_kit git && echo "${BIN_DIR}/git"; })"

    if (( RULES_LOCKED == 1 )); then
        if [[ ! -f "$lock" ]]; then
            err "--rules-locked: $(kit_rel "$lock") not found. Run --rules-only once to create it, or restore it from git."
            return 1
        fi
        read_lock_sources "$lock" || return 1
        log "Locked build: ${#SRC_NAMES[@]} source(s) from $(kit_rel "$lock") (generated $(lock_get "$lock" lock generated))"
        for i in "${!SRC_NAMES[@]}"; do
            name="${SRC_NAMES[i]}"
            if [[ "$(checkout_commit "${RULES_DIR}/${name}")" == "${SRC_COMMITS[i]}" ]]; then
                ok "${name} already at locked commit ${SRC_COMMITS[i]:0:12}"
                continue
            fi
            if (( DO_OFFLINE == 1 )) || [[ -z "$GIT_BIN" ]]; then
                err "${name} is not at locked commit ${SRC_COMMITS[i]}, and $( ((DO_OFFLINE)) && echo '--offline forbids fetching it' || echo 'git is unavailable')"
                failed=1
                continue
            fi
            log "Fetching ${name} at locked commit ${SRC_COMMITS[i]}"
            if fetch_source "$name" "${SRC_URLS[i]}" "${SRC_COMMITS[i]}" \
               && [[ "$(checkout_commit "${RULES_DIR}/${name}")" == "${SRC_COMMITS[i]}" ]]; then
                ok "${name} checked out at ${SRC_COMMITS[i]:0:12}"
            else
                err "cannot check out ${name} at locked commit ${SRC_COMMITS[i]} from ${SRC_URLS[i]}"
                err "  (commit no longer available upstream, network failure, or local changes in the checkout - see ${SETUP_LOG})"
                failed=1
            fi
        done
        if (( failed == 1 )); then
            err "Locked rebuild aborted; the existing bundle is unchanged"
            return 1
        fi
        if [[ -f "${RULES_DIR}/sources.conf" ]]; then
            local conf_names
            conf_names="$(awk '{ sub(/\r$/, "") } $1 !~ /^#/ && NF >= 2 { print $1 }' "${RULES_DIR}/sources.conf" | paste -sd' ' -)"
            [[ "$conf_names" == "${SRC_NAMES[*]}" ]] || \
                warn "sources.conf lists '${conf_names}', rules.lock '${SRC_NAMES[*]}': building the locked set (run --rules-only to re-lock)"
        fi
    else
        if ! read_rule_sources; then
            err "Fix $(kit_rel "${RULES_DIR}/sources.conf"); the existing bundle is unchanged"
            return 1
        fi
        if (( DO_OFFLINE == 1 )); then
            log "Offline mode: using rule repositories already present"
        elif [[ -z "$GIT_BIN" ]]; then
            warn "git unavailable: skipping repository update"
        else
            for i in "${!SRC_NAMES[@]}"; do
                name="${SRC_NAMES[i]}"
                log "Fetching ${name} (${SRC_REFS[i]:-default branch}) from ${SRC_URLS[i]}"
                if fetch_source "$name" "${SRC_URLS[i]}" "${SRC_REFS[i]}"; then
                    ok "${name} at $(checkout_commit "${RULES_DIR}/${name}" | cut -c1-12)"
                elif [[ -d "${RULES_DIR}/${name}/.git" ]]; then
                    warn "could not update ${name}; using existing copy"
                else
                    err "could not clone ${SRC_URLS[i]}"
                fi
            done
        fi
    fi

    if ! find "$RULES_DIR" -maxdepth 4 \( -name '*.yar' -o -name '*.yara' \) -print -quit 2>/dev/null | grep -q .; then
        err "No rule files found under ${RULES_DIR}; YARA scanning will be skipped at collection time"
        return 1
    fi

    log "Building the active rule bundle (compile-validating every rule file)"
    local yarac_bin yara_bin buildlog rc corpus
    yarac_bin="$(command -v yarac 2>/dev/null || echo "${BIN_DIR}/yarac")"
    yara_bin="$(command -v yara 2>/dev/null || echo "${BIN_DIR}/yara")"
    local -a build_args=(
        --rules-dir "$RULES_DIR"
        --out "${RULES_DIR}/active-rules.yar"
        --report "${RULES_DIR}/rule-build-report.csv"
        --compiled "${RULES_DIR}/active-rules.compiled"
        --yarac "$yarac_bin" --yara "$yara_bin"
    )
    (( RULES_LOCKED == 1 )) && build_args+=(--locked)
    for corpus in "${FP_CORPUS[@]}"; do
        build_args+=(--fp-corpus "$corpus")
    done
    (( ${#FP_CORPUS[@]} > 0 )) && log "False-positive check afterwards on: ${FP_CORPUS[*]} (can take several minutes)"

    buildlog="$(mktemp "${TMPDIR:-/tmp}/vestigium-rules.XXXXXXXXXX")" || return 1
    python3 "${TOOLS_DIR}/build-yara-rules.py" "${build_args[@]}" >"$buildlog" 2>&1
    rc=$?
    cat "$buildlog" >>"$SETUP_LOG"
    grep -v 'lock check:' "$buildlog" | tail -n 7
    if (( rc != 0 )); then
        rm -f -- "$buildlog"
        err "Rule bundle build failed (exit ${rc}); the existing bundle is unchanged - see ${SETUP_LOG}"
        return 1
    fi
    ok "Rule bundle: ${RULES_DIR}/active-rules.yar"
    ok "Build report: ${RULES_DIR}/rule-build-report.csv"
    if (( RULES_LOCKED == 1 )); then
        if grep -q 'lock check: MATCH' "$buildlog"; then
            ok "Bundle SHA256 matches $(kit_rel "$lock")"
        else
            warn "Bundle SHA256 does NOT match $(kit_rel "$lock"):"
            grep 'lock check:' "$buildlog" | sed 's/^.*lock check: */    /' | tee -a "$SETUP_LOG"
        fi
    elif grep -q 'lock unchanged' "$buildlog"; then
        ok "Lock: $(kit_rel "$lock") unchanged (same commits and bundle)"
    else
        ok "Lock: $(kit_rel "$lock") updated - commit it to pin this rule set"
    fi
    if (( ${#FP_CORPUS[@]} > 0 )) && [[ -f "${RULES_DIR}/rule-fp-report.txt" ]]; then
        ok "False-positive report: ${RULES_DIR}/rule-fp-report.txt"
    fi
    rm -f -- "$buildlog"
    return 0
}

# ---------------------------------------------------------------------------
# 4. Tool manifest
# ---------------------------------------------------------------------------
write_manifest() {
    head1 "Tool manifest"
    local manifest="${TOOLS_DIR}/TOOLS.md"
    {
        printf '# Vestigium Linux toolkit contents\n\n'
        printf 'Generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'Prepared on: %s (%s)\n' "$(hostname)" \
            "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
        printf 'Kit version: %s\n\n' "$(cat "${KIT_ROOT:-/nonexistent}/VERSION" 2>/dev/null || echo unknown)"

        printf '## Resolved commands\n\n'
        printf '| Command | Source | Version |\n|---|---|---|\n'
        local entry cmd src ver
        while IFS= read -r entry; do
            cmd="${entry%%:*}"
            if [[ -x "${BIN_DIR}/${cmd}" ]]; then src="kit"
            elif command -v "$cmd" >/dev/null 2>&1; then src="system"
            else src="missing"; fi
            ver=""
            if [[ "$src" != "missing" ]]; then
                ver="$( ("$cmd" --version 2>/dev/null || "$cmd" -V 2>/dev/null || true) | head -1 | tr -d '|')"
                # Tools without a --version flag print usage text instead; only
                # keep a line that actually looks like a version string.
                [[ "$ver" =~ [0-9]+\.[0-9]+ ]] || ver=""
                ver="${ver:0:60}"
            fi
            printf '| %s | %s | %s |\n' "$cmd" "$src" "${ver:-n/a}"
        done < <(wanted_tools)

        printf '\n## Kit binaries (SHA256)\n\n'
        if compgen -G "${BIN_DIR}/*" >/dev/null; then
            local f
            for f in "${BIN_DIR}"/*; do
                [[ -f "$f" ]] || continue
                printf -- '- `%s` %s\n' "$(basename "$f")" "$(sha256sum "$f" | awk '{print $1}')"
            done
        else
            printf -- '- (none)\n'
        fi

        printf '\n## Cached Debian packages\n\n'
        if compgen -G "${DEB_DIR}/*.deb" >/dev/null; then
            local d
            for d in "${DEB_DIR}"/*.deb; do
                printf -- '- `%s` %s\n' "$(basename "$d")" "$(sha256sum "$d" | awk '{print $1}')"
            done
        else
            printf -- '- (none)\n'
        fi

        printf '\n## YARA rules\n\n'
        printf -- '- rules directory: `%s`\n' "$(kit_rel "$RULES_DIR")"
        if [[ -f "${RULES_DIR}/active-rules.yar" ]]; then
            printf -- '- bundle: `%s`\n' "$(kit_rel "${RULES_DIR}/active-rules.yar")"
            printf -- '- rules: %s\n' "$(count_rules "${RULES_DIR}/active-rules.yar")"
            printf -- '- sha256: %s\n' "$(sha256sum "${RULES_DIR}/active-rules.yar" | awk '{print $1}')"
            [[ -f "${RULES_DIR}/active-rules.compiled" ]] && \
                printf -- '- compiled: `%s` %s\n' "$(kit_rel "${RULES_DIR}/active-rules.compiled")" \
                    "$(sha256sum "${RULES_DIR}/active-rules.compiled" | awk '{print $1}')"
            printf -- '- build report: `%s`\n' "$(kit_rel "${RULES_DIR}/rule-build-report.csv")"
        else
            printf -- '- (not built)\n'
        fi
        local repo
        for repo in "${RULES_DIR}"/*/; do
            [[ -d "${repo}.git" ]] || continue
            printf -- '- repository `%s` at commit %s (%s)\n' "$(basename "$repo")" \
                "$(git -C "$repo" rev-parse --short HEAD 2>/dev/null)" \
                "$(git -C "$repo" log -1 --format=%cI 2>/dev/null)"
        done

        printf '\n## Licensing\n\n'
        printf 'YARA rule repositories are licensed by their authors; see the LICENSE\n'
        printf 'file inside each cloned repository before redistributing this kit.\n'
    } >"$manifest"
    ok "Wrote ${manifest}"
}

# ---------------------------------------------------------------------------
head1 "Vestigium Linux toolkit setup"
log "Kit root: ${KIT_ROOT:-(not detected; standalone platform folder ${PLATFORM_DIR})}"
log "Rules directory: ${RULES_DIR}"

if (( REGEN_ONLY == 1 )); then
    log "Mode: regenerate wrappers only (offline; no apt, network or rule changes)"
    head1 "Kit wrappers"
    strip_special_bits
    generate_wrappers
    write_manifest
    report_status
    exit 0
fi

if (( RULES_ONLY == 1 )); then
    log "Mode: YARA rules only ($( ((RULES_LOCKED)) && echo 'exact commits from rules.lock' || echo 'latest per sources.conf'))"
    (( DO_OFFLINE == 1 )) && log "Network use: disabled (--offline)"
    rules_rc=0
    stage_yara_rules || rules_rc=1
    write_manifest
    report_status
    if (( rules_rc != 0 )); then
        err "YARA rule update failed - see ${SETUP_LOG}"
        exit 1
    fi
    exit 0
fi

log "Mode: $( ((DO_INSTALL)) && echo 'download + system install' || echo 'download + portable (host untouched)')"
(( DO_OFFLINE == 1 )) && log "Network use: disabled (--offline)"

(( DO_APT == 1 ))   && stage_packages
(( DO_AVML == 1 ))  && stage_avml
(( DO_BUSYBOX == 1 )) && stage_busybox
(( DO_RULES == 1 )) && stage_yara_rules
write_manifest
report_status

head1 "Next steps"
if [[ -n "$KIT_ROOT" ]]; then
    printf '  sudo %s/vestigium.sh --case-id <CASE>\n' "$KIT_ROOT"
    printf '  sudo %s/vestigium.sh --help\n\n' "$KIT_ROOT"
else
    printf '  sudo %s/vestigium-linux.sh --case-id <CASE>\n' "$PLATFORM_DIR"
    printf '  sudo %s/vestigium-linux.sh --help\n\n' "$PLATFORM_DIR"
fi
exit 0
