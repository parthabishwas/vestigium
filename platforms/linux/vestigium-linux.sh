#!/usr/bin/env bash
#
# vestigium-linux.sh - Vestigium Linux live-response evidence collector.
#
# Linux collector of the Vestigium cross-platform DFIR toolkit (Linux and
# Windows share the Vestigium kit root). Collects volatile and non-volatile
# host evidence into a timestamped, hashed, manifested evidence tree and
# packages it into a single archive.
#
# Requires root. Does not depend on any specific administrator account name:
# every user-scoped artifact path is resolved dynamically through NSS
# (getent passwd), so the tool behaves identically whichever admin account
# performs the collection.
#
# This is the Linux platform collector. It is normally launched through the
# kit-root wrapper (sudo ./vestigium.sh ...), which exports VESTIGIUM_HOME;
# it can also be run directly as platforms/linux/vestigium-linux.sh.
#
# Usage:  sudo ./vestigium.sh [options]                      (kit root)
#         sudo ./platforms/linux/vestigium-linux.sh [options] (direct)
#         vestigium-linux.sh --help
#
set -uo pipefail
umask 077     # evidence and working files must not be world/group readable

DFIR_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DFIR_TOOLS="${DFIR_ROOT}/tools"
DFIR_MODULES="${DFIR_ROOT}/modules"

# Kit root: the Vestigium project directory that holds VERSION, platforms/,
# shared/ and output/. Prefer the wrapper-exported VESTIGIUM_HOME; otherwise
# walk two levels up (platforms/linux -> kit root) and confirm the layout;
# otherwise treat this as a standalone copy rooted at the platform directory.
if [[ -n "${VESTIGIUM_HOME:-}" && -d "${VESTIGIUM_HOME}" ]]; then
    DFIR_KIT_ROOT="$(cd -- "$VESTIGIUM_HOME" && pwd -P)"
else
    _cand="$(cd -- "${DFIR_ROOT}/../.." && pwd -P 2>/dev/null || true)"
    if [[ -n "$_cand" && -f "${_cand}/VERSION" && -d "${_cand}/platforms/linux" ]]; then
        DFIR_KIT_ROOT="$_cand"
    else
        DFIR_KIT_ROOT="$DFIR_ROOT"
    fi
    unset _cand
fi

# Collector version comes from the kit VERSION file (first non-empty line).
DFIR_VERSION="$(sed -n '1{s/[[:space:]]*$//;s/^[[:space:]]*//;p};1q' "${DFIR_KIT_ROOT}/VERSION" 2>/dev/null || true)"
[[ -n "$DFIR_VERSION" ]] || DFIR_VERSION="2.0.0"

# YARA rule bundle: explicit override, else the shared kit rules, else the
# legacy per-platform tools/yara-rules copy.
if [[ -n "${VESTIGIUM_RULES_DIR:-}" ]]; then
    DFIR_RULES_DIR="$VESTIGIUM_RULES_DIR"
elif [[ -d "${DFIR_KIT_ROOT}/shared/yara-rules" ]]; then
    DFIR_RULES_DIR="${DFIR_KIT_ROOT}/shared/yara-rules"
else
    DFIR_RULES_DIR="${DFIR_TOOLS}/yara-rules"
fi

# sbin paths are not in a normal sudo PATH on every distro image.
export PATH="${DFIR_TOOLS}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive

# Record the exact invocation safely (each token %q-quoted) for the manifest.
DFIR_INVOCATION="$(printf '%q ' "$0" "$@")"
DFIR_INVOCATION="${DFIR_INVOCATION% }"

# ---------------------------------------------------------------------------
# Defaults (overridable through options)
# ---------------------------------------------------------------------------
DFIR_OUTPUT_BASE="${DFIR_KIT_ROOT}/output"
DFIR_CASE_ID=""                  # auto-generated when not supplied
DFIR_TARGET_USERS=()
DFIR_SELECTED_MODULES=()
DFIR_MODE="full"                 # full | quick
DFIR_SKIP_YARA=0
DFIR_YARA_QUICK=0
DFIR_YARA_PROCS=0
DFIR_YARA_TIMEOUT=1800
DFIR_YARA_THREADS=2
DFIR_BROWSER_HISTORY=1
DFIR_BROWSER_SESSIONS=0
DFIR_CREDENTIAL_STORES=copy       # copy | metadata (browser credential stores)
DFIR_MEMORY=0
DFIR_ROOTKIT_SCAN=0
DFIR_NO_ARCHIVE=0
DFIR_CMD_TIMEOUT=300
DFIR_MAX_FILE_MB=256
DFIR_MAX_HASH_MB=1024
DFIR_MAX_TREE_FILES=5000
DFIR_MAX_JOURNAL_MB=2048
DFIR_VERBOSE=0
DFIR_QUIET=0
DFIR_ARCHIVE=""
DFIR_PREPARE=0
DFIR_PREPARE_OFFLINE=0
DFIR_TRUSTED_TOOLS=0              # 1 = run the kit's own binaries, cross-check host

# Module registry: "Label|function". Ordered by order-of-volatility: the most
# fragile / most easily perturbed state first, bulk on-disk collection last.
DFIR_MODULE_REGISTRY=(
    "System|dfir_module_system"
    "Processes|dfir_module_processes"
    "Network|dfir_module_network"
    "Persistence|dfir_module_persistence"
    "Startup|dfir_module_startup"
    "Config|dfir_module_config"
    "ScheduledTasks|dfir_module_scheduled"
    "Services|dfir_module_services"
    "Browser|dfir_module_browser"
    "Logs|dfir_module_logs"
    "Security|dfir_module_security"
    "AntiRootkit|dfir_module_antirootkit"
    "Packages|dfir_module_packages"
    "Users|dfir_module_users"
    "Filesystem|dfir_module_filesystem"
    "Containers|dfir_module_containers"
    "Memory|dfir_module_memory"
    "Yara|dfir_module_yara"
    "IOC|dfir_module_ioc"
)

usage() {
    cat <<EOF
Vestigium Linux Collector ${DFIR_VERSION}

Usage: sudo ./vestigium.sh [options]
       sudo ./platforms/linux/vestigium-linux.sh [options]   (direct)

No option is mandatory: a bare run performs a full collection.

Scope and targeting
  --case-id ID          Case reference recorded in the manifest. When omitted,
                        one is generated as AUTO-<hostname>-<timestamp>.
  --target-user USER    Restrict user-scoped collection to USER. Accepts a
                        username, a UID, or a home directory path. Repeatable.
                        Default: root plus every account with UID 1000-64999.
  --modules LIST        Comma-separated module subset (see --list-modules).
                        Case-insensitive; run in registry (volatility) order.
  --list-modules        Print module names and exit.

Collection depth
  --quick               Triage mode: skips bulk file copies, deep filesystem
                        sweeps, full journal copy and process memory scanning.
  --no-browser-history  Do not collect browsing history/download/bookmark
                        databases (collected by default).
  --credential-stores M Browser password, cookie and autofill stores: copy
                        (default, same as Windows) or metadata (size,
                        timestamps and SHA256 only). See docs/DATA-HANDLING.md.
  --browser-sessions    Also collect current session/tab-restore artifacts.
  --no-browser-sessions Do not collect browser session artifacts (default).
  --memory              Capture physical memory with tools/bin/avml (imaged
                        first, before the collector's own heavy activity).
  --rootkit-scan        Run chkrootkit / rkhunter if available (slow).
  --trusted-tools       Run the kit's own binaries instead of the host's (the
                        host may be compromised) and cross-check host tools
                        against the kernel. Needs a prepared kit (busybox).
  --skip-yara           Do not run YARA scanning.
  --yara-quick          YARA: scan only high-signal paths.
  --yara-procs          YARA: also scan live process memory.
  --yara-timeout SEC    Per-target YARA timeout (default ${DFIR_YARA_TIMEOUT}).
  --yara-threads N      YARA worker threads, 1-64 (default ${DFIR_YARA_THREADS}).
  --max-journal-mb N    Native journal copy ceiling in MB (default ${DFIR_MAX_JOURNAL_MB}).

Output
  --output DIR          Evidence base directory (default <kit>/output).
  --no-archive          Leave the evidence tree uncompressed.
  --max-file-mb N       Per-file copy ceiling in MB (default ${DFIR_MAX_FILE_MB}).
  --cmd-timeout SEC     Per-command timeout (default ${DFIR_CMD_TIMEOUT}).

Toolkit
  --prepare             Run tools/setup-tools.sh before collecting, so any
                        missing helper tool and the YARA rule bundle are
                        staged into the kit first. Needs internet access.
  --prepare-offline     Same, but stage only from tools/deb and the rule
                        repositories already present in the kit.

Other
  -v, --verbose         Verbose progress output.
  -q, --quiet           Errors only.
  -V, --version         Print version and exit.
  -h, --help            This help.

Value options also accept the --opt=value form.

Examples
  sudo ./vestigium.sh                                    # full collection
  sudo ./vestigium.sh --case-id IR-2026-014
  sudo ./vestigium.sh --case-id IR-2026-014 --target-user j.doe
  sudo ./vestigium.sh --quick --skip-yara                # fast triage
  sudo ./vestigium.sh --output /media/evidence           # off the host disk
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
# Value-taking options; only these split an --opt=value form so that a stray
# "=" on a boolean flag is still reported as an unknown option.
_dfir_value_opts=" --output --case-id --target-user --modules --yara-timeout --max-file-mb --cmd-timeout --yara-threads --max-journal-mb --credential-stores "

dfir_require_uint() {
    # dfir_require_uint OPTION VALUE [MAX] - positive integer, else usage error.
    # Guards the arithmetic-context options: a value like 'a[$(cmd)]' would be
    # executed by bash arithmetic (as root) if it ever reached $(( )).
    local opt="$1" val="$2" max="${3:-}"
    if [[ ! "$val" =~ ^[0-9]+$ ]] || (( 10#$val < 1 )); then
        printf 'Invalid value for %s: %q (expected a positive integer)\n\n' "$opt" "$val" >&2
        usage >&2; exit 2
    fi
    if [[ -n "$max" ]] && (( 10#$val > max )); then
        printf 'Invalid value for %s: %s (maximum is %s)\n\n' "$opt" "$val" "$max" >&2
        usage >&2; exit 2
    fi
}

_shift=0
_dfir_take() {
    # Yields the value for the current option into REPLY and sets _shift to the
    # number of positionals to consume. Call as: _dfir_take "$@"
    if (( _has_val )); then _shift=1; REPLY="$_val"; return 0; fi
    if (( $# < 2 )); then
        printf 'Option %s requires a value\n\n' "$_opt" >&2; usage >&2; exit 2
    fi
    _shift=2; REPLY="$2"
}

while (( $# > 0 )); do
    _opt="$1"; _val=""; _has_val=0
    if [[ "$1" == --*=* ]]; then
        _o="${1%%=*}"
        if [[ "$_dfir_value_opts" == *" $_o "* ]]; then
            _opt="$_o"; _val="${1#*=}"; _has_val=1
        fi
    fi
    case "$_opt" in
        --output)          _dfir_take "$@"; DFIR_OUTPUT_BASE="$REPLY"; shift "$_shift" ;;
        --case-id)         _dfir_take "$@"; DFIR_CASE_ID="$REPLY"; shift "$_shift" ;;
        --target-user)     _dfir_take "$@"; DFIR_TARGET_USERS+=("$REPLY"); shift "$_shift" ;;
        --modules)         _dfir_take "$@"; IFS=',' read -r -a _mods <<<"$REPLY"
                           DFIR_SELECTED_MODULES+=("${_mods[@]}"); shift "$_shift" ;;
        --list-modules)    printf '%s\n' "${DFIR_MODULE_REGISTRY[@]%%|*}"; exit 0 ;;
        --quick)           DFIR_MODE="quick"; shift ;;
        --full)            DFIR_MODE="full"; shift ;;
        --browser-history)    DFIR_BROWSER_HISTORY=1; shift ;;
        --no-browser-history) DFIR_BROWSER_HISTORY=0; shift ;;
        --browser-sessions)   DFIR_BROWSER_SESSIONS=1; shift ;;
        --no-browser-sessions)DFIR_BROWSER_SESSIONS=0; shift ;;
        --credential-stores)  _dfir_take "$@"
                              case "${REPLY,,}" in
                                  copy)                  DFIR_CREDENTIAL_STORES=copy ;;
                                  metadata|metadataonly) DFIR_CREDENTIAL_STORES=metadata ;;
                                  *) printf 'Invalid value for --credential-stores: %q (copy or metadata)\n\n' "$REPLY" >&2
                                     usage >&2; exit 2 ;;
                              esac
                              shift "$_shift" ;;
        --memory)          DFIR_MEMORY=1; shift ;;
        --rootkit-scan)    DFIR_ROOTKIT_SCAN=1; shift ;;
        --trusted-tools)   DFIR_TRUSTED_TOOLS=1; shift ;;
        --no-trusted-tools)DFIR_TRUSTED_TOOLS=0; shift ;;
        --skip-yara)       DFIR_SKIP_YARA=1; shift ;;
        --yara-quick)      DFIR_YARA_QUICK=1; shift ;;
        --yara-procs)      DFIR_YARA_PROCS=1; shift ;;
        --yara-timeout)    _dfir_take "$@"; dfir_require_uint "$_opt" "$REPLY"; DFIR_YARA_TIMEOUT="$REPLY"; shift "$_shift" ;;
        --yara-threads)    _dfir_take "$@"; dfir_require_uint "$_opt" "$REPLY" 64; DFIR_YARA_THREADS="$REPLY"; shift "$_shift" ;;
        --max-journal-mb)  _dfir_take "$@"; dfir_require_uint "$_opt" "$REPLY"; DFIR_MAX_JOURNAL_MB="$REPLY"; shift "$_shift" ;;
        --prepare)         DFIR_PREPARE=1; shift ;;
        --prepare-offline) DFIR_PREPARE=1; DFIR_PREPARE_OFFLINE=1; shift ;;
        --no-archive)      DFIR_NO_ARCHIVE=1; shift ;;
        --max-file-mb)     _dfir_take "$@"; dfir_require_uint "$_opt" "$REPLY"; DFIR_MAX_FILE_MB="$REPLY"; shift "$_shift" ;;
        --cmd-timeout)     _dfir_take "$@"; dfir_require_uint "$_opt" "$REPLY"; DFIR_CMD_TIMEOUT="$REPLY"; shift "$_shift" ;;
        -v|--verbose)      DFIR_VERBOSE=1; shift ;;
        -q|--quiet)        DFIR_QUIET=1; shift ;;
        -V|--version)      printf 'vestigium-linux.sh %s\n' "$DFIR_VERSION"; exit 0 ;;
        -h|--help)         usage; exit 0 ;;
        *)                 printf 'Unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ "$DFIR_MODE" == "quick" ]]; then
    DFIR_YARA_QUICK=1
fi

# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------
if [[ "$(id -u)" != "0" ]]; then
    printf 'This tool requires root privileges. Re-run with: sudo %s\n' "$0" >&2
    exit 1
fi

# Operator identity is resolved dynamically; no account name is hardcoded.
DFIR_OPERATOR="${SUDO_USER:-}"
[[ -z "$DFIR_OPERATOR" ]] && DFIR_OPERATOR="$(logname 2>/dev/null || true)"
[[ -z "$DFIR_OPERATOR" ]] && DFIR_OPERATOR="$(id -un 2>/dev/null || echo root)"
DFIR_OPERATOR="${DFIR_OPERATOR} (euid $(id -u), ruid ${SUDO_UID:-$(id -u)})"

# ---------------------------------------------------------------------------
# Optional toolkit preparation
# ---------------------------------------------------------------------------
if (( DFIR_PREPARE == 1 )); then
    if [[ ! -x "${DFIR_TOOLS}/setup-tools.sh" ]]; then
        printf 'Cannot prepare: %s/setup-tools.sh is missing or not executable.\n' "$DFIR_TOOLS" >&2
        exit 1
    fi
    printf 'Preparing toolkit before collection...\n'
    if (( DFIR_PREPARE_OFFLINE == 1 )); then
        "${DFIR_TOOLS}/setup-tools.sh" --offline || printf 'Toolkit preparation reported problems; continuing.\n' >&2
    else
        "${DFIR_TOOLS}/setup-tools.sh" || printf 'Toolkit preparation reported problems; continuing.\n' >&2
    fi
    printf '\n'
fi

export DFIR_ROOT DFIR_TOOLS DFIR_MODULES DFIR_KIT_ROOT DFIR_VERSION DFIR_MODE
export DFIR_RULES_DIR DFIR_OUTPUT_BASE
export DFIR_CMD_TIMEOUT DFIR_MAX_FILE_MB DFIR_MAX_HASH_MB DFIR_MAX_TREE_FILES
export DFIR_MAX_JOURNAL_MB DFIR_YARA_TIMEOUT DFIR_YARA_THREADS DFIR_YARA_QUICK
export DFIR_YARA_PROCS DFIR_SKIP_YARA DFIR_MEMORY DFIR_ROOTKIT_SCAN
export DFIR_BROWSER_HISTORY DFIR_BROWSER_SESSIONS DFIR_CREDENTIAL_STORES
export DFIR_TRUSTED_TOOLS
# Read by the framework (dfir_log, dfir_archive) rather than by this script.
export DFIR_NO_ARCHIVE DFIR_VERBOSE DFIR_QUIET

# ---------------------------------------------------------------------------
# Load framework and modules
# ---------------------------------------------------------------------------
# shellcheck source=modules/00-lib.sh
if ! source "${DFIR_MODULES}/00-lib.sh"; then
    printf 'Failed to load framework: %s/00-lib.sh\n' "$DFIR_MODULES" >&2
    exit 1
fi

shopt -s nullglob
for _mod in "${DFIR_MODULES}"/[0-9][0-9]-*.sh; do
    [[ "$(basename "$_mod")" == "00-lib.sh" ]] && continue
    # shellcheck disable=SC1090
    source "$_mod" || { printf 'Failed to load module: %s\n' "$_mod" >&2; exit 1; }
done
shopt -u nullglob

# ---------------------------------------------------------------------------
# Initialise evidence tree
# ---------------------------------------------------------------------------
mkdir -p "$DFIR_OUTPUT_BASE" || exit 1
DFIR_OUTPUT_BASE="$(cd -- "$DFIR_OUTPUT_BASE" && pwd -P)"
export DFIR_OUTPUT_BASE

if ! dfir_init "$DFIR_OUTPUT_BASE"; then
    printf 'Initialisation failed.\n' >&2
    exit 1
fi
export DFIR_EVID

if [[ -z "$DFIR_CASE_ID" ]]; then
    DFIR_CASE_ID="AUTO-${DFIR_HOSTNAME}-${DFIR_TIMESTAMP}"
    DFIR_CASE_ID_SOURCE="auto-generated (no --case-id supplied)"
else
    DFIR_CASE_ID_SOURCE="supplied with --case-id"
fi

dfir_banner "Vestigium Linux Collector ${DFIR_VERSION}"
dfir_log INFO "Kit root: ${DFIR_KIT_ROOT}"
dfir_log INFO "Host: ${DFIR_HOSTNAME}"
dfir_log INFO "Case: ${DFIR_CASE_ID} [${DFIR_CASE_ID_SOURCE}]"
dfir_log INFO "Operator: ${DFIR_OPERATOR}"
dfir_log INFO "Mode: ${DFIR_MODE}"
if (( DFIR_TRUSTED_TOOLS == 1 )); then
    dfir_log INFO "Trusted-tools mode: using kit binaries and cross-checking the host"
    if [[ ! -x "${DFIR_TOOLS}/bin/busybox" ]]; then
        dfir_log WARN "Trusted-tools: ${DFIR_TOOLS}/bin/busybox is missing; the busybox second-opinion cross-check is unavailable (run --prepare)."
    fi
fi
dfir_log INFO "Browser credential stores: ${DFIR_CREDENTIAL_STORES}"
dfir_log INFO "Evidence root: ${DFIR_EVID}"
dfir_log INFO "Invocation: ${DFIR_INVOCATION}"

{
    printf 'collector_version=%s\n' "$DFIR_VERSION"
    printf 'kit_root=%s\n' "$DFIR_KIT_ROOT"
    printf 'case_id=%s\n' "$DFIR_CASE_ID"
    printf 'case_id_source=%s\n' "$DFIR_CASE_ID_SOURCE"
    printf 'operator=%s\n' "$DFIR_OPERATOR"
    printf 'mode=%s\n' "$DFIR_MODE"
    printf 'trusted_tools=%s\n' "$DFIR_TRUSTED_TOOLS"
    printf 'credential_stores=%s\n' "$DFIR_CREDENTIAL_STORES"
    printf 'invocation=%s\n' "$DFIR_INVOCATION"
    printf 'start_utc=%s\n' "$DFIR_START_ISO"
    printf 'start_local=%s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf 'evidence_root=%s\n' "$DFIR_EVID"
} >"${DFIR_DIR[CollectionLogs]}/run-parameters.txt"

# ---------------------------------------------------------------------------
# Pre-flight warnings
# ---------------------------------------------------------------------------
# Writing evidence onto the very filesystem under investigation risks
# overwriting unallocated space that may still hold deleted attacker artifacts.
if [[ "$(stat -c %d "$DFIR_OUTPUT_BASE" 2>/dev/null)" == "$(stat -c %d / 2>/dev/null)" ]]; then
    dfir_log WARN "Output base is on the same filesystem as / (the system under investigation)."
    dfir_log WARN "Prefer external media, e.g. --output /media/evidence, to avoid overwriting deleted data."
fi
_avail_kb="$(df -Pk "$DFIR_OUTPUT_BASE" 2>/dev/null | awk 'NR==2{print $4}')"
if [[ "$_avail_kb" =~ ^[0-9]+$ ]] && (( _avail_kb < 2 * 1024 * 1024 )); then
    dfir_log WARN "Only $((_avail_kb / 1024)) MiB free at ${DFIR_OUTPUT_BASE} (< 2 GiB); collection may run out of space."
fi

# Warn when the YARA rule bundle is not staged yet.
if [[ ! -f "${DFIR_RULES_DIR}/active-rules.yar" && "$DFIR_SKIP_YARA" == 0 ]]; then
    dfir_log WARN "YARA rule bundle missing at ${DFIR_RULES_DIR}: scanning will be skipped."
    dfir_log WARN "Prepare the kit with: sudo ${0} --prepare   (or sudo ./tools/setup-tools.sh)"
fi
for _tool in yara lsof dmidecode ss ip systemctl journalctl; do
    dfir_have "$_tool" || dfir_log WARN "Helper tool not available: ${_tool} (affected artifacts will be skipped)"
done

# ---------------------------------------------------------------------------
# Build execution plan
# ---------------------------------------------------------------------------
declare -a PLAN=()
if ((${#DFIR_SELECTED_MODULES[@]} > 0)); then
    # Case-insensitive, whitespace-trimmed, de-duplicated selection. Selected
    # modules run in REGISTRY (volatility) order, never argument order.
    declare -A _want=()
    for _m in "${DFIR_SELECTED_MODULES[@]}"; do
        _m="${_m#"${_m%%[![:space:]]*}"}"   # ltrim
        _m="${_m%"${_m##*[![:space:]]}"}"   # rtrim
        [[ -z "$_m" ]] && continue
        _want["${_m,,}"]=1
    done
    declare -A _matched=()
    for _entry in "${DFIR_MODULE_REGISTRY[@]}"; do
        _lbl="${_entry%%|*}"
        if [[ -n "${_want[${_lbl,,}]:-}" ]]; then
            PLAN+=("$_entry"); _matched["${_lbl,,}"]=1
        fi
    done
    for _k in "${!_want[@]}"; do
        [[ -z "${_matched[$_k]:-}" ]] && dfir_log WARN "Unknown module requested: ${_k}"
    done
    if ((${#PLAN[@]} == 0)); then
        printf 'No valid modules selected. Valid names:\n' >&2
        printf '  %s\n' "${DFIR_MODULE_REGISTRY[@]%%|*}" >&2
        exit 2
    fi
else
    PLAN=("${DFIR_MODULE_REGISTRY[@]}")
fi

# Physical RAM must be imaged before the collector's own heavy activity mutates
# it, so run Memory first whenever --memory was requested and it is in the plan.
if (( DFIR_MEMORY == 1 )); then
    declare -a _reordered=() _mem=()
    for _entry in "${PLAN[@]}"; do
        if [[ "${_entry%%|*}" == "Memory" ]]; then _mem=("$_entry"); else _reordered+=("$_entry"); fi
    done
    if ((${#_mem[@]} > 0)); then
        PLAN=("${_mem[@]}" "${_reordered[@]}")
    fi
fi

# ---------------------------------------------------------------------------
# Interrupt handling
# ---------------------------------------------------------------------------
# Modules run in a background subshell that the launcher waits on. Async
# commands in a non-interactive shell ignore SIGINT, so a Ctrl+C is delivered
# only to the launcher; the launcher must actively terminate the running
# module's process tree. The preserved evidence dirs in output/ came from
# Ctrl+C'd runs that never finalised - so on the first signal we still write
# hashes, manifest and (unless --no-archive) an INCOMPLETE archive.
DFIR_INTERRUPTED=0
DFIR_SIGNAL=""
DFIR_SIGCOUNT=0
DFIR_FINALIZING=0
export DFIR_INTERRUPTED

dfir_on_signal() {
    local sig="$1"
    DFIR_SIGCOUNT=$((DFIR_SIGCOUNT + 1))
    if (( DFIR_SIGCOUNT >= 2 )); then
        dfir_log ERROR "Operator forced abort (second SIG${sig}); exiting immediately."
        [[ -n "${DFIR_MODULE_PID:-}" ]] && dfir_kill_tree "$DFIR_MODULE_PID" KILL
        exit 130
    fi
    DFIR_INTERRUPTED=1
    DFIR_SIGNAL="$sig"
    if (( DFIR_FINALIZING == 1 )); then
        # Let finalisation finish; a second signal would still abort.
        dfir_log WARN "SIG${sig} during finalisation; completing finalisation then exiting."
        return
    fi
    dfir_log WARN "SIG${sig} received; terminating current module and finalising the partial collection."
    [[ -n "${DFIR_MODULE_PID:-}" ]] && dfir_kill_tree "$DFIR_MODULE_PID" TERM
}
trap 'dfir_on_signal INT'  INT
trap 'dfir_on_signal TERM' TERM
trap 'dfir_on_signal HUP'  HUP

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
DFIR_YARA_RAN=0
_total="${#PLAN[@]}"
_index=0
for _entry in "${PLAN[@]}"; do
    (( DFIR_INTERRUPTED == 1 )) && break
    _index=$((_index + 1))
    _label="${_entry%%|*}"
    dfir_run_module "$_index" "$_total" "$_label" "${_entry#*|}"
    _mrc=$?
    [[ "$_label" == "Yara" ]] && DFIR_YARA_RAN=1
    (( _mrc == 2 )) && break     # interrupted mid-module
done

if (( DFIR_INTERRUPTED == 1 )); then
    # Every module from the interrupted one's successor onward did not run.
    for (( _j = _index; _j < _total; _j++ )); do
        dfir_csv_row "$DFIR_RESULTS" "${PLAN[$_j]%%|*}" "NOT RUN" "0" "0" "0" "0" "not run"
    done
    _not_run=()
    for (( _j = _index; _j < _total; _j++ )); do _not_run+=("${PLAN[$_j]%%|*}"); done
    {
        printf 'COLLECTION INTERRUPTED\n======================\n\n'
        printf 'Signal            : SIG%s\n' "$DFIR_SIGNAL"
        printf 'Interrupted (UTC) : %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'Interrupted (loc) : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf 'Last module       : %s\n' "${PLAN[$((_index - 1))]%%|*}"
        printf '\nModules NOT run\n---------------\n'
        if ((${#_not_run[@]} > 0)); then printf '  %s\n' "${_not_run[@]}"; else printf '  (none)\n'; fi
        printf '\nHashes and manifest below were generated for the partial tree.\n'
    } >"${DFIR_DIR[CollectionLogs]}/INCOMPLETE.txt"
fi

# ---------------------------------------------------------------------------
# Finalise
# ---------------------------------------------------------------------------
DFIR_FINALIZING=1
if (( DFIR_INTERRUPTED == 1 )); then DFIR_RUN_STATUS="interrupted"; else DFIR_RUN_STATUS="completed"; fi
export DFIR_RUN_STATUS DFIR_YARA_RAN

dfir_banner "Finalising"
dfir_generate_findings
dfir_generate_hashes
dfir_generate_manifest
dfir_archive

_dur=$(( $(date +%s) - DFIR_START_EPOCH ))
if (( DFIR_INTERRUPTED == 1 )); then
    dfir_log WARN "Collection INTERRUPTED after ${_dur}s; partial evidence finalised"
else
    dfir_log SUCCESS "Collection complete in ${_dur}s"
fi

if [[ "${DFIR_QUIET}" != 1 ]]; then
    printf '\n'
    printf 'Evidence tree : %s\n' "$DFIR_EVID"
    [[ -n "${DFIR_ARCHIVE:-}" ]] && printf 'Archive       : %s\n' "$DFIR_ARCHIVE"
    printf 'Summary       : %s\n' "${DFIR_DIR[Manifest]}/summary.txt"
    printf 'Findings report : %s\n' "${DFIR_EVID}/findings.html"
    printf 'Collection log: %s\n' "$DFIR_LOGFILE"
    printf 'Verify with   : %s/vestigium.sh verify %s\n' \
        "$DFIR_KIT_ROOT" "${DFIR_ARCHIVE:-$DFIR_EVID}"
    printf '\n'
    awk -F'","' 'NR>1 {gsub(/"/,"",$1); gsub(/"/,"",$2); printf "  %-16s %s\n", $1, $2}' "$DFIR_RESULTS" 2>/dev/null
    printf '\n'
fi

# Exit: 0 on a clean run; signal-mapped code when interrupted. Per-module
# status lives in module-results.csv.
if (( DFIR_INTERRUPTED == 1 )); then
    case "$DFIR_SIGNAL" in
        INT)  exit 130 ;;
        TERM) exit 143 ;;
        HUP)  exit 129 ;;
        *)    exit 130 ;;
    esac
fi
exit 0
