#!/bin/sh
#
# vestigium.sh - Vestigium entry point for Linux, WSL, Git Bash / MSYS2 and
# Cygwin.
#
# Vestigium is a cross-platform live-response evidence collector. This script
# works out which platform it is running on and hands off to the matching
# collector:
#
#   Linux, including WSL distributions    platforms/linux/vestigium-linux.sh
#   Windows, from Git Bash/MSYS2/Cygwin   platforms/windows/vestigium-windows.ps1
#                                         (run through powershell.exe)
#
# On Windows the native entry points are vestigium.cmd and vestigium.ps1.
#
# Options may be written in either vocabulary (--case-id or -CaseId); they are
# translated for the selected collector. Options the launcher does not know
# are passed through unchanged. Run with --help for the full list.
#
# This file is POSIX sh on purpose: it has to start on any shell before it can
# tell the operator what is missing. The Linux collector itself needs bash 4.4+.

set -u

# Resolve symlinks (e.g. /usr/local/bin/vestigium -> <kit>/vestigium.sh) so
# the kit root is found wherever the launcher is invoked from.
CT_SELF=$0
while [ -L "$CT_SELF" ]; do
    _link=$(readlink "$CT_SELF") || break
    case "$_link" in
        /*) CT_SELF=$_link ;;
        *)  CT_SELF=$(dirname -- "$CT_SELF")/$_link ;;
    esac
done
CT_HOME=$(CDPATH='' cd -- "$(dirname -- "$CT_SELF")" && pwd -P) || exit 1
CT_VERSION=$(sed -n '1{s/[[:space:]]//g;p;q;}' "$CT_HOME/VERSION" 2>/dev/null)
[ -n "$CT_VERSION" ] || CT_VERSION=unknown
VESTIGIUM_HOME=$CT_HOME
export VESTIGIUM_HOME

LINUX_COLLECTOR=$CT_HOME/platforms/linux/vestigium-linux.sh
LINUX_SETUP=$CT_HOME/platforms/linux/tools/setup-tools.sh
WINDOWS_COLLECTOR=$CT_HOME/platforms/windows/vestigium-windows.ps1
WINDOWS_SETUP=$CT_HOME/platforms/windows/Tools/Setup-Windows.ps1
VERIFY_SH=$CT_HOME/shared/verify-evidence.sh
VERIFY_PS=$CT_HOME/shared/Verify-Evidence.ps1
RULES_DIR=$CT_HOME/shared/yara-rules

say() { printf 'vestigium: %s\n' "$*" >&2; }
die() { _code=$1; shift; say "$*"; exit "$_code"; }

# q ARG - single-quote ARG so an argument list can be rebuilt with eval. The
# trailing sentinel keeps command substitution from eating trailing newlines.
q() {
    _q=$(printf '%sx' "$1" | sed "s/'/'\\\\''/g")
    printf "'%s'" "${_q%x}"
}

usage() {
    cat <<EOF
Vestigium ${CT_VERSION} - cross-platform live-response evidence collector

Usage: ./vestigium.sh [command] [options]

Commands
  collect            Run a live-response collection (default)
  verify PACKAGE     Verify an evidence package: a collection folder, a Linux
                     .tar.zst / .tar.gz archive or a Windows .zip
  setup [options]    Prepare the toolkit (helper tools and YARA rules)
  info               Show the detected platform and toolkit readiness
  version            Print the version
  help               This help

Launcher options
  --platform NAME    auto (default), linux or windows
  --dry-run          Print the command that would run, then exit
  --no-elevate       Do not re-run through sudo when not root

Common collection options (translated for the detected platform)
  --case-id ID           -CaseId               Case reference for the manifest
  --target-user USER     -TargetUser           Limit user-scoped artifacts (repeatable)
  --output DIR           -OutputPath           Evidence base directory (default ./output)
  --modules A,B          -Modules              Run a subset of modules
  --list-modules         -ListModules          List the platform's modules
  --quick                -Quick                Fast triage (Windows: quick YARA scan)
  --skip-yara            -SkipYara             No YARA scanning
  --yara-quick           -YaraQuickScan        YARA on high-signal paths only
  --yara-threads N       -YaraThreads          YARA scanner threads
  --yara-timeout SEC     -YaraTimeoutSeconds   Per-target YARA timeout
  --memory               -CaptureMemory        Acquire physical memory first
  --no-archive           -NoArchive            Leave the evidence folder uncompressed
  --credential-stores M  -BrowserCredentialStores
                                               Browser credential stores: copy (default) or metadata
  -v, --verbose          -Verbose              Verbose progress output

Platform-specific options are passed through unchanged. Collector help:
  ./vestigium.sh collect --help

Examples
  sudo ./vestigium.sh --case-id IR-2026-014
  sudo ./vestigium.sh --case-id IR-2026-014 --target-user j.doe --output /media/evidence
  ./vestigium.sh verify output/web01_20260911_101500.tar.zst
  sudo ./vestigium.sh setup                        # stage tools and rules
  ./vestigium.sh --platform windows --dry-run --case-id IR-7
EOF
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
detect_platform() {
    CT_KERNEL=$(uname -s 2>/dev/null || echo unknown)
    case "$CT_KERNEL" in
        Linux)
            CT_NATIVE=linux; CT_ENV=linux
            if [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] ||
               grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
                CT_ENV=wsl
            fi ;;
        MINGW*|MSYS*) CT_NATIVE=windows; CT_ENV=msys ;;
        CYGWIN*)      CT_NATIVE=windows; CT_ENV=cygwin ;;
        Darwin)       CT_NATIVE=macos;   CT_ENV=macos ;;
        *)            CT_NATIVE=unsupported; CT_ENV=$CT_KERNEL ;;
    esac
}

os_release() { sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | head -n 1 | tr -d '"'; }

# Windows tools need Windows paths; MSYS/Cygwin and WSL each have a converter.
# WSL paths are made absolute first: powershell.exe would otherwise resolve a
# relative path against a \\wsl.localhost\ working directory.
to_win_path() {
    case "$CT_ENV" in
        msys|cygwin) cygpath -w -- "$1" 2>/dev/null || printf '%s' "$1" ;;
        wsl)
            case "$1" in
                /*) _wp=$1 ;;
                *)  _wp=$PWD/$1 ;;
            esac
            wslpath -w "$_wp" 2>/dev/null || printf '%s' "$1" ;;
        *) printf '%s' "$1" ;;
    esac
}

# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------
run() {
    if [ "$CT_DRY_RUN" = 1 ]; then
        printf 'vestigium: would run:'
        for _a in "$@"; do printf ' %s' "$(q "$_a")"; done
        printf '\n'
        exit 0
    fi
    exec "$@"
}

run_powershell() {
    _script=$1; shift
    _ps=$(command -v powershell.exe 2>/dev/null || command -v pwsh.exe 2>/dev/null || true)
    if [ -z "$_ps" ]; then
        [ "$CT_DRY_RUN" = 1 ] || die 3 "powershell.exe was not found in PATH"
        _ps=powershell.exe
    fi
    # Paths are converted explicitly; stop MSYS2 from rewriting arguments.
    MSYS2_ARG_CONV_EXCL='*'
    export MSYS2_ARG_CONV_EXCL
    run "$_ps" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$(to_win_path "$_script")" "$@"
}

elevate() {
    [ "$(id -u 2>/dev/null)" = 0 ] && return 0
    # A dry run only prints the command it would run, so it never needs root -
    # regardless of --no-elevate. This check must come before the others.
    if [ "$CT_DRY_RUN" = 1 ]; then
        if [ "$CT_ELEVATE" = 1 ]; then
            say "not root: a real run re-executes through sudo"
        else
            say "not root: a real run would require root (--no-elevate is set)"
        fi
        return 0
    fi
    [ "$CT_ELEVATE" = 1 ] || die 1 "root privileges are required; re-run as root or through sudo"
    command -v sudo >/dev/null 2>&1 || die 1 "root privileges are required and sudo is not installed"
    say "root privileges are required; re-running through sudo"
    eval "exec sudo -- /bin/sh $(q "$CT_HOME/vestigium.sh") $CT_ORIG"
}

check_bash() {
    command -v bash >/dev/null 2>&1 || die 3 "bash 4.4 or newer is required"
    # shellcheck disable=SC2016 # expanded by the inner bash, not by sh
    bash -c '[ "${BASH_VERSINFO[0]}" -gt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -ge 4 ]; }' ||
        die 3 "bash 4.4 or newer is required (found $(bash -c 'echo "$BASH_VERSION"'))"
}

note_environment() {
    _id=$(os_release ID); _like=$(os_release ID_LIKE)
    case " $_id $_like " in
        *" debian "*|*" ubuntu "*) ;;
        *) say "note: ${_id:-this distribution} is not Debian/Ubuntu-based; package-integrity checks (dpkg, debsums) and some artifacts will be unavailable (best effort)" ;;
    esac
    if [ "$CT_ENV" = wsl ]; then
        say "note: WSL detected; this collects the WSL Linux environment. For the Windows host run vestigium.cmd, or add --platform windows."
    fi
}

require_target() {
    case "$CT_TARGET" in
        linux)
            [ "$CT_NATIVE" = linux ] || die 3 "the Linux collector must run on Linux (detected: $CT_ENV)" ;;
        windows)
            case "$CT_ENV" in
                msys|cygwin|wsl) ;;
                *) [ "$CT_DRY_RUN" = 1 ] ||
                       die 3 "the Windows collector must run on Windows: use vestigium.cmd or vestigium.ps1 there (detected: $CT_ENV)" ;;
            esac ;;
        macos)
            die 3 "macOS is not supported yet. Supported: Linux (Debian/Ubuntu family; others best effort) and Windows 10/11. 'verify' works on macOS." ;;
        *)
            die 3 "unsupported platform: $CT_ENV" ;;
    esac
}

# ---------------------------------------------------------------------------
# Option translation
# ---------------------------------------------------------------------------
# linux_args ARGS... -> CT_ARGS (quoted list), CT_NOROOT (1 = no root needed)
linux_args() {
    CT_ARGS=""; CT_NOROOT=0
    while [ $# -gt 0 ]; do
        _a=$1; shift
        case "$_a" in
            --credential-stores|--credential-stores=*)
                if [ "$_a" = --credential-stores ]; then
                    [ $# -gt 0 ] || die 2 "--credential-stores needs a value"
                    _v=$1; shift
                else
                    _v=${_a#*=}
                fi
                case "$_v" in
                    copy|Copy) _v=copy ;;
                    metadata|Metadata|metadataonly|MetadataOnly) _v=metadata ;;
                    *) die 2 "--credential-stores takes copy or metadata, not '$_v'" ;;
                esac
                CT_ARGS="$CT_ARGS $(q --credential-stores) $(q "$_v")"
                continue ;;
            --list-modules|-h|--help|-V|--version) CT_NOROOT=1 ;;
        esac
        CT_ARGS="$CT_ARGS $(q "$_a")"
    done
}

# windows_args ARGS... -> CT_ARGS (quoted PowerShell parameter list)
windows_args() {
    CT_ARGS=""; _users=""
    while [ $# -gt 0 ]; do
        _a=$1; shift
        _v=""; _inline=0
        case "$_a" in
            --*=*) _v=${_a#*=}; _a=${_a%%=*}; _inline=1 ;;
        esac
        case "$_a" in
            --case-id|--target-user|--output|--modules|--yara-threads|--yara-timeout|--credential-stores|\
            --max-file-mb|--cmd-timeout|--max-journal-mb)
                if [ "$_inline" = 0 ]; then
                    [ $# -gt 0 ] || die 2 "$_a needs a value"
                    _v=$1; shift
                fi ;;
        esac
        case "$_a" in
            --case-id)       CT_ARGS="$CT_ARGS -CaseId $(q "$_v")" ;;
            --target-user)   _users=${_users:+$_users,}$_v ;;
            --output)        CT_ARGS="$CT_ARGS -OutputPath $(q "$(to_win_path "$_v")")" ;;
            --modules)       CT_ARGS="$CT_ARGS -Modules $(q "$_v")" ;;
            --list-modules)  CT_ARGS="$CT_ARGS -ListModules" ;;
            --quick|--yara-quick) CT_ARGS="$CT_ARGS -YaraQuickScan" ;;
            --skip-yara)     CT_ARGS="$CT_ARGS -SkipYara" ;;
            --yara-threads)  CT_ARGS="$CT_ARGS -YaraThreads $(q "$_v")" ;;
            --yara-timeout)  CT_ARGS="$CT_ARGS -YaraTimeoutSeconds $(q "$_v")" ;;
            --memory)        CT_ARGS="$CT_ARGS -CaptureMemory" ;;
            --no-archive)    CT_ARGS="$CT_ARGS -NoArchive" ;;
            --credential-stores)
                case "$_v" in
                    copy|Copy) CT_ARGS="$CT_ARGS -BrowserCredentialStores Copy" ;;
                    metadata|Metadata|metadataonly|MetadataOnly)
                               CT_ARGS="$CT_ARGS -BrowserCredentialStores MetadataOnly" ;;
                    *) die 2 "--credential-stores takes copy or metadata, not '$_v'" ;;
                esac ;;
            -v|--verbose)    CT_ARGS="$CT_ARGS -Verbose" ;;
            -h|--help)       CT_ARGS="$CT_ARGS -?" ;;
            -V|--version)    CT_ARGS="$CT_ARGS -Version" ;;
            --max-file-mb|--cmd-timeout|--max-journal-mb|--rootkit-scan|--yara-procs|\
            --browser-history|--no-browser-history|--browser-sessions|--no-browser-sessions|\
            --full|--prepare|--prepare-offline|-q|--quiet)
                say "note: $_a is a Linux collector option; ignored for Windows" ;;
            --*)             die 2 "unknown option for the Windows collector: $_a" ;;
            *)               CT_ARGS="$CT_ARGS $(q "$_a")" ;;   # native -Parameter or value
        esac
    done
    [ -n "$_users" ] && CT_ARGS="$CT_ARGS -TargetUser $(q "$_users")"
    return 0
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_collect() {
    require_target
    if [ "$CT_TARGET" = linux ]; then
        linux_args "$@"
        eval "set -- $CT_ARGS"
        check_bash
        [ "$CT_NOROOT" = 1 ] || { note_environment; elevate; }
        run bash "$LINUX_COLLECTOR" "$@"
    else
        windows_args "$@"
        eval "set -- $CT_ARGS"
        run_powershell "$WINDOWS_COLLECTOR" "$@"
    fi
}

cmd_verify() {
    [ $# -ge 1 ] || die 2 "usage: ./vestigium.sh verify <evidence folder | archive>"
    case "$CT_ENV" in
        msys|cygwin)
            _pkg=$(to_win_path "$1"); shift
            run_powershell "$VERIFY_PS" -Path "$_pkg" "$@" ;;
        *)
            command -v bash >/dev/null 2>&1 || die 3 "bash is required for verification"
            run bash "$VERIFY_SH" "$@" ;;
    esac
}

cmd_setup() {
    require_target
    if [ "$CT_TARGET" = linux ]; then
        check_bash
        _noroot=0
        for _a in "$@"; do
            case "$_a" in --verify|-h|--help) _noroot=1 ;; esac
        done
        [ "$_noroot" = 1 ] || elevate
        run bash "$LINUX_SETUP" "$@"
    else
        run_powershell "$WINDOWS_SETUP" "$@"
    fi
}

row() { printf '  %-26s %s\n' "$1" "$2"; }

cmd_info() {
    printf 'Vestigium %s\n\n' "$CT_VERSION"
    row "Kit root" "$CT_HOME"
    row "Detected platform" "$CT_NATIVE ($CT_ENV)"
    [ "$CT_NATIVE" = linux ] && row "Distribution" "$(os_release PRETTY_NAME)"
    row "Selected collector" "$CT_TARGET"
    row "Running as root" "$([ "$(id -u 2>/dev/null)" = 0 ] && echo yes || echo no)"
    # shellcheck disable=SC2016 # expanded by the inner bash, not by sh
    row "bash" "$(bash -c 'echo "$BASH_VERSION"' 2>/dev/null || echo missing)"
    row "python3" "$(python3 -c 'import sys; print(sys.version.split()[0])' 2>/dev/null || echo missing)"

    if [ -f "$RULES_DIR/active-rules.yar" ]; then
        _n=$(grep -cE '^[[:space:]]*((private|global)[[:space:]]+)*rule[[:space:]]+[A-Za-z_]' "$RULES_DIR/active-rules.yar" 2>/dev/null)
        row "YARA rule bundle" "present ($_n rules)"
    else
        row "YARA rule bundle" "MISSING - run ./vestigium.sh setup"
    fi
    row "Pre-compiled bundle" "$([ -f "$RULES_DIR/active-rules.compiled" ] && echo present || echo absent)"
    row "signature-base IOC lists" "$([ -d "$RULES_DIR/signature-base/iocs" ] && echo present || echo absent)"

    if [ "$CT_TARGET" = windows ]; then
        for _t in yara64.exe Autorunsc64.exe; do
            row "$_t" "$([ -f "$CT_HOME/platforms/windows/Tools/$_t" ] && echo present || echo absent)"
        done
        _pm=$(find "$CT_HOME/platforms/windows/Tools" -maxdepth 1 -iname 'winpmem_mini_x64*.exe' 2>/dev/null | head -n 1)
        row "winpmem (memory)" "$([ -n "$_pm" ] && echo present || echo absent)"
    else
        row "yara" "$(PATH="$CT_HOME/platforms/linux/tools/bin:$PATH" command -v yara 2>/dev/null || echo missing)"
        row "AVML (memory)" "$([ -x "$CT_HOME/platforms/linux/tools/bin/avml" ] && echo present || echo absent)"
    fi
    _free=$(df -Ph "$CT_HOME/output" 2>/dev/null | awk 'NR == 2 {print $4}')
    row "Default output" "$CT_HOME/output (${_free:-?} free)"
    printf '\nFull toolkit readiness: ./vestigium.sh setup --verify\n'
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
CT_ORIG=""
for _a in "$@"; do CT_ORIG="$CT_ORIG $(q "$_a")"; done

CT_COMMAND=""
CT_PLATFORM_OPT=auto
CT_DRY_RUN=0
CT_ELEVATE=1
CT_REST=""
_first=1        # the first word may name a command
_want_value=0   # the next word is an option value: never remapped or rejected
_maybe_value=0  # the previous word was an unknown -Parameter that may take one

while [ $# -gt 0 ]; do
    _a=$1; shift
    if [ "$_want_value" = 1 ]; then
        CT_REST="$CT_REST $(q "$_a")"
        _want_value=0
        continue
    fi
    case "$_a" in
        --platform)
            [ $# -gt 0 ] || die 2 "--platform needs a value"
            CT_PLATFORM_OPT=$1; shift; continue ;;
        --platform=*) CT_PLATFORM_OPT=${_a#*=}; continue ;;
        --dry-run)    CT_DRY_RUN=1; continue ;;
        --no-elevate) CT_ELEVATE=0; continue ;;
    esac
    if [ "$_first" = 1 ]; then
        _first=0
        case "$_a" in
            collect|verify|setup|info|version|help) CT_COMMAND=$_a; continue ;;
            -h|--help) CT_COMMAND=help; continue ;;
            --version) CT_COMMAND=version; continue ;;
            -*) ;;
            *) die 2 "unknown command '$_a' (collect, verify, setup, info, version, help)" ;;
        esac
    fi
    _maybe=$_maybe_value
    _maybe_value=0
    # Accept PowerShell-style names and map them to the canonical vocabulary.
    case "$(printf '%s' "$_a" | tr '[:upper:]' '[:lower:]')" in
        -caseid)                  _a=--case-id ;;
        -targetuser)              _a=--target-user ;;
        -outputpath)              _a=--output ;;
        -modules)                 _a=--modules ;;
        -listmodules)             _a=--list-modules ;;
        -quick)                   _a=--quick ;;
        -skipyara)                _a=--skip-yara ;;
        -yaraquickscan)           _a=--yara-quick ;;
        -yarathreads)             _a=--yara-threads ;;
        -yaratimeoutseconds)      _a=--yara-timeout ;;
        -capturememory)           _a=--memory ;;
        -noarchive)               _a=--no-archive ;;
        -browsercredentialstores) _a=--credential-stores ;;
        -verbose)                 _a=--verbose ;;
    esac
    case "$_a" in
        --case-id|--target-user|--output|--modules|--yara-threads|--yara-timeout|\
        --credential-stores|--max-file-mb|--cmd-timeout|--max-journal-mb)
            _want_value=1 ;;
        --*) ;;
        -?*) _maybe_value=1 ;;
        *)
            # A bare word is a value, a verify package or a setup argument;
            # anywhere else it is a typo that must not start a collection.
            if [ "${CT_COMMAND:-collect}" = collect ] && [ "$_maybe" = 0 ]; then
                die 2 "unexpected argument '$_a' (see ./vestigium.sh help)"
            fi ;;
    esac
    CT_REST="$CT_REST $(q "$_a")"
done
[ -n "$CT_COMMAND" ] || CT_COMMAND=collect
eval "set -- $CT_REST"

detect_platform
case "$CT_PLATFORM_OPT" in
    auto)          CT_TARGET=$CT_NATIVE ;;
    linux|windows) CT_TARGET=$CT_PLATFORM_OPT ;;
    *)             die 2 "unknown --platform '$CT_PLATFORM_OPT' (auto, linux or windows)" ;;
esac

case "$CT_COMMAND" in
    help)    usage ;;
    version) printf 'Vestigium %s\n' "$CT_VERSION" ;;
    info)    cmd_info ;;
    verify)  cmd_verify "$@" ;;
    setup)   cmd_setup "$@" ;;
    collect) cmd_collect "$@" ;;
esac
