#!/usr/bin/env bash
# 00-lib.sh - Shared framework for the Vestigium Linux evidence collector.
#
# Provides: logging, evidence tree creation, command execution wrappers with
# provenance capture, dynamic (username-independent) user enumeration, local
# tool resolution, local-mount discovery, process-tree termination, hashing,
# manifest generation and archiving.
#
# This file is sourced by vestigium-linux.sh; it is not meant to run
# standalone.

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

DFIR_START_EPOCH="$(date +%s)"
DFIR_START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DFIR_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DFIR_HOSTNAME="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown-host)"

# Populated by dfir_init
DFIR_EVID=""            # evidence root for this run
DFIR_LOGFILE=""         # collection.log
DFIR_CMDLOG=""          # command-log.csv
DFIR_PROVENANCE=""      # provenance.csv
DFIR_RESULTS=""         # module-results.csv
DFIR_USERS_TSV=""       # enumerated target users
declare -a DFIR_USER_ROWS=()  # cached "<name>\t<uid>\t<gid>\t<home>\t<shell>" rows
declare -A DFIR_DIR=()  # logical name -> absolute path

# Counters
DFIR_CMD_COUNT=0
DFIR_CMD_FAILED=0
DFIR_CMD_SKIPPED=0
DFIR_COPY_COUNT=0
DFIR_RCLOG=""

# PID of the module subshell currently being waited on (interrupt handling).
DFIR_MODULE_PID=""

# Evidence tree layout (logical name -> directory name)
DFIR_TREE=(
    "System:01_System"
    "Processes:02_Processes"
    "Persistence:03_Persistence"
    "Startup:04_Startup"
    "Config:05_Config"
    "ScheduledTasks:06_ScheduledTasks"
    "Services:07_Services"
    "Network:08_Network"
    "Browser:09_Browser"
    "Logs:10_Logs"
    "Hosts:11_Hosts"
    "Security:12_Security"
    "SystemInfo:13_SystemInfo"
    "Users:14_Users"
    "Filesystem:15_Filesystem"
    "Containers:16_Containers"
    "Memory:17_Memory"
    "Yara:18_Yara"
    "CollectionLogs:19_CollectionLogs"
    "Hashes:20_Hashes"
    "Manifest:21_Manifest"
)

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    _C_RST=$'\033[0m'; _C_DIM=$'\033[2m'; _C_RED=$'\033[31m'
    _C_YEL=$'\033[33m'; _C_GRN=$'\033[32m'; _C_CYN=$'\033[36m'
else
    _C_RST=""; _C_DIM=""; _C_RED=""; _C_YEL=""; _C_GRN=""; _C_CYN=""
fi

dfir_log() {
    # dfir_log LEVEL MESSAGE...
    local level="$1"; shift
    local msg="$*"
    local stamp; stamp="$(date '+%Y-%m-%d %H:%M:%S.%3N')"
    local line="${stamp} [${level}] ${msg}"

    [[ -n "$DFIR_LOGFILE" ]] && printf '%s\n' "$line" >>"$DFIR_LOGFILE" 2>/dev/null

    case "$level" in
        ERROR) printf '%s%s%s\n' "$_C_RED" "$line" "$_C_RST" >&2 ;;
        WARN)  [[ "${DFIR_QUIET:-0}" == 1 ]] || printf '%s%s%s\n' "$_C_YEL" "$line" "$_C_RST" ;;
        SUCCESS) [[ "${DFIR_QUIET:-0}" == 1 ]] || printf '%s%s%s\n' "$_C_GRN" "$line" "$_C_RST" ;;
        INFO)  [[ "${DFIR_VERBOSE:-0}" == 1 ]] && printf '%s%s%s\n' "$_C_DIM" "$line" "$_C_RST" ;;
        *)     [[ "${DFIR_QUIET:-0}" == 1 ]] || printf '%s\n' "$line" ;;
    esac
    return 0
}

dfir_banner() {
    [[ "${DFIR_QUIET:-0}" == 1 ]] && return 0
    printf '%s\n' "${_C_CYN}==> $*${_C_RST}"
    return 0
}

# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

dfir_csv_escape() {
    # Quote a single CSV field (RFC4180).
    local v="${1-}"
    v="${v//\"/\"\"}"
    printf '"%s"' "$v"
}

dfir_csv_row() {
    # dfir_csv_row FILE FIELD...
    local file="$1"; shift
    local out="" f
    for f in "$@"; do
        [[ -n "$out" ]] && out+=","
        out+="$(dfir_csv_escape "$f")"
    done
    printf '%s\n' "$out" >>"$file" 2>/dev/null
    return 0
}

# ---------------------------------------------------------------------------
# Tool resolution - local tools/bin wins over system PATH
# ---------------------------------------------------------------------------

dfir_tool() {
    # dfir_tool NAME -> prints absolute path, returns 1 when unavailable.
    #
    # The kit's own copy under tools/bin always wins, so collection never trusts
    # a host binary the kit can supply itself. When there is no kit copy we still
    # fall back to the host's PATH so collection can proceed: in trusted-tools
    # mode (DFIR_TRUSTED_TOOLS=1) that fallback is explicitly an UNTRUSTED path -
    # the host may be compromised - and dfir_record_toolset marks any such tool
    # as a "host" source (a trust gap) in tool-provenance.csv.
    local name="$1"
    if [[ -x "${DFIR_TOOLS}/bin/${name}" ]]; then
        printf '%s\n' "${DFIR_TOOLS}/bin/${name}"
        return 0
    fi
    local p
    if p="$(command -v "$name" 2>/dev/null)"; then
        printf '%s\n' "$p"
        return 0
    fi
    return 1
}

dfir_have() {
    dfir_tool "$1" >/dev/null 2>&1
}

dfir_record_toolset() {
    # Documents which binaries this run will actually use into tool-provenance.csv
    # (Tool,Source,ResolvedPath,SHA256). Valuable evidence in both normal and
    # trusted-tools mode: for each tool it records whether the kit's own copy, a
    # host binary, or nothing was resolved, and the SHA256 of the resolved file.
    # Investigative tools are resolved through dfir_tool (kit copy wins, host is
    # the untrusted fallback); the core shell utilities the collector runs inside
    # dfir_sh's `bash -c` pipelines are resolved through command -v, exactly as
    # those pipelines find them. Source is "kit" when the path is under
    # tools/bin/, else "host", else "missing".
    local out="${DFIR_DIR[CollectionLogs]}/tool-provenance.csv"
    dfir_csv_row "$out" "Tool" "Source" "ResolvedPath" "SHA256"

    # Kit-carried investigative tools plus the second-opinion / anti-rootkit
    # helpers, resolved via dfir_tool so the kit copy always wins.
    local -a investigative=(
        yara lsof pstree fuser dmidecode lspci lsusb lshw getcap debsums file
        sqlite3 jq zstd netstat arp utmpdump tune2fs lsattr mokutil efibootmgr
        ssh-keygen openssl acpi avml busybox chkrootkit rkhunter unhide
    )
    # Core shell utilities used inside dfir_sh pipelines, resolved via command -v.
    local -a core=(
        bash sh find grep awk sed sort head tail cut tr stat cat ls readlink
        sha256sum ps ss ip lsmod modinfo dpkg systemctl journalctl
    )

    local kitpre="${DFIR_TOOLS}/bin/"
    local kit=0 host=0 missing=0
    local -a trust_gap=()          # investigative tools that fell back to host / missing
    local tool path src real sha

    # Investigative tools (dfir_tool): a host/missing resolution is a trust gap.
    for tool in "${investigative[@]}"; do
        path="$(dfir_tool "$tool" 2>/dev/null || true)"
        if [[ -z "$path" ]]; then
            src="missing"; sha=""; missing=$((missing + 1)); trust_gap+=("$tool")
        elif [[ "$path" == "$kitpre"* ]]; then
            src="kit"; kit=$((kit + 1))
        else
            src="host"; host=$((host + 1)); trust_gap+=("$tool")
        fi
        sha=""
        if [[ -n "$path" ]]; then
            # Hash the resolved real file; for kit wrappers (shell scripts)
            # readlink -f resolves to the wrapper itself, which documents the
            # wrapper this run will invoke.
            real="$(readlink -f -- "$path" 2>/dev/null || true)"
            [[ -n "$real" ]] || real="$path"
            sha="$(sha256sum -- "$real" 2>/dev/null | awk '{print $1}')"
        fi
        dfir_csv_row "$out" "$tool" "$src" "$path" "$sha"
    done

    # Core shell utilities (command -v): recorded for provenance, not a trust gap.
    for tool in "${core[@]}"; do
        path="$(command -v "$tool" 2>/dev/null || true)"
        if [[ -z "$path" ]]; then
            src="missing"; sha=""; missing=$((missing + 1))
        elif [[ "$path" == "$kitpre"* ]]; then
            src="kit"; kit=$((kit + 1))
        else
            src="host"; host=$((host + 1))
        fi
        sha=""
        if [[ -n "$path" && "$path" == /* ]]; then
            real="$(readlink -f -- "$path" 2>/dev/null || true)"
            [[ -n "$real" ]] || real="$path"
            sha="$(sha256sum -- "$real" 2>/dev/null | awk '{print $1}')"
        fi
        dfir_csv_row "$out" "$tool" "$src" "$path" "$sha"
    done

    dfir_log INFO "Toolset recorded: ${kit} kit, ${host} host, ${missing} missing (see tool-provenance.csv)"
    if (( ${DFIR_TRUSTED_TOOLS:-0} == 1 )) && ((${#trust_gap[@]} > 0)); then
        dfir_log WARN "Trusted-tools: investigative tool(s) not from the kit (trust gap): ${trust_gap[*]}"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Local on-disk mount discovery
# ---------------------------------------------------------------------------

dfir_local_mounts() {
    # Prints the mount points of local, on-disk filesystems, one per line, with
    # "/" first and deduplicated by source device (so bind mounts collapse to a
    # single target). Excludes squashfs snaps, overlay, tmpfs, network and
    # pseudo filesystems by whitelisting real on-disk types. Falls back to
    # printing "/" when findmnt is unavailable. Exported so 85-filesystem.sh can
    # call it from inside the `bash -c` scripts run through dfir_sh.
    local types='ext2,ext3,ext4,xfs,btrfs,zfs,f2fs,jfs,reiserfs,vfat,exfat,ntfs,ntfs3,fuseblk'
    if ! command -v findmnt >/dev/null 2>&1; then
        printf '/\n'
        return 0
    fi

    local target source _fstype
    local root_seen=0
    local -a others=()
    declare -A seen_src=()
    # findmnt -r yields space-separated fields and escapes special characters
    # (space -> \x20, etc.); printf '%b' decodes those escapes.
    while IFS=' ' read -r target source _fstype; do
        [[ -z "$target" ]] && continue
        target="$(printf '%b' "$target")"
        source="$(printf '%b' "$source")"
        [[ -n "${seen_src[$source]:-}" ]] && continue
        seen_src["$source"]=1
        if [[ "$target" == "/" ]]; then
            root_seen=1
        else
            others+=("$target")
        fi
    done < <(findmnt -rn -o TARGET,SOURCE,FSTYPE -t "$types" 2>/dev/null)

    (( root_seen == 1 )) && printf '/\n'
    local t
    for t in "${others[@]}"; do
        printf '%s\n' "$t"
    done
    return 0
}
export -f dfir_local_mounts

# ---------------------------------------------------------------------------
# Process-tree termination (interrupt handling)
# ---------------------------------------------------------------------------

dfir_descendants() {
    # Prints every descendant PID of PID (children first / post-order) so a
    # signal can be delivered to each one. `timeout` places the command it runs
    # in its own process group, so signalling the module subshell's group is not
    # enough; we walk the tree explicitly. Uses ps when present, else /proc.
    local pid="$1" child kids
    if command -v ps >/dev/null 2>&1; then
        kids="$(ps -o pid= --ppid "$pid" 2>/dev/null)"
    else
        kids=""
        local s statline after ppid kp
        for s in /proc/[0-9]*/stat; do
            [[ -r "$s" ]] || continue
            # field 4 is PPID; comm (field 2) may contain spaces/parentheses, so
            # parse after the final ')'.
            read -r statline <"$s" 2>/dev/null || continue
            after="${statline##*) }"    # "<state> <ppid> ..."
            ppid="${after#* }"; ppid="${ppid%% *}"
            if [[ "$ppid" == "$pid" ]]; then
                kp="${s#/proc/}"; kp="${kp%/stat}"
                kids+="${kp}"$'\n'
            fi
        done
    fi
    for child in $kids; do
        [[ -z "$child" || "$child" == "$pid" ]] && continue
        dfir_descendants "$child"
        printf '%s\n' "$child"
    done
    return 0
}

dfir_kill_tree() {
    # dfir_kill_tree ROOT_PID [SIGNAL]  - signal ROOT and all descendants,
    # descendants first so parents cannot re-reap or respawn during teardown.
    local root="$1" sig="${2:-TERM}" p
    for p in $(dfir_descendants "$root"); do
        kill "-${sig}" "$p" 2>/dev/null || true
    done
    kill "-${sig}" "$root" 2>/dev/null || true
    return 0
}

# ---------------------------------------------------------------------------
# Evidence tree / context initialisation
# ---------------------------------------------------------------------------

dfir_init() {
    local base="$1"

    # Two runs started in the same second would otherwise share (and clobber)
    # one evidence directory. Claim the directory with a plain mkdir (which
    # fails atomically if it already exists) and append _2, _3, ... on a
    # collision. umask 077 in the launcher keeps the tree private.
    local stem="${base}/${DFIR_HOSTNAME}_${DFIR_TIMESTAMP}"
    local cand="$stem" n=1
    until mkdir "$cand" 2>/dev/null; do
        if [[ ! -d "$cand" ]]; then
            printf 'Cannot create evidence directory: %s\n' "$cand" >&2
            return 1
        fi
        n=$((n + 1))
        if (( n > 999 )); then
            printf 'Too many evidence-directory collisions under %s\n' "$base" >&2
            return 1
        fi
        cand="${stem}_${n}"
    done
    DFIR_EVID="$cand"
    chmod 700 "$DFIR_EVID" 2>/dev/null

    local entry name dir
    for entry in "${DFIR_TREE[@]}"; do
        name="${entry%%:*}"; dir="${entry#*:}"
        DFIR_DIR["$name"]="${DFIR_EVID}/${dir}"
        mkdir -p "${DFIR_DIR[$name]}" || return 1
    done

    DFIR_LOGFILE="${DFIR_DIR[CollectionLogs]}/collection.log"
    DFIR_CMDLOG="${DFIR_DIR[CollectionLogs]}/command-log.csv"
    DFIR_PROVENANCE="${DFIR_DIR[CollectionLogs]}/provenance.csv"
    DFIR_RESULTS="${DFIR_DIR[CollectionLogs]}/module-results.csv"
    DFIR_USERS_TSV="${DFIR_DIR[CollectionLogs]}/target-users.tsv"
    DFIR_RCLOG="${DFIR_DIR[CollectionLogs]}/.exit-codes"
    DFIR_PKG_INDEX="${DFIR_DIR[CollectionLogs]}/.packaged-files.idx"
    DFIR_PKG_MAP="${DFIR_DIR[CollectionLogs]}/.packaged-files.map"
    export DFIR_PKG_INDEX DFIR_PKG_MAP

    : >"$DFIR_LOGFILE"
    : >"$DFIR_RCLOG"
    dfir_csv_row "$DFIR_CMDLOG" "Timestamp" "Label" "Command" "ExitCode" "DurationSeconds" "OutputFile" "OutputBytes"
    dfir_csv_row "$DFIR_PROVENANCE" "Timestamp" "SourcePath" "EvidencePath" "SizeBytes" "MTimeUTC" "ATimeUTC" "CTimeUTC" "Mode" "Owner" "Group" "SourceSHA256"
    dfir_csv_row "$DFIR_RESULTS" "Module" "Status" "Commands" "Skipped" "Failures" "DurationSeconds" "Message"

    dfir_record_toolset
    dfir_build_user_list
    return 0
}

# ---------------------------------------------------------------------------
# Username-independent user enumeration
# ---------------------------------------------------------------------------

dfir_resolve_user_entry() {
    # Accepts a username, a UID, or a home-directory path. Prints a passwd line.
    local target="$1" line=""
    if [[ "$target" == /* ]]; then
        line="$(getent passwd | awk -F: -v h="${target%/}" '$6 == h {print; exit}')"
    else
        line="$(getent passwd "$target" 2>/dev/null)"
    fi
    [[ -n "$line" ]] && { printf '%s\n' "$line"; return 0; }
    return 1
}

dfir_build_user_list() {
    # Builds "<name>\t<uid>\t<gid>\t<home>\t<shell>" rows for every profile that
    # will be examined. Never assumes a particular account name exists.
    local tmp="${DFIR_USERS_TSV}.tmp"
    : >"$tmp"

    local raw=""
    if ((${#DFIR_TARGET_USERS[@]} > 0)); then
        local t
        for t in "${DFIR_TARGET_USERS[@]}"; do
            local line
            if line="$(dfir_resolve_user_entry "$t")"; then
                raw+="${line}"$'\n'
            else
                dfir_log WARN "Requested target user not found in passwd database: ${t}"
            fi
        done
    else
        # UID 0 plus regular interactive accounts. Works for local, LDAP, SSSD
        # and AD-joined systems because it goes through NSS, not /etc/passwd.
        raw="$(getent passwd | awk -F: '($3 == 0) || ($3 >= 1000 && $3 < 65000)')"
    fi

    local name pw uid gid gecos home shell
    # pw and gecos are positional passwd placeholders we intentionally discard.
    # shellcheck disable=SC2034
    while IFS=: read -r name pw uid gid gecos home shell; do
        [[ -z "${name:-}" ]] && continue
        [[ -z "${home:-}" ]] && continue
        case "$home" in
            /|/nonexistent|/dev/null|/var/run/*|/run/*) continue ;;
        esac
        [[ -d "$home" ]] || continue
        printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$uid" "$gid" "${home%/}" "${shell:-}" >>"$tmp"
    done <<<"$raw"

    sort -u -t$'\t' -k4,4 "$tmp" >"$DFIR_USERS_TSV" 2>/dev/null || cp "$tmp" "$DFIR_USERS_TSV"
    rm -f "$tmp"

    # Cache rows in memory so modules never fight over stdin while iterating.
    DFIR_USER_ROWS=()
    local row
    while IFS= read -r row; do
        [[ -n "$row" ]] && DFIR_USER_ROWS+=("$row")
    done <"$DFIR_USERS_TSV"

    dfir_log INFO "Resolved ${#DFIR_USER_ROWS[@]} user profile(s) for user-scoped collection"
    return 0
}

dfir_each_user() {
    # dfir_each_user FUNCTION -> FUNCTION <name> <uid> <gid> <home> <shell>
    local fn="$1" row name uid gid home shell
    for row in "${DFIR_USER_ROWS[@]}"; do
        IFS=$'\t' read -r name uid gid home shell <<<"$row"
        [[ -z "${name:-}" ]] && continue
        "$fn" "$name" "$uid" "$gid" "$home" "${shell:-}"
    done
    return 0
}

# ---------------------------------------------------------------------------
# Package ownership index
# ---------------------------------------------------------------------------
# `dpkg -S` costs ~60 ms per call because it re-reads the whole file database.
# Building one sorted index of every packaged path turns "is this file owned by
# a package?" into a set lookup, which matters when thousands of files are
# checked (system binaries, systemd units, udev rules, PAM modules, running
# process executables).

dfir_packaged_index() {
    # Builds the indexes on first use. DFIR_PKG_INDEX/DFIR_PKG_MAP are exported
    # so the helpers also work inside the `bash -c` subshells used by dfir_sh.
    [[ -n "${DFIR_PKG_INDEX:-}" ]] || return 1
    if [[ ! -s "$DFIR_PKG_INDEX" ]]; then
        local listfile pkg d tgt
        # Merged-/usr systems symlink /bin,/sbin,/lib,... into /usr, yet some
        # packages still list their paths under the old top dirs (e.g. ed lists
        # /bin/ed). Candidates elsewhere are canonicalised to /usr/bin/ed and
        # would then be reported UNPACKAGED. Record the canonical variant too:
        # build "<top>=<target>" pairs for each top dir that is really a symlink.
        local -a subs=()
        for d in /bin /sbin /lib /lib32 /lib64 /libx32; do
            if [[ -L "$d" ]]; then
                tgt="$(readlink "$d" 2>/dev/null)"; tgt="${tgt#/}"   # e.g. usr/bin
                [[ -n "$tgt" ]] && subs+=("${d}=/${tgt}")
            fi
        done
        {
            for listfile in /var/lib/dpkg/info/*.list; do
                [[ -f "$listfile" ]] || continue
                pkg="$(basename "$listfile" .list)"
                sed "s|\$|\t${pkg%%:*}|" "$listfile" 2>/dev/null
            done
        } | awk -F'\t' -v subs="${subs[*]}" '
            BEGIN {
                np = split(subs, a, " ")
                for (i = 1; i <= np; i++) { split(a[i], kv, "="); pre[i] = kv[1]; canon[i] = kv[2] }
            }
            {
                print $0
                for (i = 1; i <= np; i++) {
                    if (index($1, pre[i] "/") == 1) {
                        print canon[i] substr($1, length(pre[i]) + 1) "\t" $2
                    }
                }
            }' | sort -u >"${DFIR_PKG_MAP:-/dev/null}" 2>/dev/null
        cut -f1 "${DFIR_PKG_MAP:-/dev/null}" 2>/dev/null | sort -u >"$DFIR_PKG_INDEX" 2>/dev/null
    fi
    [[ -s "$DFIR_PKG_INDEX" ]]
}

dfir_is_packaged() {
    # dfir_is_packaged PATH -> 0 when an installed package owns PATH
    local path="$1" real
    dfir_packaged_index || return 1
    grep -Fxq -- "$path" "$DFIR_PKG_INDEX" && return 0
    real="$(readlink -f -- "$path" 2>/dev/null)"
    [[ -n "$real" && "$real" != "$path" ]] && grep -Fxq -- "$real" "$DFIR_PKG_INDEX" && return 0
    return 1
}

dfir_owning_package() {
    # dfir_owning_package PATH -> package name, or a marker when unowned.
    # Called for every process/service, so prefilter the ~10 MB map with a fast
    # fixed-string grep for "<path>\t" before the exact-match awk pass.
    local path="$1" pkg="" real
    dfir_packaged_index || { printf '(unknown)'; return 0; }
    pkg="$(grep -F -- "${path}"$'\t' "$DFIR_PKG_MAP" 2>/dev/null \
            | awk -F'\t' -v p="$path" '$1 == p { print $2; exit }')"
    if [[ -z "$pkg" ]]; then
        real="$(readlink -f -- "$path" 2>/dev/null)"
        if [[ -n "$real" && "$real" != "$path" ]]; then
            pkg="$(grep -F -- "${real}"$'\t' "$DFIR_PKG_MAP" 2>/dev/null \
                    | awk -F'\t' -v p="$real" '$1 == p { print $2; exit }')"
        fi
    fi
    printf '%s' "${pkg:-(not owned by a package)}"
    return 0
}

dfir_filter_unpackaged() {
    # Reads candidate paths on stdin, writes those owned by no package.
    # Canonicalise first so merged-/usr symlink paths compare correctly, in one
    # batched realpath pass rather than a readlink fork per line.
    dfir_packaged_index || { cat; return 0; }
    grep -v '^[[:space:]]*$' \
        | tr '\n' '\0' \
        | xargs -0 -r realpath -m -- 2>/dev/null \
        | sort -u | comm -23 - "$DFIR_PKG_INDEX"
    return 0
}

export -f dfir_packaged_index dfir_is_packaged dfir_owning_package dfir_filter_unpackaged

dfir_safe_name() {
    # Filesystem-safe token from arbitrary text.
    local v="${1-}"
    v="${v//[^A-Za-z0-9._-]/_}"
    printf '%s' "${v:-unnamed}"
}

# ---------------------------------------------------------------------------
# Command execution wrappers
# ---------------------------------------------------------------------------

_dfir_record_cmd() {
    local label="$1" cmd="$2" rc="$3" dur="$4" out="$5"
    local size=0
    [[ -f "$out" ]] && size="$(stat -c %s "$out" 2>/dev/null || echo 0)"
    dfir_csv_row "$DFIR_CMDLOG" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$label" "$cmd" "$rc" "$dur" "${out#$DFIR_EVID/}" "$size"
    # Exit codes are also appended to a flat file: modules run in subshells, so
    # in-memory counters cannot propagate back to the launcher, and the CSV is
    # not safely parsable by awk when a captured command contains quotes.
    printf '%s\n' "$rc" >>"$DFIR_RCLOG" 2>/dev/null
    return 0
}

dfir_cmd() {
    # dfir_cmd LABEL OUTFILE COMMAND [ARGS...]
    # Captures stdout+stderr, never aborts the collection on failure.
    local label="$1" out="$2"; shift 2
    local bin="$1"

    if ! dfir_have "$bin"; then
        dfir_log WARN "Skipped '${label}': ${bin} not available on this host"
        _dfir_record_cmd "$label" "$*" "127" "0" "$out"
        return 1
    fi
    local resolved; resolved="$(dfir_tool "$bin")"
    shift
    set -- "$resolved" "$@"

    mkdir -p "$(dirname "$out")" 2>/dev/null
    local t0 t1 rc dur
    t0="$(date +%s.%N)"
    {
        printf '### %s\n### command: %s\n### started: %s\n\n' \
            "$label" "$*" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >"$out"
    timeout --signal=TERM --kill-after=15 "${DFIR_CMD_TIMEOUT}" "$@" >>"$out" 2>&1
    rc=$?
    t1="$(date +%s.%N)"
    dur="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')"

    printf '\n### exit code: %s (duration %ss)\n' "$rc" "$dur" >>"$out"
    _dfir_record_cmd "$label" "$*" "$rc" "$dur" "$out"

    if (( rc == 124 || rc == 137 )); then
        dfir_log WARN "Timed out after ${DFIR_CMD_TIMEOUT}s: ${label}"
    elif (( rc != 0 )); then
        dfir_log INFO "Non-zero exit (${rc}) for: ${label}"
    else
        dfir_log INFO "Captured: ${label} -> ${out#$DFIR_EVID/}"
    fi
    return $rc
}

dfir_sh() {
    # dfir_sh LABEL OUTFILE 'shell pipeline'
    # For pipelines/redirection that cannot be expressed as a single argv.
    local label="$1" out="$2" script="$3"
    mkdir -p "$(dirname "$out")" 2>/dev/null
    local t0 t1 rc dur
    t0="$(date +%s.%N)"
    {
        printf '### %s\n### shell: %s\n### started: %s\n\n' \
            "$label" "$script" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >"$out"
    timeout --signal=TERM --kill-after=15 "${DFIR_CMD_TIMEOUT}" \
        bash -o pipefail -c "$script" >>"$out" 2>&1
    rc=$?
    t1="$(date +%s.%N)"
    dur="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')"
    printf '\n### exit code: %s (duration %ss)\n' "$rc" "$dur" >>"$out"
    _dfir_record_cmd "$label" "$script" "$rc" "$dur" "$out"
    if (( rc == 124 || rc == 137 )); then
        dfir_log WARN "Timed out after ${DFIR_CMD_TIMEOUT}s: ${label}"
    else
        dfir_log INFO "Captured: ${label} -> ${out#$DFIR_EVID/}"
    fi
    return $rc
}

dfir_capture() {
    # dfir_capture LABEL OUTFILE   (content on stdin)
    local label="$1" out="$2"
    mkdir -p "$(dirname "$out")" 2>/dev/null
    cat >"$out"
    _dfir_record_cmd "$label" "(stdin capture)" "0" "0" "$out"
    return 0
}

# ---------------------------------------------------------------------------
# File acquisition with provenance
# ---------------------------------------------------------------------------

dfir_record_provenance() {
    # dfir_record_provenance SOURCE DEST [SKIP_HASH]
    local src="$1" dest="$2" skip_hash="${3:-0}"
    local size="" mtime="" atime="" ctime="" mode="" owner="" group="" sha=""
    local meta

    # One TZ=UTC stat call (tab-separated) instead of seven forks. TZ=UTC makes
    # the %y/%x/%z timestamps genuinely UTC, matching the *UTC column names.
    # stat does not dereference symlinks by default, so a symlink reports its own
    # metadata (which is what we want for provenance).
    if meta="$(TZ=UTC stat --printf='%s\t%y\t%x\t%z\t%A\t%U\t%G' -- "$src" 2>/dev/null)"; then
        IFS=$'\t' read -r size mtime atime ctime mode owner group <<<"$meta"
    fi

    if [[ -L "$src" ]]; then
        # A symlink has no content to hash; record where it points instead.
        sha="symlink -> $(readlink -- "$src" 2>/dev/null)"
    elif [[ "$skip_hash" != 1 && -f "$src" && -r "$src" ]]; then
        local maxb=$((DFIR_MAX_HASH_MB * 1024 * 1024))
        if [[ -n "$size" && "$size" -le "$maxb" ]]; then
            sha="$(sha256sum -- "$src" 2>/dev/null | awk '{print $1}')"
        else
            sha="(skipped: larger than ${DFIR_MAX_HASH_MB}MB)"
        fi
    fi

    dfir_csv_row "$DFIR_PROVENANCE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$src" "${dest#"$DFIR_EVID"/}" \
        "$size" "$mtime" "$atime" "$ctime" "$mode" "$owner" "$group" "$sha"
    return 0
}

dfir_copy() {
    # dfir_copy SOURCE DEST_FILE_OR_DIR
    local src="$1" dest="$2"

    # A symlink must be tested before -e: for a dangling symlink `-e` is false,
    # so an -e-first check would wrongly report it "not present" and the link
    # (a genuine persistence artifact, e.g. /etc/cron.d/x -> /tmp/evil) would be
    # lost. Symlinks - dangling or not - are copied as links.
    if [[ -L "$src" ]]; then
        if [[ "$dest" == */ ]]; then
            mkdir -p "$dest" 2>/dev/null
            dest="${dest}$(basename -- "$src")"
        else
            mkdir -p "$(dirname "$dest")" 2>/dev/null
        fi
        dfir_record_provenance "$src" "$dest" 1
        # Never chmod a symlink: chmod follows it to the live host file.
        if cp --no-dereference --preserve=links -- "$src" "$dest" 2>/dev/null; then
            DFIR_COPY_COUNT=$((DFIR_COPY_COUNT + 1))
            return 0
        fi
        dfir_log WARN "Symlink copy failed: ${src}"
        return 1
    fi

    if [[ ! -e "$src" ]]; then
        dfir_log INFO "Not present, skipped: ${src}"
        return 1
    fi
    if [[ ! -r "$src" ]]; then
        dfir_log WARN "Not readable, skipped: ${src}"
        return 1
    fi

    local size; size="$(stat -c %s "$src" 2>/dev/null || echo 0)"
    local maxb=$((DFIR_MAX_FILE_MB * 1024 * 1024))
    if [[ -f "$src" && "$size" -gt "$maxb" ]]; then
        dfir_log WARN "Exceeds ${DFIR_MAX_FILE_MB}MB limit, metadata only: ${src}"
        dfir_record_provenance "$src" "(not copied: size limit)" 1
        return 1
    fi

    if [[ "$dest" == */ ]]; then
        mkdir -p "$dest" 2>/dev/null
        dest="${dest}$(basename -- "$src")"
    else
        mkdir -p "$(dirname "$dest")" 2>/dev/null
    fi

    dfir_record_provenance "$src" "$dest"
    if cp --preserve=all --no-dereference -- "$src" "$dest" 2>/dev/null; then
        DFIR_COPY_COUNT=$((DFIR_COPY_COUNT + 1))
        # `cp --preserve=all` as root carries setuid/setgid bits across, so a
        # setuid-root binary pulled from an attacker temp dir would become a
        # live setuid-root file in the evidence tree (and on the analyst box
        # after extraction). Strip s-bits from the COPY only; the original mode
        # is already preserved in the provenance record.
        [[ -f "$dest" && ! -L "$dest" ]] && chmod u-s,g-s -- "$dest" 2>/dev/null
        return 0
    fi
    dfir_log WARN "Copy failed: ${src}"
    return 1
}

dfir_copy_tree() {
    # dfir_copy_tree SOURCE_DIR DEST_DIR [MAX_FILES]
    local src="${1%/}" dest="${2%/}" max="${3:-$DFIR_MAX_TREE_FILES}"
    [[ -d "$src" ]] || { dfir_log INFO "Directory not present, skipped: ${src}"; return 1; }

    mkdir -p "$dest" 2>/dev/null
    local count=0 f rel
    while IFS= read -r -d '' f; do
        if (( count >= max )); then
            dfir_log WARN "Tree copy truncated at ${max} files: ${src}"
            printf 'TRUNCATED: more than %s files under %s\n' "$max" "$src" \
                >"${dest}/_TRUNCATED_.txt"
            break
        fi
        rel="${f#"$src"/}"
        dfir_copy "$f" "${dest}/${rel}" >/dev/null && count=$((count + 1))
        # Include symlinks (-type l): a find -type f pass silently drops the
        # symlinks planted in persistence dirs (e.g. /etc/cron.d/x -> /tmp/evil).
    done < <(find "$src" -xdev \( -type f -o -type l \) -print0 2>/dev/null | sort -z)

    dfir_log INFO "Copied ${count} file(s) from ${src}"
    return 0
}

dfir_list_dir() {
    # dfir_list_dir SOURCE_DIR OUTFILE [FIND_ARGS...]
    local src="$1" out="$2"; shift 2
    [[ -e "$src" ]] || { dfir_log INFO "Directory not present, skipped listing: ${src}"; return 1; }
    dfir_sh "listing ${src}" "$out" \
        "find $(printf '%q' "$src") -xdev $* -printf '%M %n %u %g %10s %TY-%Tm-%TdT%TH:%TM:%TS %p -> %l\n' 2>/dev/null | sort -k7"
    return 0
}

# ---------------------------------------------------------------------------
# Module runner
# ---------------------------------------------------------------------------

dfir_run_module() {
    # dfir_run_module INDEX TOTAL LABEL FUNCTION
    local idx="$1" total="$2" label="$3" fn="$4"
    local c0="$DFIR_CMD_COUNT" f0="$DFIR_CMD_FAILED" s0="$DFIR_CMD_SKIPPED"
    local t0 t1 rc dur

    dfir_banner "[${idx}/${total}] ${label}"
    dfir_log INFO "Module started: ${label}"
    t0="$(date +%s)"

    if ! declare -F "$fn" >/dev/null; then
        dfir_log ERROR "Module function missing: ${fn}"
        dfir_csv_row "$DFIR_RESULTS" "$label" "ERROR" "0" "0" "0" "0" "module function ${fn} not defined"
        return 1
    fi

    # Run the module in a background subshell and wait on it. A non-interactive
    # shell's async children ignore SIGINT, so a Ctrl+C is delivered only to the
    # launcher; its trap terminates this module's process tree (setting
    # DFIR_INTERRUPTED) and `wait` then returns here.
    ( set +e; "$fn" ) </dev/null &
    DFIR_MODULE_PID=$!
    wait "$DFIR_MODULE_PID"
    rc=$?
    if (( ${DFIR_INTERRUPTED:-0} == 1 )); then
        # Reap the terminated tree; ignore the delivery race.
        wait "$DFIR_MODULE_PID" 2>/dev/null
    fi
    DFIR_MODULE_PID=""
    t1="$(date +%s)"
    dur=$((t1 - t0))
    dfir_sync_counters

    local cmds=$((DFIR_CMD_COUNT - c0))
    local fails=$((DFIR_CMD_FAILED - f0))
    local skips=$((DFIR_CMD_SKIPPED - s0))
    local status="OK" msg=""
    if (( ${DFIR_INTERRUPTED:-0} == 1 )); then
        status="INTERRUPTED"
        msg="terminated by operator signal mid-module"
    elif (( rc != 0 && cmds == 0 )); then
        status="ERROR"
    elif (( rc != 0 || fails > 0 )); then
        status="PARTIAL"
    fi

    dfir_csv_row "$DFIR_RESULTS" "$label" "$status" "$cmds" "$skips" "$fails" "$dur" "$msg"
    case "$status" in
        OK)
            dfir_log SUCCESS "Module completed: ${label} (${cmds} artifacts, ${skips} skipped, ${dur}s)" ;;
        INTERRUPTED)
            dfir_log WARN "Module INTERRUPTED: ${label} (${cmds} artifacts before interrupt, ${dur}s)"
            return 2 ;;
        *)
            dfir_log WARN "Module completed with warnings: ${label} (${cmds} artifacts, ${skips} skipped, ${fails} failed, ${dur}s)" ;;
    esac
    return 0
}

# NOTE: dfir_run_module executes modules in a subshell so a fatal error inside
# one module cannot abort the run. Counters are therefore re-read from the flat
# exit-code log rather than from subshell variables.
#
# Exit-code classification:
#   0        artifact captured
#   1        command ran and reported "nothing found" (grep, yara, diff style)
#   127      tool not present on this host - recorded as skipped, not failed
#   141      SIGPIPE from an intentional `| head -n N` truncation
#   anything else counts as a genuine failure
dfir_sync_counters() {
    local counts
    counts="$(awk '{ total++ } $1 == 127 { skipped++ }
                   ($1 != 0 && $1 != 1 && $1 != 127 && $1 != 141) { failed++ }
                   END { printf "%d %d %d", total+0, skipped+0, failed+0 }' \
              "$DFIR_RCLOG" 2>/dev/null)"
    read -r DFIR_CMD_COUNT DFIR_CMD_SKIPPED DFIR_CMD_FAILED <<<"${counts:-0 0 0}"
    return 0
}

# ---------------------------------------------------------------------------
# Finalisation: hashing, manifest, archive
# ---------------------------------------------------------------------------

dfir_generate_hashes() {
    # The dpkg path indexes are derived working files, not evidence: remove them
    # so they are neither hashed nor shipped in the archive.
    rm -f "${DFIR_PKG_INDEX:-}" "${DFIR_PKG_MAP:-}" 2>/dev/null

    local out="${DFIR_DIR[Hashes]}/SHA256SUMS.txt"
    local csv="${DFIR_DIR[Hashes]}/SHA256SUMS.csv"
    dfir_log INFO "Hashing collected evidence"

    # collection.log is still being written (hashing, manifest and archiving all
    # log), so it cannot hash itself; the archive's own SHA256 covers it.
    ( cd "$DFIR_EVID" && find . -type f \
        ! -path './20_Hashes/SHA256SUMS.txt' \
        ! -path './20_Hashes/SHA256SUMS.csv' \
        ! -path './19_CollectionLogs/collection.log' \
        -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum -- ) >"$out" 2>/dev/null

    printf 'Every file in this evidence tree except 19_CollectionLogs/collection.log,\nwhich is still open while these hashes are generated. Verify with:\n    cd <evidence root> && sha256sum -c 20_Hashes/SHA256SUMS.txt\nThe collection log is covered by the SHA256 of the finished archive.\n' \
        >"${DFIR_DIR[Hashes]}/README.txt"

    # Build SHA256SUMS.csv without a per-file double-stat loop: gather size and
    # UTC mtime for the whole tree in one `TZ=UTC find -printf` pass, then join
    # it to the hash list in awk on the relative path. sha256sum is intentionally
    # NOT parallelised into one stream (interleaved lines would corrupt it).
    dfir_csv_row "$csv" "RelativePath" "SHA256" "SizeBytes" "MTimeUTC"
    local metaf="${DFIR_OUTPUT_BASE}/.hash-meta.$$"
    ( cd "$DFIR_EVID" && TZ=UTC find . -type f \
        ! -path './20_Hashes/SHA256SUMS.txt' \
        ! -path './20_Hashes/SHA256SUMS.csv' \
        ! -path './19_CollectionLogs/collection.log' \
        -printf '%p\t%s\t%TY-%Tm-%TdT%TH:%TM:%TSZ\n' ) >"$metaf" 2>/dev/null
    awk -F'\t' '
        function q(s) { gsub(/"/, "\"\"", s); return "\"" s "\"" }
        FNR == NR {
            p = $1; sub(/^\.\//, "", p); size[p] = $2; mt[p] = $3; next
        }
        {
            line = $0; off = 0
            if (substr(line, 1, 1) == "\\") off = 1        # sha256sum escapes odd names
            hash = substr(line, 1 + off, 64)
            fn = substr(line, 64 + off + 3)                 # skip "<hash><sp><mode-char>"
            key = fn; sub(/^\.\//, "", key)
            print q(key) "," q(hash) "," q(size[key]) "," q(mt[key])
        }' "$metaf" "$out" >>"$csv" 2>/dev/null
    rm -f "$metaf"

    local n; n="$(wc -l <"$out" 2>/dev/null || echo 0)"
    dfir_log SUCCESS "SHA256 inventory written for ${n} file(s)"
    return 0
}

dfir_generate_findings() {
    # Build the cross-platform findings report (findings.json + findings.html)
    # at the root of the evidence tree. Called during finalisation BEFORE
    # hashing so both files are covered by the SHA256 inventory. Reuses the same
    # DFIR_MF_* environment as the manifest. Never aborts the run.
    local json_out="${DFIR_EVID}/findings.json"
    local html_out="${DFIR_EVID}/findings.html"
    local status="${DFIR_RUN_STATUS:-completed}"
    local end_iso; end_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local end_epoch; end_epoch="$(date +%s)"

    # Resolve the shared report template: the kit's shared/ copy, else two
    # levels up from this platform directory (standalone layout).
    local template="${DFIR_KIT_ROOT}/shared/report/findings-template.html"
    [[ -f "$template" ]] || template="${DFIR_ROOT}/../../shared/report/findings-template.html"

    dfir_log INFO "Building findings report"

    local t0 t1 rc dur
    t0="$(date +%s.%N)"
    if dfir_have python3 && [[ -f "${DFIR_ROOT}/tools/build-findings.py" ]]; then
        DFIR_MF_CASE="$DFIR_CASE_ID" \
        DFIR_MF_HOST="$DFIR_HOSTNAME" \
        DFIR_MF_VER="$DFIR_VERSION" \
        DFIR_MF_START="$DFIR_START_ISO" \
        DFIR_MF_END="$end_iso" \
        DFIR_MF_DUR="$((end_epoch - DFIR_START_EPOCH))" \
        DFIR_MF_STATUS="$status" \
        DFIR_MF_KIT="${DFIR_KIT_ROOT:-}" \
        python3 "${DFIR_ROOT}/tools/build-findings.py" \
            --evidence "$DFIR_EVID" \
            --template "$template" \
            --json-out "$json_out" \
            --html-out "$html_out" >>"$DFIR_LOGFILE" 2>&1
        rc=$?
    else
        # python3 absent: write a minimal, valid findings.json (schema present,
        # no HTML) so the file still exists and is hashed. Never fail the run.
        dfir_log WARN "python3 unavailable; writing minimal findings.json without HTML report"
        {
            printf '{\n'
            printf '  "schema": "vestigium/findings/1",\n'
            printf '  "tool": "Vestigium",\n'
            printf '  "generated_utc": "%s",\n' "$end_iso"
            printf '  "case_id": "%s",\n' "$DFIR_CASE_ID"
            printf '  "host": { "hostname": "%s", "platform": "linux" },\n' "$DFIR_HOSTNAME"
            printf '  "collection": { "status": "%s", "collector_version": "%s", "evidence_root": "%s" },\n' \
                "$status" "$DFIR_VERSION" "$(basename -- "$DFIR_EVID")"
            printf '  "counts": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0 },\n'
            printf '  "findings": [],\n'
            printf '  "gaps": [],\n'
            printf '  "notes": [ "python3 unavailable; findings limited" ]\n'
            printf '}\n'
        } >"$json_out"
        rc=$?
    fi
    t1="$(date +%s.%N)"
    dur="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')"
    _dfir_record_cmd "findings report" "build-findings.py" "$rc" "$dur" "$json_out"

    if (( rc == 0 )); then
        dfir_log SUCCESS "Findings report written -> ${json_out#"$DFIR_EVID"/}"
    else
        dfir_log WARN "Findings report generation returned ${rc}; continuing"
    fi
    return 0
}

dfir_generate_manifest() {
    local manifest="${DFIR_DIR[Manifest]}/manifest.json"
    local end_epoch; end_epoch="$(date +%s)"
    local files; files="$(find "$DFIR_EVID" -type f 2>/dev/null | wc -l)"
    local bytes; bytes="$(du -sb "$DFIR_EVID" 2>/dev/null | awk '{print $1}')"

    dfir_log INFO "Writing collection manifest"

    # Collection status and (when the Yara module actually ran) the SHA256 of the
    # active rule bundle, so the manifest records what analysis was applied.
    local status="${DFIR_RUN_STATUS:-completed}"
    local rules_sha=""
    if (( ${DFIR_YARA_RAN:-0} == 1 )) && [[ -f "${DFIR_RULES_DIR:-}/active-rules.yar" ]]; then
        rules_sha="$(sha256sum -- "${DFIR_RULES_DIR}/active-rules.yar" 2>/dev/null | awk '{print $1}')"
    fi

    if dfir_have python3; then
        DFIR_MF_EVID="$DFIR_EVID" \
        DFIR_MF_HOST="$DFIR_HOSTNAME" \
        DFIR_MF_START="$DFIR_START_ISO" \
        DFIR_MF_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        DFIR_MF_DUR="$((end_epoch - DFIR_START_EPOCH))" \
        DFIR_MF_VER="$DFIR_VERSION" \
        DFIR_MF_OPER="$DFIR_OPERATOR" \
        DFIR_MF_CASE="$DFIR_CASE_ID" \
        DFIR_MF_FILES="$files" \
        DFIR_MF_BYTES="${bytes:-0}" \
        DFIR_MF_ARGS="$DFIR_INVOCATION" \
        DFIR_MF_STATUS="$status" \
        DFIR_MF_KIT="${DFIR_KIT_ROOT:-}" \
        DFIR_MF_RULES_SHA256="$rules_sha" \
        python3 "${DFIR_ROOT}/tools/make-manifest.py" >"$manifest" 2>>"$DFIR_LOGFILE"
    else
        {
            printf '{\n'
            printf '  "hostname": "%s",\n' "$DFIR_HOSTNAME"
            printf '  "collector_version": "%s",\n' "$DFIR_VERSION"
            printf '  "kit_root": "%s",\n' "${DFIR_KIT_ROOT:-}"
            printf '  "operator": "%s",\n' "$DFIR_OPERATOR"
            printf '  "case_id": "%s",\n' "$DFIR_CASE_ID"
            printf '  "collection_status": "%s",\n' "$status"
            printf '  "collection_start_utc": "%s",\n' "$DFIR_START_ISO"
            printf '  "collection_end_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            printf '  "duration_seconds": %s,\n' "$((end_epoch - DFIR_START_EPOCH))"
            printf '  "file_count": %s,\n' "$files"
            printf '  "total_bytes": %s,\n' "${bytes:-0}"
            printf '  "yara_rules_sha256": "%s",\n' "$rules_sha"
            printf '  "note": "python3 unavailable; reduced manifest"\n'
            printf '}\n'
        } >"$manifest"
    fi

    # Human readable summary alongside the JSON manifest.
    {
        printf 'Vestigium Linux Evidence Collection Summary\n'
        printf '============================================\n\n'
        printf 'Hostname          : %s\n' "$DFIR_HOSTNAME"
        printf 'Case ID           : %s\n' "$DFIR_CASE_ID"
        printf 'Collection status : %s\n' "$status"
        printf 'Credential stores : %s\n' "${DFIR_CREDENTIAL_STORES:-copy}"
        printf 'Operator account  : %s\n' "$DFIR_OPERATOR"
        printf 'Collector version : %s\n' "$DFIR_VERSION"
        printf 'Kit root          : %s\n' "${DFIR_KIT_ROOT:-}"
        printf 'Invocation        : %s\n' "$DFIR_INVOCATION"
        printf 'Start (UTC)       : %s\n' "$DFIR_START_ISO"
        printf 'End (UTC)         : %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'Duration          : %s seconds\n' "$((end_epoch - DFIR_START_EPOCH))"
        printf 'Evidence root     : %s\n' "$DFIR_EVID"
        printf 'Findings report   : %s\n' "${DFIR_EVID}/findings.html"
        printf 'Files collected   : %s\n' "$files"
        printf 'Size              : %s\n' "$(du -sh "$DFIR_EVID" 2>/dev/null | awk '{print $1}')"
        printf '\nProfiles examined\n-----------------\n'
        awk -F'\t' '{printf "  %-24s uid=%-6s home=%s\n", $1, $2, $4}' "$DFIR_USERS_TSV" 2>/dev/null
        printf '\nModule results\n--------------\n'
        awk -F'","' 'NR>1 {gsub(/"/,"",$1); gsub(/"/,"",$2); printf "  %-22s %s\n", $1, $2}' "$DFIR_RESULTS" 2>/dev/null
    } >"${DFIR_DIR[Manifest]}/summary.txt"

    return 0
}

dfir_archive() {
    [[ "${DFIR_NO_ARCHIVE}" == 1 ]] && { dfir_log INFO "Archive step disabled"; return 0; }

    # The evidence tree directory (basename of DFIR_EVID) may carry a _N
    # collision suffix; the archive is named after it. An interrupted run is
    # marked so the truncated archive is never mistaken for a complete one.
    local name; name="$(basename -- "$DFIR_EVID")"
    local suffix=""
    [[ "${DFIR_RUN_STATUS:-completed}" == "interrupted" ]] && suffix="_INCOMPLETE"
    local archive

    # A physical memory image is already compressed, is often several GB, and is
    # normally transferred and analysed on its own. Keep it beside the archive
    # (with its own SHA256) instead of paying to recompress it.
    local -a exclude=(--exclude="${name}/17_Memory/*.avml" --exclude="${name}/17_Memory/*.lime")
    if compgen -G "${DFIR_DIR[Memory]}/*.avml" >/dev/null || compgen -G "${DFIR_DIR[Memory]}/*.lime" >/dev/null; then
        dfir_log INFO "Memory image excluded from the archive; transfer it separately"
        printf 'The memory image for this collection is stored outside the archive:\n%s\n' \
            "$(ls -1 "${DFIR_DIR[Memory]}"/*.avml "${DFIR_DIR[Memory]}"/*.lime 2>/dev/null)" \
            >"${DFIR_OUTPUT_BASE}/${name}.memory-image-location.txt"
    fi

    dfir_log INFO "Creating evidence archive"
    if dfir_have zstd; then
        archive="${DFIR_OUTPUT_BASE}/${name}${suffix}.tar.zst"
        tar -C "$DFIR_OUTPUT_BASE" "${exclude[@]}" -I 'zstd -T0 -6' -cf "$archive" "$name" 2>>"$DFIR_LOGFILE" \
            || { dfir_log WARN "zstd archive failed, falling back to gzip"; archive=""; }
    fi
    if [[ -z "${archive:-}" || ! -f "${archive:-/nonexistent}" ]]; then
        archive="${DFIR_OUTPUT_BASE}/${name}${suffix}.tar.gz"
        tar -C "$DFIR_OUTPUT_BASE" "${exclude[@]}" -czf "$archive" "$name" 2>>"$DFIR_LOGFILE" \
            || { dfir_log ERROR "Archive creation failed"; return 1; }
    fi

    sha256sum -- "$archive" >"${archive}.sha256" 2>/dev/null
    chmod 600 "$archive" "${archive}.sha256" 2>/dev/null
    # Consumed by the launcher (which sources this file) for the final summary.
    # shellcheck disable=SC2034
    DFIR_ARCHIVE="$archive"
    dfir_log SUCCESS "Archive: ${archive} ($(du -sh "$archive" 2>/dev/null | awk '{print $1}'))"
    return 0
}
