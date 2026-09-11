#!/usr/bin/env bash
# 95-yara.sh - YARA scanning of disk targets and process memory (18_Yara).

dfir_module_yara() {
    local d="${DFIR_DIR[Yara]}"

    if [[ "$DFIR_SKIP_YARA" == 1 ]]; then
        dfir_log WARN "YARA scanning skipped (--skip-yara)"
        printf 'YARA scanning was skipped by operator request (--skip-yara).\n' >"${d}/SKIPPED.txt"
        return 0
    fi

    local yara; yara="$(dfir_tool yara 2>/dev/null)"
    if [[ -z "$yara" ]]; then
        dfir_log WARN "YARA skipped: the yara binary is not available. Run ./vestigium.sh setup."
        printf 'YARA binary not available on this host.\nRun sudo ./vestigium.sh setup (from the kit root) to stage it.\n' \
            >"${d}/SKIPPED.txt"
        return 0
    fi

    local rules_dir="${DFIR_RULES_DIR:-${DFIR_KIT_ROOT:-${DFIR_ROOT}/../..}/shared/yara-rules}"
    local rules="${rules_dir}/active-rules.yar"
    if [[ ! -f "$rules" ]]; then
        dfir_log WARN "YARA skipped: ${rules} not found. Run ./vestigium.sh setup."
        printf 'Rule bundle not found at %s.\nRun sudo ./vestigium.sh setup (from the kit root) to build it.\n' \
            "$rules" >"${d}/SKIPPED.txt"
        return 0
    fi

    # Compiled bundles are specific to the libyara version that wrote them, and
    # the kit wrapper prefers the host's own yara. A bundle that fails to load
    # makes every scan error out and silently yield nothing, so probe it on a
    # tiny file first and use it only when it loads AND is newer than the
    # source bundle; otherwise scan with the source bundle.
    local compiled="${rules_dir}/active-rules.compiled"
    local -a rule_arg=("$rules")
    local rule_form="source bundle (compiled per scan)"
    if [[ -f "$compiled" ]]; then
        local probe="${d}/.yara-probe" perr="${d}/.yara-probe.err"
        printf 'Vestigium YARA load probe\n' >"$probe"
        if [[ ! "$compiled" -nt "$rules" ]]; then
            dfir_log WARN "YARA: active-rules.compiled is not newer than active-rules.yar (stale); using the source bundle"
        elif ! timeout 300 "$yara" -C "$compiled" "$probe" >/dev/null 2>"$perr"; then
            dfir_log WARN "YARA: active-rules.compiled does not load with ${yara} ($("$yara" --version 2>/dev/null): $(head -c 200 "$perr" 2>/dev/null | tr '\n' ' ')); using the source bundle"
        else
            rule_arg=(-C "$compiled")
            rule_form="pre-compiled bundle ${compiled}"
            dfir_log INFO "Using pre-compiled rule bundle"
        fi
        rm -f "$probe" "$perr"
    fi

    local threads="${DFIR_YARA_THREADS:-2}"
    [[ "$threads" =~ ^[1-9][0-9]*$ ]] || threads=2

    # Never scan our own output or tooling. The kit carries ~20 MB of rule
    # sources, IOC lists and packages that would match thousands of rules.
    local kit="" outbase="" x
    [[ -n "${DFIR_KIT_ROOT:-}" && -d "$DFIR_KIT_ROOT" ]] && kit="$(readlink -f -- "$DFIR_KIT_ROOT")"
    [[ -n "${DFIR_OUTPUT_BASE:-}" && -d "$DFIR_OUTPUT_BASE" ]] && outbase="$(readlink -f -- "$DFIR_OUTPUT_BASE")"
    local -a prune=(-path /proc -o -path /sys)
    for x in "$DFIR_EVID" "$outbase" "$kit"; do
        [[ -n "$x" ]] && prune+=(-o -path "$x")
    done

    _dfir_yara_targets
    local results="${d}/yara_matches.txt"
    local mode; mode="$([[ "$DFIR_YARA_QUICK" == 1 ]] && echo quick || echo full)"

    local target kit_in=""
    if [[ -n "$kit" ]]; then
        while IFS= read -r target; do
            [[ -n "$target" && "${kit}/" == "${target%/}/"* ]] && kit_in+="${kit_in:+, }${target}"
        done <"${d}/_scan_targets.txt"
        [[ -n "$kit_in" ]] && dfir_log WARN "YARA: the Vestigium kit (${kit}) lies inside scan target ${kit_in}; it is excluded from the scan. Run the kit from removable media to avoid this."
    fi

    # Header lines added after v1 start with "#" so match counters that look
    # for "<rule> <path>" lines do not count them.
    {
        printf 'YARA SCAN\n=========\n'
        printf 'Started (UTC) : %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'Mode          : %s\n' "$mode"
        printf 'Rules         : %s\n' "$rules"
        printf 'Rule count    : %s\n' "$(grep -cE '^[[:space:]]*((private|global)[[:space:]]+)*rule[[:space:]]+[A-Za-z_]' "$rules" 2>/dev/null)"
        printf 'Binary        : %s (%s)\n' "$yara" "$("$yara" --version 2>/dev/null)"
        printf 'Per-target timeout: %ss\n' "$DFIR_YARA_TIMEOUT"
        printf '# Rule form   : %s\n' "$rule_form"
        printf '# Threads     : %s\n' "$threads"
        printf '# Excluded    : /proc /sys, evidence output %s, Vestigium kit %s\n' \
            "${outbase:-$DFIR_EVID}" "${kit:-(unknown)}"
        [[ -n "$kit_in" ]] && \
            printf '# NOTE        : the Vestigium kit lies inside scan target %s; its files were NOT scanned.\n' "$kit_in"
        printf '\n'
    } >"$results"

    local hits=0 filelist="${d}/_scan_filelist.txt"
    while IFS= read -r target; do
        [[ -z "$target" || ! -e "$target" ]] && continue

        # Build an explicit file list so the evidence tree, the kit, pseudo
        # filesystems and oversized files are never scanned.
        find "$target" -xdev \( "${prune[@]}" \) -prune -o \
            -type f -size -"${DFIR_MAX_FILE_MB}"M -print >"$filelist" 2>/dev/null

        local file_count; file_count="$(wc -l <"$filelist" 2>/dev/null || echo 0)"
        if (( file_count == 0 )); then
            dfir_log INFO "YARA: nothing to scan under ${target}"
            printf '\n===== TARGET: %s ===== (no eligible files)\n' "$target" >>"$results"
            continue
        fi

        dfir_log INFO "YARA scanning ${target} (${file_count} files)"
        printf '\n===== TARGET: %s (%s files) =====\n' "$target" "$file_count" >>"$results"
        # Low priority so a live host stays usable during collection.
        nice -n 19 ionice -c3 timeout --kill-after=30 "$DFIR_YARA_TIMEOUT" \
            "$yara" "${rule_arg[@]}" \
            --scan-list --no-warnings --fast-scan --no-follow-symlinks \
            --threads="$threads" \
            --timeout=120 --print-tags \
            "$filelist" >>"$results" 2>>"${d}/yara_errors.txt"
        local rc=$?
        case $rc in
            0) printf '(scan completed)\n' >>"$results" ;;
            124|137) printf '(TIMED OUT after %ss - target not fully scanned)\n' "$DFIR_YARA_TIMEOUT" >>"$results"
                     dfir_log WARN "YARA timed out on ${target}" ;;
            *) printf '(yara exit code %s)\n' "$rc" >>"$results" ;;
        esac
    done <"${d}/_scan_targets.txt"

    # --- Process memory scanning ------------------------------------------
    # Opt-in only: scanning every process address space with the full rule set
    # can take longer than the rest of the collection combined.
    if [[ "$DFIR_YARA_PROCS" == 1 ]]; then
        local pres="${d}/yara_process_matches.txt"
        printf 'YARA PROCESS MEMORY SCAN\n========================\nStarted %s\n\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$pres"
        [[ "${rule_arg[0]}" == "-C" ]] || \
            dfir_log WARN "YARA process scan uses the source bundle: rules are recompiled for every process (slow)"
        local pid cmd scanned=0
        local max_procs="${DFIR_YARA_MAX_PROCS:-200}"
        for pid in $(ps -eo pid= --sort=pid 2>/dev/null); do
            [[ -d "/proc/${pid}" ]] || continue
            if (( scanned >= max_procs )); then
                dfir_log WARN "YARA process scan stopped at ${max_procs} processes"
                printf '\nSTOPPED: only the first %s processes were scanned.\n' "$max_procs" >>"$pres"
                break
            fi
            # Kernel threads have no address space to scan.
            [[ -z "$(tr -d '\0' <"/proc/${pid}/cmdline" 2>/dev/null)" ]] && continue
            cmd="$(tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null | cut -c1-120)"
            local out
            out="$(nice -n 19 timeout 60 "$yara" "${rule_arg[@]}" --no-warnings --fast-scan \
                    "$pid" 2>/dev/null)"
            scanned=$((scanned + 1))
            if [[ -n "$out" ]]; then
                printf '=== PID %s: %s ===\n%s\n\n' "$pid" "$cmd" "$out" >>"$pres"
                hits=$((hits + 1))
            fi
        done
        printf '\nProcesses scanned: %s\nProcesses with matches: %s\n' "$scanned" "$hits" >>"$pres"
        _dfir_record_cmd "yara process memory scan" "yara <pid> for all user processes" "0" "0" "$pres"
    fi

    _dfir_record_cmd "yara disk scan" "yara ${mode} scan" "0" "0" "$results"
    rm -f "${d}/_scan_targets.txt" "${d}/_scan_filelist.txt"

    # --- Match summary -----------------------------------------------------
    {
        printf 'YARA MATCH SUMMARY\n==================\n\n'
        printf 'Mode: %s\n\n' "$mode"
        printf -- '--- rules that fired (file scan) ---\n'
        grep -vE '^(#|=====|\(|YARA|Started|Mode|Rules|Rule count|Binary|Per-target|$)' "$results" 2>/dev/null |
            awk '{print $1}' | sort | uniq -c | sort -rn | head -n 100
        printf -- '\n--- matched paths ---\n'
        grep -vE '^(#|=====|\(|YARA|Started|Mode|Rules|Rule count|Binary|Per-target|$)' "$results" 2>/dev/null |
            head -n 500
        if [[ -f "${d}/yara_process_matches.txt" ]]; then
            printf -- '\n--- process memory matches ---\n'
            grep '^=== PID' "${d}/yara_process_matches.txt" 2>/dev/null | head -n 100
        fi
        printf -- '\nNote: YARA hits are leads, not verdicts. Signature-base rules are\n'
        printf 'broad by design and generate false positives on packers, installers\n'
        printf 'and administrative tooling. Triage each hit against the file itself.\n'
    } | dfir_capture "yara summary" "${d}/SUMMARY.txt"

    return 0
}

# ---------------------------------------------------------------------------
_dfir_yara_targets() {
    local out="${DFIR_DIR[Yara]}/_scan_targets.txt"
    local -a raw=() canon=() keep=()
    local row home t k nested

    if [[ "$DFIR_YARA_QUICK" == 1 ]]; then
        # High-signal ingress and staging paths only.
        for row in "${DFIR_USER_ROWS[@]}"; do
            IFS=$'\t' read -r _ _ _ home _ <<<"$row"
            raw+=("${home}/Downloads" "${home}/Desktop" "${home}/.cache/thumbnails" \
                  "${home}/.local/share/Trash")
        done
        raw+=(/tmp /var/tmp /dev/shm)
    else
        for row in "${DFIR_USER_ROWS[@]}"; do
            IFS=$'\t' read -r _ _ _ home _ <<<"$row"
            raw+=("$home")
        done
        raw+=(/tmp /var/tmp /dev/shm /opt /usr/local /srv /var/www /etc /var/spool /root)
    fi

    # Canonicalise (find does not descend a symlinked start point, and
    # /run/shm vs /dev/shm would otherwise be scanned twice), deduplicate, then
    # drop paths nested inside an already-listed parent. In C collation a
    # parent always sorts before its children, so one ordered pass suffices.
    for t in "${raw[@]}"; do
        [[ -e "$t" ]] && canon+=("$(readlink -f -- "$t")")
    done
    ((${#canon[@]} > 0)) && mapfile -t canon < <(printf '%s\n' "${canon[@]}" | LC_ALL=C sort -u)
    for t in "${canon[@]}"; do
        [[ -z "$t" ]] && continue
        nested=0
        for k in "${keep[@]}"; do
            [[ "$t" == "$k" || "$t" == "${k%/}/"* ]] && { nested=1; break; }
        done
        (( nested )) || keep+=("$t")
    done
    : >"$out"
    ((${#keep[@]} > 0)) && printf '%s\n' "${keep[@]}" >"$out"
    return 0
}
