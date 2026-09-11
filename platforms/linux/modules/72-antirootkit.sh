#!/usr/bin/env bash
# 72-antirootkit.sh - Host-vs-kernel cross-checks (12_Security/antirootkit).
#
# A userland rootkit hides processes, kernel modules, listening ports and files
# by trojaning ps/ss/lsmod/ls or hooking libc's readdir. This module does not
# trust those tools: it reads the kernel's own view from /proc and /sys with
# plain bash, then diffs it against what the host utilities report. Where a
# staged static busybox is available (prepared by setup, forced in
# --trusted-tools mode) it is used as an independent third opinion. A file the
# kernel knows about but a host tool denies is a strong compromise indicator.
#
# Every discrepancy is written to discrepancies.txt with a stable prefix that
# the findings report keys on:
#   HIDDEN-PROC <pid> ...        process in /proc but hidden from ps
#   HIDDEN-MODULE <name> ...     module in /sys/module but hidden from lsmod
#   HIDDEN-PORT <proto/port> ... listening port in /proc/net but not in ss/netstat
#   DIR-NLINK-MISMATCH <dir> ... directory link count exceeds visible sub-dirs
#   HIDDEN-DIR-ENTRY <dir> ...   ls/busybox/glob disagree on a directory's entries

dfir_module_antirootkit() {
    local d="${DFIR_DIR[Security]}/antirootkit"
    mkdir -p "$d"
    local disc="${d}/discrepancies.txt"
    : >"$disc"

    local bb ps_bin ss_bin ls_bin netstat_bin
    bb="$(dfir_tool busybox 2>/dev/null || true)"
    ps_bin="$(command -v ps 2>/dev/null || true)"
    ss_bin="$(command -v ss 2>/dev/null || true)"
    ls_bin="$(command -v ls 2>/dev/null || true)"
    netstat_bin="$(dfir_tool netstat 2>/dev/null || true)"

    {
        printf 'ANTI-ROOTKIT CROSS-CHECKS\n=========================\n'
        printf 'Generated %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'Method  : the kernel view (/proc, /sys) is read with bash and\n'
        printf '          compared against the host utilities. A "second opinion"\n'
        printf '          from the kit static busybox is used when available.\n'
        printf 'Tools   : ps=%s\n          ss=%s\n          ls=%s\n          netstat=%s\n          busybox=%s\n' \
            "${ps_bin:-(none)}" "${ss_bin:-(none)}" "${ls_bin:-(none)}" \
            "${netstat_bin:-(none)}" "${bb:-(not staged; /proc-only checks)}"
        printf 'Trusted-tools mode: %s\n\n' "$([[ "${DFIR_TRUSTED_TOOLS:-0}" == 1 ]] && echo on || echo off)"
    } >"${d}/SUMMARY.txt"

    _dfir_ar_processes "$d" "$disc" "$ps_bin" "$bb"
    _dfir_ar_modules   "$d" "$disc"
    _dfir_ar_ports     "$d" "$disc" "$ss_bin" "$netstat_bin"
    _dfir_ar_dirs      "$d" "$disc" "$ls_bin" "$bb"

    # Roll the machine-readable verdict into the human summary.
    {
        printf '\n--- discrepancy summary ---\n'
        if [[ -s "$disc" ]]; then
            local prefix
            for prefix in HIDDEN-PROC HIDDEN-MODULE HIDDEN-PORT DIR-NLINK-MISMATCH HIDDEN-DIR-ENTRY; do
                printf '  %-20s %s\n' "$prefix" "$(grep -c "^${prefix} " "$disc" 2>/dev/null)"
            done
            printf '\nReview each entry in discrepancies.txt against the raw host.\n'
            printf 'A confirmed hidden process, module or port is a strong sign of a\n'
            printf 'kernel or userland rootkit; some entries have benign causes\n'
            printf '(a process that exited mid-scan, an unusual filesystem). Confirm.\n'
        else
            printf '  No host-vs-kernel discrepancies detected.\n'
            printf '  (Absence of evidence is not proof of a clean host; a rootkit that\n'
            printf '   hides consistently from both /proc and the tools would not show here.)\n'
        fi
    } >>"${d}/SUMMARY.txt"
    _dfir_record_cmd "anti-rootkit summary" "proc/sys vs ps/ss/lsmod/ls" "0" "0" "${d}/SUMMARY.txt"
    _dfir_record_cmd "anti-rootkit discrepancies" "host-vs-kernel diff" \
        "$([[ -s "$disc" ]] && echo 1 || echo 0)" "0" "$disc"
    return 0
}

# ---------------------------------------------------------------------------
# Hidden processes: PIDs the kernel exposes in /proc that ps denies.
# ---------------------------------------------------------------------------
_dfir_ar_processes() {
    local d="$1" disc="$2" ps_bin="$3" bb="$4"
    local out="${d}/processes_proc_vs_ps.txt"
    local p pid

    # Kernel truth: readdir of /proc via a bash glob.
    local -A in_proc=()
    for p in /proc/[0-9]*; do
        pid="${p#/proc/}"
        [[ -d "$p" ]] && in_proc["$pid"]=1
    done

    # Host ps and (independently) busybox ps.
    local -A in_ps=() in_bb=()
    if [[ -n "$ps_bin" ]]; then
        while read -r pid; do [[ "$pid" =~ ^[0-9]+$ ]] && in_ps["$pid"]=1; done \
            < <("$ps_bin" -e -o pid= 2>/dev/null)
    fi
    if [[ -n "$bb" ]]; then
        # busybox ps columns: PID USER ... ; take the first numeric field.
        while read -r pid _; do [[ "$pid" =~ ^[0-9]+$ ]] && in_bb["$pid"]=1; done \
            < <("$bb" ps 2>/dev/null)
    fi

    {
        printf 'HIDDEN PROCESS CHECK\n====================\n'
        printf 'PIDs in /proc: %s   ps: %s   busybox ps: %s\n\n' \
            "${#in_proc[@]}" "$([[ -n "$ps_bin" ]] && echo "${#in_ps[@]}" || echo n/a)" \
            "$([[ -n "$bb" ]] && echo "${#in_bb[@]}" || echo n/a)"

        local hidden=0
        if [[ -n "$ps_bin" ]]; then
            for pid in "${!in_proc[@]}"; do
                [[ -n "${in_ps[$pid]:-}" ]] && continue
                # Re-verify directly to rule out a process that exited mid-scan:
                # it must still be live in /proc AND still denied by a direct
                # `ps -p` query before we call it hidden.
                [[ -r "/proc/${pid}/status" ]] || continue
                "$ps_bin" -p "$pid" -o pid= >/dev/null 2>&1 && continue
                hidden=1
                local comm exe
                comm="$(tr -d '\0' <"/proc/${pid}/comm" 2>/dev/null)"
                exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null)"
                printf 'HIDDEN-PROC %s comm=%s exe=%s\n' "$pid" "${comm:-?}" "${exe:-?}" | tee -a "$disc"
            done
        fi
        # busybox disagreeing with the host ps is itself suspicious.
        if [[ -n "$bb" && -n "$ps_bin" ]]; then
            for pid in "${!in_bb[@]}"; do
                [[ -n "${in_ps[$pid]:-}" || -z "${in_proc[$pid]:-}" ]] && continue
                printf 'HIDDEN-PROC %s (busybox ps sees it, host ps does not)\n' "$pid" | tee -a "$disc"
                hidden=1
            done
        fi
        (( hidden == 0 )) && printf 'No processes hidden from ps.\n'
    } >"$out"
    _dfir_record_cmd "hidden process check" "/proc vs ps" "0" "0" "$out"
}

# ---------------------------------------------------------------------------
# Hidden kernel modules: loaded modules in /sys/module absent from lsmod.
# ---------------------------------------------------------------------------
_dfir_ar_modules() {
    local d="$1" disc="$2"
    local out="${d}/modules_sys_vs_lsmod.txt"
    local m name

    # Kernel truth: /sys/module/<m> with an initstate file is a loadable module
    # that is (or was) inserted; built-in modules have no initstate. /proc/modules
    # is the same list the honest lsmod reads.
    local -A in_sys=() in_procmod=() in_lsmod=()
    for m in /sys/module/*; do
        [[ -d "$m" ]] || continue
        [[ -f "${m}/initstate" ]] || continue          # skip built-ins
        name="${m#/sys/module/}"
        in_sys["$name"]=1
    done
    while read -r name _; do
        [[ -n "$name" ]] && in_procmod["$name"]=1
    done <"/proc/modules"
    local lsmod_bin; lsmod_bin="$(command -v lsmod 2>/dev/null || true)"
    if [[ -n "$lsmod_bin" ]]; then
        while read -r name _; do
            [[ "$name" == "Module" ]] && continue
            [[ -n "$name" ]] && in_lsmod["$name"]=1
        done < <("$lsmod_bin" 2>/dev/null)
    fi
    # Third, independent kernel source: symbols in /proc/kallsyms carry a
    # trailing "[module]" tag. A module that unlinked itself from the module
    # list (the classic list_del rootkit trick) vanishes from /proc/modules and
    # lsmod but its symbols stay tagged here. kptr_restrict only zeroes the
    # addresses, not the names.
    local -A in_ksyms=()
    if [[ -r /proc/kallsyms ]]; then
        while read -r name; do
            [[ -n "$name" ]] && in_ksyms["$name"]=1
        done < <(awk '$NF ~ /^\[.*\]$/ { print substr($NF, 2, length($NF) - 2) }' /proc/kallsyms 2>/dev/null | sort -u)
    fi

    {
        printf 'HIDDEN KERNEL MODULE CHECK\n==========================\n'
        printf '/sys/module (loadable): %s   /proc/modules: %s   lsmod: %s   kallsyms-tagged: %s\n\n' \
            "${#in_sys[@]}" "${#in_procmod[@]}" \
            "$([[ -n "$lsmod_bin" ]] && echo "${#in_lsmod[@]}" || echo n/a)" "${#in_ksyms[@]}"
        local hidden=0
        # kallsyms carries a trailing "[tag]" on many symbols. Some tags are
        # built-in subsystems (bpf, ...), not loadable modules, so a tag absent
        # from /proc/modules and /sys/module is NOT reliably a hidden module -
        # record these as review context, but do not flag them.
        local ksonly=()
        for name in "${!in_ksyms[@]}"; do
            [[ -n "${in_procmod[$name]:-}" || -n "${in_sys[$name]:-}" ]] && continue
            ksonly+=("$name")
        done
        if ((${#ksonly[@]} > 0)); then
            printf '\nkallsyms tags with no /proc/modules or /sys/module entry (usually built-in\nsubsystems such as bpf; review, not auto-flagged): %s\n' \
                "$(printf '%s ' "${ksonly[@]}")"
        fi
        for name in "${!in_sys[@]}"; do
            # "live" loadable module the kernel exposes...
            local state; state="$(cat "/sys/module/${name}/initstate" 2>/dev/null)"
            [[ "$state" == "live" ]] || continue
            if [[ -z "${in_procmod[$name]:-}" ]]; then
                printf 'HIDDEN-MODULE %s (in /sys/module, absent from /proc/modules)\n' "$name" | tee -a "$disc"
                hidden=1
            elif [[ -n "$lsmod_bin" && -z "${in_lsmod[$name]:-}" ]]; then
                printf 'HIDDEN-MODULE %s (in /proc/modules, absent from lsmod output)\n' "$name" | tee -a "$disc"
                hidden=1
            fi
        done
        (( hidden == 0 )) && printf 'No kernel modules hidden from lsmod.\n'
    } >"$out"
    _dfir_record_cmd "hidden module check" "/sys/module vs /proc/modules vs lsmod" "0" "0" "$out"
}

# ---------------------------------------------------------------------------
# Hidden listening ports: kernel /proc/net sockets absent from ss and netstat.
# ---------------------------------------------------------------------------
_dfir_ar_ports() {
    local d="$1" disc="$2" ss_bin="$3" netstat_bin="$4"
    local out="${d}/ports_procnet_vs_tools.txt"

    # Kernel truth from /proc/net. TCP listeners have state 0A; UDP sockets are
    # reported as bound local ports. Column 2 is LOCAL_ADDR "HEXIP:HEXPORT".
    # awk extracts the proto and the hex port (no gawk-only strtonum, so this is
    # mawk-safe); bash converts the hex port to decimal.
    local kernel_set f proto hexport
    kernel_set="$(
        {
            for f in tcp tcp6; do
                [[ -r "/proc/net/${f}" ]] || continue
                awk 'NR>1 && $4=="0A" { n=split($2,a,":"); print "tcp " a[n] }' "/proc/net/${f}" 2>/dev/null
            done
            for f in udp udp6; do
                [[ -r "/proc/net/${f}" ]] || continue
                awk 'NR>1 { n=split($2,a,":"); print "udp " a[n] }' "/proc/net/${f}" 2>/dev/null
            done
        } | while read -r proto hexport; do
            printf '%s/%d\n' "$proto" "$((16#$hexport))" 2>/dev/null
        done
    )"
    kernel_set="$(printf '%s\n' "$kernel_set" | sort -u | grep -vE '/0$' || true)"

    # Tool view: the UNION of ss and netstat listening/bound ports. A port is
    # only "hidden" when neither tool shows it, which removes single-tool quirks.
    local tool_set=""
    [[ -n "$ss_bin" ]] && tool_set+="$("$ss_bin" -H -tuln 2>/dev/null | awk '{n=split($5,a,":"); netid=$1; sub(/6$/,"",netid); print netid "/" a[n]}')"$'\n'
    [[ -n "$netstat_bin" ]] && tool_set+="$("$netstat_bin" -tuln 2>/dev/null | awk '/^tcp|^udp/ {proto=$1; sub(/6$/,"",proto); n=split($4,a,":"); print proto "/" a[n]}')"$'\n'
    tool_set="$(printf '%s\n' "$tool_set" | sort -u | grep -E '^(tcp|udp)/[0-9]+$' || true)"

    {
        printf 'HIDDEN LISTENING PORT CHECK\n===========================\n'
        printf 'Kernel /proc/net listeners: %s   tool-visible (ss union netstat): %s\n\n' \
            "$(printf '%s\n' "$kernel_set" | grep -c . )" "$(printf '%s\n' "$tool_set" | grep -c . )"
        if [[ -z "$ss_bin" && -z "$netstat_bin" ]]; then
            printf 'Neither ss nor netstat is available; cannot cross-check.\n'
        else
            local hidden=0 entry
            while IFS= read -r entry; do
                [[ -z "$entry" ]] && continue
                if ! grep -qxF "$entry" <<<"$tool_set"; then
                    printf 'HIDDEN-PORT %s (in /proc/net, not shown by ss/netstat)\n' "$entry" | tee -a "$disc"
                    hidden=1
                fi
            done <<<"$kernel_set"
            (( hidden == 0 )) && printf 'No listening ports hidden from ss/netstat.\n'
        fi
    } >"$out"
    _dfir_record_cmd "hidden port check" "/proc/net vs ss/netstat" "0" "0" "$out"
}

# ---------------------------------------------------------------------------
# Hidden files: directory link-count and readdir cross-checks.
# ---------------------------------------------------------------------------
_dfir_ar_dirs() {
    local d="$1" disc="$2" ls_bin="$3" bb="$4"
    local out="${d}/dirs_link_and_readdir.txt"
    local dir

    local -a raw_dirs=(/ /etc /tmp /var/tmp /dev/shm /root /bin /sbin /usr/bin /usr/sbin /usr/local/bin)
    dir="/lib/modules/$(uname -r 2>/dev/null)"; [[ -d "$dir" ]] && raw_dirs+=("$dir")
    # Home directories of the profiles under investigation.
    local row home
    for row in "${DFIR_USER_ROWS[@]}"; do
        IFS=$'\t' read -r _ _ _ home _ <<<"$row"
        [[ -d "$home" ]] && raw_dirs+=("$home")
    done
    # Deduplicate (root's home is also in the base list) by canonical path.
    local -a dirs=()
    local -A seen_dir=()
    local rp
    for dir in "${raw_dirs[@]}"; do
        rp="$(readlink -f -- "$dir" 2>/dev/null || printf '%s' "$dir")"
        [[ -n "${seen_dir[$rp]:-}" ]] && continue
        seen_dir["$rp"]=1
        dirs+=("$dir")
    done

    {
        printf 'HIDDEN FILE / DIRECTORY CHECK\n=============================\n'
        printf 'Two independent checks per directory:\n'
        printf '  1. st_nlink vs the number of sub-directories readdir returns\n'
        printf '     (a hidden sub-directory leaves nlink too high). Skipped on\n'
        printf '     filesystems that do not track directory link counts.\n'
        printf '  2. entry count from ls, busybox ls and a bash glob; any\n'
        printf '     disagreement means a tool is filtering readdir.\n\n'

        local checked=0
        for dir in "${dirs[@]}"; do
            [[ -d "$dir" && -r "$dir" ]] || continue
            (( checked++ ))
            local nlink fstype
            nlink="$(stat -c %h "$dir" 2>/dev/null)"
            fstype="$(stat -f -c %T "$dir" 2>/dev/null)"

            # Check 1: nlink vs visible sub-directories (only when the fs tracks
            # directory link counts, i.e. nlink >= 2; btrfs reports 1).
            if [[ "$nlink" =~ ^[0-9]+$ ]] && (( nlink >= 2 )); then
                local subdirs=0 e
                shopt -s nullglob
                for e in "$dir"/*/ "$dir"/.*/; do
                    e="${e%/}"
                    [[ "$e" == "$dir/." || "$e" == "$dir/.." ]] && continue
                    [[ -d "$e" && ! -L "$e" ]] && (( subdirs++ ))
                done
                shopt -u nullglob
                local expected=$(( subdirs + 2 ))
                if (( nlink > expected )); then
                    printf 'DIR-NLINK-MISMATCH %s nlink=%s visible_subdirs=%s expected=%s fs=%s\n' \
                        "$dir" "$nlink" "$subdirs" "$expected" "${fstype:-?}" | tee -a "$disc"
                else
                    printf 'ok   %-28s nlink=%s subdirs=%s (fs=%s)\n' "$dir" "$nlink" "$subdirs" "${fstype:-?}"
                fi
            else
                printf 'skip %-28s nlink=%s (fs=%s does not track dir links)\n' "$dir" "${nlink:-?}" "${fstype:-?}"
            fi

            # Check 2: readdir entry-count divergence across ls / busybox / glob.
            local n_ls="" n_bb="" n_glob=0
            [[ -n "$ls_bin" ]] && n_ls="$("$ls_bin" -A1 -- "$dir" 2>/dev/null | grep -c .)"
            [[ -n "$bb" ]] && n_bb="$("$bb" ls -A1 -- "$dir" 2>/dev/null | grep -c .)"
            shopt -s nullglob
            local g
            for g in "$dir"/* "$dir"/.*; do
                g="${g##*/}"
                [[ "$g" == "." || "$g" == ".." ]] && continue
                (( n_glob++ ))
            done
            shopt -u nullglob
            # Compare only the counts that are available; disagreement is the flag.
            local counts=() label
            [[ -n "$n_ls" ]] && counts+=("ls=$n_ls")
            [[ -n "$n_bb" ]] && counts+=("busybox=$n_bb")
            counts+=("glob=$n_glob")
            if { [[ -n "$n_ls" ]] && (( n_ls != n_glob )); } || \
               { [[ -n "$n_bb" ]] && (( n_bb != n_glob )); } || \
               { [[ -n "$n_ls" && -n "$n_bb" ]] && (( n_ls != n_bb )); }; then
                label="${counts[*]}"
                printf 'HIDDEN-DIR-ENTRY %s %s\n' "$dir" "$label" | tee -a "$disc"
            fi
        done
        (( checked == 0 )) && printf '(no readable directories to check)\n'
    } >"$out"
    _dfir_record_cmd "hidden file check" "dir nlink + ls/busybox/glob readdir" "0" "0" "$out"
}
