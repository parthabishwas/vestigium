#!/usr/bin/env bash
# 93-memory.sh - Volatile memory artifacts and optional full memory image
# (17_Memory).

dfir_module_memory() {
    local d="${DFIR_DIR[Memory]}"

    # --- Always: lightweight volatile state -------------------------------
    dfir_cmd "memory summary"   "${d}/meminfo.txt"      cat /proc/meminfo
    dfir_cmd "slab allocator"   "${d}/slabinfo.txt"     cat /proc/slabinfo
    dfir_cmd "vmstat"           "${d}/vmstat.txt"       vmstat -s
    dfir_cmd "memory map ranges" "${d}/iomem.txt"       cat /proc/iomem
    dfir_cmd "swap usage"       "${d}/swaps.txt"        cat /proc/swaps
    dfir_sh  "per-process memory" "${d}/process_memory.txt" \
        "ps -eo pid,ppid,user,rss,vsz,pmem,comm,args --sort=-rss | head -n 200"

    dfir_sh "kernel symbol exposure" "${d}/kallsyms_state.txt" '
        printf "kptr_restrict = %s\n" "$(sysctl -n kernel.kptr_restrict 2>/dev/null)"
        printf "First 20 kernel symbols (all-zero addresses mean symbols are restricted):\n"
        head -n 20 /proc/kallsyms 2>/dev/null
        exit 0'

    # Syscall table / kernel hooking indicators available without a full dump.
    dfir_sh "kernel integrity indicators" "${d}/kernel_integrity.txt" '
        printf -- "--- kernel taint flags ---\n"
        t=$(cat /proc/sys/kernel/tainted 2>/dev/null)
        printf "tainted=%s\n" "$t"
        for bit in "0:proprietary module" "1:force-loaded module" "2:SMP with non-SMP kernel" \
                   "3:force unloaded module" "4:machine check" "5:bad page" "6:user forced taint" \
                   "7:module from unsupported kernel" "9:out-of-tree module" "10:unsigned module" \
                   "11:soft lockup" "12:live patch" "13:auxiliary taint" "14:struct randomisation"; do
            n=${bit%%:*}; label=${bit#*:}
            if [ -n "$t" ] && [ $(( t >> n & 1 )) -eq 1 ]; then printf "  bit %-3s SET: %s\n" "$n" "$label"; fi
        done
        printf -- "\n--- loaded modules with no backing file ---\n"
        lsmod 2>/dev/null | tail -n +2 | awk "{print \$1}" | while read -r m; do
            modinfo -n "$m" >/dev/null 2>&1 || printf "  %s (no module file on disk)\n" "$m"
        done
        printf -- "\n--- /proc/modules addresses ---\n"
        head -n 40 /proc/modules 2>/dev/null
        exit 0'

    # --- Optional: full physical memory acquisition ------------------------
    if [[ "$DFIR_MEMORY" != 1 ]]; then
        dfir_log INFO "Physical memory image not requested (enable with --memory)"
        printf 'Physical memory was not acquired. Re-run with --memory to capture it.\n' \
            >"${d}/memory-image-NOT-COLLECTED.txt"
        return 0
    fi

    local avml; avml="$(dfir_tool avml 2>/dev/null)"
    if [[ -z "$avml" ]]; then
        dfir_log ERROR "--memory requested but tools/bin/avml is missing. Run tools/setup-tools.sh."
        printf 'AVML not available; no memory image was captured.\n' >"${d}/memory-image-FAILED.txt"
        return 1
    fi

    # Refuse to fill the evidence volume: memory image needs RAM-sized space.
    local mem_kb avail_kb
    mem_kb="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
    avail_kb="$(df -Pk "$DFIR_EVID" 2>/dev/null | awk 'NR==2{print $4}')"
    if [[ -n "$mem_kb" && -n "$avail_kb" ]] && (( avail_kb < mem_kb + 1048576 )); then
        dfir_log ERROR "Insufficient free space for a memory image (need ~$((mem_kb / 1024)) MB, have $((avail_kb / 1024)) MB)"
        printf 'Insufficient free space for a memory image.\nRequired: %s MB\nAvailable: %s MB\n' \
            "$((mem_kb / 1024))" "$((avail_kb / 1024))" >"${d}/memory-image-FAILED.txt"
        return 1
    fi

    local image="${d}/memory.avml"
    dfir_log INFO "Acquiring physical memory with AVML (this takes several minutes)"

    # AVML 0.10+ uses subcommands (`avml acquire FILE`); older builds take the
    # filename directly. Try the modern form first, then fall back.
    local captured=0
    if timeout 7200 "$avml" acquire --compress "$image" >"${d}/avml_output.txt" 2>&1; then
        captured=1
    elif timeout 7200 "$avml" --compress "$image" >>"${d}/avml_output.txt" 2>&1; then
        captured=1
    fi

    if (( captured == 1 )) && [[ -s "$image" ]]; then
        sha256sum -- "$image" >"${image}.sha256" 2>/dev/null
        dfir_record_provenance "$image" "$image" 1
        dfir_log SUCCESS "Memory image written: ${image} ($(du -sh "$image" 2>/dev/null | awk '{print $1}'))"
        {
            printf 'Physical memory image\n=====================\n\n'
            printf 'Tool          : AVML %s\n' "$("$avml" --version 2>/dev/null | head -1)"
            printf 'Format        : AVML container, snappy-compressed\n'
            printf 'Acquired (UTC): %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            printf 'Host kernel   : %s\n' "$(uname -r)"
            printf 'Size          : %s\n' "$(du -h "$image" 2>/dev/null | awk '{print $1}')"
            printf 'SHA256        : %s\n' "$(awk '{print $1}' "${image}.sha256" 2>/dev/null)"
            printf '\nConvert to a format an analysis tool can read:\n'
            printf '  avml convert --format lime memory.avml memory.lime\n'
            printf '  avml convert --format raw  memory.avml memory.raw\n'
            printf '\nThen analyse with Volatility 3, using a symbol table built for\n'
            printf 'this exact kernel (%s):\n' "$(uname -r)"
            printf '  vol -f memory.lime linux.pslist.PsList\n'
            printf '  vol -f memory.lime linux.malfind.Malfind\n'
        } >"${d}/memory-image-README.txt"
    else
        dfir_log ERROR "AVML acquisition failed - see ${d}/avml_output.txt"
        rm -f "$image"
        return 1
    fi
    return 0
}
