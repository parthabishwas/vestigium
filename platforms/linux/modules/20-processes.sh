#!/usr/bin/env bash
# 20-processes.sh - Running process state and open files (02_Processes).

dfir_module_processes() {
    local d="${DFIR_DIR[Processes]}"

    # --- Classic process views -------------------------------------------
    dfir_cmd "ps full listing" "${d}/ps_auxwwf.txt" ps auxwwwf
    dfir_sh  "ps wide fields"  "${d}/ps_detailed.txt" \
        "ps -eo pid,ppid,pgid,sid,user,uid,group,gid,tty,stat,psr,nice,pri,rss,vsz,pmem,pcpu,nlwp,lstart,etimes,wchan:20,args --sort=pid"
    dfir_cmd "process tree"    "${d}/pstree.txt"   pstree -alnp
    dfir_cmd "top snapshot"    "${d}/top.txt"      top -b -n 1 -w 512
    dfir_cmd "namespaces"      "${d}/lsns.txt"     lsns
    dfir_cmd "ipc facilities"  "${d}/ipcs.txt"     ipcs -a
    dfir_cmd "kernel ring buffer" "${d}/dmesg.txt" dmesg -T

    # --- Per-process detail from /proc ------------------------------------
    # exe/cwd/cmdline/environ/uid/hash for every visible PID. The walk runs once
    # per PID, so it stays close to fork-free: /proc/PID/status is parsed with a
    # single `read` loop, and user names, hashes and package owners are cached
    # per UID / executable.
    local csv="${d}/process_details.csv"
    dfir_csv_row "$csv" "PID" "PPID" "User" "UID" "GID" "StartTime" "State" "Threads" \
        "ExePath" "ExeDeleted" "CWD" "SHA256" "PackageOwner" "CommandLine"

    # StartTime = boot time + /proc/PID/stat field 22 (starttime, clock ticks
    # since boot), in UTC. The mtime of /proc/PID is merely when procfs created
    # the inode and says nothing about when the process started.
    local clk btime="" key val rest
    clk="$(getconf CLK_TCK 2>/dev/null)"
    [[ "$clk" =~ ^[1-9][0-9]*$ ]] || clk=100
    while read -r key val rest; do
        [[ "$key" == "btime" ]] && { btime="$val"; break; }
    done </proc/stat

    local -A user_cache=() sha_cache=() owner_cache=()
    local -a pids=() fields=() argv=()
    local p pid exe cwd cmdline state ppid uid gid user threads start deleted sha owner statline pw
    pids=(/proc/[0-9]*)
    mapfile -t pids < <(printf '%s\n' "${pids[@]#/proc/}" | sort -n)
    for pid in "${pids[@]}"; do
        p="/proc/${pid}"
        [[ -d "$p" ]] || continue
        # Kernel threads have no exe link at all; readlink fails for them.
        exe=""; deleted="no"
        if exe="$(readlink "${p}/exe" 2>/dev/null)"; then
            if [[ "$exe" == *"(deleted)" ]]; then
                deleted="YES"
            else
                exe="$(readlink -f "${p}/exe" 2>/dev/null || printf '%s' "$exe")"
            fi
        fi
        cwd="$(readlink -f "${p}/cwd" 2>/dev/null)"
        argv=()
        mapfile -d '' -t argv 2>/dev/null <"${p}/cmdline"
        cmdline="${argv[*]}"
        [[ -z "$cmdline" ]] && cmdline="[kernel thread]"

        state=""; ppid=""; uid=""; gid=""; threads=""
        while read -r key val rest; do
            case "$key" in
                State:)   state="${val}${rest:+ ${rest}}" ;;
                PPid:)    ppid="$val" ;;
                Uid:)     uid="$val" ;;
                Gid:)     gid="$val" ;;
                Threads:) threads="$val"; break ;;
            esac
        done 2>/dev/null <"${p}/status"

        user=""
        if [[ -n "$uid" ]]; then
            if [[ -z "${user_cache[$uid]+set}" ]]; then
                pw="$(getent passwd "$uid" 2>/dev/null)"
                user_cache[$uid]="${pw%%:*}"
            fi
            user="${user_cache[$uid]}"
        fi

        # comm (field 2) may contain spaces and parentheses: split after the
        # LAST ") ", where fields[0] is stat field 3, so field 22 is fields[19].
        start=""
        if [[ -n "$btime" ]] && read -r statline 2>/dev/null <"${p}/stat"; then
            read -ra fields <<<"${statline##*) }"
            if [[ "${fields[19]:-}" =~ ^[0-9]+$ ]]; then
                TZ=UTC printf -v start '%(%Y-%m-%dT%H:%M:%SZ)T' "$(( btime + fields[19] / clk ))"
            fi
        fi

        sha=""; owner=""
        if [[ -n "$exe" && "$deleted" == "no" && -f "$exe" ]]; then
            if [[ -z "${sha_cache[$exe]+set}" ]]; then
                sha="$(sha256sum -- "$exe" 2>/dev/null)"
                sha="${sha%% *}"
                sha_cache[$exe]="${sha#\\}"
                owner_cache[$exe]="$(dfir_owning_package "$exe")"
            fi
            sha="${sha_cache[$exe]}"; owner="${owner_cache[$exe]}"
        fi

        dfir_csv_row "$csv" "$pid" "$ppid" "$user" "$uid" "$gid" "$start" "$state" \
            "$threads" "$exe" "$deleted" "$cwd" "$sha" "$owner" "$cmdline"
    done
    _dfir_record_cmd "per-process /proc detail" "/proc walk" "0" "0" "$csv"

    # --- Process environment blocks --------------------------------------
    # Environment variables frequently expose injected LD_PRELOAD, proxies and
    # attacker tooling paths.
    dfir_sh "process environments" "${d}/process_environ.txt" '
        for p in /proc/[0-9]*; do
            pid=${p#/proc/}
            [ -r "$p/environ" ] || continue
            printf "=== PID %s : %s ===\n" "$pid" "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)"
            tr "\0" "\n" < "$p/environ" 2>/dev/null
            printf "\n"
        done'

    # --- High-signal anomaly views ---------------------------------------
    dfir_sh "processes running deleted binaries" "${d}/anomaly_deleted_binaries.txt" '
        found=0
        for p in /proc/[0-9]*; do
            t=$(readlink "$p/exe" 2>/dev/null) || continue
            case "$t" in
                *"(deleted)")
                    found=1
                    printf "PID %-8s %s\n    cmdline: %s\n" "${p#/proc/}" "$t" \
                        "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)" ;;
            esac
        done
        [ "$found" = 0 ] && echo "No processes are executing deleted binaries."
        exit 0'

    dfir_sh "processes from world-writable or temp paths" "${d}/anomaly_suspicious_exec_paths.txt" '
        found=0
        for p in /proc/[0-9]*; do
            t=$(readlink -f "$p/exe" 2>/dev/null) || continue
            case "$t" in
                /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|/home/*|/root/*|/var/www/*|/srv/*|*/.*)
                    found=1
                    printf "PID %-8s uid=%-6s %s\n    cmdline: %s\n" "${p#/proc/}" \
                        "$(awk "/^Uid:/{print \$2}" "$p/status" 2>/dev/null)" "$t" \
                        "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)" ;;
            esac
        done
        [ "$found" = 0 ] && echo "No processes executing from temporary, home or web paths."
        exit 0'

    dfir_sh "memfd / anonymous executable mappings" "${d}/anomaly_memfd_maps.txt" '
        found=0
        for p in /proc/[0-9]*; do
            [ -r "$p/maps" ] || continue
            if grep -qE "memfd:|/dev/shm|\(deleted\)" "$p/maps" 2>/dev/null; then
                found=1
                printf "=== PID %s : %s ===\n" "${p#/proc/}" "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)"
                grep -E "memfd:|/dev/shm|\(deleted\)" "$p/maps" 2>/dev/null
                printf "\n"
            fi
        done
        [ "$found" = 0 ] && echo "No memfd, /dev/shm or deleted executable mappings found."
        exit 0'

    dfir_sh "LD_PRELOAD injected processes" "${d}/anomaly_ld_preload.txt" '
        found=0
        for p in /proc/[0-9]*; do
            [ -r "$p/environ" ] || continue
            if tr "\0" "\n" < "$p/environ" 2>/dev/null | grep -qE "^LD_(PRELOAD|LIBRARY_PATH|AUDIT)="; then
                found=1
                printf "PID %-8s %s\n" "${p#/proc/}" "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)"
                tr "\0" "\n" < "$p/environ" 2>/dev/null | grep -E "^LD_"
                printf "\n"
            fi
        done
        [ "$found" = 0 ] && echo "No processes with LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT set."
        exit 0'

    dfir_sh "orphan and reparented processes" "${d}/anomaly_orphans.txt" \
        "ps -eo pid,ppid,user,stat,lstart,args --sort=ppid | awk 'NR==1 || \$2==1'"

    # --- Open files and sockets ------------------------------------------
    dfir_cmd "lsof full"          "${d}/lsof_all.txt"      lsof -nP -b -w
    dfir_cmd "lsof network"       "${d}/lsof_network.txt"  lsof -nPi -b -w
    dfir_cmd "lsof deleted files" "${d}/lsof_deleted.txt"  lsof -nP +L1 -b -w
    dfir_cmd "fuser tmp"          "${d}/fuser_tmp.txt"     fuser -v -m /tmp

    # --- Loaded shared objects per process (library injection hunting) ----
    dfir_sh "loaded shared objects" "${d}/loaded_shared_objects.txt" '
        for p in /proc/[0-9]*; do
            [ -r "$p/maps" ] || continue
            libs=$(awk "\$6 ~ /\.so/ {print \$6}" "$p/maps" 2>/dev/null | sort -u)
            [ -z "$libs" ] && continue
            printf "=== PID %s : %s ===\n%s\n\n" "${p#/proc/}" \
                "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)" "$libs"
        done'

    return 0
}
