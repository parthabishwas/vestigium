#!/usr/bin/env bash
# 85-filesystem.sh - Filesystem state, privileged binaries and timeline
# material (15_Filesystem).

dfir_module_filesystem() {
    local d="${DFIR_DIR[Filesystem]}"

    # --- Mounts and layout -------------------------------------------------
    dfir_cmd "mount table"   "${d}/mount.txt"     mount
    dfir_cmd "findmnt"       "${d}/findmnt.txt"   findmnt -a -o TARGET,SOURCE,FSTYPE,OPTIONS,LABEL,UUID
    dfir_cmd "proc mounts"   "${d}/proc_mounts.txt" cat /proc/mounts
    dfir_cmd "disk usage"    "${d}/df.txt"        df -hT
    dfir_cmd "inode usage"   "${d}/df_inodes.txt" df -i
    dfir_copy /etc/fstab "${d}/fstab"

    # --- Walk scope ----------------------------------------------------------
    # `find / -xdev` stays on the root filesystem and silently misses separate
    # /home, /var, /tmp or /opt partitions (standard on CIS-hardened builds).
    # Every whole-system walk therefore starts from each local on-disk mount,
    # still with -xdev so pseudo and network filesystems are never entered.
    local -a mounts=()
    declare -F dfir_local_mounts >/dev/null && mapfile -t mounts < <(dfir_local_mounts 2>/dev/null)
    ((${#mounts[@]} > 0)) || mounts=(/)

    # Our own evidence output and tooling are never evidence: prune both.
    local -a skip_roots=() prune_args=()
    local r
    for r in "${DFIR_OUTPUT_BASE:-}" "${DFIR_KIT_ROOT:-}"; do
        [[ -n "$r" && -d "$r" ]] && skip_roots+=("$(readlink -f -- "$r")")
    done
    local prune_q=""                # same expression, quoted for dfir_sh
    if ((${#skip_roots[@]} > 0)); then
        prune_args=('(')
        for r in "${skip_roots[@]}"; do
            ((${#prune_args[@]} > 1)) && prune_args+=(-o)
            prune_args+=(-path "$r")
        done
        prune_args+=(')' -prune -o)
        prune_q="$(printf '%q ' "${prune_args[@]}")"
    fi
    local mounts_q; mounts_q="$(printf '%q ' "${mounts[@]}")"
    dfir_log INFO "Filesystem walks cover ${#mounts[@]} local mount(s): ${mounts[*]}"

    # --- Privileged, writable and unowned files: one pass -------------------
    # SUID/SGID, world-writable and unowned files used to cost four full walks.
    # One find pass writes a tagged TSV (removed afterwards) and each report is
    # derived from it with its original name and line format. It gets three
    # command timeouts because it replaces four separately-timed walks.
    local walk="${d}/.permission_walk.tsv" t0=$SECONDS rc
    timeout --signal=TERM --kill-after=15 "$(( DFIR_CMD_TIMEOUT * 3 ))" \
        find "${mounts[@]}" -xdev "${prune_args[@]}" \( \
            \( -type f -perm /6000 -printf 'SUGID\t%M %u:%g %10s %TY-%Tm-%TdT%TH:%TM %p\n' \) , \
            \( -type f -perm -4000 -printf 'SUID\t%p\n' \) , \
            \( -type d -perm -0002 ! -perm -1000 -printf 'WWDIR\t%M %u:%g %p\n' \) , \
            \( -type f -perm -0002 ! -path '/tmp/*' ! -path '/proc/*' -printf 'WWFILE\t%M %u:%g %10s %p\n' \) , \
            \( \( -nouser -o -nogroup \) -printf 'NOOWNER\t%U:%G %10s %p\n' \) \
        \) >"$walk" 2>/dev/null
    rc=$?
    if (( rc == 124 || rc == 137 )); then
        dfir_log WARN "Permission walk timed out after $(( DFIR_CMD_TIMEOUT * 3 ))s: SUID/world-writable/unowned lists are incomplete"
    fi
    # dfir_sh scripts only see exported variables; the module runs in its own
    # subshell, so these exports do not leak into later modules.
    export DFIR_FS_WALK="$walk"
    export DFIR_FS_SCOPE="Scope: local filesystems ${mounts[*]} (each walked with -xdev; evidence output and Vestigium kit excluded)"

    dfir_sh "setuid and setgid binaries" "${d}/suid_sgid_binaries.txt" '
        printf "SUID/SGID executables on local filesystems.\n"
        printf "Compare against a known-good baseline; unexpected entries enable escalation.\n"
        printf "%s\n\n" "$DFIR_FS_SCOPE"
        sed -n "s/^SUGID\t//p" "$DFIR_FS_WALK" | sort -k5
        exit 0'

    dfir_sh "unpackaged setuid binaries" "${d}/suid_unpackaged.txt" '
        printf "Setuid binaries with no owning package: the classic privilege\n"
        printf "escalation backdoor (for example a copied setuid shell).\n\n"
        sed -n "s/^SUID\t//p" "$DFIR_FS_WALK" |
        dfir_filter_unpackaged |
        while read -r f; do
            printf "UNPACKAGED %s\n" "$f"
            stat -c "    mode=%A owner=%U:%G size=%s mtime=%y" "$f" 2>/dev/null
            file -b "$f" 2>/dev/null | sed "s/^/    type: /"
            sha256sum "$f" 2>/dev/null | sed "s/^/    sha256 /"
        done
        exit 0'

    dfir_sh "world-writable files and directories" "${d}/world_writable.txt" '
        printf -- "--- world-writable directories without the sticky bit ---\n"
        sed -n "s/^WWDIR\t//p" "$DFIR_FS_WALK" | head -n 300
        printf -- "\n--- world-writable files outside /tmp and /proc ---\n"
        sed -n "s/^WWFILE\t//p" "$DFIR_FS_WALK" | head -n 300
        exit 0'

    dfir_sh "files with no owner" "${d}/unowned_files.txt" \
        'sed -n "s/^NOOWNER\t//p" "$DFIR_FS_WALK" | head -n 300; exit 0'

    _dfir_record_cmd "local filesystem permission walk" \
        "find ${mounts_q}-xdev (merged SUID/SGID, world-writable, unowned)" \
        "$rc" "$(( SECONDS - t0 ))" "${d}/suid_sgid_binaries.txt"
    rm -f "$walk"

    # `getcap -r /` ignores -xdev and descends into /proc and /sys, so feed it
    # regular files from the same local-mount walk instead.
    if dfir_have getcap; then
        dfir_sh "file capabilities" "${d}/file_capabilities.txt" \
            "find ${mounts_q}-xdev ${prune_q}-type f -print0 2>/dev/null | xargs -0 -r getcap 2>/dev/null | head -n 500; exit 0"
    else
        dfir_log WARN "Skipped 'file capabilities': getcap not available on this host"
        _dfir_record_cmd "file capabilities" "getcap" "127" "0" "${d}/file_capabilities.txt"
    fi

    # --- Volatile and staging directories ---------------------------------
    local dir
    for dir in /tmp /var/tmp /dev/shm /run/shm /run/user /var/spool /opt /usr/local /srv /var/www; do
        [[ -e "$dir" ]] || continue
        dfir_sh "listing ${dir}" "${d}/listing_$(dfir_safe_name "${dir#/}").txt" \
            "find $(printf '%q' "$dir") -xdev -printf '%M %u:%g %10s %TY-%Tm-%TdT%TH:%TM %p\n' 2>/dev/null | sort -k5 | head -n 5000"
    done

    dfir_sh "executables in temporary directories" "${d}/executables_in_temp.txt" '
        found=0
        for dir in /tmp /var/tmp /dev/shm /run/shm; do
            [ -d "$dir" ] || continue
            while IFS= read -r f; do
                found=1
                printf "%s\n" "$f"
                stat -c "    mode=%A owner=%U:%G size=%s mtime=%y" "$f" 2>/dev/null
                printf "    type: %s\n" "$(file -b "$f" 2>/dev/null)"
                sha256sum "$f" 2>/dev/null | sed "s/^/    sha256 /"
            done < <(find "$dir" -xdev -type f \( -perm -u+x -o -name "*.sh" -o -name "*.py" -o -name "*.elf" -o -name "*.bin" \) 2>/dev/null | head -n 300)
        done
        [ "$found" = 0 ] && echo "No executable files found in temporary directories."
        exit 0'

    # Copy small suspicious files from temp locations for later analysis.
    if [[ "$DFIR_MODE" == "full" ]]; then
        local f count=0
        while IFS= read -r f; do
            (( count >= 200 )) && break
            dfir_copy "$f" "${d}/collected-temp-files/$(dfir_safe_name "${f#/}")" && count=$((count + 1))
        done < <(find /tmp /var/tmp /dev/shm -xdev -type f -size -10M \
                    \( -perm -u+x -o -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.elf' \) 2>/dev/null)
        (( count > 0 )) && dfir_log INFO "Collected ${count} executable/script file(s) from temporary directories"
    fi

    # --- Timeline material -------------------------------------------------
    dfir_sh "recently modified system files (30 days)" "${d}/timeline_system_30d.txt" \
        "find /etc /bin /sbin /usr/bin /usr/sbin /usr/local /lib /lib64 /opt /boot \
            -xdev -type f -mtime -30 -printf '%TY-%Tm-%TdT%TH:%TM:%TS %10s %M %u:%g %p\n' 2>/dev/null | sort -r | head -n 5000"

    dfir_sh "recently changed inode metadata (30 days)" "${d}/timeline_ctime_30d.txt" \
        "find /etc /bin /sbin /usr/bin /usr/sbin /usr/local /lib -xdev -type f -ctime -30 \
            -printf '%CY-%Cm-%CdT%CH:%CM:%CS %10s %p\n' 2>/dev/null | sort -r | head -n 5000"

    dfir_sh "recently modified files in home directories (30 days)" "${d}/timeline_home_30d.txt" "
        while IFS=\$'\t' read -r u uid gid home shell; do
            find \"\$home\" -xdev ${prune_q}-type f -mtime -30 \
                -printf '%TY-%Tm-%TdT%TH:%TM:%TS %10s %u:%g %p\n' 2>/dev/null
        done < $(printf '%q' "$DFIR_USERS_TSV") | sort -r | head -n 20000
        exit 0"

    # Full body-file style timeline for the areas that matter most.
    if [[ "$DFIR_MODE" == "full" ]]; then
        local tl="${d}/timeline_mactime.csv"
        dfir_csv_row "$tl" "MTimeUTC" "ATimeUTC" "CTimeUTC" "SizeBytes" "Mode" "UID" "GID" "Path"
        dfir_sh "MAC timeline extraction" "${d}/_timeline_raw.txt" \
            "find /etc /root /home /opt /usr/local /var/www /srv /tmp /var/tmp /dev/shm \
                -xdev ${prune_q}-type f \
                -printf '%T@\t%A@\t%C@\t%s\t%M\t%U\t%G\t%p\n' 2>/dev/null | head -n 200000" >/dev/null
        if [[ -f "${d}/_timeline_raw.txt" ]]; then
            # strftime follows TZ, so pin it to UTC to match the column names
            # and the Z suffix (mawk-compatible; int() avoids mawk rounding).
            TZ=UTC awk -F'\t' 'NF==8 {
                gsub(/"/, "\"\"", $8)
                printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                    strftime("%Y-%m-%dT%H:%M:%SZ", int($1)), strftime("%Y-%m-%dT%H:%M:%SZ", int($2)),
                    strftime("%Y-%m-%dT%H:%M:%SZ", int($3)), $4, $5, $6, $7, $8
            }' "${d}/_timeline_raw.txt" >>"$tl" 2>/dev/null
            rm -f "${d}/_timeline_raw.txt"
            _dfir_record_cmd "MAC timeline" "find -printf timeline" "0" "0" "$tl"
        fi
    fi

    # --- Deleted-but-open files (recoverable evidence) --------------------
    dfir_sh "deleted files still held open" "${d}/deleted_open_files.txt" '
        found=0
        for fd in /proc/[0-9]*/fd/*; do
            t=$(readlink "$fd" 2>/dev/null) || continue
            case "$t" in
                *"(deleted)")
                    found=1
                    pid=${fd#/proc/}; pid=${pid%%/*}
                    printf "PID %-8s %-40s -> %s\n" "$pid" \
                        "$(tr "\0" " " < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-40)" "$t" ;;
            esac
        done
        [ "$found" = 0 ] && echo "No deleted files are currently held open."
        exit 0'

    # --- Filesystem-level metadata ----------------------------------------
    dfir_sh "filesystem superblock information" "${d}/filesystem_superblocks.txt" '
        for dev in $(lsblk -pnlo NAME,FSTYPE 2>/dev/null | awk "\$2 ~ /^ext[234]$/ {print \$1}"); do
            printf "=== %s ===\n" "$dev"
            tune2fs -l "$dev" 2>/dev/null
            printf "\n"
        done
        exit 0'

    return 0
}
