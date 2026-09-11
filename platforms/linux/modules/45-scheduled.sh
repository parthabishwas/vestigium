#!/usr/bin/env bash
# 45-scheduled.sh - Readable enumeration of scheduled execution (06_ScheduledTasks).
# Equivalent of `schtasks /query /fo LIST /v` on Windows. File-level copies of
# the same artifacts live under 03_Persistence.

dfir_module_scheduled() {
    local d="${DFIR_DIR[ScheduledTasks]}"

    # --- systemd timers ----------------------------------------------------
    dfir_cmd "timers (active)"  "${d}/timers_active.txt" systemctl list-timers --no-pager
    dfir_cmd "timers (all)"     "${d}/timers_all.txt"    systemctl list-timers --all --no-pager
    dfir_sh  "timer definitions" "${d}/timer_definitions.txt" '
        systemctl list-unit-files --type=timer --no-pager 2>/dev/null | awk "NR>1 && \$1 ~ /\.timer$/ {print \$1}" |
        while read -r t; do
            [ -n "$t" ] || continue
            printf "########## %s ##########\n" "$t"
            systemctl cat "$t" 2>/dev/null
            svc="${t%.timer}.service"
            printf "\n----- triggered unit: %s -----\n" "$svc"
            systemctl cat "$svc" 2>/dev/null || printf "(no matching service unit)\n"
            printf "\n"
        done
        exit 0'

    # --- cron --------------------------------------------------------------
    dfir_sh "all cron entries" "${d}/cron_entries.txt" "
        printf '========== /etc/crontab ==========\n'
        cat /etc/crontab 2>/dev/null

        printf '\n========== /etc/cron.d ==========\n'
        for f in /etc/cron.d/*; do
            [ -f \"\$f\" ] || continue
            printf -- '--- %s (owner %s, mtime %s) ---\n' \"\$f\" \
                \"\$(stat -c %U \"\$f\" 2>/dev/null)\" \"\$(stat -c %y \"\$f\" 2>/dev/null)\"
            cat \"\$f\" 2>/dev/null
        done

        printf '\n========== periodic directories ==========\n'
        for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
            printf -- '--- %s ---\n' \"\$dir\"
            ls -la \"\$dir\" 2>/dev/null
        done

        printf '\n========== user crontabs ==========\n'
        while IFS=\$'\t' read -r u uid gid home shell; do
            printf -- '--- crontab -u %s ---\n' \"\$u\"
            crontab -l -u \"\$u\" 2>&1
            printf '\n'
        done < $(printf '%q' "$DFIR_USERS_TSV")

        printf '\n========== crontab spool metadata ==========\n'
        ls -la /var/spool/cron/crontabs 2>/dev/null
        exit 0"

    dfir_cmd "anacron"     "${d}/anacrontab.txt"  cat /etc/anacrontab
    dfir_sh  "at queue"    "${d}/at_queue.txt"    'atq 2>&1; echo; ls -la /var/spool/cron/atjobs 2>/dev/null; exit 0'

    # --- Consolidated schedule view ---------------------------------------
    {
        printf 'SCHEDULED EXECUTION OVERVIEW\n============================\n\n'
        printf -- '--- systemd timers: next/last run ---\n'
        systemctl list-timers --all --no-pager 2>/dev/null

        printf '\n--- enabled timer units ---\n'
        systemctl list-unit-files --type=timer --state=enabled --no-pager 2>/dev/null

        printf '\n--- cron jobs referencing interpreters, downloads or temp paths ---\n'
        {
            grep -rhnE '' /etc/crontab /etc/cron.d/* 2>/dev/null
            while IFS=$'\t' read -r u _ _ _ _; do
                crontab -l -u "$u" 2>/dev/null | sed "s|^|crontab(${u}): |"
            done <"$DFIR_USERS_TSV"
        } 2>/dev/null | grep -vE '^\s*#' |
          grep -EI '(curl|wget|base64|/tmp/|/dev/shm|/var/tmp|nc |ncat|socat|python|perl|php|ruby|bash -|sh -)' |
          sort -u

        printf '\n--- recent cron execution from the journal ---\n'
        journalctl -u cron.service --no-pager -n 200 2>/dev/null | tail -n 200
    } | dfir_capture "scheduled execution overview" "${d}/SUMMARY.txt"

    return 0
}
