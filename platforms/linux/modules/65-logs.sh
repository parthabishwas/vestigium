#!/usr/bin/env bash
# 65-logs.sh - System logs, journal and login records (10_Logs).
# Linux equivalent of the Windows EVTX export module.

dfir_module_logs() {
    local d="${DFIR_DIR[Logs]}"

    _dfir_logs_journal   "${d}/journal"
    _dfir_logs_varlog    "${d}/var-log"
    _dfir_logs_logins    "${d}/logins"
    _dfir_logs_audit     "${d}/audit"
    _dfir_logs_highlights "${d}"
    return 0
}

# ---------------------------------------------------------------------------
_dfir_logs_journal() {
    local d="$1"; mkdir -p "$d"

    dfir_cmd "journal boots"      "${d}/boots.txt"        journalctl --list-boots --no-pager
    dfir_cmd "journal disk usage" "${d}/disk_usage.txt"   journalctl --disk-usage
    dfir_cmd "journal verify"     "${d}/verify.txt"       journalctl --verify
    _dfir_logs_sealing "$d"

    # Text exports: current boot, recent history, errors, and key units.
    dfir_sh "journal current boot" "${d}/journal_current_boot.txt" \
        "journalctl -b -o short-iso-precise --no-pager"
    dfir_sh "journal last 30 days" "${d}/journal_last_30d.txt" \
        "journalctl --since '30 days ago' -o short-iso-precise --no-pager"
    dfir_sh "journal errors" "${d}/journal_priority_err.txt" \
        "journalctl -p err -b -o short-iso-precise --no-pager"
    dfir_sh "journal kernel" "${d}/journal_kernel.txt" \
        "journalctl -k -o short-iso-precise --no-pager"

    local unit
    for unit in ssh sshd sudo su cron systemd-logind gdm gdm3 lightdm polkit \
                apparmor auditd snapd packagekit unattended-upgrades \
                NetworkManager systemd-resolved ufw docker containerd; do
        dfir_sh "journal unit ${unit}" "${d}/units/${unit}.txt" \
            "journalctl -u $(printf '%q' "${unit}.service") --no-pager -o short-iso-precise 2>/dev/null | tail -n 20000; exit 0"
    done

    # Structured export for downstream tooling (bounded).
    dfir_sh "journal json export (7 days)" "${d}/journal_last_7d.json" \
        "journalctl --since '7 days ago' -o json --no-pager"

    # Native journal files preserve authenticity metadata (FSS sealing).
    if [[ "$DFIR_MODE" == "full" && -d /var/log/journal ]]; then
        local size_mb
        size_mb="$(du -sm /var/log/journal 2>/dev/null | awk '{print $1}')"
        if [[ -n "$size_mb" && "$size_mb" -le "$DFIR_MAX_JOURNAL_MB" ]]; then
            dfir_log INFO "Copying native journal (${size_mb} MB)"
            dfir_copy_tree /var/log/journal "${d}/native-journal" 20000
        else
            dfir_log WARN "Native journal is ${size_mb} MB (limit ${DFIR_MAX_JOURNAL_MB} MB): text exports only"
            printf 'Native journal not copied: %s MB exceeds the %s MB limit.\n' \
                "$size_mb" "$DFIR_MAX_JOURNAL_MB" >"${d}/native-journal-SKIPPED.txt"
        fi
    fi
}

# ---------------------------------------------------------------------------
_dfir_logs_sealing() {
    # Forward Secure Sealing (FSS) makes the journal tamper-evident: without
    # an FSS key, root can rewrite history at will, so this decides how much a
    # journal-based timeline can be trusted. RESULT line is machine-readable.
    local d="$1"
    local out="${d}/journal_sealing.txt"
    local mid seal storage key="" verdict reason
    mid="$(cat /etc/machine-id 2>/dev/null)"
    seal="$(grep -hs '^Seal=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null | tail -n 1)"
    storage="$(grep -hs '^Storage=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null | tail -n 1)"
    [[ -n "$mid" && -f "/var/log/journal/${mid}/fss" ]] && key="/var/log/journal/${mid}/fss"

    local pass fail
    pass="$(grep -c '^PASS' "${d}/verify.txt" 2>/dev/null)"; pass="${pass//[^0-9]/}"
    fail="$(grep -c '^FAIL' "${d}/verify.txt" 2>/dev/null)"; fail="${fail//[^0-9]/}"

    if [[ -n "$key" && "${fail:-0}" == 0 ]]; then
        verdict="enabled"; reason="FSS key present at ${key}; journalctl --verify reported no failures"
    elif [[ -n "$key" ]]; then
        verdict="disabled"; reason="FSS key present but journalctl --verify reported ${fail} failure(s): sealing chain broken or journals damaged"
    else
        verdict="disabled"; reason="no FSS key (${mid:+/var/log/journal/${mid}/fss }not present); journals are not sealed and can be rewritten by root"
    fi

    {
        printf 'JOURNAL TAMPER-EVIDENCE (FORWARD SECURE SEALING)\n'
        printf '================================================\n\n'
        printf 'RESULT: journal_fss=%s\n' "$verdict"
        printf 'Reason: %s\n\n' "$reason"
        printf 'Seal= setting     : %s\n' "${seal:-(not set; default yes, active only with a key)}"
        printf 'Storage= setting  : %s\n' "${storage:-(not set; default auto)}"
        printf 'Persistent journal: %s\n' "$([[ -d /var/log/journal ]] && echo "yes (/var/log/journal)" || echo "no (volatile only: lost at reboot)")"
        printf 'FSS key file      : %s\n' "${key:-absent}"
        printf 'journalctl --verify: %s PASS, %s FAIL (see verify.txt)\n' "${pass:-0}" "${fail:-0}"
        printf '\nInterpretation: with sealing enabled, a journal file altered after\n'
        printf 'sealing fails verification. Without it, the journal is ordinary data\n'
        printf 'that root (or a rootkit) can edit; corroborate with wtmp/btmp, auditd\n'
        printf 'and remote syslog where available.\n'
    } >"$out"
    _dfir_record_cmd "journal sealing status" "journald FSS check" "0" "0" "$out"
}

# ---------------------------------------------------------------------------
_dfir_logs_varlog() {
    local d="$1"; mkdir -p "$d"

    dfir_sh "var log inventory" "${d}/_inventory.txt" \
        "find /var/log -xdev -type f -printf '%10s  %TY-%Tm-%TdT%TH:%TM:%TS  %M %u:%g  %p\n' 2>/dev/null | sort -k2"

    # Text logs that matter for authentication, package and kernel history.
    local pattern
    for pattern in 'auth.log*' 'syslog*' 'kern.log*' 'dpkg.log*' 'ufw.log*' \
                   'boot.log*' 'alternatives.log*' 'faillog' 'dmesg*' \
                   'unattended-upgrades/*' 'apt/*' 'installer/*' 'gpu-manager*' \
                   'Xorg.*.log*' 'cups/*' 'fontconfig.log' 'vmware-*' 'landscape/*'; do
        while IFS= read -r -d '' f; do
            dfir_copy "$f" "${d}/${f#/var/log/}"
        done < <(find /var/log -xdev -path "/var/log/${pattern}" -type f -print0 2>/dev/null)
    done

    # Anything modified recently that we have not already picked up.
    dfir_sh "recently modified logs" "${d}/_recently_modified.txt" \
        "find /var/log -xdev -type f -mtime -14 -printf '%TY-%Tm-%TdT%TH:%TM  %10s  %p\n' 2>/dev/null | sort -r"

    # Truncated or zero-length logs are a common anti-forensics indicator.
    # Every timestamp in this report is UTC (find -printf and awk strftime both
    # follow TZ). strftime is supported by mawk, Ubuntu's default awk; int()
    # keeps mawk from rounding fractional epochs up to the next second.
    dfir_sh "zero-length and gap indicators" "${d}/_tampering_indicators.txt" '
        export TZ=UTC
        printf -- "--- zero-length log files (mtime UTC) ---\n"
        find /var/log -xdev -type f -size 0 -printf "%TY-%Tm-%TdT%TH:%TM  %p\n" 2>/dev/null | sort
        printf -- "\n--- logs whose mtime is older than the last boot (mtime UTC) ---\n"
        boot=$(date -d "$(uptime -s)" +%s 2>/dev/null || echo 0)
        find /var/log -xdev -type f -name "*.log" -printf "%T@ %p\n" 2>/dev/null |
            TZ=UTC awk -v b="$boot" "\$1 < b { p = \$0; sub(/^[^ ]+ /, \"\", p); printf \"%s %s\n\", strftime(\"%Y-%m-%dT%H:%M\", int(\$1)), p }" | sort
        printf -- "\n--- journal files with unexpected ownership ---\n"
        find /var/log/journal -xdev -type f ! -user root -printf "%u:%g %p\n" 2>/dev/null
        exit 0'
}

# ---------------------------------------------------------------------------
_dfir_logs_logins() {
    local d="$1"; mkdir -p "$d"

    # Binary accounting databases plus decoded views.
    local f
    for f in /var/log/wtmp /var/log/wtmp.1 /var/log/btmp /var/log/btmp.1 \
             /var/log/lastlog /var/run/utmp /run/utmp; do
        dfir_copy "$f" "${d}/$(dfir_safe_name "${f#/}")"
    done

    dfir_cmd "successful logins"  "${d}/last.txt"        last -Fxwai
    dfir_cmd "failed logins"      "${d}/lastb.txt"       lastb -Fxwai
    dfir_cmd "last login per user" "${d}/lastlog.txt"    lastlog
    dfir_cmd "current sessions"   "${d}/who.txt"         who -a
    dfir_cmd "logind sessions"    "${d}/loginctl_sessions.txt" loginctl list-sessions --no-pager
    dfir_cmd "logind users"       "${d}/loginctl_users.txt"    loginctl list-users --no-pager
    dfir_sh  "utmp dump"          "${d}/utmpdump_wtmp.txt"     "utmpdump /var/log/wtmp 2>&1; exit 0"
    dfir_sh  "btmp dump"          "${d}/utmpdump_btmp.txt"     "utmpdump /var/log/btmp 2>&1; exit 0"

    # Authentication events extracted from auth.log and the journal.
    dfir_sh "authentication events" "${d}/auth_events.txt" '
        printf -- "===== sudo invocations =====\n"
        { grep -hE "sudo:" /var/log/auth.log /var/log/auth.log.1 2>/dev/null;
          journalctl -t sudo --no-pager -o short-iso 2>/dev/null; } | tail -n 3000

        printf -- "\n===== su invocations =====\n"
        { grep -hE " su(\[|:)" /var/log/auth.log /var/log/auth.log.1 2>/dev/null;
          journalctl -t su --no-pager -o short-iso 2>/dev/null; } | tail -n 1000

        printf -- "\n===== ssh accepted =====\n"
        { grep -hE "Accepted (password|publickey|keyboard-interactive)" /var/log/auth.log* 2>/dev/null;
          journalctl -u ssh.service --no-pager -o short-iso 2>/dev/null | grep -E "Accepted"; } | tail -n 2000

        printf -- "\n===== ssh failures =====\n"
        { grep -hE "Failed password|Invalid user|authentication failure|Connection closed by authenticating" /var/log/auth.log* 2>/dev/null;
          journalctl -u ssh.service --no-pager -o short-iso 2>/dev/null | grep -Ei "failed|invalid"; } | tail -n 3000

        printf -- "\n===== account and group changes =====\n"
        grep -hE "useradd|userdel|usermod|groupadd|groupdel|groupmod|passwd\[|chage|gpasswd" \
            /var/log/auth.log* 2>/dev/null | tail -n 1000

        printf -- "\n===== pam session opens for uid 0 =====\n"
        grep -hE "session opened for user root" /var/log/auth.log* 2>/dev/null | tail -n 1000
        exit 0'
}

# ---------------------------------------------------------------------------
_dfir_logs_audit() {
    local d="$1"
    [[ -d /var/log/audit ]] || { dfir_log INFO "auditd logs not present"; return 0; }
    mkdir -p "$d"

    dfir_copy_tree /var/log/audit "${d}/raw" 200
    dfir_sh "audit summary"       "${d}/aureport_summary.txt" "aureport --summary -i 2>&1; exit 0"
    dfir_sh "audit auth report"   "${d}/aureport_auth.txt"    "aureport -au -i 2>&1; exit 0"
    dfir_sh "audit exec report"   "${d}/aureport_exec.txt"    "aureport -x -i 2>&1; exit 0"
    dfir_sh "audit file report"   "${d}/aureport_file.txt"    "aureport -f -i 2>&1; exit 0"
    dfir_sh "audit anomalies"     "${d}/aureport_anomaly.txt" "aureport --anomaly -i 2>&1; exit 0"
}

# ---------------------------------------------------------------------------
_dfir_logs_highlights() {
    local d="$1"
    {
        printf 'LOG REVIEW HIGHLIGHTS\n=====================\n\n'

        printf -- '--- last 25 successful logins ---\n'
        last -Fxwa 2>/dev/null | head -n 25

        printf -- '\n--- last 25 failed logins ---\n'
        lastb -Fxwa 2>/dev/null | head -n 25

        printf -- '\n--- privilege escalation (last 50 sudo events) ---\n'
        { grep -h "sudo:" /var/log/auth.log /var/log/auth.log.1 2>/dev/null;
          journalctl -t sudo --no-pager -o short-iso 2>/dev/null; } | tail -n 50

        printf -- '\n--- package installs in the last 30 days ---\n'
        grep -h " install " /var/log/dpkg.log /var/log/dpkg.log.1 2>/dev/null | tail -n 100

        printf -- '\n--- new user/group activity ---\n'
        grep -hE "useradd|groupadd|usermod" /var/log/auth.log* 2>/dev/null | tail -n 50

        printf -- '\n--- USB device attachments ---\n'
        journalctl -k --no-pager -o short-iso 2>/dev/null |
            grep -iE "usb .*(new|SerialNumber|Product:|Manufacturer:)" | tail -n 100

        printf -- '\n--- shutdown/reboot history ---\n'
        last -Fxw reboot shutdown 2>/dev/null | head -n 30

        printf -- '\n--- journal retention window ---\n'
        journalctl --no-pager -n 1 -o short-iso --reverse 2>/dev/null | head -1
        journalctl --no-pager -o short-iso 2>/dev/null | head -1
    } | dfir_capture "log highlights" "${d}/SUMMARY.txt"
}
