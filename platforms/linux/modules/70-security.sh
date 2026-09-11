#!/usr/bin/env bash
# 70-security.sh - Security controls, integrity verification and malware
# tooling output (12_Security). Linux analogue of the Defender module.

dfir_module_security() {
    local d="${DFIR_DIR[Security]}"

    _dfir_sec_mac        "${d}/mac"
    _dfir_sec_firewall   "${d}/firewall"
    _dfir_sec_audit      "${d}/audit"
    _dfir_sec_integrity  "${d}/integrity"
    _dfir_sec_av         "${d}/antimalware"
    _dfir_sec_rootkit    "${d}/rootkit"
    _dfir_sec_edr        "${d}/agents"
    return 0
}

# ---------------------------------------------------------------------------
_dfir_sec_mac() {
    local d="$1"; mkdir -p "$d"

    dfir_cmd "apparmor status"   "${d}/apparmor_status.txt"   aa-status
    dfir_cmd "apparmor profiles" "${d}/apparmor_profiles.txt" cat /sys/kernel/security/apparmor/profiles
    [[ -d /etc/apparmor.d ]] && dfir_list_dir /etc/apparmor.d "${d}/apparmor_profile_listing.txt" -maxdepth 2
    dfir_sh "apparmor local overrides" "${d}/apparmor_local_overrides.txt" '
        ls -la /etc/apparmor.d/local 2>/dev/null
        for f in /etc/apparmor.d/local/*; do
            [ -f "$f" ] || continue
            printf "\n=== %s ===\n" "$f"; cat "$f"
        done
        printf "\n--- profiles in complain (non-enforcing) mode ---\n"
        aa-status 2>/dev/null | sed -n "/complain mode/,/profiles are in/p"
        exit 0'
    dfir_sh "apparmor denials" "${d}/apparmor_denials.txt" \
        "journalctl -k --no-pager 2>/dev/null | grep -i 'apparmor=\"DENIED\"' | tail -n 2000; exit 0"

    dfir_cmd "selinux status" "${d}/sestatus.txt" sestatus
    dfir_cmd "yama ptrace scope" "${d}/yama_ptrace_scope.txt" sysctl kernel.yama.ptrace_scope
}

# ---------------------------------------------------------------------------
_dfir_sec_firewall() {
    local d="$1"; mkdir -p "$d"
    dfir_cmd "ufw status"      "${d}/ufw_status.txt"    ufw status verbose
    dfir_cmd "ufw app list"    "${d}/ufw_apps.txt"      ufw app list
    dfir_cmd "fail2ban status" "${d}/fail2ban_status.txt" fail2ban-client status
    dfir_sh  "fail2ban jails"  "${d}/fail2ban_jails.txt" '
        for j in $(fail2ban-client status 2>/dev/null | sed -n "s/.*Jail list:\s*//p" | tr "," " "); do
            printf "=== %s ===\n" "$j"; fail2ban-client status "$j" 2>/dev/null; printf "\n"
        done
        exit 0'
    [[ -d /etc/fail2ban ]] && dfir_copy_tree /etc/fail2ban "${d}/etc_fail2ban" 200
}

# ---------------------------------------------------------------------------
_dfir_sec_audit() {
    local d="$1"; mkdir -p "$d"
    dfir_cmd "auditd status" "${d}/auditctl_status.txt" auditctl -s
    dfir_cmd "audit rules"   "${d}/auditctl_rules.txt"  auditctl -l
    [[ -d /etc/audit ]] && dfir_copy_tree /etc/audit "${d}/etc_audit" 200
}

# ---------------------------------------------------------------------------
_dfir_sec_integrity() {
    local d="$1"; mkdir -p "$d"

    if [[ "$DFIR_MODE" == "quick" ]]; then
        dfir_log INFO "Quick mode: package integrity verification skipped"
        printf 'Package integrity verification (dpkg --verify, debsums) is skipped in\n--quick mode. Re-run without --quick to include it.\n' \
            >"${d}/SKIPPED-in-quick-mode.txt"
        return 0
    fi

    # dpkg's own verification and debsums each re-read every packaged file
    # (minutes apiece on a full install). They are independent, so they run
    # concurrently; each writes its own output and only appends short records
    # to the shared logs. The module's interrupt handling still reaches both.
    local pid_verify pid_debsums
    dfir_sh "dpkg verify" "${d}/dpkg_verify.txt" '
        printf "Files whose checksum, mode or ownership differs from the package database.\n"
        printf "Columns: ??5?????? = content changed, ?????U?? = owner changed.\n\n"
        dpkg --verify 2>/dev/null
        printf "\n(no output above means every packaged file matched)\n"
        exit 0' &
    pid_verify=$!

    # debsums adds md5 verification for files dpkg does not track.
    dfir_sh "debsums changed files" "${d}/debsums_changed.txt" \
        "debsums -c 2>&1 | head -n 2000; exit 0" &
    pid_debsums=$!
    dfir_sh "debsums missing files" "${d}/debsums_missing.txt" \
        "debsums -l 2>&1 | head -n 2000; exit 0"
    wait "$pid_verify" "$pid_debsums"

    # Core binaries that are not owned by any package: replaced system tools.
    dfir_sh "unpackaged system binaries" "${d}/unpackaged_binaries.txt" '
        printf "Executables in system binary directories with no owning package.\n"
        printf "Legitimate causes: locally compiled tools, vendor agents, kit wrappers.\n\n"
        find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib/systemd \
             -xdev -maxdepth 1 -type f -print 2>/dev/null |
        dfir_filter_unpackaged |
        while read -r f; do
            printf "UNPACKAGED %-56s " "$f"
            stat -c "mode=%A owner=%U:%G size=%s mtime=%y" "$f" 2>/dev/null
            sha256sum "$f" 2>/dev/null | sed "s/^/    sha256 /"
        done
        exit 0'

    dfir_sh "immutable attributes on system paths" "${d}/immutable_files.txt" '
        printf "Files carrying the immutable (i) or append-only (a) attribute.\n"
        printf "Rootkits set these to protect their own files from removal.\n\n"
        for dir in /etc /root /var/spool/cron /usr/local; do
            [ -d "$dir" ] || continue
            lsattr -R -a "$dir" 2>/dev/null | grep -E "^[-a-zA-Z]{4}[ia]" | head -n 200
        done
        find /bin /sbin /usr/bin /usr/sbin -maxdepth 1 -type f -print0 2>/dev/null |
            xargs -0 -r -n 200 lsattr -d 2>/dev/null |
            grep -E "^[-a-zA-Z]{4}[ia]" | head -n 100
        exit 0'
}

# ---------------------------------------------------------------------------
_dfir_sec_av() {
    local d="$1"; mkdir -p "$d"

    dfir_sh "installed security products" "${d}/installed_products.txt" '
        printf -- "--- packages ---\n"
        dpkg -l 2>/dev/null | grep -iE "clamav|sophos|eset|mcafee|trend|crowdstrike|falcon|sentinel|carbonblack|cortex|defender|mdatp|osquery|wazuh|ossec|rkhunter|chkrootkit|aide|tripwire|snort|suricata|auditd" || printf "(none found)\n"
        printf -- "\n--- running security-related services ---\n"
        systemctl list-units --type=service --state=running --no-pager 2>/dev/null |
            grep -iE "clamav|sophos|eset|mcafee|trend|crowdstrike|falcon|sentinel|carbonblack|cortex|mdatp|osquery|wazuh|ossec|auditd|apparmor" || printf "(none running)\n"
        printf -- "\n--- vendor directories present ---\n"
        for p in /opt/sophos-spl /opt/eset /opt/McAfee /opt/CrowdStrike /opt/microsoft/mdatp \
                 /opt/Trellix /var/lib/clamav /var/ossec /var/ossec-agent /opt/osquery /opt/Cortex; do
            [ -e "$p" ] && printf "PRESENT %s\n" "$p"
        done
        exit 0'

    # ClamAV state and logs when installed.
    if dfir_have clamscan || [[ -d /var/lib/clamav ]]; then
        dfir_cmd "clamav version" "${d}/clamav_version.txt" clamscan --version
        dfir_sh "clamav database state" "${d}/clamav_database.txt" \
            'ls -la /var/lib/clamav 2>/dev/null; freshclam --version 2>/dev/null; exit 0'
        local f
        for f in /var/log/clamav/freshclam.log /var/log/clamav/clamav.log; do
            dfir_copy "$f" "${d}/$(basename "$f")"
        done
    fi

    # Microsoft Defender for Endpoint on Linux, if deployed.
    if dfir_have mdatp; then
        dfir_cmd "mdatp health"      "${d}/mdatp_health.txt"      mdatp health
        dfir_cmd "mdatp threat list" "${d}/mdatp_threats.txt"     mdatp threat list
        dfir_cmd "mdatp exclusions"  "${d}/mdatp_exclusions.txt"  mdatp exclusion list
    fi

    # CrowdStrike Falcon sensor state, if deployed.
    dfir_have falconctl && dfir_cmd "falcon sensor" "${d}/falconctl.txt" falconctl -g --aid --rfm-state --version
}

# ---------------------------------------------------------------------------
_dfir_sec_rootkit() {
    local d="$1"

    if [[ "$DFIR_ROOTKIT_SCAN" != 1 ]]; then
        dfir_log INFO "Rootkit scanners not run (enable with --rootkit-scan)"
        return 0
    fi
    mkdir -p "$d"

    # Rootkit scanners routinely run for several minutes; the normal per-command
    # timeout would kill them mid-scan. Raised only for this section (the module
    # runs in its own subshell, so the change cannot leak).
    local saved_timeout="$DFIR_CMD_TIMEOUT"
    DFIR_CMD_TIMEOUT="${DFIR_ROOTKIT_TIMEOUT:-1800}"
    dfir_log INFO "Rootkit scanners running with a ${DFIR_CMD_TIMEOUT}s timeout"

    if dfir_have chkrootkit; then
        dfir_sh "chkrootkit" "${d}/chkrootkit.txt" "chkrootkit -q 2>&1; exit 0"
    else
        dfir_log WARN "chkrootkit not installed (run tools/setup-tools.sh)"
    fi

    if dfir_have rkhunter; then
        dfir_sh "rkhunter" "${d}/rkhunter.txt" \
            "rkhunter --check --skip-keypress --report-warnings-only --nocolors 2>&1; exit 0"
        dfir_copy /var/log/rkhunter.log "${d}/rkhunter.log"
    else
        dfir_log WARN "rkhunter not installed (run tools/setup-tools.sh)"
    fi

    if dfir_have unhide; then
        dfir_sh "unhide processes" "${d}/unhide_procs.txt" "unhide -m quick 2>&1; exit 0"
    fi

    DFIR_CMD_TIMEOUT="$saved_timeout"
}

# ---------------------------------------------------------------------------
_dfir_sec_edr() {
    local d="$1"; mkdir -p "$d"
    # Copy recent logs from any security agent that is present, mirroring the
    # Windows collector's Malwarebytes/ESET handling.
    local base
    for base in /opt/sophos-spl/logs /opt/eset/RemoteAdministrator/Agent/Logs \
                /var/log/crowdstrike /var/log/microsoft/mdatp /var/ossec/logs \
                /var/log/osquery /var/log/wazuh /opt/Cortex/logs /var/log/suricata; do
        [[ -d "$base" ]] || continue
        dfir_log INFO "Security agent logs found: ${base}"
        dfir_sh "recent logs ${base}" "${DFIR_DIR[Security]}/agents/$(dfir_safe_name "${base#/}")_listing.txt" \
            "find $(printf '%q' "$base") -type f -printf '%TY-%Tm-%TdT%TH:%TM %10s %p\n' 2>/dev/null | sort -r | head -n 200"
        # Copy the 50 most recent files only, to bound the evidence size.
        local count=0 f
        while IFS= read -r f; do
            (( count >= 50 )) && break
            dfir_copy "$f" "${d}/$(dfir_safe_name "${base#/}")/$(basename "$f")" && count=$((count + 1))
        done < <(find "$base" -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -50 | cut -d' ' -f2-)
    done
}
