#!/usr/bin/env bash
# 30-persistence.sh - System-wide persistence and autostart mechanisms
# (03_Persistence). Linux equivalent of the Windows Run-key / Autoruns sweep.

dfir_module_persistence() {
    local d="${DFIR_DIR[Persistence]}"

    _dfir_persist_systemd  "${d}/systemd"
    _dfir_persist_cron     "${d}/cron"
    _dfir_persist_initrc   "${d}/init"
    _dfir_persist_shell    "${d}/shell-profiles"
    _dfir_persist_loader   "${d}/dynamic-linker"
    _dfir_persist_pam      "${d}/pam"
    _dfir_persist_kernel   "${d}/kernel-modules"
    _dfir_persist_misc     "${d}/misc"
    _dfir_persist_summary  "${d}"
    return 0
}

# ---------------------------------------------------------------------------
# systemd units, timers, generators
# ---------------------------------------------------------------------------
_dfir_persist_systemd() {
    local d="$1"; mkdir -p "$d"

    dfir_cmd "systemd unit files"  "${d}/list-unit-files.txt" systemctl list-unit-files --all --no-pager
    dfir_cmd "systemd units"       "${d}/list-units.txt"      systemctl list-units --all --no-pager
    dfir_cmd "systemd timers"      "${d}/list-timers.txt"     systemctl list-timers --all --no-pager
    dfir_cmd "systemd sockets"     "${d}/list-sockets.txt"    systemctl list-sockets --all --no-pager
    dfir_cmd "systemd enabled"     "${d}/enabled-units.txt"   systemctl list-unit-files --state=enabled --no-pager
    dfir_cmd "systemd dependencies" "${d}/default-target-tree.txt" systemctl list-dependencies default.target --no-pager
    dfir_cmd "systemd config diff" "${d}/systemd-delta.txt"   systemd-delta --no-pager

    # Unit definition trees. /etc and /run take priority over vendor units and
    # are where operator- or attacker-created units live.
    local src
    for src in /etc/systemd/system /etc/systemd/user /run/systemd/system \
               /usr/local/lib/systemd/system /etc/systemd/system.conf.d; do
        [[ -d "$src" ]] && dfir_copy_tree "$src" "${d}/files/$(dfir_safe_name "${src#/}")"
    done
    dfir_copy /etc/systemd/system.conf "${d}/files/system.conf"
    dfir_copy /etc/systemd/user.conf   "${d}/files/user.conf"
    dfir_copy /etc/systemd/journald.conf "${d}/files/journald.conf"

    # Units whose files are not owned by any installed package.
    dfir_sh "unpackaged systemd units" "${d}/unpackaged-units.txt" '
        printf "Unit files with no owning package: operator-created, vendor-installed\n"
        printf "outside dpkg, or attacker-created persistence.\n\n"
        find /etc/systemd/system /run/systemd/system /lib/systemd/system \
             /usr/lib/systemd/system -maxdepth 2 -type f \
             \( -name "*.service" -o -name "*.timer" -o -name "*.socket" -o -name "*.path" \) \
             -print 2>/dev/null |
        dfir_filter_unpackaged |
        while read -r f; do
            printf "=== %s ===\n" "$f"
            stat -c "  owner=%U:%G mode=%A size=%s mtime=%y" "$f" 2>/dev/null
            sed -n "1,80p" "$f" 2>/dev/null | sed "s/^/  /"
            printf "\n"
        done
        exit 0'

    # ExecStart lines referencing interpreters, temp paths or network fetches.
    dfir_sh "suspicious unit ExecStart lines" "${d}/suspicious-execstart.txt" '
        grep -rHnE "^(ExecStart|ExecStartPre|ExecStartPost|ExecReload|ExecStop)=" \
            /etc/systemd/system /run/systemd/system /lib/systemd/system \
            /usr/lib/systemd/system 2>/dev/null |
        grep -EI "(/tmp/|/var/tmp/|/dev/shm/|curl |wget |nc |ncat |socat |base64|python|perl|ruby|php|bash -[ci]|sh -[ci]|/home/)" |
        sort -u
        exit 0'
}

# ---------------------------------------------------------------------------
# cron / at
# ---------------------------------------------------------------------------
_dfir_persist_cron() {
    local d="$1"; mkdir -p "$d"

    local src
    for src in /etc/crontab /etc/anacrontab; do
        dfir_copy "$src" "${d}/$(basename "$src")"
    done
    for src in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
               /etc/cron.monthly /etc/cron.deny /etc/cron.allow \
               /var/spool/cron /var/spool/anacron; do
        if [[ -d "$src" ]]; then
            dfir_copy_tree "$src" "${d}/$(dfir_safe_name "${src#/}")"
        elif [[ -f "$src" ]]; then
            dfir_copy "$src" "${d}/$(basename "$src")"
        fi
    done

    # Per-user crontabs via the crontab command (authoritative, covers all
    # spool layouts) - iterates every resolved profile, no hardcoded names.
    dfir_sh "per-user crontabs" "${d}/user-crontabs.txt" "
        while IFS=\$'\t' read -r u uid gid home shell; do
            printf '=== crontab -u %s ===\n' \"\$u\"
            crontab -l -u \"\$u\" 2>&1 | sed 's/^/  /'
            printf '\n'
        done < $(printf '%q' "$DFIR_USERS_TSV")
        exit 0"

    dfir_sh "at jobs" "${d}/at-jobs.txt" '
        atq 2>/dev/null || echo "atq unavailable"
        for f in /var/spool/cron/atjobs/* /var/spool/at/*; do
            [ -f "$f" ] || continue
            printf "\n=== %s ===\n" "$f"
            stat -c "  owner=%U mode=%A mtime=%y" "$f" 2>/dev/null
            cat "$f" 2>/dev/null | sed "s/^/  /"
        done
        exit 0'

    dfir_cmd "cron journal" "${d}/cron-journal.txt" \
        journalctl -u cron.service -u crond.service -u atd.service --no-pager -n 5000
}

# ---------------------------------------------------------------------------
# SysV init, rc scripts, upstart leftovers
# ---------------------------------------------------------------------------
_dfir_persist_initrc() {
    local d="$1"; mkdir -p "$d"

    local src
    for src in /etc/rc.local /etc/rc.common /etc/inittab; do
        dfir_copy "$src" "${d}/$(basename "$src")"
    done
    for src in /etc/init.d /etc/init /etc/rcS.d /etc/rc0.d /etc/rc1.d /etc/rc2.d \
               /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/update-motd.d; do
        [[ -d "$src" ]] && dfir_list_dir "$src" "${d}/$(dfir_safe_name "${src#/}")_listing.txt"
    done
    [[ -d /etc/init.d ]] && dfir_copy_tree /etc/init.d "${d}/init.d" 500
    [[ -d /etc/update-motd.d ]] && dfir_copy_tree /etc/update-motd.d "${d}/update-motd.d" 200
}

# ---------------------------------------------------------------------------
# Shell profile persistence (system scope)
# ---------------------------------------------------------------------------
_dfir_persist_shell() {
    local d="$1"; mkdir -p "$d"

    local src
    for src in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment \
               /etc/zsh/zshrc /etc/zsh/zshenv /etc/zsh/zprofile \
               /etc/csh.cshrc /etc/csh.login /etc/skel/.bashrc /etc/skel/.profile; do
        dfir_copy "$src" "${d}/$(dfir_safe_name "${src#/}")"
    done
    for src in /etc/profile.d /etc/environment.d /etc/zsh /etc/fish/conf.d; do
        [[ -d "$src" ]] && dfir_copy_tree "$src" "${d}/$(dfir_safe_name "${src#/}")" 300
    done

    dfir_sh "system profile suspicious entries" "${d}/suspicious-profile-entries.txt" '
        grep -rHnEI "(curl |wget |base64 |nc |ncat |socat |/dev/tcp/|eval |LD_PRELOAD|python -c|perl -e|bash -i)" \
            /etc/profile /etc/profile.d /etc/bash.bashrc /etc/environment /etc/zsh 2>/dev/null | sort -u
        exit 0'
}

# ---------------------------------------------------------------------------
# Dynamic linker hijacking
# ---------------------------------------------------------------------------
_dfir_persist_loader() {
    local d="$1"; mkdir -p "$d"

    # The RESULT: line is a machine-readable verdict for verify-evidence.sh;
    # it must be distinguishable from the command header, which echoes this
    # script's own source into the top of the output file.
    dfir_sh "ld.so.preload" "${d}/ld.so.preload.txt" '
        if [ -e /etc/ld.so.preload ]; then
            echo "RESULT: ld.so.preload=PRESENT"
            echo "/etc/ld.so.preload exists - classic rootkit persistence. Review now."
            stat -c "mode=%A owner=%U:%G size=%s mtime=%y" /etc/ld.so.preload
            echo "--- contents ---"
            cat /etc/ld.so.preload
        else
            echo "RESULT: ld.so.preload=absent"
            echo "/etc/ld.so.preload does not exist (expected on a clean host)."
        fi
        exit 0'
    dfir_copy /etc/ld.so.preload "${d}/ld.so.preload"
    dfir_copy /etc/ld.so.conf "${d}/ld.so.conf"
    [[ -d /etc/ld.so.conf.d ]] && dfir_copy_tree /etc/ld.so.conf.d "${d}/ld.so.conf.d" 200
    dfir_cmd "ldconfig cache" "${d}/ldconfig_cache.txt" ldconfig -p
}

# ---------------------------------------------------------------------------
# PAM / NSS / polkit / dbus
# ---------------------------------------------------------------------------
_dfir_persist_pam() {
    local d="$1"; mkdir -p "$d"

    [[ -d /etc/pam.d ]] && dfir_copy_tree /etc/pam.d "${d}/pam.d" 300
    [[ -d /etc/security ]] && dfir_copy_tree /etc/security "${d}/security" 300
    dfir_copy /etc/nsswitch.conf "${d}/nsswitch.conf"

    dfir_sh "pam modules not owned by a package" "${d}/unpackaged-pam-modules.txt" '
        printf "PAM modules with no owning package are a credential-theft vector\n"
        printf "(a malicious pam_unix replacement logs every password).\n\n"
        ls -1 /lib/*/security/*.so /lib/security/*.so /usr/lib/*/security/*.so 2>/dev/null |
        dfir_filter_unpackaged |
        while read -r f; do
            printf "UNPACKAGED %s\n" "$f"
            stat -c "  mode=%A owner=%U:%G size=%s mtime=%y" "$f"
            sha256sum "$f" 2>/dev/null | sed "s/^/  sha256 /"
        done
        exit 0'

    [[ -d /etc/polkit-1 ]] && dfir_copy_tree /etc/polkit-1 "${d}/polkit-1" 300
    [[ -d /etc/dbus-1 ]] && dfir_copy_tree /etc/dbus-1 "${d}/dbus-1" 300
    dfir_list_dir /usr/share/dbus-1/system-services "${d}/dbus-system-services.txt"
}

# ---------------------------------------------------------------------------
# Kernel modules
# ---------------------------------------------------------------------------
_dfir_persist_kernel() {
    local d="$1"; mkdir -p "$d"

    dfir_cmd "lsmod"          "${d}/lsmod.txt"        lsmod
    dfir_cmd "proc modules"   "${d}/proc_modules.txt" cat /proc/modules
    dfir_copy /etc/modules "${d}/etc_modules"
    [[ -d /etc/modules-load.d ]] && dfir_copy_tree /etc/modules-load.d "${d}/modules-load.d" 100
    [[ -d /etc/modprobe.d ]] && dfir_copy_tree /etc/modprobe.d "${d}/modprobe.d" 100

    dfir_sh "module details" "${d}/module-details.txt" '
        lsmod 2>/dev/null | tail -n +2 | awk "{print \$1}" | while read -r m; do
            printf "=== %s ===\n" "$m"
            modinfo "$m" 2>/dev/null | sed "s/^/  /"
            printf "\n"
        done
        exit 0'

    dfir_sh "unsigned or out-of-tree modules" "${d}/unpackaged-modules.txt" '
        printf "Kernel taint value: %s\n" "$(cat /proc/sys/kernel/tainted 2>/dev/null)"
        printf "(bit 12 = out-of-tree module, bit 13 = unsigned module)\n\n"
        lsmod 2>/dev/null | tail -n +2 | awk "{print \$1}" | while read -r m; do
            f=$(modinfo -n "$m" 2>/dev/null) || continue
            [ -n "$f" ] || continue
            sig=$(modinfo "$m" 2>/dev/null | awk -F": *" "/^sig_id|^signer/{print \$2}" | paste -sd, -)
            if ! dfir_is_packaged "$f"; then
                printf "UNPACKAGED %-24s %s (signer: %s)\n" "$m" "$f" "${sig:-none}"
            elif [ -z "$sig" ]; then
                printf "UNSIGNED   %-24s %s\n" "$m" "$f"
            fi
        done
        exit 0'
}

# ---------------------------------------------------------------------------
# udev, apt hooks, desktop autostart (system scope), motd, binfmt
# ---------------------------------------------------------------------------
_dfir_persist_misc() {
    local d="$1"; mkdir -p "$d"

    [[ -d /etc/udev/rules.d ]] && dfir_copy_tree /etc/udev/rules.d "${d}/udev-rules.d" 300
    dfir_sh "unpackaged udev rules" "${d}/unpackaged-udev-rules.txt" '
        printf "udev rules with no owning package (RUN+= gives arbitrary code execution\n"
        printf "on device events).\n\n"
        ls -1 /lib/udev/rules.d/* /usr/lib/udev/rules.d/* /etc/udev/rules.d/* 2>/dev/null |
        dfir_filter_unpackaged |
        while read -r f; do
            [ -f "$f" ] || continue
            printf "UNPACKAGED %s\n" "$f"
            sed "s/^/  /" "$f" 2>/dev/null
            printf "\n"
        done
        exit 0'

    [[ -d /etc/apt/apt.conf.d ]] && dfir_copy_tree /etc/apt/apt.conf.d "${d}/apt.conf.d" 200
    dfir_sh "apt hook commands" "${d}/apt-hooks.txt" '
        grep -rHnE "(Pre-Invoke|Post-Invoke|Pre-Install-Pkgs|DPkg::Post-Invoke)" \
            /etc/apt/apt.conf /etc/apt/apt.conf.d 2>/dev/null
        printf "\n--- dpkg hook directories ---\n"
        ls -la /etc/dpkg/dpkg.cfg.d 2>/dev/null
        exit 0'

    [[ -d /etc/xdg/autostart ]] && dfir_copy_tree /etc/xdg/autostart "${d}/xdg-autostart" 300
    [[ -d /etc/binfmt.d ]] && dfir_copy_tree /etc/binfmt.d "${d}/binfmt.d" 50
    [[ -d /etc/NetworkManager/dispatcher.d ]] && \
        dfir_copy_tree /etc/NetworkManager/dispatcher.d "${d}/nm-dispatcher.d" 100

    dfir_list_dir /etc/systemd/system-generators "${d}/systemd-generators.txt"
    dfir_list_dir /usr/lib/systemd/system-generators "${d}/systemd-generators-usr.txt"
    dfir_list_dir /etc/sudoers.d "${d}/sudoers.d_listing.txt"
}

# ---------------------------------------------------------------------------
# Analyst-facing rollup
# ---------------------------------------------------------------------------
_dfir_persist_summary() {
    local d="$1"
    {
        printf 'PERSISTENCE SWEEP SUMMARY\n=========================\n'
        printf 'Generated %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

        printf -- '--- systemd units enabled outside vendor paths ---\n'
        find /etc/systemd/system -maxdepth 2 \( -name '*.service' -o -name '*.timer' \) \
            -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | sort -r | head -n 100

        printf '\n--- /etc/ld.so.preload ---\n'
        if [[ -e /etc/ld.so.preload ]]; then
            printf 'PRESENT - review immediately\n'; cat /etc/ld.so.preload 2>/dev/null
        else
            printf 'absent\n'
        fi

        printf '\n--- cron entries (all sources, comments stripped) ---\n'
        {
            [[ -f /etc/crontab ]] && sed 's|^|/etc/crontab: |' /etc/crontab
            for f in /etc/cron.d/*; do
                [[ -f "$f" ]] && sed "s|^|${f}: |" "$f"
            done
            while IFS=$'\t' read -r u _ _ _ _; do
                crontab -l -u "$u" 2>/dev/null | sed "s|^|crontab(${u}): |"
            done <"$DFIR_USERS_TSV"
        } 2>/dev/null | grep -vE '^\S+: *(#|$)' | head -n 200

        printf '\n--- recently modified persistence locations (last 30 days) ---\n'
        find /etc/systemd /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/init.d \
             /etc/profile.d /etc/rc.local /etc/ld.so.conf.d /etc/udev/rules.d \
             /etc/pam.d /etc/sudoers.d /etc/apt/apt.conf.d \
             -xdev -type f -mtime -30 -printf '%TY-%Tm-%TdT%TH:%TM %10s %p\n' 2>/dev/null |
            sort -r | head -n 200

        printf '\n--- kernel taint ---\n'
        printf 'tainted=%s\n' "$(cat /proc/sys/kernel/tainted 2>/dev/null)"
    } | dfir_capture "persistence summary" "${d}/SUMMARY.txt"
}
