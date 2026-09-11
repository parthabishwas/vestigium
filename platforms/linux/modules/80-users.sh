#!/usr/bin/env bash
# 80-users.sh - Account state and per-user activity artifacts (14_Users).

dfir_module_users() {
    local d="${DFIR_DIR[Users]}"

    _dfir_users_accounts "${d}/accounts"
    dfir_each_user _dfir_users_profile
    _dfir_users_live_shell_history "${d}/live-shell-history"
    _dfir_users_summary "${d}"
    return 0
}

# ---------------------------------------------------------------------------
_dfir_users_live_shell_history() {
    # On-disk history can be switched off (HISTFILE=/dev/null, HISTSIZE=0,
    # `set +o history`), but a live interactive shell still holds its history
    # in memory. For every interactive shell process this records the history
    # settings from its environment, flags the ones whose on-disk history is
    # disabled (HISTORY-DISABLED marker lines in SUMMARY.txt), and, best effort,
    # carves candidate command lines from the process heap.
    local d="$1"; mkdir -p "$d"
    local summary="${d}/SUMMARY.txt"
    local carver="${DFIR_TOOLS}/recover-shell-history.py"
    local have_py=0; dfir_have python3 && [[ -f "$carver" ]] && have_py=1

    {
        printf 'LIVE INTERACTIVE SHELLS AND THEIR HISTORY SETTINGS\n'
        printf '==================================================\n'
        printf 'Generated %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'Carving of in-memory history: %s\n\n' \
            "$([[ $have_py == 1 ]] && echo 'enabled (best effort, see pid*.txt)' || echo 'unavailable (python3 or the carver is missing)')"
    } >"$summary"

    local p pid comm statline tty argv0 cmdline user uid home
    local histfile histsize histfilesize histcontrol disabled reason shells=0 flagged=0
    for p in /proc/[0-9]*; do
        pid="${p#/proc/}"
        comm="$(tr -d '\0' <"${p}/comm" 2>/dev/null)" || continue
        case "$comm" in bash|zsh|sh|dash|ksh|mksh|fish) ;; *) continue ;; esac

        # Decide whether this shell is an interactive session worth carving.
        # A controlling tty (stat field 7 after the comm) is the common case, but
        # a login shell (argv0 starts with -), an explicit -i, or a shell whose
        # stdin/stdout is a SOCKET (the classic tty-less reverse shell) all count
        # too - missing those would skip exactly the shells an attacker uses. A
        # plain `bash script.sh` under cron/CI matches none of these.
        read -r statline <"${p}/stat" 2>/dev/null || continue
        statline="${statline##*) }"; read -r _ _ _ _ tty _ <<<"$statline"
        mapfile -d '' -t argv <"${p}/cmdline" 2>/dev/null
        argv0="${argv[0]:-}"
        local why="" fd0 fd1
        [[ "${tty:-0}" != 0 ]] && why="tty"
        [[ "$argv0" == -* ]] && why="${why:+$why,}login"
        case " ${argv[*]} " in *" -i "*) why="${why:+$why,}interactive" ;; esac
        fd0="$(readlink "${p}/fd/0" 2>/dev/null)"; fd1="$(readlink "${p}/fd/1" 2>/dev/null)"
        [[ "$fd0" == socket:* || "$fd1" == socket:* ]] && why="${why:+$why,}socket(possible reverse shell)"
        [[ -z "$why" ]] && continue
        cmdline="${argv[*]}"
        shells=$((shells + 1))

        uid="$(awk '/^Uid:/{print $2}' "${p}/status" 2>/dev/null)"
        user="$(getent passwd "${uid:-x}" 2>/dev/null | cut -d: -f1)"; user="${user:-uid${uid}}"
        home="$(getent passwd "${uid:-x}" 2>/dev/null | cut -d: -f6)"

        # Shell variables are not exported by default, so only an explicit
        # anti-forensic value in the environment counts as evidence.
        histfile="$(tr '\0' '\n' <"${p}/environ" 2>/dev/null | sed -n 's/^HISTFILE=//p' | head -n 1)"
        histsize="$(tr '\0' '\n' <"${p}/environ" 2>/dev/null | sed -n 's/^HISTSIZE=//p' | head -n 1)"
        histfilesize="$(tr '\0' '\n' <"${p}/environ" 2>/dev/null | sed -n 's/^HISTFILESIZE=//p' | head -n 1)"
        histcontrol="$(tr '\0' '\n' <"${p}/environ" 2>/dev/null | sed -n 's/^HISTCONTROL=//p' | head -n 1)"
        local histfile_set=0
        tr '\0' '\n' <"${p}/environ" 2>/dev/null | grep -q '^HISTFILE=' && histfile_set=1

        disabled=0; reason=""
        if (( histfile_set == 1 )) && [[ -z "$histfile" || "$histfile" == /dev/null ]]; then
            disabled=1; reason="HISTFILE=${histfile:-(empty)} in the environment"
        elif [[ "$histsize" == 0 || "$histfilesize" == 0 ]]; then
            disabled=1; reason="HISTSIZE/HISTFILESIZE=0 in the environment"
        elif [[ -n "$home" ]]; then
            local hf
            case "$comm" in zsh) hf="${home}/.zsh_history" ;; fish) hf="" ;; *) hf="${home}/.bash_history" ;; esac
            if [[ -n "$hf" && -L "$hf" && "$(readlink "$hf" 2>/dev/null)" == /dev/null ]]; then
                disabled=1; reason="${hf} is a symlink to /dev/null"
            fi
        fi

        local out
        out="${d}/pid${pid}_$(dfir_safe_name "$user").txt"
        {
            printf 'pid=%s user=%s shell=%s interactive_because=%s\ncmdline=%s\ncwd=%s\n' "$pid" "$user" "$comm" "$why" "$cmdline" \
                "$(readlink "${p}/cwd" 2>/dev/null)"
            printf 'HISTFILE=%s\nHISTSIZE=%s\nHISTFILESIZE=%s\nHISTCONTROL=%s\n' \
                "$([[ $histfile_set == 1 ]] && printf '%s' "$histfile" || echo '(not in environment)')" \
                "${histsize:-(not in environment)}" "${histfilesize:-(not in environment)}" "${histcontrol:-(not in environment)}"
            printf 'on_disk_history=%s\n\n' "$([[ $disabled == 1 ]] && echo "DISABLED: ${reason}" || echo 'enabled or default')"
            if (( have_py == 1 )); then
                printf -- '--- candidate command lines carved from process memory (best effort, address order) ---\n'
                timeout 120 python3 "$carver" --pid "$pid" 2>&1
            fi
        } >"$out"
        _dfir_record_cmd "live shell history pid ${pid}" "environ + heap carve" "0" "0" "$out"

        if (( disabled == 1 )); then
            flagged=$((flagged + 1))
            printf 'HISTORY-DISABLED %s pid=%s shell=%s histfile=%s reason=%s\n' \
                "$user" "$pid" "$comm" "${histfile:-(unset)}" "$reason" >>"$summary"
        fi
    done

    printf '\nInteractive shells examined: %s; on-disk history disabled: %s\n' "$shells" "$flagged" >>"$summary"
    _dfir_record_cmd "live shell history summary" "interactive shells vs history settings" "0" "0" "$summary"
    return 0
}

# ---------------------------------------------------------------------------
_dfir_users_accounts() {
    local d="$1"; mkdir -p "$d"

    dfir_cmd "passwd database" "${d}/getent_passwd.txt" getent passwd
    dfir_cmd "group database"  "${d}/getent_group.txt"  getent group
    dfir_cmd "shadow database" "${d}/getent_shadow.txt" getent shadow

    dfir_sh "account analysis" "${d}/account_analysis.txt" '
        printf -- "===== accounts with UID 0 (root equivalents) =====\n"
        getent passwd | awk -F: "\$3 == 0 {print}"

        printf -- "\n===== accounts with an interactive shell =====\n"
        getent passwd | awk -F: "\$7 !~ /(nologin|false|sync|halt|shutdown)$/ {printf \"%-22s uid=%-6s home=%-28s shell=%s\n\", \$1, \$3, \$6, \$7}"

        printf -- "\n===== accounts with no password set =====\n"
        awk -F: "\$2 == \"\" {print \$1 \" HAS AN EMPTY PASSWORD FIELD\"}" /etc/shadow 2>/dev/null || true

        printf -- "\n===== accounts with a password hash =====\n"
        awk -F: "\$2 ~ /^\\\$/ {printf \"%-22s hash_algo=%s last_change_days=%s\n\", \$1, substr(\$2,1,3), \$3}" /etc/shadow 2>/dev/null

        printf -- "\n===== locked accounts =====\n"
        awk -F: "\$2 ~ /^[!*]/ {print \$1}" /etc/shadow 2>/dev/null | paste -sd\" \" -

        printf -- "\n===== administrative group membership =====\n"
        for g in sudo admin wheel adm root lpadmin docker lxd libvirt sambashare; do
            m=$(getent group "$g" 2>/dev/null | cut -d: -f4)
            [ -n "$m" ] && printf "%-14s %s\n" "$g:" "$m"
        done

        printf -- "\n===== password aging =====\n"
        getent passwd | awk -F: "\$3 >= 1000 && \$3 < 65000 {print \$1}" | while read -r u; do
            printf -- "--- %s ---\n" "$u"
            chage -l "$u" 2>/dev/null | sed "s/^/  /"
        done

        printf -- "\n===== /etc/passwd and /etc/shadow modification times =====\n"
        stat -c "%n mtime=%y ctime=%z" /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers 2>/dev/null
        exit 0'

    dfir_sh "duplicate uids and gids" "${d}/duplicate_ids.txt" '
        printf -- "--- duplicate UIDs ---\n"
        getent passwd | cut -d: -f3 | sort | uniq -d | while read -r id; do
            getent passwd | awk -F: -v i="$id" "\$3 == i {print}"
        done
        printf -- "\n--- duplicate usernames ---\n"
        getent passwd | cut -d: -f1 | sort | uniq -d
        printf -- "\n--- duplicate GIDs ---\n"
        getent group | cut -d: -f3 | sort | uniq -d
        exit 0'
}

# ---------------------------------------------------------------------------
_dfir_users_profile() {
    local user="$1" uid="$2" gid="$3" home="$4" shell="$5"
    local d
    d="${DFIR_DIR[Users]}/profiles/$(dfir_safe_name "$user")"
    mkdir -p "$d"

    {
        printf 'user=%s\nuid=%s\ngid=%s\nhome=%s\nshell=%s\n' "$user" "$uid" "$gid" "$home" "$shell"
        printf 'groups=%s\n' "$(id -nG "$user" 2>/dev/null)"
        printf 'home_owner=%s\nhome_mode=%s\n' \
            "$(stat -c %U:%G "$home" 2>/dev/null)" "$(stat -c %A "$home" 2>/dev/null)"
        printf 'last_login=%s\n' "$(lastlog -u "$user" 2>/dev/null | tail -n +2)"
    } >"${d}/_profile.txt"

    # --- Command history --------------------------------------------------
    local hist
    for hist in .bash_history .zsh_history .sh_history .ash_history .history \
                .python_history .node_repl_history .mysql_history .psql_history \
                .sqlite_history .rediscli_history .lesshst .viminfo .wget-hsts \
                .local/share/fish/fish_history; do
        dfir_copy "${home}/${hist}" "${d}/history/$(dfir_safe_name "$hist")"
    done

    # --- SSH: keys and trust relationships --------------------------------
    if [[ -d "${home}/.ssh" ]]; then
        dfir_list_dir "${home}/.ssh" "${d}/ssh_listing.txt"
        local f
        for f in authorized_keys authorized_keys2 known_hosts known_hosts.old config \
                 environment rc; do
            dfir_copy "${home}/.ssh/${f}" "${d}/ssh/${f}"
        done
        # Public keys are collected; private key material is recorded as
        # metadata and fingerprint only.
        dfir_sh "ssh key inventory ${user}" "${d}/ssh_key_inventory.txt" "
            for k in $(printf '%q' "${home}/.ssh")/*; do
                [ -f \"\$k\" ] || continue
                case \"\$k\" in
                    *.pub) printf 'PUBLIC  %s : %s\n' \"\$k\" \"\$(ssh-keygen -lf \"\$k\" 2>/dev/null)\" ;;
                    *authorized_keys*|*known_hosts*|*config*) : ;;
                    *)
                        if head -1 \"\$k\" 2>/dev/null | grep -q 'PRIVATE KEY'; then
                            printf 'PRIVATE %s : %s (content NOT collected)\n' \"\$k\" \
                                \"\$(ssh-keygen -lf \"\$k\" 2>/dev/null || echo 'fingerprint unavailable')\"
                            stat -c '        mode=%A owner=%U:%G size=%s mtime=%y' \"\$k\" 2>/dev/null
                        fi ;;
                esac
            done
            exit 0"
    fi

    # --- Cloud / developer credential locations: metadata only ------------
    dfir_sh "credential file inventory ${user}" "${d}/credential_locations.txt" "
        printf 'Credential-bearing locations (metadata only, contents NOT collected)\n\n'
        for p in .aws .config/gcloud .azure .kube .docker/config.json .npmrc .pypirc \
                 .git-credentials .netrc .my.cnf .pgpass .gnupg .password-store \
                 .local/share/keyrings .config/rclone .ssh/id_rsa .ssh/id_ed25519 \
                 .mozilla/firefox .config/Bitwarden .config/1Password .config/KeePass; do
            t=$(printf '%q' "$home")/\$p
            [ -e \"\$t\" ] || continue
            printf '%s\n' \"\$t\"
            find \"\$t\" -maxdepth 2 -printf '    %M %u:%g %10s %TY-%Tm-%TdT%TH:%TM %p\n' 2>/dev/null | head -n 40
        done
        exit 0"

    # --- Desktop and file access activity ---------------------------------
    dfir_copy "${home}/.local/share/recently-used.xbel" "${d}/recently-used.xbel"
    dfir_copy "${home}/.config/user-dirs.dirs" "${d}/user-dirs.dirs"
    [[ -d "${home}/.local/share/gvfs-metadata" ]] && \
        dfir_list_dir "${home}/.local/share/gvfs-metadata" "${d}/gvfs_metadata_listing.txt"

    dfir_sh "trash contents ${user}" "${d}/trash_listing.txt" "
        for t in $(printf '%q' "${home}")/.local/share/Trash $(printf '%q' "${home}")/.Trash; do
            [ -d \"\$t\" ] || continue
            printf '=== %s ===\n' \"\$t\"
            find \"\$t\" -printf '%TY-%Tm-%TdT%TH:%TM %10s %p\n' 2>/dev/null | sort -r | head -n 500
        done
        exit 0"
    [[ -d "${home}/.local/share/Trash/info" ]] && \
        dfir_copy_tree "${home}/.local/share/Trash/info" "${d}/trash-info" 500

    # --- Downloads and Desktop: what arrived on the machine ---------------
    local dir
    for dir in Downloads Desktop Documents Pictures Videos Music Public Templates; do
        [[ -d "${home}/${dir}" ]] || continue
        dfir_sh "listing ${dir} (${user})" "${d}/listing_${dir}.txt" \
            "find $(printf '%q' "${home}/${dir}") -xdev -printf '%TY-%Tm-%TdT%TH:%TM  %10s  %M %u:%g  %p\n' 2>/dev/null | sort -r | head -n 5000"
    done

    # Hash every file in Downloads: the primary malware ingress path.
    dfir_sh "Downloads hashes (${user})" "${d}/downloads_hashes.txt" "
        d=$(printf '%q' "${home}/Downloads")
        [ -d \"\$d\" ] || { echo '(no Downloads directory)'; exit 0; }
        find \"\$d\" -xdev -type f -size -256M -printf '%p\n' 2>/dev/null | head -n 2000 |
            while IFS= read -r f; do
                printf '%s  %s  %s\n' \
                    \"\$(sha256sum -- \"\$f\" 2>/dev/null | awk '{print \$1}')\" \
                    \"\$(stat -c '%y' \"\$f\" 2>/dev/null | cut -d. -f1)\" \"\$f\"
            done
        exit 0"

    # --- Hidden files and dot-directories ---------------------------------
    dfir_sh "hidden entries in home (${user})" "${d}/hidden_entries.txt" \
        "find $(printf '%q' "$home") -maxdepth 2 -name '.*' -printf '%M %u:%g %10s %TY-%Tm-%TdT%TH:%TM %p\n' 2>/dev/null | sort -k5"

    # --- GNOME keyring / secret storage: presence only --------------------
    [[ -d "${home}/.local/share/keyrings" ]] && \
        dfir_sh "keyring metadata (${user})" "${d}/keyring_metadata.txt" \
            "ls -la $(printf '%q' "${home}/.local/share/keyrings") 2>/dev/null; echo; echo 'Keyring contents are deliberately NOT collected.'; exit 0"
}

# ---------------------------------------------------------------------------
_dfir_users_summary() {
    local d="$1"
    {
        printf 'ACCOUNT SUMMARY\n===============\n\n'
        printf '%-22s %-7s %-30s %-24s %s\n' USER UID HOME SHELL "LAST LOGIN"
        local row user uid gid home shell
        for row in "${DFIR_USER_ROWS[@]}"; do
            IFS=$'\t' read -r user uid gid home shell <<<"$row"
            printf '%-22s %-7s %-30s %-24s %s\n' "$user" "$uid" "$home" "$shell" \
                "$(lastlog -u "$user" 2>/dev/null | tail -n +2 | awk '{$1=""; print}' | sed 's/^ *//')"
        done

        printf '\n--- sudo-capable accounts ---\n'
        getent group sudo admin wheel 2>/dev/null | awk -F: '{printf "  %-10s %s\n", $1, $4}'

        printf '\n--- accounts created or modified in the last 90 days ---\n'
        find /home -maxdepth 1 -mindepth 1 -ctime -90 -printf '  %TY-%Tm-%Td %p\n' 2>/dev/null
        grep -hE "useradd|usermod" /var/log/auth.log* 2>/dev/null | tail -n 30

        printf '\n--- shell history sizes ---\n'
        for row in "${DFIR_USER_ROWS[@]}"; do
            IFS=$'\t' read -r user uid gid home shell <<<"$row"
            local h
            for h in .bash_history .zsh_history; do
                [[ -f "${home}/${h}" ]] && printf '  %-22s %-16s %8s bytes  %s lines  mtime %s\n' \
                    "$user" "$h" "$(stat -c %s "${home}/${h}" 2>/dev/null)" \
                    "$(wc -l <"${home}/${h}" 2>/dev/null)" \
                    "$(stat -c %y "${home}/${h}" 2>/dev/null | cut -d. -f1)"
            done
            # A history file symlinked to /dev/null is deliberate evidence destruction.
            for h in .bash_history .zsh_history; do
                if [[ -L "${home}/${h}" ]]; then
                    printf '  %-22s %-16s SYMLINK -> %s (history disabled)\n' \
                        "$user" "$h" "$(readlink "${home}/${h}")"
                fi
            done
        done
    } | dfir_capture "account summary" "${d}/SUMMARY.txt"
}
