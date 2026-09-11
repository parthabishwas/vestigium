#!/usr/bin/env bash
# 35-startup.sh - Per-user session startup and autostart artifacts (04_Startup).
# Equivalent of the Windows per-profile Startup folder / HKCU Run collection.

dfir_module_startup() {
    dfir_each_user _dfir_startup_for_user
    _dfir_startup_summary
    return 0
}

_dfir_startup_for_user() {
    local user="$1" uid="$2" gid="$3" home="$4" shell="$5"
    local d
    d="${DFIR_DIR[Startup]}/$(dfir_safe_name "$user")"
    mkdir -p "$d"

    {
        printf 'user=%s\nuid=%s\ngid=%s\nhome=%s\nshell=%s\n' "$user" "$uid" "$gid" "$home" "$shell"
        printf 'home_owner=%s\nhome_mode=%s\n' \
            "$(stat -c %U:%G "$home" 2>/dev/null)" "$(stat -c %A "$home" 2>/dev/null)"
    } >"${d}/_profile.txt"

    # --- Shell login/interactive files -----------------------------------
    local f
    for f in .bashrc .bash_profile .bash_login .bash_logout .profile .zshrc .zshenv \
             .zprofile .zlogin .zlogout .kshrc .cshrc .tcshrc .inputrc .selected_editor \
             .xsessionrc .xprofile .xinitrc .Xsession .gtkrc-2.0 .pam_environment; do
        dfir_copy "${home}/${f}" "${d}/shell/${f}"
    done
    [[ -d "${home}/.config/fish" ]] && dfir_copy_tree "${home}/.config/fish" "${d}/shell/fish" 100
    [[ -d "${home}/.bashrc.d" ]] && dfir_copy_tree "${home}/.bashrc.d" "${d}/shell/bashrc.d" 100

    # --- XDG desktop autostart -------------------------------------------
    [[ -d "${home}/.config/autostart" ]] && \
        dfir_copy_tree "${home}/.config/autostart" "${d}/autostart" 200
    [[ -d "${home}/.local/share/applications" ]] && \
        dfir_copy_tree "${home}/.local/share/applications" "${d}/local-applications" 300
    [[ -d "${home}/.config/autostart-scripts" ]] && \
        dfir_copy_tree "${home}/.config/autostart-scripts" "${d}/autostart-scripts" 100

    # --- User systemd units and timers ------------------------------------
    [[ -d "${home}/.config/systemd/user" ]] && \
        dfir_copy_tree "${home}/.config/systemd/user" "${d}/systemd-user" 300
    [[ -d "${home}/.local/share/systemd/user" ]] && \
        dfir_copy_tree "${home}/.local/share/systemd/user" "${d}/systemd-user-local" 300

    dfir_sh "systemd --user units for ${user}" "${d}/systemd-user-units.txt" \
        "systemctl --user --machine=$(printf '%q' "$user")@ list-unit-files --no-pager 2>&1 || \
         echo 'user manager not reachable (no active session for this account)'"

    # --- Per-user crontab -------------------------------------------------
    dfir_sh "crontab for ${user}" "${d}/crontab.txt" \
        "crontab -l -u $(printf '%q' "$user") 2>&1; exit 0"

    # --- Desktop environment autostart extras ----------------------------
    [[ -d "${home}/.config/plasma-workspace/env" ]] && \
        dfir_copy_tree "${home}/.config/plasma-workspace/env" "${d}/plasma-env" 50
    [[ -d "${home}/.local/share/gnome-shell/extensions" ]] && \
        dfir_list_dir "${home}/.local/share/gnome-shell/extensions" "${d}/gnome-shell-extensions.txt" -maxdepth 2

    # --- Snap/flatpak user overrides --------------------------------------
    [[ -d "${home}/.local/share/flatpak/overrides" ]] && \
        dfir_copy_tree "${home}/.local/share/flatpak/overrides" "${d}/flatpak-overrides" 50
}

_dfir_startup_summary() {
    local out="${DFIR_DIR[Startup]}/SUMMARY.txt"
    {
        printf 'PER-USER STARTUP SUMMARY\n========================\n\n'
        local row user uid gid home shell
        for row in "${DFIR_USER_ROWS[@]}"; do
            IFS=$'\t' read -r user uid gid home shell <<<"$row"
            printf '### %s (uid %s, home %s)\n' "$user" "$uid" "$home"

            printf '  autostart entries:\n'
            if [[ -d "${home}/.config/autostart" ]]; then
                grep -H '^Exec=' "${home}"/.config/autostart/*.desktop 2>/dev/null | sed 's/^/    /' \
                    || printf '    (none)\n'
            else
                printf '    (no ~/.config/autostart)\n'
            fi

            printf '  user systemd units:\n'
            find "${home}/.config/systemd/user" -maxdepth 1 -type f -printf '    %f\n' 2>/dev/null \
                || printf '    (none)\n'

            printf '  crontab:\n'
            crontab -l -u "$user" 2>/dev/null | grep -vE '^\s*(#|$)' | sed 's/^/    /' \
                || printf '    (none)\n'

            printf '  shell rc files containing network or encoding commands:\n'
            grep -lEI '(curl |wget |base64 |/dev/tcp/|nc |ncat |socat |python -c|perl -e)' \
                "${home}"/.bashrc "${home}"/.profile "${home}"/.bash_profile "${home}"/.zshrc 2>/dev/null |
                sed 's/^/    HIT: /' || printf '    (none)\n'
            printf '\n'
        done
    } | dfir_capture "startup summary" "$out"
}
