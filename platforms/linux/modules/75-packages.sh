#!/usr/bin/env bash
# 75-packages.sh - Installed software, kernel state and environment
# (13_SystemInfo). Equivalent of systeminfo / driverquery / installed apps.

dfir_module_packages() {
    local d="${DFIR_DIR[SystemInfo]}"

    # --- APT / dpkg --------------------------------------------------------
    dfir_cmd "dpkg list"          "${d}/dpkg_list.txt"        dpkg -l
    dfir_cmd "dpkg selections"    "${d}/dpkg_selections.txt"  dpkg --get-selections
    dfir_cmd "manually installed" "${d}/apt_manual.txt"       apt-mark showmanual
    dfir_cmd "held packages"      "${d}/apt_hold.txt"         apt-mark showhold
    dfir_cmd "apt sources"        "${d}/apt_policy.txt"       apt-cache policy
    dfir_cmd "upgradable"         "${d}/apt_upgradable.txt"   apt list --upgradable

    local csv="${d}/installed_packages.csv"
    dfir_csv_row "$csv" "Package" "Version" "Architecture" "Status" "Origin" "InstalledSizeKB" "Description"
    dfir_sh "package inventory" "${d}/_pkg_raw.txt" \
        "dpkg-query -W -f='\${Package}\t\${Version}\t\${Architecture}\t\${db:Status-Abbrev}\t\${Origin}\t\${Installed-Size}\t\${binary:Summary}\n' 2>/dev/null" >/dev/null
    local pkg ver arch st origin size desc
    while IFS=$'\t' read -r pkg ver arch st origin size desc; do
        [[ -z "$pkg" ]] && continue
        dfir_csv_row "$csv" "$pkg" "$ver" "$arch" "$st" "$origin" "$size" "$desc"
    done < <(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${Origin}\t${Installed-Size}\t${binary:Summary}\n' 2>/dev/null)
    _dfir_record_cmd "package inventory" "dpkg-query -W" "0" "0" "$csv"
    rm -f "${d}/_pkg_raw.txt"

    # Installation timeline: what changed and when.
    dfir_sh "package install timeline" "${d}/package_timeline.txt" '
        printf -- "===== dpkg.log: install/remove/upgrade =====\n"
        for f in /var/log/dpkg.log.* /var/log/dpkg.log; do
            [ -f "$f" ] || continue
            case "$f" in
                *.gz) zcat "$f" 2>/dev/null ;;
                *) cat "$f" 2>/dev/null ;;
            esac
        done | grep -E " (install|remove|purge|upgrade) " | sort | tail -n 3000

        printf -- "\n===== apt history =====\n"
        for f in /var/log/apt/history.log.* /var/log/apt/history.log; do
            [ -f "$f" ] || continue
            case "$f" in
                *.gz) zcat "$f" 2>/dev/null ;;
                *) cat "$f" 2>/dev/null ;;
            esac
        done | tail -n 3000
        exit 0'

    dfir_sh "packages installed in the last 30 days" "${d}/recent_installs.txt" '
        cutoff=$(date -d "30 days ago" +%Y-%m-%d 2>/dev/null)
        grep -h " install " /var/log/dpkg.log /var/log/dpkg.log.1 2>/dev/null |
            awk -v c="$cutoff" "\$1 >= c" | sort
        exit 0'

    # --- Snap / flatpak / language-level package managers ------------------
    dfir_cmd "snap list"     "${d}/snap_list.txt"    snap list --all
    dfir_cmd "snap changes"  "${d}/snap_changes.txt" snap changes
    dfir_cmd "snap services" "${d}/snap_services.txt" snap services
    dfir_cmd "snap connections" "${d}/snap_connections.txt" snap connections
    dfir_cmd "flatpak list"  "${d}/flatpak_list.txt" flatpak list --columns=all
    dfir_cmd "flatpak remotes" "${d}/flatpak_remotes.txt" flatpak remotes -d
    dfir_sh  "appimage files" "${d}/appimages.txt" \
        "find /home /opt /usr/local /root -xdev -iname '*.AppImage' -printf '%TY-%Tm-%Td %10s %p\n' 2>/dev/null | sort -r | head -n 200; exit 0"

    dfir_sh "language package managers" "${d}/language_packages.txt" "
        printf -- '===== pip (system) =====\n'
        pip3 list 2>/dev/null || pip list 2>/dev/null || printf '(pip not installed)\n'
        printf -- '\n===== npm global =====\n'
        npm ls -g --depth=0 2>/dev/null || printf '(npm not installed)\n'
        printf -- '\n===== gem =====\n'
        gem list --local 2>/dev/null || printf '(gem not installed)\n'
        printf -- '\n===== per-user pip packages =====\n'
        while IFS=\$'\t' read -r u uid gid home shell; do
            [ -d \"\$home/.local/lib\" ] || continue
            printf -- '--- %s ---\n' \"\$u\"
            find \"\$home/.local/lib\" -maxdepth 3 -name '*.dist-info' -printf '  %f\n' 2>/dev/null | sort | head -n 200
        done < $(printf '%q' "$DFIR_USERS_TSV")
        exit 0"

    # --- Kernel, modules and drivers (driverquery analogue) ----------------
    dfir_cmd "loaded modules"    "${d}/lsmod.txt"          lsmod
    dfir_cmd "kernel versions"   "${d}/installed_kernels.txt" dpkg -l linux-image*
    dfir_cmd "hardware drivers"  "${d}/lshw.txt"           lshw -short
    dfir_cmd "pci drivers"       "${d}/lspci_drivers.txt"  lspci -k
    dfir_cmd "usb tree"          "${d}/lsusb_tree.txt"     lsusb -t
    dfir_sh  "module inventory"  "${d}/module_inventory.txt" '
        printf "%-28s %-10s %-12s %s\n" MODULE SIZE USEDBY PATH
        lsmod 2>/dev/null | tail -n +2 | while read -r name size used rest; do
            printf "%-28s %-10s %-12s %s\n" "$name" "$size" "$used" "$(modinfo -n "$name" 2>/dev/null)"
        done
        exit 0'

    # --- Environment and runtime state ------------------------------------
    dfir_sh "environment variables" "${d}/environment.txt" '
        printf -- "--- collector process environment ---\n"; env | sort
        printf -- "\n--- /etc/environment ---\n"; cat /etc/environment 2>/dev/null
        printf -- "\n--- systemd manager environment ---\n"; systemctl show-environment 2>/dev/null
        exit 0'
    dfir_cmd "limits"      "${d}/ulimit.txt"     bash -c "ulimit -a"
    dfir_cmd "locale"      "${d}/locale.txt"     locale
    dfir_cmd "alternatives" "${d}/alternatives.txt" update-alternatives --get-selections

    # --- systeminfo-style single-file overview -----------------------------
    {
        printf 'SOFTWARE AND KERNEL OVERVIEW\n============================\n\n'
        printf 'Distribution   : %s\n' "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
        printf 'Kernel         : %s\n' "$(uname -srvm)"
        printf 'Running kernel : %s\n' "$(uname -r)"
        printf 'Installed kernels:\n'
        dpkg -l 'linux-image-[0-9]*' 2>/dev/null | awk '/^ii/{printf "  %s %s\n", $2, $3}'
        printf '\nPackages installed: %s\n' "$(dpkg -l 2>/dev/null | grep -c '^ii')"
        printf 'Snaps installed   : %s\n' "$(snap list 2>/dev/null | tail -n +2 | wc -l)"
        printf 'Flatpaks installed: %s\n' "$(flatpak list 2>/dev/null | wc -l)"
        printf 'Kernel modules    : %s\n' "$(lsmod 2>/dev/null | tail -n +2 | wc -l)"
        printf 'Kernel taint      : %s\n' "$(cat /proc/sys/kernel/tainted 2>/dev/null)"
        printf '\n--- third-party apt repositories ---\n'
        grep -rhE '^\s*(deb|deb-src|URIs:)' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null |
            grep -vE 'archive\.ubuntu\.com|security\.ubuntu\.com|ports\.ubuntu\.com|\.launchpad\.net/ubuntu' | sort -u
        printf '\n--- last 20 package operations ---\n'
        grep -hE " (install|remove|purge) " /var/log/dpkg.log 2>/dev/null | tail -n 20
    } | dfir_capture "software overview" "${d}/SUMMARY.txt"

    return 0
}
