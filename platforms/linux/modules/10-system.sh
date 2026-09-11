#!/usr/bin/env bash
# 10-system.sh - Asset identification and host baseline (01_System).

dfir_module_system() {
    local d="${DFIR_DIR[System]}"

    # --- Identity and platform -------------------------------------------
    dfir_cmd "hostnamectl"        "${d}/hostnamectl.txt"        hostnamectl status
    dfir_cmd "uname"              "${d}/uname.txt"              uname -a
    dfir_cmd "uptime"             "${d}/uptime.txt"             uptime -p
    dfir_cmd "timedatectl"        "${d}/timedatectl.txt"        timedatectl status
    dfir_cmd "localectl"          "${d}/localectl.txt"          localectl status
    dfir_cmd "virtualisation"     "${d}/systemd-detect-virt.txt" systemd-detect-virt --vm --container
    dfir_cmd "current sessions"   "${d}/who.txt"                who -a
    dfir_cmd "logged-on detail"   "${d}/w.txt"                  w -i

    for f in /etc/os-release /etc/lsb-release /etc/machine-id /etc/hostname \
             /etc/timezone /proc/cmdline /proc/version /proc/uptime; do
        dfir_copy "$f" "${d}/etc/$(dfir_safe_name "${f#/}")"
    done

    # --- Hardware ---------------------------------------------------------
    dfir_cmd "dmidecode system"   "${d}/dmidecode_system.txt"   dmidecode -t system
    dfir_cmd "dmidecode bios"     "${d}/dmidecode_bios.txt"     dmidecode -t bios
    dfir_cmd "dmidecode baseboard" "${d}/dmidecode_baseboard.txt" dmidecode -t baseboard
    dfir_cmd "dmidecode chassis"  "${d}/dmidecode_chassis.txt"  dmidecode -t chassis
    dfir_cmd "dmidecode memory"   "${d}/dmidecode_memory.txt"   dmidecode -t memory
    dfir_cmd "lscpu"              "${d}/lscpu.txt"              lscpu
    dfir_cmd "lsmem"              "${d}/lsmem.txt"              lsmem
    dfir_cmd "meminfo"            "${d}/meminfo.txt"            cat /proc/meminfo
    dfir_cmd "free"               "${d}/free.txt"               free -h
    dfir_cmd "lspci"              "${d}/lspci.txt"              lspci -vnn
    dfir_cmd "lsusb"              "${d}/lsusb.txt"              lsusb -v
    dfir_cmd "usb history"        "${d}/usb_devices_journal.txt" journalctl -k --no-pager --grep 'usb|USB'

    # --- Storage ----------------------------------------------------------
    dfir_cmd "lsblk"              "${d}/lsblk.txt" \
        lsblk -o NAME,KNAME,MAJ:MIN,FSTYPE,LABEL,UUID,PARTUUID,SIZE,TYPE,MOUNTPOINTS,MODEL,SERIAL,ROTA,RM
    dfir_cmd "blkid"              "${d}/blkid.txt"              blkid
    dfir_cmd "df"                 "${d}/df.txt"                 df -hT
    dfir_cmd "swap"               "${d}/swapon.txt"             swapon --show

    # --- Boot / firmware integrity ---------------------------------------
    dfir_cmd "secure boot state"  "${d}/secureboot.txt"         mokutil --sb-state
    if [[ -d /sys/firmware/efi ]]; then
        dfir_cmd "efi variables"  "${d}/efivars.txt"            efibootmgr -v
    else
        printf 'This host booted in legacy BIOS mode; no EFI variables exist.\n' \
            >"${d}/efivars.txt"
        dfir_log INFO "Legacy BIOS boot: efibootmgr not applicable"
    fi
    dfir_cmd "boot history"       "${d}/boot_history.txt"       journalctl --list-boots --no-pager
    dfir_sh  "last boots"         "${d}/last_reboot.txt"        "last -Fxw reboot shutdown 2>/dev/null | head -n 100"

    # --- Asset summary (single-file overview for the case file) ----------
    {
        printf 'ASSET INFORMATION\n=================\n\n'
        printf '%-22s %s\n' "Collected (UTC)"  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '%-22s %s\n' "Collected (local)" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf '%-22s %s\n' "Case ID"          "$DFIR_CASE_ID"
        printf '%-22s %s\n' "Operator"         "$DFIR_OPERATOR"
        printf '\n--- Host ---\n'
        printf '%-22s %s\n' "Hostname"         "$DFIR_HOSTNAME"
        printf '%-22s %s\n' "FQDN"             "$(hostname -f 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Machine ID"       "$(cat /etc/machine-id 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Boot ID"          "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "OS"               "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
        printf '%-22s %s\n' "Kernel"           "$(uname -r) $(uname -v)"
        printf '%-22s %s\n' "Architecture"     "$(uname -m)"
        printf '%-22s %s\n' "Install date"     "$(stat -c %y /var/log/installer/syslog 2>/dev/null || stat -c %y /etc/machine-id 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Last boot"        "$(uptime -s 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Uptime"           "$(uptime -p 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Timezone"         "$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Time synced"      "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Virtualisation"   "$(systemd-detect-virt 2>/dev/null || echo unknown)"

        printf '\n--- Hardware ---\n'
        printf '%-22s %s\n' "Manufacturer"     "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Model"            "$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Product version"  "$(cat /sys/class/dmi/id/product_version 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Serial number"    "$(cat /sys/class/dmi/id/product_serial 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "UUID"             "$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Baseboard serial" "$(cat /sys/class/dmi/id/board_serial 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "Chassis serial"   "$(cat /sys/class/dmi/id/chassis_serial 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "BIOS vendor"      "$(cat /sys/class/dmi/id/bios_vendor 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "BIOS version"     "$(cat /sys/class/dmi/id/bios_version 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "BIOS date"        "$(cat /sys/class/dmi/id/bios_date 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "UEFI boot"        "$([[ -d /sys/firmware/efi ]] && echo yes || echo 'no (legacy BIOS)')"
        printf '%-22s %s\n' "Secure Boot"      "$(mokutil --sb-state 2>/dev/null | head -1 || echo unknown)"
        printf '%-22s %s\n' "CPU"              "$(lscpu 2>/dev/null | awk -F': +' '/^Model name/{print $2; exit}')"
        printf '%-22s %s\n' "CPU cores"        "$(nproc 2>/dev/null || echo unknown)"
        printf '%-22s %s\n' "RAM"              "$(free -h 2>/dev/null | awk '/^Mem:/{print $2}')"

        printf '\n--- Disks ---\n'
        lsblk -d -o NAME,SIZE,TYPE,ROTA,RM,MODEL,SERIAL 2>/dev/null

        printf '\n--- Filesystems ---\n'
        df -hT -x tmpfs -x devtmpfs 2>/dev/null

        printf '\n--- Network interfaces ---\n'
        local ifc
        for ifc in /sys/class/net/*; do
            [[ -e "$ifc" ]] || continue
            printf '%-14s mac=%-18s state=%-6s ipv4=%s\n' \
                "$(basename "$ifc")" \
                "$(cat "$ifc/address" 2>/dev/null || echo -)" \
                "$(cat "$ifc/operstate" 2>/dev/null || echo -)" \
                "$(ip -4 -o addr show dev "$(basename "$ifc")" 2>/dev/null | awk '{print $4}' | paste -sd, - )"
        done

        printf '\n--- Accounts examined ---\n'
        awk -F'\t' '{printf "%-24s uid=%-6s gid=%-6s home=%-28s shell=%s\n", $1, $2, $3, $4, $5}' \
            "$DFIR_USERS_TSV" 2>/dev/null

        printf '\n--- Currently logged on ---\n'
        who -a 2>/dev/null
    } | dfir_capture "asset summary" "${d}/AssetInfo.txt"

    return 0
}
