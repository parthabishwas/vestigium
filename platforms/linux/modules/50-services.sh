#!/usr/bin/env bash
# 50-services.sh - Service state (07_Services). Equivalent of Get-Service /
# Win32_Service / sc query.

dfir_module_services() {
    local d="${DFIR_DIR[Services]}"

    dfir_cmd "services (all)"      "${d}/services_all.txt"     systemctl list-units --type=service --all --no-pager
    dfir_cmd "services (running)"  "${d}/services_running.txt" systemctl list-units --type=service --state=running --no-pager
    dfir_cmd "services (failed)"   "${d}/services_failed.txt"  systemctl list-units --state=failed --no-pager
    dfir_cmd "unit files"          "${d}/unit_files.txt"       systemctl list-unit-files --no-pager
    dfir_cmd "systemd status"      "${d}/systemctl_status.txt" systemctl status --no-pager --full
    dfir_cmd "boot performance"    "${d}/systemd_analyze.txt"  systemd-analyze blame --no-pager
    dfir_cmd "sysv services"       "${d}/service_status_all.txt" service --status-all
    dfir_cmd "systemd environment" "${d}/systemd_environment.txt" systemctl show-environment

    # CSV inventory: unit, state, main PID, exec path, package owner.
    local csv="${d}/services_inventory.csv"
    dfir_csv_row "$csv" "Unit" "LoadState" "ActiveState" "SubState" "UnitFileState" \
        "MainPID" "User" "ExecStart" "FragmentPath" "PackageOwner"

    local unit props load active sub filestate pid user exec frag owner
    while read -r unit; do
        [[ -z "$unit" ]] && continue
        props="$(systemctl show "$unit" \
            -p LoadState -p ActiveState -p SubState -p UnitFileState -p MainPID \
            -p User -p ExecStart -p FragmentPath --no-pager 2>/dev/null)"
        load="$(sed -n 's/^LoadState=//p'      <<<"$props")"
        active="$(sed -n 's/^ActiveState=//p'  <<<"$props")"
        sub="$(sed -n 's/^SubState=//p'        <<<"$props")"
        filestate="$(sed -n 's/^UnitFileState=//p' <<<"$props")"
        pid="$(sed -n 's/^MainPID=//p'         <<<"$props")"
        user="$(sed -n 's/^User=//p'           <<<"$props")"
        exec="$(sed -n 's/^ExecStart=//p'      <<<"$props" | head -1)"
        frag="$(sed -n 's/^FragmentPath=//p'   <<<"$props")"
        owner=""
        [[ -n "$frag" && -f "$frag" ]] && owner="$(dfir_owning_package "$frag")"
        dfir_csv_row "$csv" "$unit" "$load" "$active" "$sub" "$filestate" \
            "$pid" "$user" "$exec" "$frag" "$owner"
    done < <(systemctl list-unit-files --type=service --no-pager 2>/dev/null |
             awk '$1 ~ /\.service$/ {print $1}')
    _dfir_record_cmd "service inventory" "systemctl show per unit" "0" "0" "$csv"

    # Full definition of every unit that is loaded, including drop-ins.
    dfir_sh "loaded unit definitions" "${d}/loaded_unit_definitions.txt" '
        systemctl list-units --type=service --all --no-pager 2>/dev/null |
        awk "\$1 ~ /\.service$/ {print \$1}" | sed "s/^●//" | while read -r u; do
            [ -n "$u" ] || continue
            printf "########## %s ##########\n" "$u"
            systemctl cat "$u" 2>/dev/null
            printf "\n"
        done
        exit 0'

    dfir_cmd "socket units" "${d}/socket_units.txt" systemctl list-units --type=socket --all --no-pager
    dfir_cmd "mount units"  "${d}/mount_units.txt"  systemctl list-units --type=mount --all --no-pager
    dfir_cmd "scope units"  "${d}/scope_units.txt"  systemctl list-units --type=scope --all --no-pager
    dfir_cmd "slice units"  "${d}/slice_units.txt"  systemctl list-units --type=slice --all --no-pager

    return 0
}
