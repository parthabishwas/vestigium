#!/usr/bin/env bash
# 55-network.sh - Network configuration, connections and egress state (08_Network).

dfir_module_network() {
    local d="${DFIR_DIR[Network]}"

    # --- Interfaces and addressing ----------------------------------------
    dfir_cmd "ip addr"      "${d}/ip_addr.txt"      ip -d -s addr show
    dfir_cmd "ip link"      "${d}/ip_link.txt"      ip -d -s link show
    dfir_cmd "ip route v4"  "${d}/ip_route4.txt"    ip -4 route show table all
    dfir_cmd "ip route v6"  "${d}/ip_route6.txt"    ip -6 route show table all
    dfir_cmd "ip rule"      "${d}/ip_rule.txt"      ip rule show
    dfir_cmd "ip neighbour" "${d}/ip_neigh.txt"     ip neigh show
    dfir_cmd "arp table"    "${d}/arp.txt"          arp -an
    dfir_cmd "network namespaces" "${d}/ip_netns.txt" ip netns list

    # --- Sockets and owning processes -------------------------------------
    dfir_cmd "ss all sockets"     "${d}/ss_all.txt"        ss -tulpanew
    dfir_cmd "ss established"     "${d}/ss_established.txt" ss -tupan state established
    dfir_cmd "ss listening"       "${d}/ss_listening.txt"  ss -tulpn
    dfir_cmd "ss summary"         "${d}/ss_summary.txt"    ss -s
    dfir_cmd "ss unix sockets"    "${d}/ss_unix.txt"       ss -xap
    dfir_cmd "netstat fallback"   "${d}/netstat_anp.txt"   netstat -anp
    dfir_cmd "proc net tcp"       "${d}/proc_net_tcp.txt"  cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6

    # Listening services mapped to binary + package + hash. Rows are parsed
    # in-process: `ss -tulpnH` columns are Netid State Recv-Q Send-Q Local Peer
    # Process.
    local csv="${d}/listening_sockets.csv"
    dfir_csv_row "$csv" "Protocol" "LocalAddress" "LocalPort" "PID" "Process" "ExePath" "SHA256" "PackageOwner"
    local re_pid='pid=([0-9]+)' re_name='\(\("([^"]+)'
    local -A sha_cache=() owner_cache=()
    local proto local_addr procs port pid pname exe sha owner
    while read -r proto _ _ _ local_addr _ procs; do
        [[ -z "$proto" ]] && continue
        port="${local_addr##*:}"
        pid=""; pname=""
        [[ "$procs" =~ $re_pid ]] && pid="${BASH_REMATCH[1]}"
        [[ "$procs" =~ $re_name ]] && pname="${BASH_REMATCH[1]}"
        exe=""; sha=""; owner=""
        if [[ -n "$pid" && -e "/proc/${pid}/exe" ]]; then
            exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null)"
            if [[ -f "$exe" ]]; then
                if [[ -z "${sha_cache[$exe]+set}" ]]; then
                    sha="$(sha256sum -- "$exe" 2>/dev/null)"
                    sha_cache[$exe]="${sha%% *}"
                    owner_cache[$exe]="$(dfir_owning_package "$exe")"
                fi
                sha="${sha_cache[$exe]}"; owner="${owner_cache[$exe]}"
            fi
        fi
        dfir_csv_row "$csv" "$proto" "${local_addr%:*}" "$port" "$pid" "$pname" "$exe" "$sha" "$owner"
    done < <(ss -tulpnH 2>/dev/null)
    _dfir_record_cmd "listening socket inventory" "ss -tulpnH + /proc" "0" "0" "$csv"

    # Established connections with remote endpoints (egress evidence). With a
    # state filter ss drops the State column: Netid Recv-Q Send-Q Local Peer
    # Process.
    local ecsv="${d}/established_connections.csv"
    dfir_csv_row "$ecsv" "Protocol" "LocalAddress" "PeerAddress" "PeerHost" "PID" "Process" "ExePath"
    local peer peerhost
    while read -r proto _ _ local_addr peer procs; do
        [[ -z "$proto" ]] && continue
        pid=""; pname=""
        [[ "$procs" =~ $re_pid ]] && pid="${BASH_REMATCH[1]}"
        [[ "$procs" =~ $re_name ]] && pname="${BASH_REMATCH[1]}"
        exe=""
        [[ -n "$pid" ]] && exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null)"
        # PeerHost is deliberately left empty: the collector makes no DNS
        # lookups. Reverse lookups from a compromised host can tip off an
        # attacker who watches the resolver or controls the PTR zone; resolve
        # peers offline during analysis instead.
        peerhost=""
        dfir_csv_row "$ecsv" "$proto" "$local_addr" "$peer" "$peerhost" "$pid" "$pname" "$exe"
    done < <(ss -tupanH state established 2>/dev/null)
    _dfir_record_cmd "established connection inventory" "ss -tupanH state established" "0" "0" "$ecsv"

    # --- Firewall ----------------------------------------------------------
    dfir_cmd "iptables v4"    "${d}/iptables_save.txt"   iptables-save
    dfir_cmd "iptables v6"    "${d}/ip6tables_save.txt"  ip6tables-save
    dfir_cmd "nftables"       "${d}/nft_ruleset.txt"     nft list ruleset
    dfir_cmd "ufw status"     "${d}/ufw_status.txt"      ufw status verbose
    dfir_cmd "ufw rules"      "${d}/ufw_rules.txt"       ufw show raw
    [[ -d /etc/ufw ]] && dfir_copy_tree /etc/ufw "${d}/etc_ufw" 100
    dfir_copy /etc/nftables.conf "${d}/nftables.conf"

    # --- Managed connections, VPN and proxy -------------------------------
    dfir_cmd "nmcli devices"     "${d}/nmcli_devices.txt"     nmcli -f ALL device show
    dfir_cmd "nmcli connections" "${d}/nmcli_connections.txt" nmcli -f ALL connection show
    dfir_cmd "nmcli wifi"        "${d}/nmcli_wifi.txt"        nmcli -f ALL device wifi list
    dfir_list_dir /etc/NetworkManager/system-connections "${d}/nm_system_connections_listing.txt"
    dfir_sh "NetworkManager profiles (secrets redacted)" "${d}/nm_profiles_redacted.txt" '
        for f in /etc/NetworkManager/system-connections/*; do
            [ -f "$f" ] || continue
            printf "=== %s ===\n" "$f"
            stat -c "  mode=%A owner=%U:%G mtime=%y" "$f"
            sed -E "s/^(psk|password|password-raw|wep-key[0-9]*|private-key-password)=.*/\1=<REDACTED>/I" "$f" | sed "s/^/  /"
            printf "\n"
        done
        exit 0'
    [[ -d /etc/netplan ]] && dfir_copy_tree /etc/netplan "${d}/etc_netplan" 50
    [[ -d /etc/wpa_supplicant ]] && dfir_copy_tree /etc/wpa_supplicant "${d}/etc_wpa_supplicant" 50

    dfir_cmd "wireguard"       "${d}/wireguard.txt"    wg show all
    [[ -d /etc/wireguard ]] && dfir_list_dir /etc/wireguard "${d}/wireguard_listing.txt"
    [[ -d /etc/openvpn ]] && dfir_copy_tree /etc/openvpn "${d}/etc_openvpn" 100
    dfir_sh "proxy configuration" "${d}/proxy_configuration.txt" "
        printf -- '--- environment-wide proxy settings ---\n'
        grep -riE '(http_proxy|https_proxy|all_proxy|no_proxy)' /etc/environment /etc/profile /etc/profile.d /etc/apt/apt.conf.d 2>/dev/null
        printf -- '\n--- per-user GNOME proxy settings ---\n'
        while IFS=\$'\t' read -r u uid gid home shell; do
            printf 'user %s: ' \"\$u\"
            sudo -u \"\$u\" DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/\"\$uid\"/bus \
                gsettings get org.gnome.system.proxy mode 2>/dev/null || printf '(unavailable)\n'
        done < $(printf '%q' "$DFIR_USERS_TSV")
        printf -- '\n--- snap proxy settings ---\n'
        snap get system proxy 2>/dev/null || true
        exit 0"

    # --- Shares, RPC and discovery ----------------------------------------
    dfir_cmd "nfs exports"  "${d}/exports.txt"  exportfs -v
    dfir_cmd "rpc services" "${d}/rpcinfo.txt"  rpcinfo -p
    dfir_cmd "smb shares"   "${d}/smb_shares.txt" smbstatus --shares
    dfir_copy /etc/samba/smb.conf "${d}/smb.conf"
    dfir_cmd "avahi browse" "${d}/avahi.txt"    avahi-browse -atrp

    # --- Interface statistics and packet counters -------------------------
    dfir_cmd "interface stats" "${d}/proc_net_dev.txt" cat /proc/net/dev
    dfir_sh "promiscuous interfaces" "${d}/promiscuous_interfaces.txt" '
        found=0
        for i in /sys/class/net/*; do
            n=$(basename "$i")
            f=$(cat "$i/flags" 2>/dev/null) || continue
            if [ $(( $(printf "%d" "$f") & 0x100 )) -ne 0 ]; then
                printf "PROMISCUOUS: %s\n" "$n"; found=1
            fi
        done
        [ "$found" = 0 ] && echo "No interfaces in promiscuous mode."
        exit 0'

    return 0
}
