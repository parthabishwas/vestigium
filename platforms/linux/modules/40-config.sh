#!/usr/bin/env bash
# 40-config.sh - System configuration state (05_Config) and name resolution
# artifacts (11_Hosts). Linux analogue of the Windows registry hive export.

dfir_module_config() {
    local d="${DFIR_DIR[Config]}"
    local h="${DFIR_DIR[Hosts]}"

    # --- Account and authorisation databases ------------------------------
    # /etc/shadow and /etc/gshadow contain password hashes. They are collected
    # because account tampering is in scope; the evidence tree is mode 700 and
    # the archive mode 600. Remove them if your engagement rules forbid hashes.
    local f
    for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/subuid /etc/subgid \
             /etc/login.defs /etc/adduser.conf /etc/nsswitch.conf /etc/sudoers \
             /etc/securetty /etc/shells /etc/hosts.allow /etc/hosts.deny; do
        dfir_copy "$f" "${d}/etc/$(dfir_safe_name "${f#/}")"
    done
    [[ -d /etc/sudoers.d ]] && dfir_copy_tree /etc/sudoers.d "${d}/etc/sudoers.d" 200
    [[ -d /etc/sssd ]] && dfir_copy_tree /etc/sssd "${d}/etc/sssd" 50
    [[ -d /etc/krb5.conf.d ]] && dfir_copy_tree /etc/krb5.conf.d "${d}/etc/krb5.conf.d" 50
    dfir_copy /etc/krb5.conf "${d}/etc/krb5.conf"

    dfir_cmd "sudoers parse check" "${d}/sudo_check.txt" visudo -c
    dfir_sh  "effective sudo rules" "${d}/sudo_rules.txt" '
        grep -rhvE "^\s*(#|$)" /etc/sudoers /etc/sudoers.d 2>/dev/null
        printf "\n--- accounts with NOPASSWD or ALL privileges ---\n"
        grep -rhnE "NOPASSWD|ALL\s*=\s*\(ALL" /etc/sudoers /etc/sudoers.d 2>/dev/null
        exit 0'

    # --- SSH ---------------------------------------------------------------
    [[ -d /etc/ssh ]] && dfir_copy_tree /etc/ssh "${d}/etc/ssh" 200
    dfir_cmd "sshd effective config" "${d}/sshd_effective_config.txt" sshd -T
    dfir_sh "ssh host key fingerprints" "${d}/ssh_host_key_fingerprints.txt" '
        for k in /etc/ssh/*.pub; do [ -f "$k" ] && ssh-keygen -lf "$k" 2>/dev/null; done
        exit 0'

    # --- Kernel and system tunables ---------------------------------------
    dfir_cmd "sysctl all" "${d}/sysctl_all.txt" sysctl -a
    dfir_copy /etc/sysctl.conf "${d}/etc/sysctl.conf"
    [[ -d /etc/sysctl.d ]] && dfir_copy_tree /etc/sysctl.d "${d}/etc/sysctl.d" 100
    dfir_sh "security-relevant tunables" "${d}/security_tunables.txt" '
        for k in kernel.yama.ptrace_scope kernel.kptr_restrict kernel.dmesg_restrict \
                 kernel.unprivileged_bpf_disabled kernel.randomize_va_space \
                 kernel.modules_disabled fs.protected_hardlinks fs.protected_symlinks \
                 fs.suid_dumpable net.ipv4.ip_forward net.ipv4.conf.all.rp_filter \
                 net.ipv4.conf.all.accept_redirects net.ipv6.conf.all.disable_ipv6; do
            printf "%-46s %s\n" "$k" "$(sysctl -n "$k" 2>/dev/null || echo "(unset)")"
        done
        exit 0'

    # --- Boot, mount and default configuration ----------------------------
    for f in /etc/fstab /etc/crypttab /etc/mtab /etc/default/grub /etc/hosts \
             /etc/hostname /etc/resolv.conf /etc/nftables.conf; do
        dfir_copy "$f" "${d}/etc/$(dfir_safe_name "${f#/}")"
    done
    [[ -d /etc/default ]] && dfir_copy_tree /etc/default "${d}/etc/default" 200
    [[ -d /etc/grub.d ]] && dfir_copy_tree /etc/grub.d "${d}/etc/grub.d" 50

    # --- Package sources (rogue repositories are a supply-chain indicator) -
    dfir_copy /etc/apt/sources.list "${d}/apt/sources.list"
    [[ -d /etc/apt/sources.list.d ]] && dfir_copy_tree /etc/apt/sources.list.d "${d}/apt/sources.list.d" 100
    [[ -d /etc/apt/preferences.d ]] && dfir_copy_tree /etc/apt/preferences.d "${d}/apt/preferences.d" 100
    [[ -d /etc/apt/auth.conf.d ]] && dfir_list_dir /etc/apt/auth.conf.d "${d}/apt/auth.conf.d_listing.txt"
    dfir_sh "apt signing keys" "${d}/apt/signing_keys.txt" '
        apt-key list 2>/dev/null
        printf "\n--- keyring files ---\n"
        ls -la /etc/apt/trusted.gpg.d /usr/share/keyrings 2>/dev/null
        for k in /etc/apt/trusted.gpg.d/*.gpg /etc/apt/trusted.gpg.d/*.asc; do
            [ -f "$k" ] || continue
            printf "\n=== %s ===\n" "$k"
            gpg --show-keys --with-fingerprint "$k" 2>/dev/null || true
        done
        exit 0'

    # --- Trust stores: a rogue CA enables TLS interception ----------------
    dfir_sh "custom trusted CAs" "${d}/trusted_ca_review.txt" '
        printf -- "--- locally added CA certificates (/usr/local/share/ca-certificates) ---\n"
        ls -la /usr/local/share/ca-certificates 2>/dev/null
        for c in /usr/local/share/ca-certificates/*; do
            [ -f "$c" ] || continue
            printf "\n=== %s ===\n" "$c"
            openssl x509 -in "$c" -noout -subject -issuer -dates -fingerprint 2>/dev/null
        done
        printf "\n--- certificates in /etc/ssl/certs not owned by a package ---\n"
        for c in /etc/ssl/certs/*.pem /etc/ssl/certs/*.crt; do
            [ -f "$c" ] || continue
            [ -L "$c" ] && continue
            dfir_is_packaged "$c" || {
                printf "UNPACKAGED %s\n" "$c"
                openssl x509 -in "$c" -noout -subject -issuer -dates 2>/dev/null | sed "s/^/    /"
            }
        done
        printf "\n--- ca-certificates.conf disabled/enabled entries ---\n"
        cat /etc/ca-certificates.conf 2>/dev/null | grep -vE "^\s*(#|$)" | tail -n 50
        exit 0'
    [[ -d /usr/local/share/ca-certificates ]] && \
        dfir_copy_tree /usr/local/share/ca-certificates "${d}/ca-certificates-local" 100

    # --- Desktop-wide policy ----------------------------------------------
    [[ -d /etc/dconf ]] && dfir_copy_tree /etc/dconf "${d}/etc/dconf" 100
    [[ -d /etc/gdm3 ]] && dfir_copy_tree /etc/gdm3 "${d}/etc/gdm3" 50
    [[ -d /etc/opt/chrome/policies ]] && dfir_copy_tree /etc/opt/chrome/policies "${d}/policies/chrome" 100
    [[ -d /etc/chromium/policies ]] && dfir_copy_tree /etc/chromium/policies "${d}/policies/chromium" 100
    [[ -d /etc/opt/edge/policies ]] && dfir_copy_tree /etc/opt/edge/policies "${d}/policies/edge" 100
    [[ -d /etc/firefox/policies ]] && dfir_copy_tree /etc/firefox/policies "${d}/policies/firefox" 100
    [[ -d /usr/lib/firefox/distribution ]] && dfir_copy_tree /usr/lib/firefox/distribution "${d}/policies/firefox-distribution" 50

    # --- Name resolution (11_Hosts) ---------------------------------------
    for f in /etc/hosts /etc/hosts.allow /etc/hosts.deny /etc/resolv.conf \
             /etc/nsswitch.conf /etc/networks /etc/gai.conf; do
        dfir_copy "$f" "${h}/$(dfir_safe_name "${f#/}")"
    done
    dfir_copy /run/systemd/resolve/stub-resolv.conf "${h}/stub-resolv.conf"
    dfir_copy /run/systemd/resolve/resolv.conf "${h}/systemd-resolved-resolv.conf"
    dfir_cmd "resolvectl status"     "${h}/resolvectl_status.txt"     resolvectl status
    dfir_cmd "resolvectl statistics" "${h}/resolvectl_statistics.txt" resolvectl statistics
    dfir_cmd "resolvectl dns"        "${h}/resolvectl_dns.txt"        resolvectl dns
    dfir_sh "hosts file review" "${h}/hosts_review.txt" '
        printf -- "--- non-default /etc/hosts entries ---\n"
        grep -vE "^\s*(#|$)" /etc/hosts 2>/dev/null |
            grep -vE "^\s*(127\.0\.0\.1|127\.0\.1\.1|::1|fe00::|ff00::|ff02::)\s" || \
            printf "(none beyond loopback defaults)\n"
        printf "\n--- /etc/hosts metadata ---\n"
        stat -c "mode=%A owner=%U:%G size=%s mtime=%y" /etc/hosts 2>/dev/null
        exit 0'

    return 0
}
