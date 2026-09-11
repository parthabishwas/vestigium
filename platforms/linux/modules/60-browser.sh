#!/usr/bin/env bash
# 60-browser.sh - Browser artifacts (09_Browser).
#
# Scope policy (the same on Linux and Windows; see docs/DATA-HANDLING.md):
#   ALWAYS  : extension inventories and manifests, native messaging hosts,
#             browser policies, profile inventories, preference files,
#             certificate stores, and size/timestamps/SHA256 of every
#             credential and session store.
#   DEFAULT : credential stores - saved passwords, cookies, autofill/payment
#             data (Login Data, Cookies, Network/Cookies, Web Data, key4.db,
#             logins.json, cookies.sqlite, ...) and the raw Local State are
#             COPIED, as the Windows collector does. With
#             --credential-stores metadata (DFIR_CREDENTIAL_STORES=metadata)
#             only their metadata is recorded.
#             Browsing history / downloads / bookmarks are copied too (disable
#             with --no-browser-history).
#   OPT-IN  : session stores - Chromium Current/Last Session, Current/Last
#             Tabs and Sessions/, Firefox sessionstore.jsonlz4 and
#             sessionstore-backups/. Only their metadata is recorded unless
#             --browser-sessions (DFIR_BROWSER_SESSIONS=1) is given.

# Credential stores, relative to the profile directory; current Chromium keeps
# its cookie and trust-token stores under Network/. Journals and WAL files are
# listed so a copied SQLite database is consistent.
DFIR_BROWSER_CREDENTIAL_FILES=(
    "Login Data" "Login Data For Account" "Login Data-journal"
    "Login Data For Account-journal"
    "Cookies" "Cookies-journal" "Network/Cookies" "Network/Cookies-journal"
    "Trust Tokens" "Trust Tokens-journal" "Network/Trust Tokens" "Network/Trust Tokens-journal"
    "Web Data" "Web Data-journal" "Affiliation Database" "Network Action Predictor"
    "logins.json" "logins-backup.json" "key3.db" "key4.db"
    "cookies.sqlite" "cookies.sqlite-wal" "formhistory.sqlite"
    "signons.sqlite" "credentialstate.sqlite"
)

# Session stores: metadata by default, copied only with --browser-sessions.
# An entry ending in "/*" covers every file in that sub-directory.
DFIR_BROWSER_SESSION_FILES=(
    "Current Session" "Current Tabs" "Last Session" "Last Tabs" "Sessions/*"
    "sessionstore.jsonlz4" "sessionstore-backups/*"
)

# Chromium files copied unless --no-browser-history is supplied.
DFIR_BROWSER_HISTORY_FILES=(
    "History" "History-journal" "Archived History" "Top Sites" "Shortcuts"
    "Visited Links" "Bookmarks" "Bookmarks.bak" "Preferences" "Secure Preferences"
)

dfir_module_browser() {
    dfir_each_user _dfir_browser_for_user
    _dfir_browser_system_policies
    _dfir_browser_summary
    return 0
}

_dfir_browser_copy_credentials() {
    [[ "${DFIR_CREDENTIAL_STORES:-copy}" == copy ]]
}

# ---------------------------------------------------------------------------
_dfir_browser_for_user() {
    local user="$1" home="$4"
    local base
    base="${DFIR_DIR[Browser]}/$(dfir_safe_name "$user")"

    # Chromium-family user-data roots: native packages, snap and flatpak.
    local -a chromium_roots=(
        "Chrome|${home}/.config/google-chrome"
        "Chrome-Beta|${home}/.config/google-chrome-beta"
        "Chrome-Unstable|${home}/.config/google-chrome-unstable"
        "Chromium|${home}/.config/chromium"
        "Chromium-Snap|${home}/snap/chromium/common/chromium"
        "Edge|${home}/.config/microsoft-edge"
        "Edge-Dev|${home}/.config/microsoft-edge-dev"
        "Brave|${home}/.config/BraveSoftware/Brave-Browser"
        "Brave-Snap|${home}/snap/brave/current/.config/BraveSoftware/Brave-Browser"
        "Opera|${home}/.config/opera"
        "Vivaldi|${home}/.config/vivaldi"
        "Chrome-Flatpak|${home}/.var/app/com.google.Chrome/config/google-chrome"
        "Chromium-Flatpak|${home}/.var/app/org.chromium.Chromium/config/chromium"
        "Edge-Flatpak|${home}/.var/app/com.microsoft.Edge/config/microsoft-edge"
        "Brave-Flatpak|${home}/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"
    )
    local entry
    for entry in "${chromium_roots[@]}"; do
        _dfir_browser_chromium "$user" "${entry%%|*}" "${entry#*|}" "$base"
    done

    local -a firefox_roots=(
        "Firefox|${home}/.mozilla/firefox"
        "Firefox-Snap|${home}/snap/firefox/common/.mozilla/firefox"
        "Firefox-Flatpak|${home}/.var/app/org.mozilla.firefox/.mozilla/firefox"
        "Thunderbird|${home}/.thunderbird"
    )
    for entry in "${firefox_roots[@]}"; do
        _dfir_browser_firefox "$user" "${entry%%|*}" "${entry#*|}" "$base"
    done

    # Native messaging hosts: a documented browser-to-local-binary bridge and a
    # recurring infostealer / exfiltration mechanism.
    local nm
    for nm in "${home}/.config/google-chrome/NativeMessagingHosts" \
              "${home}/.config/chromium/NativeMessagingHosts" \
              "${home}/.config/microsoft-edge/NativeMessagingHosts" \
              "${home}/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts" \
              "${home}/.mozilla/native-messaging-hosts" \
              "${home}/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts"; do
        [[ -d "$nm" ]] && dfir_copy_tree "$nm" "${base}/native-messaging/$(dfir_safe_name "${nm#"$home"/}")" 100
    done
}

# ---------------------------------------------------------------------------
_dfir_browser_chromium() {
    local user="$1" browser="$2" root="$3" base="$4"
    [[ -d "$root" ]] || return 0

    local out="${base}/${browser}"
    mkdir -p "$out"
    dfir_log INFO "Chromium-family profile found: ${browser} (${root})"
    printf 'user_data_root=%s\n' "$root" >"${out}/_source.txt"

    # Local State names every profile and the signed-in account. A readable
    # copy with the credential-decryption keys (DPAPI-style and app-bound)
    # redacted is always written; the raw file is copied as well when
    # credential stores are copied, since those keys belong with the stores.
    if [[ -f "${root}/Local State" ]]; then
        dfir_record_provenance "${root}/Local State" "${out}/Local_State.redacted.json"
        if dfir_have python3; then
            python3 "${DFIR_TOOLS}/browser-json.py" redact-local-state \
                "${root}/Local State" >"${out}/Local_State.redacted.json" 2>/dev/null
        else
            sed -E 's/"(app_bound_encrypted_key|encrypted_key)":"[^"]*"/"\1":"<REDACTED>"/g' \
                "${root}/Local State" >"${out}/Local_State.redacted.json" 2>/dev/null
        fi
        _dfir_browser_copy_credentials && dfir_copy "${root}/Local State" "${out}/credential-stores/Local State"
    fi

    # Profile directories are those containing a Preferences file.
    local profile pname pout
    while IFS= read -r profile; do
        [[ -z "$profile" ]] && continue
        pname="$(basename "$profile")"
        pout="${out}/$(dfir_safe_name "$pname")"
        mkdir -p "$pout"

        # Extension manifests.
        local extroot="${profile}/Extensions"
        if [[ -d "$extroot" ]]; then
            local manifest rel
            while IFS= read -r -d '' manifest; do
                rel="${manifest#"$extroot"/}"
                dfir_copy "$manifest" "${pout}/extensions/${rel}"
                printf '%s\t%s\t%s\t%s\n' "$browser" "$user" "$pname" "$manifest" \
                    >>"${DFIR_DIR[Browser]}/_chromium_manifests.tsv"
            done < <(find "$extroot" -mindepth 3 -maxdepth 3 -name manifest.json -print0 2>/dev/null)

            dfir_list_dir "$extroot" "${pout}/extensions_listing.txt" -maxdepth 3
        fi

        # Preference files describe extension state, startup URLs, search engine
        # hijacking and proxy overrides.
        local pf
        for pf in "Preferences" "Secure Preferences"; do
            [[ -f "${profile}/${pf}" ]] && dfir_copy "${profile}/${pf}" "${pout}/$(dfir_safe_name "$pf").json"
        done
        if [[ -f "${profile}/Preferences" ]] && dfir_have python3; then
            python3 "${DFIR_TOOLS}/browser-json.py" chromium-prefs "${profile}/Preferences" \
                >"${pout}/preferences_highlights.txt" 2>/dev/null
        fi

        # Managed policies applied to this profile.
        [[ -d "${profile}/Policy" ]] && dfir_copy_tree "${profile}/Policy" "${pout}/Policy" 50

        # Full metadata inventory of every file in the profile (no content).
        dfir_sh "profile inventory ${browser}/${pname} (${user})" "${pout}/profile_file_inventory.txt" \
            "find $(printf '%q' "$profile") -maxdepth 1 -type f -printf '%10s  %TY-%Tm-%TdT%TH:%TM:%TS  %p\n' 2>/dev/null | sort -k3"

        # Optional history/bookmark acquisition.
        if [[ "$DFIR_BROWSER_HISTORY" == 1 ]]; then
            local hf
            for hf in "${DFIR_BROWSER_HISTORY_FILES[@]}"; do
                [[ -f "${profile}/${hf}" ]] && dfir_copy "${profile}/${hf}" "${pout}/history/${hf}"
            done
        fi

        # Session stores: metadata, plus contents only with --browser-sessions.
        _dfir_browser_session_stores "$profile" "$pout"

        # Credential stores: metadata always, contents per --credential-stores.
        _dfir_browser_credential_stores "$profile" "$pout"

    done < <(find "$root" -mindepth 1 -maxdepth 1 -type d \
                \( -name 'Default' -o -name 'Profile *' -o -name 'System Profile' -o -name 'Guest Profile' \) 2>/dev/null)
}

# ---------------------------------------------------------------------------
_dfir_browser_firefox() {
    local user="$1" browser="$2" root="$3" base="$4"
    [[ -d "$root" ]] || return 0

    local out="${base}/${browser}"
    mkdir -p "$out"
    dfir_log INFO "Mozilla profile root found: ${browser} (${root})"
    printf 'profile_root=%s\n' "$root" >"${out}/_source.txt"

    dfir_copy "${root}/profiles.ini" "${out}/profiles.ini"
    dfir_copy "${root}/installs.ini" "${out}/installs.ini"

    local profile pname pout
    while IFS= read -r profile; do
        [[ -z "$profile" ]] && continue
        pname="$(basename "$profile")"
        pout="${out}/$(dfir_safe_name "$pname")"
        mkdir -p "$pout"

        local f
        for f in extensions.json addons.json extension-preferences.json \
                 extension-settings.json addonStartup.json.lz4 prefs.js user.js \
                 handlers.json search.json.mozlz4 containers.json permissions.sqlite \
                 cert9.db pkcs11.txt times.json compatibility.ini; do
            [[ -f "${profile}/${f}" ]] && dfir_copy "${profile}/${f}" "${pout}/${f}"
        done

        # Installed add-on packages (XPI) and unpacked extension directories.
        if [[ -d "${profile}/extensions" ]]; then
            dfir_list_dir "${profile}/extensions" "${pout}/extensions_listing.txt" -maxdepth 2
            dfir_copy_tree "${profile}/extensions" "${pout}/extensions" 400
        fi

        # Parse extensions.json into the shared inventory.
        if [[ -f "${profile}/extensions.json" ]]; then
            printf '%s\t%s\t%s\t%s\n' "$browser" "$user" "$pname" "${profile}/extensions.json" \
                >>"${DFIR_DIR[Browser]}/_firefox_addons.tsv"
        fi

        # prefs.js highlights: proxy, homepage, search, update and policy keys.
        if [[ -f "${profile}/prefs.js" ]]; then
            dfir_sh "prefs.js highlights ${pname} (${user})" "${pout}/prefs_highlights.txt" \
                "grep -E '(proxy|homepage|startup\\.homepage|keyword\\.URL|browser\\.search|extensions\\.|xpinstall|security\\.|network\\.dns|autoconfig)' $(printf '%q' "${profile}/prefs.js") 2>/dev/null | sort"
        fi

        dfir_sh "profile inventory ${browser}/${pname} (${user})" "${pout}/profile_file_inventory.txt" \
            "find $(printf '%q' "$profile") -maxdepth 1 -type f -printf '%10s  %TY-%Tm-%TdT%TH:%TM:%TS  %p\n' 2>/dev/null | sort -k3"

        if [[ "$DFIR_BROWSER_HISTORY" == 1 ]]; then
            for f in places.sqlite places.sqlite-wal downloads.sqlite; do
                [[ -f "${profile}/${f}" ]] && dfir_copy "${profile}/${f}" "${pout}/history/${f}"
            done
        fi

        # sessionstore.jsonlz4 / sessionstore-backups hold session cookies and
        # form data: metadata only unless --browser-sessions.
        _dfir_browser_session_stores "$profile" "$pout"

        # logins.json + key4.db, cookies.sqlite, formhistory.sqlite: metadata
        # always, contents per --credential-stores.
        _dfir_browser_credential_stores "$profile" "$pout"

    done < <(find "$root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | grep -vE '/(Crash Reports|Pending Pings)$')
}

# ---------------------------------------------------------------------------
_dfir_browser_file_metadata() {
    # _dfir_browser_file_metadata PROFILE TITLE ENTRY...   (report on stdout)
    # Records existence, size, timestamps and hash of each store, so tampering
    # and timeline questions stay answerable whether or not it is copied.
    # ENTRY is relative to PROFILE, may name a sub-path ("Network/Cookies"), or
    # may end in "/*" to cover every file in a sub-directory ("Sessions/*").
    local profile="$1" title="$2"; shift 2
    printf '%s\n' "$title"
    printf 'Profile: %s\n\n' "$profile"
    local entry p sha
    local -a hits
    for entry in "$@"; do
        hits=()
        if [[ "$entry" == */\* ]]; then
            [[ -d "${profile}/${entry%/\*}" ]] || continue
            for p in "${profile}/${entry%/\*}"/*; do
                [[ -f "$p" ]] && hits+=("$p")
            done
        elif [[ -e "${profile}/${entry}" ]]; then
            hits=("${profile}/${entry}")
        fi
        for p in "${hits[@]}"; do
            sha="$(sha256sum -- "$p" 2>/dev/null)"
            printf '%-34s size=%-12s mtime=%s\n' "${p#"$profile"/}" \
                "$(stat -c %s "$p" 2>/dev/null)" "$(stat -c %y "$p" 2>/dev/null)"
            printf '%-34s sha256=%s\n' "" "${sha%% *}"
        done
    done
}

_dfir_browser_credential_stores() {
    # _dfir_browser_credential_stores PROFILE PROFILE_OUT
    # Always writes credential_store_metadata.txt. With the default policy
    # (--credential-stores copy) the stores are also copied into
    # PROFILE_OUT/credential-stores/, with provenance and SHA256 like every
    # other acquired file; --credential-stores metadata stops at the metadata.
    local profile="$1" pout="$2"
    local out="${pout}/credential_store_metadata.txt" title
    if _dfir_browser_copy_credentials; then
        title='Credential store metadata (contents COPIED to credential-stores/; --credential-stores metadata records metadata only)'
    else
        title='Credential store metadata (contents NOT collected: --credential-stores metadata)'
    fi
    _dfir_browser_file_metadata "$profile" "$title" "${DFIR_BROWSER_CREDENTIAL_FILES[@]}" >"$out"
    _dfir_record_cmd "credential store metadata" "stat/sha256 of credential stores" "0" "0" "$out"

    _dfir_browser_copy_credentials || return 0
    local entry
    for entry in "${DFIR_BROWSER_CREDENTIAL_FILES[@]}"; do
        [[ -f "${profile}/${entry}" ]] && dfir_copy "${profile}/${entry}" "${pout}/credential-stores/${entry}"
    done
    return 0
}

_dfir_browser_session_stores() {
    # _dfir_browser_session_stores PROFILE PROFILE_OUT
    # Always writes session_store_metadata.txt; copies the stores into
    # PROFILE_OUT/sessions/ only when DFIR_BROWSER_SESSIONS=1.
    local profile="$1" pout="$2"
    local out="${pout}/session_store_metadata.txt" title
    if [[ "${DFIR_BROWSER_SESSIONS:-0}" == 1 ]]; then
        title='Session store metadata (contents COPIED to sessions/ because --browser-sessions was given)'
    else
        title='Session store metadata (contents NOT collected: they embed session cookies and form data; use --browser-sessions)'
    fi
    _dfir_browser_file_metadata "$profile" "$title" "${DFIR_BROWSER_SESSION_FILES[@]}" >"$out"
    _dfir_record_cmd "session store metadata" "stat/sha256 of session stores" "0" "0" "$out"

    [[ "${DFIR_BROWSER_SESSIONS:-0}" == 1 ]] || return 0
    local entry
    for entry in "${DFIR_BROWSER_SESSION_FILES[@]}"; do
        if [[ "$entry" == */\* ]]; then
            [[ -d "${profile}/${entry%/\*}" ]] && \
                dfir_copy_tree "${profile}/${entry%/\*}" "${pout}/sessions/${entry%/\*}" 100
        elif [[ -f "${profile}/${entry}" ]]; then
            dfir_copy "${profile}/${entry}" "${pout}/sessions/${entry}"
        fi
    done
    return 0
}

# ---------------------------------------------------------------------------
_dfir_browser_system_policies() {
    local d="${DFIR_DIR[Browser]}/_system"
    mkdir -p "$d"
    local p
    for p in /etc/opt/chrome/policies /etc/chromium/policies /etc/opt/edge/policies \
             /etc/brave/policies /etc/firefox/policies /usr/lib/firefox/distribution \
             /etc/opt/chrome/native-messaging-hosts /etc/chromium/native-messaging-hosts \
             /usr/lib/mozilla/native-messaging-hosts /etc/opt/edge/native-messaging-hosts; do
        [[ -d "$p" ]] && dfir_copy_tree "$p" "${d}/$(dfir_safe_name "${p#/}")" 100
    done
    dfir_sh "installed browser packages" "${d}/installed_browsers.txt" '
        dpkg -l 2>/dev/null | grep -iE "chrome|chromium|firefox|edge|brave|opera|vivaldi|thunderbird" || true
        printf "\n--- snap ---\n"
        snap list 2>/dev/null | grep -iE "chrom|firefox|brave|edge|opera" || true
        printf "\n--- flatpak ---\n"
        flatpak list 2>/dev/null | grep -iE "chrom|firefox|brave|edge|opera" || true
        exit 0'
}

# ---------------------------------------------------------------------------
_dfir_browser_summary() {
    local d="${DFIR_DIR[Browser]}"
    local ext_csv="${d}/extensions_inventory.csv"

    if dfir_have python3; then
        python3 "${DFIR_TOOLS}/browser-json.py" build-inventory \
            --chromium "${d}/_chromium_manifests.tsv" \
            --firefox  "${d}/_firefox_addons.tsv" \
            --out "$ext_csv" 2>>"$DFIR_LOGFILE"
        _dfir_record_cmd "extension inventory" "browser-json.py build-inventory" "0" "0" "$ext_csv"
    else
        dfir_log WARN "python3 unavailable: extension inventory limited to copied manifests"
    fi
    rm -f "${d}/_chromium_manifests.tsv" "${d}/_firefox_addons.tsv"

    {
        printf 'BROWSER ARTIFACT SUMMARY\n========================\n\n'
        printf 'History/bookmark acquisition: %s\n' \
            "$([[ "$DFIR_BROWSER_HISTORY" == 1 ]] && echo 'collected (default)' || echo 'DISABLED (--no-browser-history)')"
        if [[ "${DFIR_BROWSER_SESSIONS:-0}" == 1 ]]; then
            printf 'Session stores (open tabs, session cookies, form data): COLLECTED (--browser-sessions)\n'
            printf '  Copies under */sessions/ contain live session cookies: handle this package as credential material.\n'
        else
            printf 'Session stores (open tabs, session cookies, form data): NOT collected (metadata only; --browser-sessions to collect)\n'
        fi
        if _dfir_browser_copy_credentials; then
            printf 'Password, cookie, token and autofill stores: COPIED to */credential-stores/ (default; --credential-stores metadata to disable)\n'
            printf '  This package contains browser credential material: store, transfer and destroy it accordingly.\n\n'
        else
            printf 'Password, cookie, token and autofill stores: NOT collected (metadata only; --credential-stores metadata)\n\n'
        fi

        printf -- '--- profiles discovered ---\n'
        find "$d" -maxdepth 3 -name '_source.txt' -printf '%h\n' 2>/dev/null |
            sed "s|^${d}/||" | sort

        if [[ -f "$ext_csv" ]]; then
            printf '\n--- extension count by browser ---\n'
            awk -F'","' 'NR>1 {gsub(/^"/,"",$1); print $1}' "$ext_csv" 2>/dev/null | sort | uniq -c | sort -rn

            printf '\n--- extensions requesting high-risk permissions ---\n'
            awk -F'","' 'NR>1 && ($8 ~ /<all_urls>|webRequest|cookies|nativeMessaging|debugger|proxy|clipboardRead|management|tabCapture|desktopCapture/ || $9 ~ /<all_urls>|\*:\/\/\*\//) {
                gsub(/"/,"",$1); gsub(/"/,"",$2); gsub(/"/,"",$4); gsub(/"/,"",$6);
                printf "  %-16s %-14s %-34s %s\n", $1, $2, $6, $4 }' "$ext_csv" 2>/dev/null

            printf '\n--- extensions not installed from an official store ---\n'
            awk -F'","' 'NR>1 && $10 !~ /clients2.google.com|addons.mozilla.org/ {
                gsub(/"/,"",$1); gsub(/"/,"",$2); gsub(/"/,"",$4); gsub(/"/,"",$6); gsub(/"/,"",$10);
                printf "  %-16s %-14s %-34s update_url=%s\n", $1, $2, $6, $10 }' "$ext_csv" 2>/dev/null
        fi

        printf '\n--- native messaging hosts (browser to local binary bridges) ---\n'
        find "$d" -path '*native-messaging*' -name '*.json' -printf '  %p\n' 2>/dev/null | sed "s|${d}/||"
    } | dfir_capture "browser summary" "${d}/SUMMARY.txt"
}
