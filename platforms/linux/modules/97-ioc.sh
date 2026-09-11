#!/usr/bin/env bash
# 97-ioc.sh - Cross-references collected evidence against the IOC lists that
# ship with the signature-base rule repository (18_Yara/ioc-matches).
#
# Inputs are artifacts this run already produced: process/binary hashes,
# listening-socket inventories, download hashes and hosts-file entries.

dfir_module_ioc() {
    local d="${DFIR_DIR[Yara]}/ioc-matches"
    local rules_dir="${DFIR_RULES_DIR:-${DFIR_KIT_ROOT:-${DFIR_ROOT}/../..}/shared/yara-rules}"
    local ioc_dir="${rules_dir}/signature-base/iocs"

    mkdir -p "$d"

    if [[ ! -d "$ioc_dir" ]]; then
        dfir_log INFO "IOC lists not present (run ./vestigium.sh setup to fetch signature-base)"
        printf 'IOC lists were not available at %s.\nRun sudo ./vestigium.sh setup (from the kit root) to fetch them.\n' \
            "$ioc_dir" >"${d}/SKIPPED.txt"
        return 0
    fi

    # Paths inside our own kit (rule sources, IOC lists) and the evidence
    # output must never be reported as indicator hits.
    local -a exclude=()
    [[ -n "${DFIR_KIT_ROOT:-}" ]]    && exclude+=(--exclude-prefix "$DFIR_KIT_ROOT")
    [[ -n "${DFIR_OUTPUT_BASE:-}" ]] && exclude+=(--exclude-prefix "$DFIR_OUTPUT_BASE")

    if ! dfir_have python3; then
        dfir_log WARN "IOC matching skipped: python3 unavailable"
        printf 'python3 is required for IOC matching.\n' >"${d}/SKIPPED.txt"
        return 0
    fi

    local report="${d}/ioc_matches.txt"
    python3 "${DFIR_TOOLS}/ioc-match.py" \
        --ioc-dir "$ioc_dir" \
        --evidence "$DFIR_EVID" \
        "${exclude[@]}" \
        --out "$report" >>"$DFIR_LOGFILE" 2>&1
    local rc=$?
    _dfir_record_cmd "ioc matching" "ioc-match.py" "$rc" "0" "$report"

    if (( rc == 0 )) && [[ -f "$report" ]]; then
        local hits
        hits="$(grep -c '^MATCH' "$report" 2>/dev/null)"
        hits="${hits//[^0-9]/}"; hits="${hits:-0}"
        if (( hits > 0 )); then
            dfir_log WARN "IOC matching produced ${hits} hit(s): ${report}"
        else
            dfir_log SUCCESS "IOC matching completed with no hits"
        fi
    else
        dfir_log WARN "IOC matching did not complete cleanly (exit ${rc})"
    fi
    return 0
}
