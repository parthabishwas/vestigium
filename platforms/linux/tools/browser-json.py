#!/usr/bin/env python3
"""Browser JSON helpers for the Vestigium Linux collector.

Subcommands
  redact-local-state FILE      Print a Chromium "Local State" file with the
                               credential-decryption key removed.
  chromium-prefs FILE          Print investigation-relevant keys from a
                               Chromium "Preferences" file.
  build-inventory ...          Merge Chromium manifests and Firefox
                               extensions.json data into one CSV inventory.

Only standard library modules are used so the collector stays dependency free.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Iterable


def utc_iso(epoch: float) -> str:
    """Epoch seconds -> ISO-8601 UTC. Timezone-aware: datetime.utcfromtimestamp
    is deprecated since Python 3.12 and its warnings would pollute the log."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


REDACT_KEYS = {"encrypted_key", "app_bound_encrypted_key", "os_crypt_key",
               "refresh_token", "access_token"}

FIELDS = [
    "Browser", "User", "Profile", "ExtensionID", "Version", "Name",
    "Description", "Permissions", "HostPermissions", "UpdateURL",
    "ManifestVersion", "State", "InstallDate", "Signed", "SourcePath",
]


def clean(value: Any) -> str:
    """Flatten a manifest value into a single-line, quote-free CSV field."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        parts = []
        for item in value:
            if isinstance(item, dict):
                parts.append(";".join(f"{k}={v}" for k, v in item.items()))
            else:
                parts.append(str(item))
        value = ";".join(parts)
    elif isinstance(value, dict):
        value = ";".join(f"{k}={v}" for k, v in value.items())
    text = str(value)
    return text.replace('"', "'").replace("\r", " ").replace("\n", " ").strip()


def load_json(path: str) -> Any:
    with open(path, "rb") as handle:
        raw = handle.read()
    # Chromium occasionally leaves a BOM or trailing NULs in these files.
    raw = raw.lstrip(b"\xef\xbb\xbf").rstrip(b"\x00")
    return json.loads(raw.decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
def cmd_redact_local_state(args: argparse.Namespace) -> int:
    try:
        data = load_json(args.path)
    except Exception as exc:                     # noqa: BLE001 - diagnostic path
        print(json.dumps({"error": f"unparsable: {exc}", "source": args.path}))
        return 1

    def scrub(node: Any) -> Any:
        if isinstance(node, dict):
            return {
                k: ("<REDACTED BY COLLECTOR>" if k in REDACT_KEYS else scrub(v))
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [scrub(v) for v in node]
        return node

    json.dump(scrub(data), sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


# ---------------------------------------------------------------------------
def cmd_chromium_prefs(args: argparse.Namespace) -> int:
    try:
        prefs = load_json(args.path)
    except Exception as exc:                     # noqa: BLE001
        print(f"unparsable Preferences file: {exc}")
        return 1

    def get(path: str, default: Any = None) -> Any:
        node: Any = prefs
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    print(f"Preferences highlights for {args.path}")
    print("=" * 72)

    for label, key in [
        ("Profile name",            "profile.name"),
        ("Signed-in account",       "account_info"),
        ("Sync account e-mail",     "google.services.last_signed_in_username"),
        ("Sync username",           "google.services.username"),
        ("Startup type",            "session.restore_on_startup"),
        ("Startup URLs",            "session.startup_urls"),
        ("Homepage",                "homepage"),
        ("Homepage is newtab",      "homepage_is_newtabpage"),
        ("Default search provider", "default_search_provider_data.template_url_data.short_name"),
        ("Search URL",              "default_search_provider_data.template_url_data.url"),
        ("Proxy mode",              "proxy.mode"),
        ("Proxy server",            "proxy.server"),
        ("PAC URL",                 "proxy.pac_url"),
        ("Download directory",      "download.default_directory"),
        ("Prompt for download",     "download.prompt_for_download"),
        ("Safe Browsing enabled",   "safebrowsing.enabled"),
        ("Extensions in dev mode",  "extensions.ui.developer_mode"),
        ("Alternate error pages",   "alternate_error_pages.enabled"),
    ]:
        value = get(key)
        if value is not None:
            print(f"{label:<26}: {clean(value)}")

    accounts = get("account_info") or []
    if isinstance(accounts, list) and accounts:
        print("\nAccounts bound to this profile")
        print("-" * 72)
        for account in accounts:
            if isinstance(account, dict):
                print("  email={} gaia={} hosted_domain={}".format(
                    account.get("email", "?"),
                    account.get("gaia", "?"),
                    account.get("hosted_domain", "?"),
                ))

    settings = get("extensions.settings") or {}
    if isinstance(settings, dict) and settings:
        print("\nExtension settings block")
        print("-" * 72)
        for ext_id, meta in sorted(settings.items()):
            if not isinstance(meta, dict):
                continue
            manifest = meta.get("manifest") or {}
            print("  {:<34} state={} location={} name={} from_webstore={}".format(
                ext_id,
                meta.get("state", "?"),
                meta.get("location", "?"),
                clean(manifest.get("name", "")),
                meta.get("from_webstore", "?"),
            ))
            if meta.get("path"):
                print(f"  {'':<34} path={clean(meta.get('path'))}")
            if meta.get("install_time"):
                print(f"  {'':<34} install_time={meta.get('install_time')}")
    return 0


# ---------------------------------------------------------------------------
def rows_from_chromium(tsv_path: str) -> Iterable[dict]:
    if not tsv_path or not os.path.isfile(tsv_path):
        return
    with open(tsv_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 4:
                continue
            browser, user, profile, manifest_path = parts
            # .../Extensions/<extension id>/<version>/manifest.json
            pieces = manifest_path.split(os.sep)
            ext_id = pieces[-3] if len(pieces) >= 3 else ""
            version_dir = pieces[-2] if len(pieces) >= 2 else ""
            try:
                manifest = load_json(manifest_path)
            except Exception as exc:             # noqa: BLE001
                yield {
                    "Browser": browser, "User": user, "Profile": profile,
                    "ExtensionID": ext_id, "Version": version_dir,
                    "Name": f"(unparsable manifest: {exc})", "SourcePath": manifest_path,
                }
                continue

            name = manifest.get("name", "")
            if isinstance(name, str) and name.startswith("__MSG_"):
                name = f"{name} (localised)"

            try:
                install_date = os.path.getmtime(manifest_path)
                install_date = utc_iso(install_date)
            except OSError:
                install_date = ""

            yield {
                "Browser": browser,
                "User": user,
                "Profile": profile,
                "ExtensionID": ext_id,
                "Version": manifest.get("version", version_dir),
                "Name": name,
                "Description": manifest.get("description", ""),
                "Permissions": manifest.get("permissions", []),
                "HostPermissions": manifest.get("host_permissions", manifest.get("optional_permissions", [])),
                "UpdateURL": manifest.get("update_url", ""),
                "ManifestVersion": manifest.get("manifest_version", ""),
                "State": "",
                "InstallDate": install_date,
                "Signed": "",
                "SourcePath": manifest_path,
            }


def rows_from_firefox(tsv_path: str) -> Iterable[dict]:
    if not tsv_path or not os.path.isfile(tsv_path):
        return
    signed_states: dict[Any, str] = {
        -1: "broken", 0: "unknown/unsigned", 1: "missing", 2: "preliminary",
        3: "signed", 4: "system", 5: "privileged",
    }
    with open(tsv_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 4:
                continue
            browser, user, profile, json_path = parts
            try:
                data = load_json(json_path)
            except Exception as exc:             # noqa: BLE001
                yield {"Browser": browser, "User": user, "Profile": profile,
                       "Name": f"(unparsable extensions.json: {exc})",
                       "SourcePath": json_path}
                continue

            for addon in data.get("addons", []) or []:
                if not isinstance(addon, dict):
                    continue
                locale = addon.get("defaultLocale") or {}
                user_perms = addon.get("userPermissions") or {}
                install_ms = addon.get("installDate") or 0
                try:
                    install_date = utc_iso(int(install_ms) / 1000)
                except Exception:                # noqa: BLE001
                    install_date = ""

                signed_raw = addon.get("signedState")
                if not isinstance(signed_raw, int):
                    signed_raw = None

                yield {
                    "Browser": browser,
                    "User": user,
                    "Profile": profile,
                    "ExtensionID": addon.get("id", ""),
                    "Version": addon.get("version", ""),
                    "Name": locale.get("name", ""),
                    "Description": locale.get("description", ""),
                    "Permissions": user_perms.get("permissions", []),
                    "HostPermissions": user_perms.get("origins", []),
                    "UpdateURL": addon.get("sourceURI") or addon.get("updateURL") or "",
                    "ManifestVersion": addon.get("manifestVersion", ""),
                    "State": "enabled" if addon.get("active") else "disabled",
                    "InstallDate": install_date,
                    "Signed": signed_states.get(signed_raw, str(signed_raw if signed_raw is not None else "")),
                    "SourcePath": addon.get("path") or json_path,
                }


def cmd_build_inventory(args: argparse.Namespace) -> int:
    rows = list(rows_from_chromium(args.chromium)) + list(rows_from_firefox(args.firefox))
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, quoting=csv.QUOTE_ALL,
                                extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: clean(row.get(field, "")) for field in FIELDS})
    print(f"{len(rows)} extension record(s) written to {args.out}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_redact = sub.add_parser("redact-local-state")
    p_redact.add_argument("path")
    p_redact.set_defaults(func=cmd_redact_local_state)

    p_prefs = sub.add_parser("chromium-prefs")
    p_prefs.add_argument("path")
    p_prefs.set_defaults(func=cmd_chromium_prefs)

    p_inv = sub.add_parser("build-inventory")
    p_inv.add_argument("--chromium", default="")
    p_inv.add_argument("--firefox", default="")
    p_inv.add_argument("--out", required=True)
    p_inv.set_defaults(func=cmd_build_inventory)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
