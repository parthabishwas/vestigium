# Data handling

A Vestigium evidence package is sensitive by design. It holds account
databases, command histories, browsing history and, by default, **browser
credential stores**. This page says exactly what is collected, what can be
decrypted from it, and how to handle the package.

## Policy at a glance

| Data | Linux | Windows | Switch |
|---|---|---|---|
| Browser saved passwords, cookies, autofill / payment data | **Copied** | **Copied** | `--credential-stores metadata` / `-BrowserCredentialStores MetadataOnly` |
| Chromium `Local State` (holds the wrapped decryption key) | Copied raw, plus a redacted readable copy | Copied raw; redacted copy only in metadata mode | same switch |
| Metadata of every credential store (size, timestamps, SHA256) | Always | In metadata mode | none |
| Browser session / tab-restore stores | Metadata only | Not collected | `--browser-sessions` (Linux) |
| Browsing history, downloads, bookmarks, extensions | Copied | Copied | `--no-browser-history` (Linux) |
| `/etc/shadow`, `/etc/gshadow` (password hashes) | Copied | n/a | Remove from `modules/40-config.sh` if forbidden |
| Private SSH keys | Fingerprint and metadata only | n/a | none |
| GNOME Keyring / KWallet / `pass` contents | Presence and metadata only | n/a | none |
| Cloud and developer credentials (`.aws`, `.kube`, `.docker`, `.netrc`, ...) | Location inventory only | n/a | none |
| Wi-Fi PSKs, VPN secrets (NetworkManager) | Redacted in place | n/a | none |
| Windows machine hives `SAM` / `SECURITY` / `SYSTEM` / `SOFTWARE` (local password hashes, LSA secrets, cached domain credentials) | n/a | **Copied** (via a Volume Shadow Copy, `05_Registry\Hives_VSS\_MACHINE\`) | exclude the `Forensics` step (`-Modules` without it) |
| Windows DPAPI master keys | n/a | Not extracted (the SYSTEM/SECURITY hives that back them are copied) | as above |

Both platforms therefore behave the same by default: **credential stores are
copied**. The operator can reduce this to metadata only when the rules of
engagement require it.

## Credential stores that are copied

On Linux they land in `09_Browser/<user>/<browser>/<profile>/credential-stores/`.
On Windows they land in `09_Browser\<Browser>_ProfileData\<user>\<profile>\`.
Each copy gets a provenance record with the source timestamps, and a SHA256.

| Browser family | Files |
|---|---|
| Chromium (Chrome, Edge, Brave, Opera, Vivaldi, Chromium; native, snap, flatpak) | `Login Data`, `Login Data For Account`, `Web Data`, `Cookies` / `Network/Cookies`, `Trust Tokens` / `Network/Trust Tokens`, `Affiliation Database`, `Network Action Predictor`, their `-journal` files, and the user-data `Local State` |
| Firefox / Thunderbird | `logins.json`, `logins-backup.json`, `key4.db` (`key3.db`), `cookies.sqlite` (+ `-wal`), `formhistory.sqlite`, `signons.sqlite`, `credentialstate.sqlite` |

`credential_store_metadata.txt` (Linux) and `CredentialStoreMetadata.csv`
(Windows metadata mode) record each store's size, timestamps and SHA256. That
answers "was the credential store read, modified or replaced, and when"
without opening the store.

## What can be decrypted from a package

| Store | Decryptable offline from the package? |
|---|---|
| **Firefox** `logins.json` + `key4.db` | **Yes**, unless the user set a Primary Password. Both platforms. |
| **Firefox** `cookies.sqlite` | **Yes**: cookie values are stored in plaintext. |
| **Chromium on Linux**, values prefixed `v10` | **Yes**. The fallback "basic" password store uses a fixed, publicly known key. This is common on servers and minimal desktops without a keyring. |
| **Chromium on Linux**, values prefixed `v11` | Only with the `Chrome Safe Storage` secret from the user's GNOME Keyring or KWallet. Vestigium does **not** collect keyring contents. |
| **Chromium on Windows** | Only with the user's DPAPI master key (the user's password, or the domain backup key) and, on current Chrome, the app-bound encryption key. Neither is collected. |
| **Windows `SAM` + `SYSTEM` hives** | **Yes**: local account NT hashes are recoverable offline (e.g. `secretsdump.py`, `samdump2`) and crackable. |
| **Windows `SECURITY` + `SYSTEM` hives** | **Yes**: LSA secrets, service-account passwords and cached domain credentials are recoverable offline. |

**Treat every default collection as containing live credentials and session
cookies.** Stolen cookies allow session hijacking without a password. On Windows
a default package also contains the machine hives, so it holds **offline-crackable
local password hashes and recoverable LSA/cached-domain secrets** - store and
transfer it as highly sensitive material.

## When to use metadata mode

Use `--credential-stores metadata` / `-BrowserCredentialStores MetadataOnly`
when:

- the engagement letter, a data-protection officer or local law forbids
  handling user credentials
- the package will pass through parties who must not receive credential
  material
- the question is only whether the stores were accessed or modified (the
  metadata answers that)

The chosen policy is recorded in:

- **Linux:** `19_CollectionLogs/run-parameters.txt` (`credential_stores=`),
  `21_Manifest/manifest.json` (`collection.browser_credential_stores`) and
  `09_Browser/SUMMARY.txt`
- **Windows:** `16_Manifest\Manifest.json` (`BrowserCredentialStores`) and
  `19_Triage\Findings.md`

## Handling the package

- **Access control:** on Linux the evidence directory is created mode `700`,
  archives mode `600`, and everything the collector writes uses umask `077`.
  Keep equivalent controls on Windows output media.
- **Encrypt for transport and storage.** For example:
  `age -r <recipient> -o pkg.tar.zst.age pkg.tar.zst`, or
  `gpg --encrypt --recipient <id> pkg.zip`. Never send a plain package by
  e-mail or chat.
- **Chain of custody:** keep the `.sha256` sidecar with the archive, and run
  `vestigium verify` on receipt and before analysis. Record who held the
  package, when, and where.
- **Least exposure:** analyse copies, and extract credential stores only on an
  isolated analysis host. Never open copied browser profiles in a live browser
  that is signed in.
- **Retention:** delete packages, and any decrypted material, when the case
  closes or retention obligations expire.
- **Reporting:** redact credentials, cookies and personal data from reports.
  Reference evidence paths and hashes instead.

## Changing the defaults

The defaults are deliberate, for credential-exposure investigations. For a
different posture, set the switches in your runbooks or wrapper scripts, for
example `sudo ./vestigium.sh --credential-stores metadata --no-browser-history`,
rather than editing the modules. The manifest then shows the reduced scope.
