# KeePassDX-FIDO2 — KeePass for Android with FIDO2, NFC and fingerprint

<img src="art/fido2-icon.svg" width="128" alt="KeePassDX FIDO2 icon">

**Unlock your KeePass database with a Token2 security key over NFC or USB-C, using its PIN or your fingerprint.**

KeePassDX-FIDO2 is Ordanexa's independent fork of [Kunzisoft/KeePassDX](https://github.com/Kunzisoft/KeePassDX), based on KeePassDX **4.5.8**. It supports **Token2 PIN+ Dual**, FIDO2 `hmac-secret`, optional **Key Files** and up to **five alternative tokens** per database and Android installation. This is not an official Kunzisoft release.

The KDBX remains compatible with standard KeePass clients such as KeePassXC. The app encrypts a local copy of the master password using a token-derived key; it does not change the database format or enforce the token as a mandatory database factor.

## Download — 0.2.0

**[Download KeePassDX-FIDO2 0.2.0 APK](https://github.com/ordanexa/KeePassDX-FIDO2/releases/download/v0.2.0/keepassdx-fido2-0.2.0.apk)**

[Latest release and checksums](https://github.com/ordanexa/KeePassDX-FIDO2/releases/latest) · [All releases](https://github.com/ordanexa/KeePassDX-FIDO2/releases)

**0.2.0 is the first regular release**, combining token PIN, biometric-protected PIN storage, NFC/USB unlock and automatic login defaults. Install over the existing FIDO2 app to preserve local enrollment and saved PINs. **Do not uninstall or clear app data.** The package and signing identity remain unchanged.

| Requirement | Supported scope |
| --- | --- |
| Android | Android 13 or later |
| Security key | Token2 PIN+ Dual with configured PIN and FIDO2 `hmac-secret` |
| NFC | NFC-capable Android device with NFC enabled |
| USB-C | Android USB host support; token USB ID `349e:0024` |
| Fingerprint login | Strong biometrics, hardware-backed Android Keystore and a saved token PIN for the selected database |
| Database | KDBX with Master Password and optional Key File |
| App package | `com.kunzisoft.keepass.fido2` — installs alongside standard KeePassDX |

## Everyday login

1. Select your database. When NFC is available and enabled, **NFC is selected automatically**; otherwise use USB-C. **USB verwenden** and **NFC verwenden** let you change the connection.
2. With a saved biometric-protected token PIN, **Token + Fingerprint starts automatically**. If only one token has a saved fingerprint PIN, it is selected directly, even if other tokens are enrolled. With several saved fingerprint PINs, **Token wählen** asks which token to use.
3. Authorize the fingerprint prompt, then hold the token against the NFC antenna when asked. Over USB-C, connect the token and touch it when prompted.
4. Without a saved PIN, enter the Token PIN. **Token PIN verwenden** explicitly chooses manual entry. Cancelling the fingerprint prompt enables manual PIN entry without an automatic prompt loop.

To enable fingerprint login, first enroll the token using **Token hinzufügen**, then choose **Token PIN für Fingerprint speichern**. The token is still required for every token unlock; fingerprint only releases its locally encrypted PIN. PIN stores remain independent of FidoParole and other apps.

**Master Password verwenden** remains available for recovery. Any Key File required by the database remains required. See [login, NFC and fingerprint details](docs/fido2-unlock-ui.md), [multiple tokens](docs/fido2-multiple-tokens.md) and [Key Files](docs/fido2-key-file.md).

The owner confirmed USB token + fingerprint, NFC token + fingerprint and the automatic login defaults on their device. Individual negative/recovery cases and broader device compatibility are not exhaustively validated. The one-saved-PIN selection refinement is included in 0.2.0; its device acceptance remains open.

## What this fork adds

- **NFC/USB token + PIN or fingerprint unlock** after one-time enrollment, without typing the database master password each time.
- **Automatic input switching:** enabled NFC or a connected supported USB token selects token mode; saved biometric PINs use **Token + Fingerprint** by default.
- **Master-password fallback even with a token connected**, through **Master Password verwenden** in the menu.
- **Separate enrollment prompts** for the database master password and token PIN, so enrollment remains available with the token plugged in.
- **A simplified unlock screen:** the legacy hardware-key/YubiKey row is hidden. From 0.1.6, the Key File and password switches are also hidden; optional Key Files are managed through the login menu.
- **Optional Key File (from 0.1.6):** associate an existing file per database through **Key File zuordnen / ändern**. It is used for both manual and token unlock. See [Key File behavior and testing](docs/fido2-key-file.md).
- **Multiple alternative tokens (from 0.1.8):** up to five named tokens; individual removal and automatic selection on unlock.
- **Persistent local enrollment** that survives closing the database and restarting the app.
- **A FIDO2 badge on the launcher icon** since 0.1.4, including themed-icon support.

The underlying KeePassDX editor, groups, entries, search, Autofill, Magikeyboard and other upstream functionality remain available. This change adds an unlock method; it does not replace the database format.

## First-time enrollment

1. Back up your KDBX and keep its master password in a safe, independent place.
2. Install the FIDO2 APK and select your database. From 0.1.6, if the database requires a Key File, associate that file through **Key File zuordnen** before enrollment. Earlier releases support the password-only flow.
3. Connect the Token2 PIN+ Dual by USB-C.
4. Open the menu and choose **Token hinzufügen** (called **Enroll USB token** through 0.1.7).
5. Enter the **database master password** in the separate enrollment dialog.
6. Grant the Android USB permission when requested, enter the **token PIN**, and touch the token when prompted.
7. After successful enrollment, lock the database and verify token unlock.

Enrollment is saved only after the supplied master password successfully opens the matching database.

## Everyday use and recovery

**Unlock:** select the same database, connect the enrolled token, enter its PIN in **Token PIN**, then use **Open** or the keyboard's Done action. Touch the token when prompted.

**Use the password:** choose **Master Password verwenden**. **USB verwenden** or **NFC verwenden** switches back to token mode.

**Keep your master password and any required Key File.** Together they remain a valid way to unlock the unchanged KDBX, including in desktop clients such as KeePassXC. If the KDBX requires a Key File, the password alone is insufficient. This is not mandatory token enforcement on the database.

| Situation | What to do |
| --- | --- |
| Token lost or reset | Open with the master password, then add a replacement |
| App reinstalled, app data cleared or new Android device | Open with the master password and enroll on that installation |
| Database master password changed | Remove and add each local token again using the new master password |
| Database selected through a different document URI | Enrollment may need to be repeated for that URI |
| Remove token enrollment | Removes only the selected local token enrollment; leaves the database and token unchanged |

**Unplugging the token does not lock an already open database.** KeePassDX's normal session-lock settings still apply.

## How the unlock works

The PIN authorizes a FIDO2 operation on the token; it is not the KDBX password. The token's `hmac-secret` output is passed through HKDF-SHA256 to derive an AES-256-GCM key. That key encrypts a local copy of the database master password. After token authorization, the app decrypts the password and supplies it to KeePassDX's existing database-opening pipeline.

The enrollment record is stored in the app's private `filesDir/fido2-v1` directory and bound to the database URI and credential metadata. The FIDO2 variant disables app backup and excludes app data from configured backup/transfer mechanisms. The integration never persists a plaintext PIN or plaintext copy of the master password. Fingerprint login can optionally persist the PIN encrypted under a hardware-backed, per-use biometric Android Keystore key. An unlocked app necessarily handles the recovered password in memory.

## Scope and validation

- USB-C and NFC/ISO-DEP; USB and NFC fingerprint unlock have owner-reported successful device tests.
- Other security-key models are not currently supported by the device filter.
- Optional Key Files are included from 0.1.6; physical-device validation is pending. From 0.1.8, up to five alternative tokens can be enrolled; connect only one USB token at a time.
- From 0.1.8, up to five named enrollments per database URI per Android installation. Adding a token preserves existing ones. Each device requires its own enrollment; synchronizing the KDBX alone does not transfer token unlock.
- Failed PIN authentication is not retried automatically.
- **This fork has not undergone an independent security audit.** Java/Android cannot guarantee complete memory zeroization.

The owner reported successful device use of enrollment, persistent unlock and the 0.1.3 login UI. This does not establish compatibility with other devices or complete all negative/recovery tests.

The 0.1.6 build passed 306 protocol checks, 10 Android unit tests, release build, release lint, signing and alignment checks. The downloaded APK checksum and source marker were verified, and the published GitHub asset matches the verified APK. Application ID and signing identity are unchanged; app backup remains disabled. See the [0.1.6 release](https://github.com/ordanexa/KeePassDX-FIDO2/releases/tag/v0.1.6-test) and [Key File validation](docs/fido2-key-file.md) for the checksum, source commit and test scope.

The 0.1.8 APK and published asset were verified against source `237f149d50d607ddf8bd9d9705448144f49d7d45`; 583 protocol checks, 19 Android unit tests, release build/lint, signing, alignment and unchanged permissions passed. See the [0.1.8 release](https://github.com/ordanexa/KeePassDX-FIDO2/releases/tag/v0.1.8-test) and [multi-token validation](docs/fido2-multiple-tokens.md).

## Project identity

The repository is `ordanexa/KeePassDX-FIDO2`; the Android app is named **KeePassDX FIDO2** from 0.1.5 onward. The application ID and signing identity are unchanged, so an in-place update preserves app data and local enrollment. Version 0.1.5 introduced the current app label; 0.1.6 added optional Key Files. Version 0.1.8 reads legacy enrollment and writes a versioned collection when adding/removing tokens, preserving the original encrypted envelope.

## Development and upstream updates

- `feature/fido2-hmac-secret` is this fork's **default branch** and contains the modified application.
- `master` is reserved for the upstream KeePassDX baseline.
- To update: sync **master** with upstream, merge those changes into the FIDO2 branch, resolve conflicts, run tests, build and verify a signed APK, then publish a new release.
- Syncing `master` alone does not update the modified app.
- Release tags identify the source used for each published APK. Signing credentials are not stored in this public repository.

Build the variant with `./gradlew :app:assembleFido2Release`. The output is unsigned until signed with the fork's existing signing identity; the upstream signing fingerprint does not authenticate this fork.

## Upstream and license

KeePassDX is developed by Jeremy Jamet / [Kunzisoft](https://www.kunzisoft.com) and contributors. The original project, documentation, official downloads and donation options are at [keepassdx.com](https://www.keepassdx.com) and [Kunzisoft/KeePassDX](https://github.com/Kunzisoft/KeePassDX).

Copyright © 2026 Jeremy Jamet / Kunzisoft and respective contributors. KeePassDX is free software under the **GNU General Public License, version 3 or later**, without warranty. Existing source notices and licenses are retained in this fork; see [LICENSES](LICENSES).

KeePassDX itself is a fork of [KeePassDroid](https://github.com/bpellin/keepassdroid) by bpellin.
