# KeePassDX-FIDO2 — Ordanexa fork

<img src="art/fido2-icon.svg" width="128" alt="KeePassDX FIDO2 icon">

**Unlock your KeePass database on Android with a Token2 USB security key and its PIN.**

This is an independent, experimental modification of [Kunzisoft/KeePassDX](https://github.com/Kunzisoft/KeePassDX), based on KeePassDX **4.5.8**. It is not an official KeePassDX release.

## Download

**[Download the 0.1.6 test APK](https://github.com/ordanexa/KeePassDX-FIDO2/releases/download/v0.1.6-test/keepassdx-fido2-0.1.6-test.apk)** · [Release notes and downloads](https://github.com/ordanexa/KeePassDX-FIDO2/releases)

**Current release: 0.1.6-test**, with optional per-database Key Files for both Master Password and Token + PIN unlock, configured through the login menu. Build, 306 protocol checks, 10 Android unit tests, release lint and signing checks passed; physical-device acceptance of the Key File changes remains pending. Earlier releases remain available.

| Requirement | Supported scope |
| --- | --- |
| Android | Android 13 or later, with USB host support |
| Security key | Token2 PIN+ Dual over USB-C; USB ID `349e:0024` |
| Token capability | FIDO2 `hmac-secret`, with an existing token PIN |
| Database | KDBX with Master Password and optional Key File; database credentials remain unchanged |
| App package | `com.kunzisoft.keepass.fido2` — installs alongside standard KeePassDX |

Install an update over the existing FIDO2 test app to keep its local enrollment. Do not uninstall or clear app data first. Store/F-Droid releases of the original project do **not** include this fork's USB unlock integration.

## What this fork adds

- **USB token + PIN unlock** after one-time enrollment, without typing the database master password each time.
- **Automatic input switching:** a connected supported token changes the main field to **Token PIN**; without it, the field is **Master Password**.
- **Master-password fallback even with a token connected**, through **Master Password verwenden** in the menu.
- **Separate enrollment prompts** for the database master password and token PIN, so enrollment remains available with the token plugged in.
- **A simplified unlock screen:** the legacy hardware-key/YubiKey row is hidden. From 0.1.6, the Key File and password switches are also hidden; optional Key Files are managed through the login menu.
- **Optional Key File (from 0.1.6):** associate an existing file per database through **Key File zuordnen / ändern**. It is used for both manual and token unlock. See [Key File behavior and testing](docs/fido2-key-file.md).
- **Persistent local enrollment** that survives closing the database and restarting the app.
- **A FIDO2 badge on the launcher icon** since 0.1.4, including themed-icon support.

The underlying KeePassDX editor, groups, entries, search, Autofill, Magikeyboard and other upstream functionality remain available. This change adds an unlock method; it does not replace the database format.

## First-time enrollment

1. Back up your KDBX and keep its master password in a safe, independent place.
2. Install the FIDO2 APK and select your database. With 0.1.6, if the database requires a Key File, associate that file through **Key File zuordnen** before enrollment. Earlier releases support the password-only flow.
3. Connect the Token2 PIN+ Dual by USB-C.
4. Open the menu and choose **Enroll USB token**.
5. Enter the **database master password** in the separate enrollment dialog.
6. Grant the Android USB permission when requested, enter the **token PIN**, and touch the token when prompted.
7. After successful enrollment, lock the database and verify token unlock.

Enrollment is saved only after the supplied master password successfully opens the matching database.

## Everyday use and recovery

**Unlock:** select the same database, connect the enrolled token, enter its PIN in **Token PIN**, then use **Open** or the keyboard's Done action. Touch the token when prompted.

**Use the password:** unplug the token or choose **Master Password verwenden**. **Unlock with USB token** switches back to PIN mode.

**Keep your master password and any required Key File.** Together they remain a valid way to unlock the unchanged KDBX, including in desktop clients such as KeePassXC. If the KDBX requires a Key File, the password alone is insufficient. This is not mandatory token enforcement on the database.

| Situation | What to do |
| --- | --- |
| Token lost or reset | Open with the master password, then enroll a replacement |
| App reinstalled, app data cleared or new Android device | Open with the master password and enroll on that installation |
| Database master password changed | Use the new master password and enroll again |
| Database selected through a different document URI | Enrollment may need to be repeated for that URI |
| Remove token enrollment | Deletes only this app's local enrollment record; leaves the database and token unchanged |

**Unplugging the token does not lock an already open database.** KeePassDX's normal session-lock settings still apply.

## How the unlock works

The PIN authorizes a FIDO2 operation on the token; it is not the KDBX password. The token's `hmac-secret` output is passed through HKDF-SHA256 to derive an AES-256-GCM key. That key encrypts a local copy of the database master password. After token authorization, the app decrypts the password and supplies it to KeePassDX's existing database-opening pipeline.

The enrollment record is stored in the app's private `filesDir/fido2-v1` directory and bound to the database URI and credential metadata. The FIDO2 variant disables app backup and excludes app data from configured backup/transfer mechanisms. The integration does not persist the PIN or a plaintext copy of the master password. An unlocked app necessarily handles the recovered password in memory.

## Scope and validation

- USB only: **NFC is not implemented** in this integration.
- Other security-key models are not currently supported by the device filter.
- Optional Key Files are included from 0.1.6; physical-device validation is pending. Simultaneous backup-token enrollment remains outside the supported flow.
- One enrollment per database URI per Android installation; enrolling another token replaces that local enrollment.
- Failed PIN authentication is not retried automatically.
- **Experimental test build, not an independently security-audited release.** Java/Android cannot guarantee complete memory zeroization.

The owner reported successful device use of enrollment, persistent unlock and the 0.1.3 login UI. This does not establish compatibility with other devices or complete all negative/recovery tests.

The 0.1.6 build passed 306 protocol checks, 10 Android unit tests, release build, release lint, signing and alignment checks. The downloaded APK checksum and source marker were verified, and the published GitHub asset matches the verified APK. Application ID and signing identity are unchanged; app backup remains disabled. See the [0.1.6 release](https://github.com/ordanexa/KeePassDX-FIDO2/releases/tag/v0.1.6-test) and [Key File validation](docs/fido2-key-file.md) for the checksum, source commit and test scope.

## Project identity

The repository is `ordanexa/KeePassDX-FIDO2`; the Android app is named **KeePassDX FIDO2** from 0.1.5 onward. The application ID and signing identity are unchanged, so an in-place update preserves app data and local enrollment. Version 0.1.5 introduced the current app label; 0.1.6 adds optional Key File support without changing the enrollment record format.

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
