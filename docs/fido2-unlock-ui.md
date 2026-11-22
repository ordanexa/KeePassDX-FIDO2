# FIDO2 unlock screen

The FIDO2 variant hides the legacy hardware-key row and ignores any restored hardware-key selection. Other variants keep their original credential view.

The credential screen checks USB connection state while visible, including tokens already attached when opened. A connected compatible USB token changes the main input label to **Token PIN**. The normal Open button and keyboard Done submit that PIN to the token flow. Without the token, the input remains **Master Password**. Changing modes clears the input.

The menu provides **Master Password verwenden** even with a connected token, for manual recovery. **Unlock with USB token** switches back to PIN mode. **Enroll USB token** always opens a separate, explicitly labeled Master Password dialog, then requests the token PIN separately. An enrollment password is never taken from the PIN field.

PIN mode cannot return a KDBX master credential or supply data to the upstream biometric database-credential store. The separate encrypted token-PIN feature introduced below does not use that store. The input is excluded from saved view state and autofill; it is cleared on submission, mode change and screen stop. Pending inline PIN bytes are wiped on cancellation and after the operation. The enrollment password dialog is cleared and dismissed when the screen stops.

Tests cover removal of the hardware row, restoration of master-password input, clearing on mode changes, prevention of PIN submission to database/biometric credential paths, and rejection of programmatic master-password population in PIN mode. Physical USB attach/detach and the complete enrollment/recovery UI require device acceptance.

## Verified 0.1.3 artifact

Source commit: `390fa9f0bf5cd6a771abb8a76456b131450f9ca0`.

- 306 protocol checks passed in CI.
- Six Android/Robolectric tests passed locally and in CI: four input/credential-separation tests plus two storage/backup tests.
- Release build and lint passed. Downloaded artifact checksum, source marker, versionCode 45803, signature, ZIP alignment and compiled backup exclusions verified.
- APK: `keepassdx-fido2-0.1.3-test.apk`.
- SHA-256: `9791427add3b00b0d8c86e6d7728b99c4202780dd6b6a1779437169009320326`.
- Existing enrollment format and location are unchanged from 0.1.2. Install as an update.
- The owner reported that the updated login UI works correctly on their device. Individual edge cases (including lifecycle/cancellation and every keyboard path) have not been independently revalidated.


## Token + Fingerprint (0.1.9 development)

### Purpose and architecture

The FIDO2 flavor offers biometric release of a locally saved **token PIN**, while still requiring the connected USB token, its signed hmac-secret assertion and user presence (touch). It never stores the recovered database master password in Android's biometric credential store. Direct upstream biometric database unlock is disabled in this flavor, including late callbacks in Master Password mode. Other flavors keep upstream behavior.

The PIN envelope uses AES-256-GCM and a hardware-backed Android Keystore key. Every encryption/decryption requires a fresh `BIOMETRIC_STRONG` CryptoObject authorization; device PIN/pattern is not accepted by this feature. Android chooses the available strong biometric modality (on the owner's Samsung devices, fingerprint); this is not a fingerprint-only API on all Android hardware. A changed biometric enrollment invalidates the key. Software-only Keystore implementations fail closed.

Each key/envelope is bound to the complete local token enrollment record, which includes the database URI and credential metadata. The encrypted envelope is stored in private `fido2_biometric_pins` preferences, covered by the existing all-preferences backup exclusions and disabled app backup. It does not synchronize across devices or apps. Re-enrollment requires saving the PIN again.

### Setup and daily use

1. Select the database and connect exactly one enrolled Token2 PIN+ Dual.
2. Choose **Token PIN für Fingerprint speichern** in the menu.
3. Enter its PIN and touch the token. The app first verifies a signed hmac-secret assertion and decrypts the local password envelope; an incorrect PIN or unmatched credential cannot be saved.
4. Confirm the biometric prompt to encrypt and save that verified PIN. The normal database pipeline then checks the database password and any assigned Key File.
5. On subsequent opens, use **Token + Fingerprint**, authenticate, and touch the connected token. No PIN is placed in the login field.

With multiple enrollments, choose the connected token's name before biometric release. This explicit selection matters when tokens have different PINs: choosing a different token's saved PIN can consume one PIN attempt. The app never tries other saved PINs automatically. A CTAP incorrect-PIN response discards that saved PIN. The existing low-retry guard still stops when two or fewer token PIN attempts remain.

**Gespeicherte Token PINs entfernen** removes this database's biometric PIN envelopes/keys on this device without removing token enrollments. Removing an individual token also removes its saved PIN. Manual Token PIN and Master Password (with any required Key File) remain recovery paths. After changing the token PIN, remove the saved PINs and save the new PIN explicitly; after a biometric change, re-save (or remove saved PINs first if the Keystore reports an unrecoverable key).

Cancellation, screen stop, database/mode change and USB detachment cancel the prompt/operation and clear pending secrets. No failed biometric operation falls back to device credentials or sends a token PIN automatically. Token removal does not lock a database already open; normal session locking still applies.

### Validation and device acceptance

Automated checks cover per-use strong-biometric key policy, PIN ownership cleanup on cancellation, enrollment/database isolation and rejection without a connected token, alongside the existing input, Key File, enrollment and protocol suites. A Robolectric test cannot establish actual Android Keystore or sensor security.

Physical acceptance is required before describing this feature as device-verified:

- Update in place with the existing signing identity; existing token unlock must still work.
- Save a PIN, lock, and open with token + fingerprint + touch. Without the token, fingerprint must not open the database.
- Cancel fingerprint, disconnect USB, background/reopen and rotate during the prompt; no stale callback may open a database or persist a PIN.
- Try an unrecognized fingerprint and biometric lockout; manual Token PIN must remain usable.
- Verify both enrolled tokens separately, including distinct PINs, and removal of one saved PIN/enrollment.
- Change the token PIN and biometric enrollment; old saved PIN access must fail without automatic retries, with explicit re-saving available.
- Verify required/wrong/missing Key Files and Master Password recovery.

References: [Android biometric CryptoObject](https://developer.android.com/identity/sign-in/biometric-auth) and [Keystore per-use authentication policy](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,%20int)).


### Local verification (2026-11-20)

- Independent simulator: 583 protocol checks passed.
- Unsigned release assembly and release vital lint passed on the final code.
- Android/Robolectric: 23 FIDO2 tests passed (including four new biometric-PIN tests), zero failures/errors.
- The full lint run reported five errors in unchanged upstream files (SuspiciousIndentation, RestrictedApi, StringFormatInvalid and two UnsafeImplicitIntentLaunch findings). It also found a MissingTranslation error for the new button label; that label is now explicitly non-translatable. Full lint is not a clean gate for this checkout; no global suppression or unrelated upstream code changes were added.
- Test version: `4.5.8-fido2-0.1.9-test`, version code `45809`, unchanged application ID. The signed CI artifact is verified; physical acceptance remains pending.


### Verified signed 0.1.9 artifact

- [GitHub Actions build 44819824892](https://github.com/ordanexa/fidoparole-android-reader/actions/runs/44819824892) completed successfully, including protocol checks, Android unit tests, release assembly, signing and artifact upload.
- APK source: `7c69d2605ab0a13d85d5c6a6272ce7c97819973d`; source marker checked against the downloaded artifact.
- Artifact ZIP SHA-256 matched GitHub's digest: `342ab85fda406142488a72c665161ab83a7259678609f72949ea7e9471bfde95`.
- APK SHA-256: `890f9ddcaeb38ffb19924e2dbdfb2d7ffbd90fbd72eea4d334280aca4b9dd011`.
- APK v3 signature, original signing certificate SHA-256 `707f6d453412ec20afbf0aa498d6c63d07c3d4548688030b45f5cd7b04c8b485`, ZIP alignment, application ID, version code `45809`, minSdk 33 and targetSdk 36 independently checked after download.
- Install as an in-place update. Existing enrollments are preserved; enable PIN storage explicitly through the login menu. Real sensor/token acceptance remains pending.


## Device feedback: 0.1.9 (2026-11-21)

The owner reported a successful device test of token + fingerprint in 0.1.9-test. This confirms the reported functional USB/biometric flow. The exact handset and every negative/recovery scenario were not separately enumerated; this is not an independent security audit.

## NFC transport: 0.1.10-test

### Reuse and boundaries

The NFC APDU transport is adapted into Java from Token2's MIT-licensed FidoParole Mobile code, read from `ordanexa/fidoparole-mobile`: `core/src/ctap/nfc.rs` (blob `f73df85dfd49fa690232c58e505d37953bd5986b`) and Android `keys/NfcFido.kt` (blob `3a2f60a740f0bc9423ee176e617b9741cd6fa4e5`). Reader-mode lifetime follows `KeyAccess.kt`: keep Reader Mode enabled until all tag operations have finished. Copyright and the full MIT notice are included in `LICENSES/LICENSE_TOKEN2_FIDOPAROLE` and packaged in `assets/licenses/Token2-FidoParole-MIT.txt`.

`CtapTransport` is the common USB-HID/NFC message interface. `FidoToken` keeps its existing PIN-protocol, hmac-secret, RP, UP/UV, credential-ID and signature validation; no FidoParole vault login, RP, credentials, largeBlob data or PIN store is shared. Existing local token records and biometric PIN bindings are unchanged. Whether a specific physical token exposes its existing credential identically over USB and NFC still needs physical acceptance; the app does not silently enroll a replacement or downgrade verification.

The port adds bounded APDU/response sizes, a per-command deadline, keepalive polling and reader-specific transmit limits. CTAP GET RESPONSE uses the CTAP CLA; the final NFCCTAP_MSG advertises keepalive support via P1. U2F_V2 selection is allowed for dual-protocol keys, but CTAP2 GetInfo, configured client PIN and hmac-secret remain mandatory before PIN authentication. Processing/GET RESPONSE polling never resends the original CTAP/PIN command.

### Use

1. On an NFC-capable Android phone, enable NFC and select the database.
2. Choose **NFC verwenden** in the login menu. **USB verwenden** switches back to the tested USB path.
3. Enter the Token PIN and press Open, or use **Token + Fingerprint** with an already saved PIN.
4. Only when asked, hold the token flat against the phone's NFC antenna until completion. The PIN/biometric step comes first, so the token need not stay in the field while typing or using the sensor.
5. **Token hinzufügen** and **Token PIN für Fingerprint speichern** use the selected connection as well. Enrollment is still committed only after a successful database load. PIN saving still follows a verified token assertion.

NFC is optional in the manifest; USB use remains available on devices without NFC. There are no NFC intent filters or exported NFC login activities. Scanning is explicit and limited to the current unlock operation. Reader Mode remains active throughout ISO-DEP I/O and is disabled on completion, cancel, timeout, transport change, pause or screen stop. Pending PIN bytes are wiped. An old tag callback after cancellation cannot resume the operation. A lost tag fails the attempt without automatic retry; reconnect by starting a new attempt explicitly. The scan wait times out after 60 seconds.

### Validation and acceptance

The independent Python-authenticator fixture passed 1,933 checks over both USB and a simulated NFC APDU link, including PIN protocols 1/2, fragmented requests/responses, processing polls, wrong PIN, low retry count, missing hmac-secret, UV/UP/RP/credential/signature errors and replay. These are protocol simulations, not RF/hardware tests.

Additional Android/JVM tests cover APDU bounds/status handling/cancellation and Android Reader Mode opt-in, pause cleanup, timeout cleanup and stale-tag rejection. The CI run below passed the Android/JVM test task and release assembly on this source.

Physical NFC acceptance is pending: existing enrollment and saved PIN via NFC, manual PIN, explicit enrollment over NFC, required/missing Key Files, token removal during I/O, pause/rotation/cancel, and subsequent USB fallback. Keep the existing USB/master-password recovery paths available.

Protocol references: [FIDO CTAP 2.2, NFC section](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#nfc) and [Android Reader Mode](https://developer.android.com/reference/android/nfc/NfcAdapter#enableReaderMode(android.app.Activity,%20android.nfc.NfcAdapter.ReaderCallback,%20int,%20android.os.Bundle)).


### Verified signed 0.1.10 artifact

- [GitHub Actions build 44869348850](https://github.com/ordanexa/fidoparole-android-reader/actions/runs/44869348850) completed successfully: 1,933 protocol checks, Android/JVM FIDO2 tests, release assembly, signing and artifact upload.
- APK source: `8c8f91ed7332eb951e7a8d7acc37c1334d44c6de` (source marker independently checked).
- Downloaded ZIP SHA-256 matched GitHub's artifact digest: `f763831f06f877c70617981a9b1e3fc6c75337e4173cede7148d47a31ee78ddb`.
- APK SHA-256: `ae43f5142bc6bd09aab492bcabbbf424646336299d13df55e5f725efc5770304`.
- Independently verified APK v3 signature, original signing certificate `707f6d453412ec20afbf0aa498d6c63d07c3d4548688030b45f5cd7b04c8b485`, ZIP alignment, unchanged application ID, version code `45810`, minSdk 33 and targetSdk 36.
- Only `android.permission.NFC` was added relative to the verified 0.1.9 APK. The complete Token2 MIT license was checked inside the APK assets against the source copy.
- Install in place. USB device feedback for 0.1.9 is recorded above; physical NFC acceptance is still pending.


## Device feedback: NFC 0.1.10 (2026-11-22)

The owner reported that token NFC + fingerprint successfully unlocks the vault. UI and operating-flow refinements remain open. This is owner-reported functional acceptance; individual negative/recovery tests and the exact handset were not enumerated.

## Login defaults: 0.1.11-test

- An NFC-capable device with NFC enabled defaults to NFC on each fresh login screen. With NFC unavailable/disabled, USB remains selected. A manual **USB verwenden** or **NFC verwenden** choice overrides the default for the current screen and survives recreation; it is not a global preference.
- For a selected database with a saved biometric-protected token PIN and available strong biometrics, **Token + Fingerprint** is the default method. A phone fingerprint alone, without a saved token PIN, does not qualify.
- After matching database metadata and any Key File association are ready and the screen is resumed, the fingerprint flow starts once automatically. For USB, it waits for the connected token; for NFC, the fingerprint step precedes the tag scan. Open/keyboard Done also use the default method.
- Cancellation or biometric failure exposes manual PIN input and suppresses automatic re-prompting for this login. **Token PIN verwenden** explicitly selects manual PIN; **Master Password verwenden** keeps recovery available. The Fingerprint button can retry explicitly. Setup/management/recovery actions suppress background automatic prompts. An explicit transport choice can request one fresh default attempt.
- Automatic-attempt/manual-PIN state survives recreation. Repeated UI emissions, polling and resume events do not create prompt loops. Multiple saved tokens still use the existing named selection; no PINs are tried in sequence.
- Database metadata now carries the database URI. Late callbacks for an old selection are ignored; automatic startup cannot consume a previous database's Key File or read/write configuration. A file-revoked warning blocks automatic startup, while explicit manual recovery remains available.

Nine JVM policy tests cover the NFC default/manual override, startup prerequisites, one-time prompts, saved-PIN requirement, cancellation/manual fallback, setup/recovery suppression, database switching, recreation and explicit transport retries. Android build and signed-artifact verification are recorded below. Physical acceptance of these new UI defaults remains pending; the underlying USB/NFC/fingerprint device feedback above remains valid.


### Verified signed 0.1.11 artifact

- [GitHub Actions build 45004604569](https://github.com/ordanexa/fidoparole-android-reader/actions/runs/45004604569) passed 1,933 protocol checks, the Android/JVM FIDO2 test task, release assembly, signing and artifact upload. The nine new policy tests also passed independently on the local JVM.
- APK source: `19bc913b095e79292a57289166404608483af9e4`; the archive source marker was checked.
- Downloaded ZIP SHA-256 matched GitHub's artifact digest: `ac9926bd24da9511f63955149d73a6d4cf1609534f12f52af9850988534f7d0d`.
- APK SHA-256: `ef077890757b31a51171a46bd885dddbf3dff8a71282854dd1052ffe51f769dd`.
- APK v3 signature and original certificate `707f6d453412ec20afbf0aa498d6c63d07c3d4548688030b45f5cd7b04c8b485` independently verified; ZIP alignment passed. Application ID is unchanged, version code is `45811`, minSdk 33 and targetSdk 36.
- APK permissions are identical to 0.1.10. The packaged Token2 MIT notice matches the source. The Outbox APK was downloaded again and its SHA-256 matched.
- Install as an in-place update. Physical acceptance remains pending for automatic fingerprint startup, enabled/disabled NFC defaults, cancellation/manual PIN, explicit USB override, and Key File readiness.


## Regular release 0.2.0

The owner reported that the automatic defaults in 0.1.11 work (2026-11-22). The fingerprint token picker now uses **Token wählen** for both NFC and USB. Selection is based on tokens with saved biometric-protected PINs: one eligible token is used directly even when several tokens are enrolled; several eligible tokens retain the explicit named picker. No sequential PIN trials are introduced.

Version 0.2.0 is the first regular release, with no `test` suffix and Android version code `45820`. Its app package, signing identity, enrollment records and encrypted PIN format are unchanged. Device acceptance of the final picker refinement remains open. Build and artifact verification will be recorded after CI.
