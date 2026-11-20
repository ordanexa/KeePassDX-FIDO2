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
