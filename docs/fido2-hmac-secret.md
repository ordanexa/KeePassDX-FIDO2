# FIDO2 hmac-secret unlock prototype

**Status:** V1 implementation in progress; no device validation of this fork yet.

## V1 decision record (2026-11-14)

- User approved USB-C, Token2 PIN+ Dual, password-only unchanged KDBX, and manual password recovery. NFC and key-file integration are deferred.
- The private `pascalep/fidoparole-android-reader` README and `docs/VALIDATION.md` record USB device 349e:0024 and successful 0.1.2-test use on Samsung S24 and tablet. This proves the existing reader flow, not this fork's enrollment or unlock.
- Reuse the reader's USB/HID, bounded CBOR and PIN protocol primitives, with a separate KDBX-specific credential and RP ID. Never access or modify FidoParole credentials or largeBlob storage.
- KeyDriver source was inspected: response extras are `result` and `resultOpt`; its assertion response omits authenticatorData, which is needed for independent signature/UV verification. V1 therefore uses direct USB rather than adding a second trusted app.
- Enrollment creates a non-discoverable ES256 credential with hmac-secret; PIN verification and presence are required. Retain the credential public key and verify subsequent assertion signatures, RP hash, UV/UP flags and credential ID.
- Derive a purpose-specific AES-256-GCM key with HKDF-SHA256. Bind the version, database URI, credential ID and random salt as authenticated metadata. Keep the encrypted record in Android no-backup storage; never persist PIN or plaintext password.
- Commit enrollment only after a successful KDBX unlock. Cancelled/failed replacement must preserve the previous record. App data loss or password change requires manual password recovery and enrollment again.
- Existing signing identity is explicitly authorized by the user; do not generate a replacement or expose signing secrets. Hardware tests remain mandatory before using real data.

## Agreed behavior

- The Android app asks for the hardware key and its PIN, then unlocks the database.
- The FIDO2 `hmac-secret` output protects a locally stored copy of the KeePass master password. KeePassDX then supplies that password to its existing KDBX unlock path.
- Version 1 keeps the KDBX credentials unchanged. A database opened this way remains openable in KeePassXC with its ordinary master password.
- A key file can be added later as a normal KDBX factor. Once added to the database, the same key file is also required by KeePassXC.
- V1 supports one token enrollment per database URI. Recovery is the independently retained master password; concurrent backup-token enrollment is deferred.

The authenticator PIN authorizes the CTAP operation; it is not itself the KDBX password or a substitute for the hmac-secret output. See the [FIDO CTAP specification](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).

## Findings in the upstream code

- KeePassDX already has a `HardwareKey` abstraction and a `MasterCredential` composition path for password, key file, and hardware-key data.
- `HardwareKey.FIDO2_SECRET` and its launcher path are commented out as unfinished. The current YubiKey route uses a separate challenge-response driver intent.
- KeePassDX's Android Credential Manager passkey provider contains PRF extension handling. It computes output from a PRF secret stored with a passkey entry; this is separate from directly talking to a USB/NFC security key over CTAP.
- The older GitHub Key Driver mirror and the 0.1.2 tag show SoloKey hmac-secret integration as unfinished. The current [Kunzisoft GitLab KeyDriver documentation](https://gitlab.com/kunzisoft/android-hardware-key-driver) describes hmac-secret over USB or NFC for compatible authenticators with `clientPin` or built-in user verification. It documents `HMAC_SECRET_CREATE` and `HMAC_SECRET_CHALLENGE_RESPONSE` intents. The tags page lists 0.2.0 as “Compose & Hmac-Secret”.

The initial KeyDriver plan has been superseded by the direct USB decision above. The inspected driver source returns `result` and `resultOpt`, but not the assertion authenticatorData required for independent signature verification. V1 does not call KeyDriver.

Do not simply enable `FIDO2_SECRET` in the KDBX master-credential composition path: that would make the hardware response part of the database's master key and conflict with the agreed desktop-unlock behavior.

## Scope and remaining checks

- Direct USB transport, authenticated local storage and the credential-screen integration are implemented below.
- Exact token firmware and physical acceptance of this fork remain to be verified on the user's device. Prior reader success is not evidence that this APK works.
- NFC, key-file support and concurrent backup-token enrollment are deferred.
- Signing uses the authorized existing identity through secrets in the private reader repository. No signing key or password is stored in this public fork.

## Implemented test flow

In the FIDO2 test variant, select a disposable password-only KDBX. Enter its master password and choose **Enroll USB token** from the toolbar menu. Connect exactly one Token2 PIN+ Dual, grant USB permission, enter its PIN and touch when prompted. Enrollment creates a new non-discoverable credential; existing FidoParole data is not touched. After successful database load, an atomic encrypted record is stored in `noBackupFilesDir/fido2-v1`.

Lock the database, select **Unlock with USB token**, enter the token PIN and touch again. **Remove token enrollment** removes only the local encrypted record. V1 keeps one enrollment per database URI per Android installation; enrolling a replacement requires the master password and does not replace the old record until database unlock succeeds. A second token is not yet enrolled concurrently. Recovery is the master password.

The test build requires Android 13+, identifies itself as **KeePassDX FIDO2 Test**, and uses package `com.kunzisoft.keepass.fido2`. Existing KeePassDX database-session locking behavior is unchanged: unplugging the token cancels an in-progress token operation, but does not automatically close an already unlocked database. Lock it using KeePassDX as usual.

## Validation

Run `tests/fido2/run.sh` with JDK 21 and the Python dependencies in `tests/fido2/requirements.txt`. `FIDO_TEST_PYTHON` can select a dedicated Python venv. The independent Python simulator uses python-fido2 PIN protocols and cryptography ECDSA/HKDF/AES, rather than the Java implementation. Initial run passed 210 checks including PIN v1/v2, enrollment, stable secret, password roundtrip, ciphertext tampering, wrong PIN, low retry count, absent extension, missing UV/UP, wrong RP/credential, wrong signature and replay rejection. Java sources also compile against Android API 35. Full APK build and hardware acceptance remain pending until explicitly recorded below.

## Required device acceptance

- Enrollment with a correct password, then lock/unlock, save, restart, unlock again.
- Open the same KDBX in KeePassXC with its unchanged master password.
- Wrong database password during enrollment must preserve the previous local record.
- Cancel, rotate, background the app, and unplug during PIN/enrollment/unlock; no delayed unlock or replacement record may occur.
- Wrong token and modified record must fail closed; manual password must still work.
- Do not deliberately exhaust token PIN retries. No automatic PIN retries are implemented.
- Test password changes and app-data loss using disposable data; recover with the manual password and enroll again.

This is an experimental build, not a security-audited release. Java/Android cannot guarantee complete memory zeroization. No real vaults or credentials are part of the tests.
