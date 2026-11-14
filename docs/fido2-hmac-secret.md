# FIDO2 hmac-secret unlock prototype

**Status:** Historical protocol notes for the V1 implementation. Current setup, downloads and supported scope are in the [README](../README.md). The owner has reported working enrollment, persistent unlock and the 0.1.3 login UI on their device; broader negative/recovery testing remains open.

## V1 scope

USB-C, Token2 PIN+ Dual, password-only unchanged KDBX, manual master-password recovery. NFC, key files and concurrent backup-token enrollment are deferred.

The token PIN authorizes a CTAP operation; it is not a KDBX decryption key. The hmac-secret output derives an AES-256-GCM key through HKDF-SHA256, protecting a local copy of the master password. KeePassDX supplies the recovered password to its existing database-loading pipeline. The KDBX credentials remain unchanged, so desktop clients can still use the ordinary master password.

The integration is in MainCredentialActivity, not the KDBX hardware-key component. Direct USB transport validates assertion signatures, credential ID, RP hash and UV/UP flags. The separate RP ID is keepassdx-fido2.ordanexa.com.

Enrollment creates a non-discoverable credential. The encrypted record binds its version, database URI, credential ID, public key and salt. It is stored atomically under filesDir/fido2-v1 (since 0.1.2; the original noBackupFilesDir location was incorrect) only after the matching database/password load succeeds. Failed replacement preserves the existing enrollment. PINs and plaintext passwords are not persisted by this integration.

## Test flow

1. Install KeePassDX FIDO2 on Android 13 or later (called KeePassDX FIDO2 Test before 0.1.5).
2. Select a disposable password-only KDBX and enter its master password.
3. Connect the USB token, choose **Enroll USB token**, grant USB permission, enter the token PIN and touch when prompted.
4. After successful enrollment, lock the database and choose **Unlock with USB token**.
5. Verify saving, app restart and another unlock.
6. Verify the same KDBX opens in KeePassXC with its unchanged master password.

One enrollment is stored per database URI per Android installation. **Remove token enrollment** deletes the local encrypted record only. App-data loss or a changed master password requires manual recovery and enrollment again.

Unplugging cancels an in-progress token operation. It does not close an already unlocked database; ordinary KeePassDX session-lock behavior remains in effect.

## Automated validation

Source commit: a4c23889c64863ada6545861d8755e01ab3bc31b.

The independent Python CTAP simulator passed 210 checks: PIN v1/v2, enrollment, stable secret, password roundtrip, ciphertext tampering, wrong PIN, low retry count, missing extension, missing UV/UP, wrong RP/credential, invalid signature and replay rejection. Run tests/fido2/run.sh with its documented Python dependencies and JDK 21.

The Android release build passed, including resource linking and lintVital. The signed artifact was downloaded and independently checked with apksigner and zipalign. Its checksum matched the build artifact manifest.

- APK: keepassdx-fido2-0.1.0-test.apk
- SHA-256: 6ad6e2c1eef4a06fa87d4d5ac9027a36ad4dadd7a1db893fe88187306cc2d4fa
- Version: 4.5.8-fido2-0.1.0-test / versionCode 45800
- Package: com.kunzisoft.keepass.fido2
- minSdk 33 / targetSdk 36
- App backups disabled; separate installation from standard KeePassDX.
- No signing keys or passwords are stored in this repository.

## Pending device acceptance

- Correct enrollment; lock/unlock, save, restart and unlock again.
- Desktop unlock of the same KDBX using the master password.
- Incorrect enrollment password preserves the previous record.
- Cancel, rotate, background and USB disconnect during token operations.
- Wrong token and modified local record fail closed.
- Manual recovery after password changes or app-data loss.
- No automatic PIN retries; do not deliberately exhaust the token retry counter.

This is an experimental build, not a security-audited release. The owner has reported successful physical-device use; this is not independent security review or comprehensive device acceptance. Java/Android cannot guarantee complete memory zeroization.

## 0.1.1 enrollment authorization fix

MakeCredential consumes user-verification state and token permissions. Version 0.1.0 incorrectly reused that authorization for the following GetAssertion. Version 0.1.1 obtains a fresh, operation-scoped authorization for each command, without retrying failed PIN authentication. The PIN remains only in memory for the bounded enrollment flow and is wiped afterwards. UV/signature checks remain mandatory.

The simulator now consumes authorization and permissions after each successful operation. Before the fix, this reproduced CTAP 0x33; a regression test explicitly verifies stale authorization is rejected. Tests also cover rejection of the second authorization request. This establishes a protocol bug and its correction, not physical-device acceptance. Error messages now include the failed CTAP command.

Reference: [CTAP 2.3 MakeCredential and GetAssertion algorithms](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).
