# Enrollment persistence fix

## Version 0.1.2

KeePassDX uses Context.getBinaryDir(), which resolves to noBackupFilesDir on supported Android versions, as a temporary attachment directory. Database.clearAndClose() recursively deletes its contents. Versions 0.1.0 and 0.1.1 incorrectly stored enrollment there, so a successful enrollment disappeared on database close.

Enrollment now uses the private filesDir/fido2-v1 directory. The FIDO2 flavor uses exclusion-only rules for every app-data domain, covering cloud backup, device transfer and legacy backup; allowBackup remains false. Database cache cleanup is unchanged. Deleted enrollment cannot be recovered: update without uninstalling and enroll once again using the master password.

EnrollmentStorageTest invokes the actual Database.clearAndClose() and verifies deletion of the old location and temporary attachments, survival and authenticated decryption of the new record, separation between database URIs, and explicit backup exclusions. This is a Robolectric integration test, not physical-device acceptance.

## Verified 0.1.2 artifact

Source commit: `00df392aa6ff38e8852ed1a003a16163fbe2ee70`.

- 306 protocol checks passed.
- Two Robolectric integration tests passed locally and in CI: actual database cleanup preserves and reopens the encrypted record; backup exclusions cover all configured backup modes.
- Release build and lint passed. The downloaded APK's checksum, source marker, versionCode 45802, signature, ZIP alignment and compiled backup rules were verified.
- APK: `keepassdx-fido2-0.1.2-test.apk`.
- SHA-256: `f1d11854c2d17a7a7bf92ac7673ea3ba103745447adbb1b38e00a7d9278843a5`.
- The owner reported that enrollment and subsequent unlock work after this fix. This is user-reported device acceptance, not an independently repeated full recovery/negative-test matrix.
