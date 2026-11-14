# Enrollment persistence fix

## Version 0.1.2

KeePassDX uses Context.getBinaryDir(), which resolves to noBackupFilesDir on supported Android versions, as a temporary attachment directory. Database.clearAndClose() recursively deletes its contents. Versions 0.1.0 and 0.1.1 incorrectly stored enrollment there, so a successful enrollment disappeared on database close.

Enrollment now uses the private filesDir/fido2-v1 directory. The FIDO2 flavor uses exclusion-only rules for every app-data domain, covering cloud backup, device transfer and legacy backup; allowBackup remains false. Database cache cleanup is unchanged. Deleted enrollment cannot be recovered: update without uninstalling and enroll once again using the master password.

EnrollmentStorageTest invokes the actual Database.clearAndClose() and verifies deletion of the old location and temporary attachments, survival and authenticated decryption of the new record, separation between database URIs, and explicit backup exclusions. This is a Robolectric integration test, not physical-device acceptance.
