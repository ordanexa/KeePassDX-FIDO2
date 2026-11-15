# Optional Key File (0.1.6 test build)

## Behavior

The FIDO2 login shows one secret input: Master Password, or Token PIN when a supported USB token is connected. The legacy Key File and password switches are hidden in this login only. Database creation and credential-changing dialogs retain their standard controls.

Use the login menu **Key File zuordnen / Key File ändern** to select an existing document with Android's document picker. **Key File-Zuordnung entfernen** removes only the local reference, with confirmation; it does not delete the file or change the database credentials. The existing **Master Password verwenden** menu remains available with a connected token.

The association is per database URI and persists across app restarts. Only the document URI is saved in private preferences, covered by the existing backup exclusions. Key file contents are read during database loading, not copied into the token enrollment record. Explicit removal overrides the old database-history suggestion. Moving a database to a new URI requires a new association, just as token enrollment is URI-scoped.

| Database credentials | Manual unlock | Token unlock |
| --- | --- | --- |
| Password only | Master Password | Token + PIN |
| Password and Key File | Master Password + associated file | Token + PIN + associated file |

The token still recovers only the encrypted master password. The optional Key File URI is captured at the start of the token operation and passed to the normal KeePass credential pipeline. Enrollment is committed only after the database load succeeds with the matching database, recovered password and selected Key File URI. Changing the association cancels pending token work.

## Errors and database protection

An unreadable associated file causes an explicit Key File error. A null file stream must not silently downgrade the operation to password-only. A wrong but readable file produces the normal invalid-credentials error. No automatic retry without the file is performed.

The menu does not add a new cryptographic factor to an existing database. To protect a password-only database with a Key File, change its credentials using the existing database credential-changing function first, then associate that same file on the login screen. Other KeePass clients must use the same password and file. Password-only recovery is insufficient once the KDBX itself requires a Key File.

If no association exists, the app cannot infer from a failed unlock that a Key File was specifically omitted; the normal credentials error applies. File-provider availability and Android read grants remain necessary. Removing an association does not bypass KDBX protection.

## Validation

Automated coverage targets the hidden controls, retained file selection across PIN/password switches, independent database associations, explicit-removal precedence, missing-file failure, and equality of the composed KeePass key for manual versus recovered passwords with the same file. It also verifies that omitted or changed file contents produce different composed keys. Existing protocol and enrollment-storage regressions remain applicable.

Physical device acceptance is pending: test a disposable password-only database and one protected by password plus Key File; verify manual unlock, token unlock, enrollment, app restart, missing/revoked file, wrong file, and removal/reassignment. A local or CI build does not establish physical USB or file-provider behavior.

## Verified build result

Source commit: `164bc7d98d3f51c92e52b58f40489fec053e75e0`.

Local and CI release builds, release lint and the FIDO2 Android unit tests passed. The local report contains 10 tests with no failures or errors. The independent protocol suite passed all 306 checks locally and in CI.

The downloaded signed APK has version `4.5.8-fido2-0.1.6-test` (45806), application ID `com.kunzisoft.keepass.fido2`, and label `KeePassDX FIDO2`. Its checksum and source marker match the build artifact. Signature identity and ZIP alignment were verified; permissions match 0.1.3 and app backup remains disabled. Physical-device acceptance of the Key File changes remains pending.

APK SHA-256: `9eee91400b8e80ad86ad96dfcfdc3f4f5b00596179d26dec9c3afba0c8bdec5d`.
