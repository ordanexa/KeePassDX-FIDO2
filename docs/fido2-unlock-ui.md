# FIDO2 unlock screen: 0.1.3

The FIDO2 variant hides the legacy hardware-key row and ignores any restored hardware-key selection. Other variants keep their original credential view.

The credential screen checks USB connection state while visible, including tokens already attached when opened. A connected compatible USB token changes the main input label to **Token PIN**. The normal Open button and keyboard Done submit that PIN to the token flow. Without the token, the input remains **Master Password**. Changing modes clears the input.

The menu provides **Master Password verwenden** even with a connected token, for manual recovery. **Unlock with USB token** switches back to PIN mode. **Enroll USB token** always opens a separate, explicitly labeled Master Password dialog, then requests the token PIN separately. An enrollment password is never taken from the PIN field.

PIN mode cannot return a KDBX master credential or supply data to biometric credential storage. The input is excluded from saved view state and autofill; it is cleared on submission, mode change and screen stop. Pending inline PIN bytes are wiped on cancellation and after the operation. The enrollment password dialog is cleared and dismissed when the screen stops.

Tests cover removal of the hardware row, restoration of master-password input, clearing on mode changes, prevention of PIN submission to database/biometric credential paths, and rejection of programmatic master-password population in PIN mode. Physical USB attach/detach and the complete enrollment/recovery UI require device acceptance.

## Verified 0.1.3 artifact

Source commit: `390fa9f0bf5cd6a771abb8a76456b131450f9ca0`.

- 306 protocol checks passed in CI.
- Six Android/Robolectric tests passed locally and in CI: four input/credential-separation tests plus two storage/backup tests.
- Release build and lint passed. Downloaded artifact checksum, source marker, versionCode 45803, signature, ZIP alignment and compiled backup exclusions verified.
- APK: `keepassdx-fido2-0.1.3-test.apk`.
- SHA-256: `9791427add3b00b0d8c86e6d7728b99c4202780dd6b6a1779437169009320326`.
- Existing enrollment format and location are unchanged from 0.1.2. Install as an update.
- Device acceptance remains pending for automatic USB mode switching, inline PIN submission, keyboard Done, master-password menu override and enrollment with an attached token.
