# FIDO2 unlock screen: 0.1.3

The FIDO2 variant hides the legacy hardware-key row and ignores any restored hardware-key selection. Other variants keep their original credential view.

The credential screen checks USB connection state while visible, including tokens already attached when opened. A connected compatible USB token changes the main input label to **Token PIN**. The normal Open button and keyboard Done submit that PIN to the token flow. Without the token, the input remains **Master Password**. Changing modes clears the input.

The menu provides **Master Password verwenden** even with a connected token, for manual recovery. **Unlock with USB token** switches back to PIN mode. **Enroll USB token** always opens a separate, explicitly labeled Master Password dialog, then requests the token PIN separately. An enrollment password is never taken from the PIN field.

PIN mode cannot return a KDBX master credential or supply data to biometric credential storage. The input is excluded from saved view state and autofill; it is cleared on submission, mode change and screen stop. Pending inline PIN bytes are wiped on cancellation and after the operation. The enrollment password dialog is cleared and dismissed when the screen stops.

Tests cover removal of the hardware row, restoration of master-password input, clearing on mode changes, prevention of PIN submission to database/biometric credential paths, and rejection of programmatic master-password population in PIN mode. Physical USB attach/detach and the complete enrollment/recovery UI require device acceptance.
