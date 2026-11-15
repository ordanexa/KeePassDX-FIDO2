# Quiet USB attachment (0.1.7 test)

## Intended behavior

The FIDO2 variant registers a dedicated USB attachment activity for the already-supported USB model (vendor 0x349e, product 0x0024). Android can offer KeePassDX FIDO2 as the default handler when the token is attached. The user must accept the initial association; the app cannot silently grant itself permission or set its own default.

Android grants the selected handler's application USB permission before launching its activity. The new activity uses Theme.NoDisplay, has its own task affinity, is excluded from Recents and immediately calls finish() from onCreate(). It does not start the database picker, login activity, background service or any token operation. It does not open a USB connection, claim an interface, request PIN/touch, read a database, or change enrollment. The ordinary application process may be initialized by Android.

A separate task affinity avoids deliberately bringing an existing KeePass task to the foreground. This is a mitigation, not proof that every Android version or OEM browser authentication flow remains unaffected by the system's activity dispatch.

Actual USB access still begins only when the user requests unlock/enrollment in KeePass. The existing hasPermission check and requestPermission fallback remain unchanged. Without a saved default, after defaults are cleared, or when Android has not granted access, the normal permission dialog remains available. PIN and touch requirements are unchanged.

## Setup and test

1. Install the update over the existing test app.
2. Remove and reconnect the token. If Android offers KeePassDX FIDO2 as a handler, select it and enable the option to always use it for this USB device (wording varies by Android/OEM).
3. Verify that neither the database picker nor login screen appears.
4. Open KeePass manually and test unlock. Reconnect and repeat to check whether the separate USB permission prompt is gone.
5. Repeat while a browser is waiting for a security-key login, first with KeePass closed and then with it in the background. Verify that the browser flow succeeds without losing focus or being cancelled. A briefly flashing window also counts as a defect.
6. Test unplug/replug while KeePass's PIN screen is already open, app process restart, and normal manual permission fallback when no default is saved.

Other apps are not deliberately denied token access by this activity. Nevertheless, successful concurrent/adjacent use by a browser must be established on the actual device. USB selection matches a model, not an individual enrolled token; matching replacement/spare tokens may also trigger the handler. Only the FIDO2 build variant contains the attachment registration.

To revert the association, clear the app's USB/default-opening assignment in Android's app settings (the available controls depend on the device). Do not uninstall or clear app storage just to remove the association, since that would erase local token enrollment.

## Validation scope

Unit tests cover immediate termination for USB and arbitrary external intents, no launched activity/service, the no-display theme, independent task affinity, no-history/Recents flags and the exact device filter. Existing unlock, Key File and enrollment-storage regressions also run. Static inspection of the activity verifies it contains no token I/O. These tests cannot validate Android's actual permission grants, Samsung UI transitions, or third-party login behavior.

References: Android USB host documentation and AOSP UsbProfileGroupSettingsManager grant permission before starting the selected USB handler. Android Activity documentation describes windowNoDisplay and finishing before onResume.

- https://developer.android.com/develop/connectivity/usb/host
- https://developer.android.com/reference/android/app/Activity
- https://android.googlesource.com/platform/frameworks/base/+/master/services/usb/java/com/android/server/usb/UsbProfileGroupSettingsManager.java

## Verified build (2026-11-15)

- APK source commit: `b0588a701980ca705a1337cc775c5052c36c1c14`.
- Version: `4.5.8-fido2-0.1.7-test`, version code `45807`.
- 306 protocol checks passed in CI. All 13 focused Android unit tests passed locally; the same focused test suite, release build and release lint passed in CI.
- The downloaded artifact's archive digest, APK checksum and source marker were verified. APK signature matches the previous test signing identity; zip alignment, application ID, version and unchanged permissions were checked. App backup remains disabled.
- APK SHA-256: `5277b9fa790fdf9033cf9ff3cdd227decbae9506589d926efa9d03db9a2d7fde`.
- The verified APK was supplied for device testing. Public GitHub release publication remains pending; the README retains the last verified public release link.
- Physical USB default assignment, repeated connections and browser login coexistence remain unverified until the device tests above are completed.
