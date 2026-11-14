# FIDO2 hmac-secret unlock prototype

**Status:** Development preparation. No FIDO2 unlock implementation is included yet.

## Agreed behavior

- The Android app asks for the hardware key and its PIN, then unlocks the database.
- The FIDO2 `hmac-secret` output protects a locally stored copy of the KeePass master password. KeePassDX then supplies that password to its existing KDBX unlock path.
- Version 1 keeps the KDBX credentials unchanged. A database opened this way remains openable in KeePassXC with its ordinary master password.
- A key file can be added later as a normal KDBX factor. Once added to the database, the same key file is also required by KeePassXC.
- Enroll and verify a second hardware key before relying on the first key for recovery.

The authenticator PIN authorizes the CTAP operation; it is not itself the KDBX password or a substitute for the hmac-secret output. See the [FIDO CTAP specification](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).

## Findings in the upstream code

- KeePassDX already has a `HardwareKey` abstraction and a `MasterCredential` composition path for password, key file, and hardware-key data.
- `HardwareKey.FIDO2_SECRET` and its launcher path are commented out as unfinished. The current YubiKey route uses a separate challenge-response driver intent.
- KeePassDX's Android Credential Manager passkey provider contains PRF extension handling. It computes output from a PRF secret stored with a passkey entry; this is separate from directly talking to a USB/NFC security key over CTAP.
- The older GitHub Key Driver mirror and the 0.1.2 tag show SoloKey hmac-secret integration as unfinished. The current [Kunzisoft GitLab KeyDriver documentation](https://gitlab.com/kunzisoft/android-hardware-key-driver) describes hmac-secret over USB or NFC for compatible authenticators with `clientPin` or built-in user verification. It documents `HMAC_SECRET_CREATE` and `HMAC_SECRET_CHALLENGE_RESPONSE` intents. The tags page lists 0.2.0 as “Compose & Hmac-Secret”.

This gives us a likely integration path through the KeyDriver intent API instead of implementing CTAP from scratch. We still need to verify the released driver's exact response extras and test it with the selected Token2 key. The docs show differing response-extra names in the prose and sample, so the adapter must be checked against the actual version before use.

Do not simply enable `FIDO2_SECRET` in the KDBX master-credential composition path: that would make the hardware response part of the database's master key and conflict with the agreed desktop-unlock behavior.

## Development sequence

1. Add an isolated Android test variant with its own application ID so it can coexist with the normal KeePassDX app.
2. Verify the released KeyDriver API and confirm the selected Token2 key exposes `hmac-secret` over USB or NFC.
3. Design and implement authenticated encryption for the locally stored master-password record. Never persist the master password in plaintext. Keep key derivation, nonce handling, credential identifiers, app backup behavior, and memory clearing explicit. Verify the driver's attestation/signature before trusting a returned secret.
4. Implement credential enrollment and unlock. Validate the flow with a disposable KDBX: unlock, save, restart the app, and unlock again.
5. Enroll a second key and verify recovery before treating the flow as usable.
6. Add optional key-file handling and verify that the unchanged KDBX still opens on Windows with KeePassXC when supplied the same password and key file.

## Open implementation checks

- Exact KeyDriver release and response-extra contract.
- Token2 model, firmware, and Android USB/NFC behavior for CTAP `hmac-secret`.
- Secure storage format, backup exclusion, reset/re-enrollment, and loss-of-key recovery.
- A separate release signing key must remain outside the repository; the test variant's package ID alone does not configure release signing.
