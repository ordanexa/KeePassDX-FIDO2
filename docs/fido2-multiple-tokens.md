# Multiple local tokens (0.1.8 test)

## Decision and user flow

Support up to **five named tokens per database URI and Android app installation**. Two (daily and backup) are the usual setup; five is an application limit, not a FIDO2 limit. Only the existing supported Token2 USB model is enabled.

- **Token hinzufügen** asks for a unique local name and the database Master Password. The selected optional Key File remains part of database verification. Token PIN and touch follow separately.
- Existing enrollments are retained. A newly created credential must return a valid, signed hmac-secret assertion, decrypt the candidate envelope, and successfully open the database with the selected factors before the addition is committed.
- **Tokens verwalten** lists names and removes one selected enrollment after confirmation. Removing the last one warns that Master Password and any required Key File remain the recovery path. Removal is local: no token reset/deletion command is sent, and neither KDBX nor Key File is changed.
- Unlock selects the connected token automatically using one CTAP allowList assertion. There is no loop of PIN attempts over records. Exactly one supported USB token must be attached.
- A token already enrolled for this database on this installation is rejected using MakeCredential's excludeList. Existing enrollment stays intact. Names must be unique, 1–40 characters. Names are labels, not proof of token identity.

## Architecture and recovery

The database is independent of token enrollment. Master Password plus any database-required Key File remain valid in compatible KeePass clients. Token unlock is an app convenience, not mandatory token-based enforcement of the KDBX key.

Every app installation requires its own enrollment of each token. KDBX synchronization does not transfer enrollments. A backup token alone cannot recover a lost installation; retain Master Password and any required Key File independently. Enrollment export/import is not implemented.

After changing the database Master Password, each old token envelope contains the previous password. Remove and add each token again with the new password; adding one token does not update the others. This also applies if the password was changed in another KeePass client. Never reset a token to refresh a local enrollment.

## Storage and protocol

A bounded v2 CBOR collection contains up to five labels and independent, unchanged v1 authenticated envelopes. Each token credential derives its own encryption key from its own hmac-secret output. All entries for a database use the same **public random salt**, enabling a single allowList request whose returned credential ID selects the appropriate stored public key and encrypted password. The signature, RP, UP, UV, extension and authenticated envelope are checked before using the password.

A legacy single-envelope file is read without rewriting and displayed as **Bisheriger Token**. Its original salt and envelope bytes are preserved when adding the second token. The collection is written atomically only after successful verification. A compare-and-write guard rejects stale callbacks/management dialogs instead of losing a newly added token or restoring a removed one. Corrupt, oversized and unsupported files fail closed. Removing the final token stores an empty collection.

The file location and backup exclusions remain unchanged. An older APK that only understands v1 cannot read a collection once changed by 0.1.8; downgrading is not a supported way to undo enrollment changes. Password-based database access remains independent.

The token's advertised credential-list limit is respected; unsupported list sizes fail without overwriting local data. Actual firmware compatibility for lists of up to five needs physical-device testing. Failed/cancelled enrollment can leave an unused non-resident credential handle discarded by the app; there are no reset, PIN-change or credential-management commands.

Protocol reference: [FIDO CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html), MakeCredential excludeList, GetAssertion allowList, GetInfo maxCredentialCountInList and hmac-secret.

## Acceptance tests

Automated checks cover legacy migration, retaining the original encrypted envelope, five-token capacity, duplicate names/IDs, independent envelope decryption, individual and last-token removal, stale writes, malformed storage, failed/cancelled/mismatched database callbacks, and successful addition. The independent CTAP simulator exercises list selection at every position under PIN protocols 1 and 2, duplicate exclusion, unknown credentials and the existing signature/UV/RP/PIN negative cases.

Physical acceptance remains pending:

1. Update without uninstalling; unlock with the existing token before adding another.
2. Add a second supported token with its own name and PIN; lock and unlock with each token alternately.
3. Repeat using a database that requires a Key File; a missing/wrong file must still fail.
4. Attempt duplicate enrollment, wrong database password, cancel and disconnect. Verify the old token still works and no addition was saved.
5. Test a wrong token PIN once only when known retries are sufficient; no automatic retry must occur.
6. Remove only the backup entry; the daily token must still work, and the removed token must fail for this database.
7. Verify manual recovery, app restart, and the existing quiet USB/browser-login behavior. Higher token counts need real hardware before being described as device-verified.
