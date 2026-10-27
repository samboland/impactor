# Experimental Windows security-key authentication

This local patch adds a Windows WebAuthn assertion path to GrandSlam login.
It is not yet verified against a live Apple Account or a signing operation.

## Behavior

- Read `/auth` before requesting a trusted-device or SMS code.
- If Apple returns `fsaChallenge`, use Windows' native security-key dialog.
- Preserve Apple's challenge, credential allowlist, request ID, and session headers.
- Submit the assertion to `/auth/verify/security/key`, then repeat GrandSlam login.
- Do not treat an assertion HTTP response as a completed account login.
- Stop if Apple still requests a security key after assertion verification.
- Keep the existing device and SMS code paths when no challenge is present.
- Report security-key authentication as unsupported on other platforms.

The new path does not remove security keys or change account settings.
It does not register a new credential on the YubiKey.
Windows handles the PIN, key touch, and cancellation dialog.

## Evidence and open questions

The challenge and assertion field names follow the existing iCloudPy implementation:
https://github.com/mandarons/icloudpy/blob/main/icloudpy/base.py

iCloudPy authenticates to `idmsa.apple.com`; Impactor uses native GrandSlam on
`gsa.apple.com`. The native challenge availability, verification endpoint, and
`https://gsa.apple.com` client-data origin need live verification. A working
iCloud web session alone does not prove developer signing works.

Windows API reference:
https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion

## Local checks

Run from this checkout:

```powershell
cargo test -p plume_core --lib --features tweaks --locked
cargo build --bin plumeimpactor --locked
```

The `tweaks` feature matches the GUI's existing dependency configuration.
The upstream core crate does not compile without it because it exports gated types.

The seven offline tests cover encoding, client-data binding, assertion payloads,
relying-party rejection, redacted diagnostics, and code-account compatibility.
They do not contact Apple or invoke the hardware key.

## Live test

1. Close the stock Impactor app.
2. Start `target/debug/plumeimpactor.exe`.
3. Open Settings and sign in yourself.
4. If Windows requests a security key, select your YubiKey and approve the request.
5. Confirm the account appears in Impactor.
6. Sign and install TrollInstallerX on the paired iPhone.

Also test cancellation, an incorrect key, and ordinary device/SMS accounts.
Logs report challenge presence and trusted-phone count, without challenge values
or session headers. Do not publish account files, passwords, or authentication logs.

## Upstream contribution

No upstream PR is part of this patch. The contribution guide says AI-generated
PRs are automatically closed. This implementation used AI assistance.
The maintainer has not approved an exception.

## 2026-10-27 discovery failure

The live native `/auth` lookup returned HTTP 403 with a non-JSON response.
No security-key challenge reached the Windows client in that attempt.
A separate probe with a dummy identity token returned 403 for a Windows
profile and 401 for the modern Mac AuthKit profile used by SideInstaller.
The probe did not use account credentials or a real session token.

Discovery now retries a non-JSON 403 once with that Mac client-info header,
preserving the same anisette and identity token. JSON denials, 401, and 429
do not trigger a retry. A successful challenge carries the compatibility
header into assertion verification. Live authentication still needs testing.

The app title includes `security-key test 3` to distinguish this test build.
There are eight offline tests after the retry classification check.

## Test 3 live result and test 4

The compatibility retry reached HTTP 200 and a native `fsaChallenge`.
Windows produced an assertion. A subsequent login still required authentication.
Test 4 records assertion status, token presence, and service-token count without
recording token values. If Apple returns an `X-Apple-PE-Token`, the client keeps
it only in the current in-memory session and uses it for the completing SRP
handshake. The handshake and developer-service checks must still succeed.
The code does not mark login complete from an assertion HTTP status alone.

There are thirteen offline tests, including native PET formats, missing tokens,
malformed tokens, and duplicate-token rejection. The test 4 live result is pending.

Verification also rejects Apple service-error payloads inside accepted HTTP responses.
Only numeric service codes enter diagnostics; response messages and tokens do not.

## Test 4 live result and test 5

Apple accepted key verification with HTTP 200 and issued a PET plus 15 service
tokens. Reusing the PET as an SRP password failed with -22406. Test 5 removes
that extra handshake and keeps the service tokens from the native response.
`get_app_token` selects only the requested service token. Developer API calls
still validate that token before an account is saved.

The Windows request now defaults to `discouraged` user verification for this
password-plus-key flow. Explicit `required` or `preferred` values from Apple's
challenge take precedence. No account or hardware-key settings change.
Windows or the authenticator can still require UV because of their own policy.

Sixteen offline tests cover the token response, exact service scope, redacted
diagnostics, and user-verification policy. Live signing still needs verification.
The test 5 window is labeled explicitly.
