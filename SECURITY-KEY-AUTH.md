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
