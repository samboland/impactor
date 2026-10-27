//! Apple security-key challenges and the Windows WebAuthn client.
//!
//! Native GrandSlam verification still needs an end-to-end account test.

use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityKeyChallenge {
    challenge: String,
    key_handles: Vec<String>,
    rp_id: Option<String>,
    request_id: Option<String>,
    #[serde(skip)]
    pub(crate) session_headers: reqwest::header::HeaderMap,
}

impl std::fmt::Debug for SecurityKeyChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityKeyChallenge")
            .field("credential_count", &self.key_handles.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecurityKeyAssertion {
    challenge: String,
    client_data: String,
    signature_data: String,
    authenticator_data: String,
    user_handle: String,
    #[serde(rename = "credentialID")]
    credential_id: String,
    rp_id: String,
    request_id: String,
}

fn key_error(message: impl Into<String>) -> Error {
    Error::AuthSrpWithMessage(0, message.into())
}

fn decode(value: &str) -> Result<Vec<u8>, Error> {
    // Apple's challenge and handles can use either base64 alphabet and padding.
    let normalized = value.replace('-', "+").replace('_', "/");
    general_purpose::STANDARD_NO_PAD
        .decode(normalized.trim_end_matches('='))
        .map_err(|_| key_error("Apple returned invalid security-key challenge data"))
}

impl SecurityKeyChallenge {
    fn rp_id(&self) -> Result<&str, Error> {
        match self.rp_id.as_deref().unwrap_or("apple.com") {
            rp @ ("apple.com" | "gsa.apple.com") => Ok(rp),
            _ => Err(key_error(
                "Apple returned an unsupported security-key relying party",
            )),
        }
    }

    fn client_data(&self) -> Result<Vec<u8>, Error> {
        self.rp_id()?;
        let challenge = decode(&self.challenge)?;
        if challenge.is_empty() || self.key_handles.is_empty() {
            return Err(key_error("Apple returned an empty security-key challenge"));
        }
        serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "origin": "https://gsa.apple.com",
            "crossOrigin": false,
        }))
        .map_err(Error::from)
    }

    fn assertion(
        &self,
        client_data: &[u8],
        credential_id: &[u8],
        authenticator_data: &[u8],
        signature: &[u8],
        user_handle: &[u8],
    ) -> Result<SecurityKeyAssertion, Error> {
        // Always submit the exact client data passed to Windows for signing.
        Ok(SecurityKeyAssertion {
            challenge: general_purpose::STANDARD_NO_PAD.encode(decode(&self.challenge)?),
            client_data: general_purpose::STANDARD.encode(client_data),
            signature_data: general_purpose::STANDARD.encode(signature),
            authenticator_data: general_purpose::STANDARD.encode(authenticator_data),
            user_handle: general_purpose::STANDARD_NO_PAD.encode(user_handle),
            credential_id: general_purpose::STANDARD.encode(credential_id),
            rp_id: self.rp_id()?.to_owned(),
            request_id: self.request_id.clone().unwrap_or_default(),
        })
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn sign(_challenge: SecurityKeyChallenge) -> Result<SecurityKeyAssertion, Error> {
    Err(key_error(
        "Security-key authentication is currently supported only on Windows",
    ))
}

#[cfg(target_os = "windows")]
pub(crate) fn sign(challenge: SecurityKeyChallenge) -> Result<SecurityKeyAssertion, Error> {
    use windows::Win32::{
        Networking::WindowsWebServices::*, UI::WindowsAndMessaging::GetForegroundWindow,
    };
    use windows::core::{HSTRING, w};

    let mut client_json = challenge.client_data()?;
    let rp_id = HSTRING::from(challenge.rp_id()?);
    let mut handles = challenge
        .key_handles
        .iter()
        .map(|handle| decode(handle))
        .collect::<Result<Vec<_>, _>>()?;
    if handles.iter().any(Vec::is_empty) {
        return Err(key_error("Apple returned an empty security-key credential"));
    }
    let mut credentials = handles
        .iter_mut()
        .map(|handle| WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: handle.len() as u32,
            pbId: handle.as_mut_ptr(),
            pwszCredentialType: w!("public-key"),
        })
        .collect::<Vec<_>>();
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: client_json.len() as u32,
        pbClientDataJSON: client_json.as_mut_ptr(),
        pwszHashAlgId: w!("SHA-256"),
    };
    // Version 1 is supported by the baseline Windows 10 WebAuthn API.
    let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: 1,
        dwTimeoutMilliseconds: 120_000,
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: credentials.len() as u32,
            pCredentials: credentials.as_mut_ptr(),
        },
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
        ..Default::default()
    };

    struct OwnedAssertion(*mut WEBAUTHN_ASSERTION);
    impl Drop for OwnedAssertion {
        fn drop(&mut self) {
            // SAFETY: Windows allocated this assertion after a successful call.
            unsafe { WebAuthNFreeAssertion(self.0) };
        }
    }
    unsafe fn bytes<'a>(ptr: *const u8, len: u32) -> Result<&'a [u8], Error> {
        if len == 0 {
            return Ok(&[]);
        }
        if ptr.is_null() {
            return Err(key_error(
                "Windows returned an invalid security-key assertion",
            ));
        }
        // SAFETY: The caller retains the owning Windows assertion for this read.
        Ok(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
    }
    // SAFETY: All option buffers remain allocated until the synchronous call returns.
    // Windows owns the consent, PIN, touch, and cancellation UI.
    let assertion = unsafe {
        WebAuthNAuthenticatorGetAssertion(
            GetForegroundWindow(),
            &rp_id,
            &client_data,
            Some(&options),
        )
    }
    .map_err(|error| {
        key_error(format!(
            "Security-key authentication failed or was cancelled: {error}"
        ))
    })?;
    if assertion.is_null() {
        return Err(key_error("Windows returned no security-key assertion"));
    }
    let owned = OwnedAssertion(assertion);
    // SAFETY: owned retains the valid assertion and its buffers until serialization ends.
    unsafe {
        let result = &*owned.0;
        challenge.assertion(
            &client_json,
            bytes(result.Credential.pbId, result.Credential.cbId)?,
            bytes(result.pbAuthenticatorData, result.cbAuthenticatorData)?,
            bytes(result.pbSignature, result.cbSignature)?,
            bytes(result.pbUserId, result.cbUserId)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> SecurityKeyChallenge {
        serde_json::from_value(serde_json::json!({
            "challenge": "-_8", "keyHandles": ["AQI="],
            "rpId": "apple.com", "requestId": "fixture-request",
        }))
        .unwrap()
    }

    #[test]
    fn accepts_both_base64_alphabets_and_padding() {
        for encoded in ["-_8", "-_8=", "+/8", "+/8="] {
            assert_eq!(decode(encoded).unwrap(), vec![251, 255]);
        }
        assert!(decode("not base64!").is_err());
    }

    #[test]
    fn client_data_binds_challenge_to_native_apple_origin() {
        let data: serde_json::Value =
            serde_json::from_slice(&challenge().client_data().unwrap()).unwrap();
        assert_eq!(data["type"], "webauthn.get");
        assert_eq!(data["challenge"], "-_8");
        assert_eq!(data["origin"], "https://gsa.apple.com");
        assert_eq!(data["crossOrigin"], false);
    }

    #[test]
    fn rejects_empty_challenge_and_unrelated_relying_party() {
        let mut input = challenge();
        input.rp_id = Some("example.org".into());
        assert!(input.client_data().is_err());
        input.rp_id = None;
        input.challenge.clear();
        assert!(input.client_data().is_err());
        input.challenge = "AQI".into();
        input.key_handles.clear();
        assert!(input.client_data().is_err());
    }

    #[test]
    fn serializes_apple_assertion_without_changing_signed_client_data() {
        let input = challenge();
        let client_data = input.client_data().unwrap();
        let body = serde_json::to_value(
            input
                .assertion(&client_data, &[1, 2], &[3], &[4], &[])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["challenge"], "+/8");
        assert_eq!(
            body["clientData"],
            general_purpose::STANDARD.encode(&client_data)
        );
        assert_eq!(body["credentialID"], "AQI=");
        assert_eq!(body["authenticatorData"], "Aw==");
        assert_eq!(body["signatureData"], "BA==");
        assert_eq!(body["userHandle"], "");
        assert_eq!(body["requestId"], "fixture-request");
    }

    #[test]
    fn debug_does_not_disclose_challenge_or_session_headers() {
        let mut input = challenge();
        input
            .session_headers
            .insert("scnt", "private-session".parse().unwrap());
        let debug = format!("{input:?}");
        assert!(!debug.contains("private-session"));
        assert!(!debug.contains("-_8"));
    }
}

#[cfg(test)]
mod auth_extras_tests {
    use crate::auth::AuthenticationExtras;

    #[test]
    fn security_key_account_does_not_require_trusted_phone_numbers() {
        let extras: AuthenticationExtras = serde_json::from_value(serde_json::json!({
            "fsaChallenge": {"challenge": "AQI", "keyHandles": ["AwQ"]}
        }))
        .unwrap();
        assert!(extras.trusted_phone_numbers.is_empty());
        assert!(extras.fsa_challenge.is_some());
    }

    #[test]
    fn ordinary_device_and_sms_accounts_still_parse() {
        let extras: AuthenticationExtras = serde_json::from_value(serde_json::json!({
            "trustedPhoneNumbers": [{"numberWithDialCode": "+1 *** *** **42", "lastTwoDigits": "42", "pushMode": "sms", "id": 7}]
        })).unwrap();
        assert!(extras.fsa_challenge.is_none());
        assert_eq!(extras.trusted_phone_numbers[0].id, 7);
    }
}

/// A PET is a password-equivalent token. Never include it in diagnostics.
pub(crate) fn password_token(
    headers: &reqwest::header::HeaderMap,
) -> Result<Option<String>, Error> {
    let mut tokens = headers.get_all("x-apple-pe-token").iter();
    let Some(header) = tokens.next() else {
        return Ok(None);
    };
    if tokens.next().is_some() {
        return Err(key_error(
            "Apple returned multiple password-equivalent tokens",
        ));
    }
    let value = header
        .to_str()
        .map_err(|_| key_error("Apple returned an invalid password-token header"))?;
    let decoded = decode(value)?;
    let decoded = std::str::from_utf8(&decoded)
        .map_err(|_| key_error("Apple returned an invalid password-token encoding"))?;
    let mut fields = decoded.split(':');
    let identifier = fields.next().unwrap_or_default();
    let token = fields.next().unwrap_or_default();
    if identifier.is_empty() || token.is_empty() {
        return Err(key_error(
            "Apple returned an incomplete password-token header",
        ));
    }
    Ok(Some(token.to_owned()))
}

#[cfg(test)]
mod password_token_tests {
    use super::*;
    use reqwest::header::HeaderMap;

    #[test]
    fn extracts_pet_from_native_response_with_optional_lifetime() {
        for value in [
            "fixture-account:fixture-token",
            "fixture-account:fixture-token:300:1234567890",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-apple-pe-token",
                general_purpose::STANDARD.encode(value).parse().unwrap(),
            );
            assert_eq!(
                password_token(&headers).unwrap().as_deref(),
                Some("fixture-token")
            );
        }
    }

    #[test]
    fn absent_pet_is_not_treated_as_verified_login() {
        assert!(password_token(&HeaderMap::new()).unwrap().is_none());
        let mut headers = HeaderMap::new();
        headers.insert("x-apple-gs-token", "fixture-service-token".parse().unwrap());
        assert!(password_token(&headers).unwrap().is_none());
    }

    #[test]
    fn invalid_pet_headers_fail_without_disclosing_values() {
        for value in ["fixture-account:", ":fixture-token", "fixture-account"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-apple-pe-token",
                general_purpose::STANDARD.encode(value).parse().unwrap(),
            );
            let error = password_token(&headers).unwrap_err().to_string();
            assert!(!error.contains("fixture-account"));
            assert!(!error.contains("fixture-token"));
        }
        let mut headers = HeaderMap::new();
        headers.append("x-apple-pe-token", "Zm9vOmJhcg==".parse().unwrap());
        headers.append("x-apple-pe-token", "Zm9vOmJheg==".parse().unwrap());
        assert!(password_token(&headers).is_err());
    }
}
