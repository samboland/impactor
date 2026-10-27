use std::str::FromStr;

use crate::Error;
use base64::{Engine, engine::general_purpose};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::auth::{Account, AuthenticationExtras, LoginState, PhoneNumber, VerifyBody, VerifyCode};

impl Account {
    pub async fn send_2fa_to_devices(&self) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(false).await;

        let res = self
            .client
            .get("https://gsa.apple.com/auth/verify/trusteddevice")
            .headers(headers)
            .send()
            .await?;

        let status_code = res.status();

        if !status_code.is_success() {
            return Err(Error::AuthSrpWithMessage(
                status_code.as_u16() as i64,
                "Failed to send 2FA to devices".to_string(),
            ));
        }

        return Ok(LoginState::Needs2FAVerification);
    }

    pub async fn send_sms_2fa_to_devices(&self, phone_id: u32) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(true).await;

        let body = VerifyBody {
            phone_number: PhoneNumber { id: phone_id },
            mode: "sms".to_string(),
            security_code: None,
        };

        let res = self
            .client
            .put("https://gsa.apple.com/auth/verify/phone")
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        let status_code = res.status();

        if !status_code.is_success() {
            return Err(Error::AuthSrpWithMessage(
                status_code.as_u16() as i64,
                "Failed to send SMS 2FA to devices".to_string(),
            ));
        }

        return Ok(LoginState::NeedsSMS2FAVerification(body));
    }

    pub async fn get_auth_extras(&self) -> Result<AuthenticationExtras, Error> {
        let mut headers = self.build_2fa_headers(true).await;

        let mut req = self
            .client
            .get("https://gsa.apple.com/auth")
            .headers(headers.clone())
            .header("Accept", "application/json")
            .send()
            .await?;
        let mut compatibility_profile = None;
        if bare_client_rejection(req.status(), req.headers()) {
            // Apple's auth pages reject some client profiles before reading the
            // account token. Retry once, retaining the same anisette and token.
            // Profile reference: FrizzleM/SideInstaller grandslam.rs.
            let client_info = HeaderValue::from_static(
                "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
            );
            headers.insert("X-Mme-Client-Info", client_info.clone());
            log::info!(
                "Apple auth page rejected the client profile; trying Mac compatibility headers once"
            );
            req = self
                .client
                .get("https://gsa.apple.com/auth")
                .headers(headers)
                .send()
                .await?;
            compatibility_profile = Some(client_info);
        }
        let status = req.status();
        let json_response = req
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("json"));
        log::info!(
            "Apple authentication discovery: HTTP {status}, JSON response = {json_response}"
        );
        if !status.is_success() {
            return Err(Error::AuthSrpWithMessage(
                status.as_u16().into(),
                "Failed to read authentication methods".into(),
            ));
        }
        let mut session_headers = HeaderMap::new();
        if let Some(client_info) = compatibility_profile {
            session_headers.insert("X-Mme-Client-Info", client_info);
        }
        for name in ["scnt", "x-apple-id-session-id"] {
            if let Some(value) = req.headers().get(name) {
                session_headers.insert(HeaderName::from_static(name), value.clone());
            }
        }
        let value = req.json::<serde_json::Value>().await?;
        log::info!(
            "Apple authentication discovery fields: fsaChallenge = {}, trustedPhoneNumbers = {}",
            value.get("fsaChallenge").is_some(),
            value.get("trustedPhoneNumbers").is_some()
        );
        let mut new_state =
            serde_json::from_value::<AuthenticationExtras>(value).map_err(|_| {
                Error::AuthSrpWithMessage(
                    0,
                    "Apple returned an unsupported authentication response shape".into(),
                )
            })?;
        log::info!(
            "Apple authentication methods: security key = {}, trusted phone count = {}",
            new_state.fsa_challenge.is_some(),
            new_state.trusted_phone_numbers.len()
        );
        if let Some(challenge) = &mut new_state.fsa_challenge {
            challenge.session_headers = session_headers;
        }
        if status.as_u16() == 201 && new_state.fsa_challenge.is_none() {
            if let Some(phone) = new_state.trusted_phone_numbers.first() {
                new_state.new_state = Some(LoginState::NeedsSMS2FAVerification(VerifyBody {
                    phone_number: PhoneNumber { id: phone.id },
                    mode: "sms".to_string(),
                    security_code: None,
                }));
            }
        }

        Ok(new_state)
    }

    pub(crate) async fn verify_security_key(
        &self,
        assertion: crate::auth::security_key::SecurityKeyAssertion,
        session_headers: HeaderMap,
    ) -> Result<Option<String>, Error> {
        let mut headers = self.build_2fa_headers(true).await;
        headers.extend(session_headers);
        let response = self
            .client
            .post("https://gsa.apple.com/auth/verify/security/key")
            .headers(headers)
            .json(&assertion)
            .send()
            .await?;
        let status = response.status();
        let pet_present = response.headers().contains_key("x-apple-pe-token");
        let service_token_count = response
            .headers()
            .get_all("x-apple-gs-token")
            .iter()
            .count();
        log::info!(
            "Apple security-key assertion: HTTP {status}, PET header = {pet_present}, service-token count = {service_token_count}"
        );
        // A conflict can indicate another required authentication step. It does
        // not grant access: a fresh GrandSlam login must still issue valid tokens.
        if !status.is_success() && status.as_u16() != 409 {
            return Err(Error::AuthSrpWithMessage(
                status.as_u16().into(),
                "Apple rejected the security-key assertion".into(),
            ));
        }
        let password_token = crate::auth::security_key::password_token(response.headers())?;
        let json_response = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("json"));
        if json_response {
            let body = response.json::<serde_json::Value>().await?;
            if let Some(message) = verification_service_error(&body) {
                log::warn!("Apple security-key assertion: {message}");
                return Err(Error::AuthSrpWithMessage(status.as_u16().into(), message));
            }
        }
        Ok(password_token)
    }

    pub async fn verify_2fa(&self, code: String) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(false);
        let res = self
            .client
            .get("https://gsa.apple.com/grandslam/GsService2/validate")
            .headers(headers.await)
            .header(
                HeaderName::from_str("security-code").unwrap(),
                HeaderValue::from_str(&code).unwrap(),
            )
            .send()
            .await?;

        let res: plist::Dictionary = plist::from_bytes(res.text().await?.as_bytes())?;

        super::check_error(&res)?;

        Ok(LoginState::NeedsLogin)
    }

    pub async fn verify_sms_2fa(
        &self,
        code: String,
        mut body: VerifyBody,
    ) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(true).await;
        body.security_code = Some(VerifyCode { code });
        let res = self
            .client
            .post("https://gsa.apple.com/auth/verify/phone/securitycode")
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        let status_code = res.status();

        // TODO: 423 http code may occur, in this case we to ask for sending
        // last code sent (unlikely it would even work), or try again later
        if !status_code.is_success() {
            return Err(Error::Bad2faCode);
        }

        Ok(LoginState::NeedsLogin)
    }

    async fn build_2fa_headers(&self, sms: bool) -> HeaderMap {
        let spd = self.spd.as_ref().unwrap();
        let dsid = spd.get("adsid").unwrap().as_string().unwrap();
        let token = spd.get("GsIdmsToken").unwrap().as_string().unwrap();

        let identity_token = general_purpose::STANDARD.encode(format!("{}:{}", dsid, token));

        let mut headers = HeaderMap::new();
        let valid_anisette = self.get_anisette().await;
        for (k, v) in valid_anisette.generate_headers(false, true, true) {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(&v).unwrap(),
            );
        }
        if !sms {
            headers.insert("Content-Type", HeaderValue::from_static("text/x-xml-plist"));
            headers.insert("Accept", HeaderValue::from_static("text/x-xml-plist"));
        } else {
            headers.insert("Content-Type", HeaderValue::from_static("application/json"));
            headers.insert("Accept", HeaderValue::from_static("application/json"));
        }
        headers.insert("User-Agent", HeaderValue::from_static("Xcode"));
        headers.insert("Accept-Language", HeaderValue::from_static("en-us"));
        headers.append(
            "X-Apple-Identity-Token",
            HeaderValue::from_str(&identity_token).unwrap(),
        );

        if let Ok(locale) = valid_anisette.get_header("x-apple-locale") {
            headers.insert("Loc", HeaderValue::from_str(&locale).unwrap());
        }

        headers
    }
}

// A JSON denial can be an account-specific decision. Do not retry those,
// invalid credentials, rate limits, or other server failures with a new profile.
fn bare_client_rejection(status: reqwest::StatusCode, headers: &HeaderMap) -> bool {
    status == reqwest::StatusCode::FORBIDDEN
        && !headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("json"))
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn only_bare_profile_denials_get_a_compatibility_retry() {
        let mut headers = HeaderMap::new();
        assert!(bare_client_rejection(StatusCode::FORBIDDEN, &headers));
        headers.insert("content-type", "text/html".parse().unwrap());
        assert!(bare_client_rejection(StatusCode::FORBIDDEN, &headers));
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::OK,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert!(!bare_client_rejection(status, &headers));
        }
        headers.insert(
            "content-type",
            "application/json;charset=UTF-8".parse().unwrap(),
        );
        assert!(!bare_client_rejection(StatusCode::FORBIDDEN, &headers));
    }
}

// Apple can return a service error with an otherwise accepted HTTP status.
// Include only numeric error codes, never arbitrary server response values.
fn verification_service_error(body: &serde_json::Value) -> Option<String> {
    let errors = body.get("serviceErrors")?.as_array()?;
    if errors.is_empty() {
        return None;
    }
    let code = errors
        .first()
        .and_then(|error| error.get("code"))
        .and_then(|code| match code {
            serde_json::Value::String(code) => Some(code.clone()),
            serde_json::Value::Number(code) => Some(code.to_string()),
            _ => None,
        })
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 12
                && code.chars().all(|c| c.is_ascii_digit() || c == '-')
        });
    Some(match code {
        Some(code) => format!("Apple rejected security-key verification (service code {code})"),
        None => "Apple rejected security-key verification (service error)".into(),
    })
}

#[cfg(test)]
mod verification_response_tests {
    use super::*;

    #[test]
    fn service_errors_are_not_accepted_as_completed_verification() {
        let body = serde_json::json!({"serviceErrors": [{"code": "-21669", "message": "private fixture detail"}]});
        let error = verification_service_error(&body).unwrap();
        assert!(error.contains("-21669"));
        assert!(!error.contains("private fixture detail"));
        assert!(verification_service_error(&serde_json::json!({"serviceErrors": []})).is_none());
    }

    #[test]
    fn arbitrary_error_code_text_is_not_exposed() {
        let error = verification_service_error(
            &serde_json::json!({"serviceErrors": [{"code": "private fixture value"}]}),
        )
        .unwrap();
        assert!(!error.contains("private fixture value"));
    }
}
