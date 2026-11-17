//! Sign-in with the external OpenID provider on the enrollment portal, and the OpenID step of
//! the desktop client's MFA (VPN MFA and MFA configuration). New code, AGPL-3.0.
//!
//! - `POST /openid/auth_info` asks Core for the provider's authorization URL. Core keeps the PKCE
//!   verifier and nonce; Edge gets the OAuth `state` and a random binding secret, and keeps both
//!   in an encrypted, HTTP-only cookie limited to `/api/v1/openid` for 10 minutes.
//! - `POST /openid/callback` (enrollment) and `POST /openid/callback/mfa` finish the sign-in: the
//!   state from the provider must match the cookie (compared in constant time), the cookie is
//!   removed whatever happens, and Core gets the code with the binding. Without the cookie of the
//!   browser that started the sign-in, a code is useless.

use std::time::Duration;

use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use axum_extra::extract::PrivateCookieJar;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    error::ApiError,
    handlers::get_core_response,
    http::{AppState, remove_session_cookie, session_cookie},
    proto::{
        AuthCallbackRequest, AuthFlowType, AuthInfoRequest, ClientMfaOidcAuthenticateRequest,
        DeviceInfo, OpenIdProviderKind, core_request, core_response,
    },
};

pub(crate) const OPENID_COOKIE_NAME: &str = "xguard_openid";
pub(crate) const OPENID_COOKIE_PATH: &str = "/api/v1/openid";
/// Matches how long Core keeps a started sign-in.
const OPENID_COOKIE_MAX_AGE: time::Duration = time::Duration::minutes(10);
/// Finishing a sign-in includes Core's round trip to the provider.
const CORE_OPENID_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_MFA_STATE_LEN: usize = 160;
const MAX_STATE_LEN: usize = 512;
const MAX_CODE_LEN: usize = 4096;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/auth_info", post(auth_info))
        .route("/callback", post(enrollment_callback))
        .route("/callback/mfa", post(mfa_callback))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FlowType {
    Enrollment,
    Mfa,
}

/// What the browser keeps between starting and finishing a sign-in (encrypted by the cookie jar).
#[derive(Deserialize, Serialize)]
struct PendingSignIn {
    flow: FlowType,
    state: String,
    binding: String,
}

/// The provider kinds the web UI has buttons for.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProviderKind {
    Custom,
    Google,
    Microsoft,
    Okta,
    JumpCloud,
}

impl ProviderKind {
    fn new(kind: OpenIdProviderKind, url: &str) -> Self {
        match kind {
            OpenIdProviderKind::Google => Self::Google,
            OpenIdProviderKind::Microsoft => Self::Microsoft,
            OpenIdProviderKind::Okta => Self::Okta,
            OpenIdProviderKind::Jumpcloud => Self::JumpCloud,
            OpenIdProviderKind::Custom | OpenIdProviderKind::Zitadel => Self::Custom,
            // Older Core versions send no kind; recognise the big providers by their URL.
            OpenIdProviderKind::Unspecified => {
                match Url::parse(url).ok().as_ref().and_then(Url::host_str) {
                    Some("accounts.google.com") => Self::Google,
                    Some("login.microsoftonline.com") => Self::Microsoft,
                    _ => Self::Custom,
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthInfoData {
    #[serde(rename = "type")]
    flow: FlowType,
    /// For MFA: the session token from the desktop client's link, `<token>` or
    /// `<token>.<step attempt ID>`.
    #[serde(default)]
    state: Option<String>,
}

#[derive(Debug, PartialEq, Serialize)]
pub(crate) struct AuthInfo {
    url: String,
    button_display_name: Option<String>,
    provider_kind: ProviderKind,
}

#[derive(Deserialize)]
pub(crate) struct CallbackData {
    code: String,
    state: String,
}

#[derive(Debug, PartialEq, Serialize)]
pub(crate) struct EnrollmentCallbackResponse {
    url: String,
    token: String,
}

/// Compares secrets without leaking where they differ through timing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn valid_mfa_state(state: &str) -> bool {
    !state.is_empty()
        && state.len() <= MAX_MFA_STATE_LEN
        && state
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.')
}

/// Request the provider's authorization URL from Core and remember the sign-in in a cookie.
#[instrument(level = "debug", skip_all)]
async fn auth_info(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    private_cookies: PrivateCookieJar,
    Json(data): Json<AuthInfoData>,
) -> Result<(PrivateCookieJar, Json<AuthInfo>), ApiError> {
    let (auth_flow_type, session) = match data.flow {
        FlowType::Enrollment => (AuthFlowType::Enrollment, None),
        FlowType::Mfa => {
            let session = data
                .state
                .filter(|session| valid_mfa_state(session))
                .ok_or_else(|| ApiError::BadRequest("Missing or invalid MFA session".into()))?;
            (AuthFlowType::Mfa, Some(session))
        }
    };
    let request = AuthInfoRequest {
        #[allow(deprecated)]
        redirect_url: String::new(),
        state: session,
        auth_flow_type: auth_flow_type as i32,
    };
    let rx = state
        .grpc_server
        .send(core_request::Payload::AuthInfo(request), device_info)?;
    let core_response::Payload::AuthInfo(response) = get_core_response(rx, None).await? else {
        error!("Received an invalid gRPC response type for OpenID auth info");
        return Err(ApiError::InvalidResponseType);
    };
    let pending = serde_json::to_string(&PendingSignIn {
        flow: data.flow,
        state: response.csrf_token.clone(),
        binding: response.nonce.clone(),
    })
    .map_err(|err| ApiError::Unexpected(err.to_string()))?;
    let cookie = session_cookie(
        OPENID_COOKIE_NAME,
        pending,
        OPENID_COOKIE_PATH,
        state.cookie_secure(),
    )
    .max_age(OPENID_COOKIE_MAX_AGE)
    .build();
    let provider_kind = ProviderKind::new(response.provider_kind(), &response.url);
    debug!("Started an OpenID sign-in ({:?})", data.flow);
    Ok((
        private_cookies.add(cookie),
        Json(AuthInfo {
            url: response.url,
            button_display_name: response.button_display_name,
            provider_kind,
        }),
    ))
}

/// Takes the pending sign-in out of the cookie jar (it works once) and checks the callback
/// against it.
fn take_pending(
    state: &AppState,
    private_cookies: PrivateCookieJar,
    flow: FlowType,
    data: &CallbackData,
) -> (PrivateCookieJar, Result<PendingSignIn, ApiError>) {
    let pending = private_cookies
        .get(OPENID_COOKIE_NAME)
        .and_then(|cookie| serde_json::from_str::<PendingSignIn>(cookie.value()).ok());
    let private_cookies = remove_session_cookie(
        private_cookies,
        OPENID_COOKIE_NAME,
        OPENID_COOKIE_PATH,
        state.cookie_secure(),
    );
    let result = if data.code.is_empty() || data.code.len() > MAX_CODE_LEN {
        Err(ApiError::BadRequest(
            "Missing or invalid authorization code".into(),
        ))
    } else if data.state.len() > MAX_STATE_LEN {
        Err(ApiError::BadRequest("Invalid state".into()))
    } else {
        match pending {
            None => Err(ApiError::Unauthorized(
                "The sign-in expired or was started in another browser".into(),
            )),
            Some(pending) if pending.flow != flow => Err(ApiError::BadRequest(
                "This sign-in is not for this page".into(),
            )),
            Some(pending) if !constant_time_eq(&pending.state, &data.state) => {
                warn!("OpenID callback state does not match the sign-in started in this browser");
                Err(ApiError::Unauthorized("State mismatch".into()))
            }
            Some(pending) => Ok(pending),
        }
    };
    (private_cookies, result)
}

/// Finish an enrollment portal sign-in. Returns the enrollment token Core issued.
///
/// The cookie is removed whether or not the sign-in succeeds.
#[instrument(level = "debug", skip_all)]
async fn enrollment_callback(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    private_cookies: PrivateCookieJar,
    Json(data): Json<CallbackData>,
) -> Response {
    let (private_cookies, pending) =
        take_pending(&state, private_cookies, FlowType::Enrollment, &data);
    match finish_enrollment(&state, device_info, pending, data).await {
        Ok(response) => (private_cookies, Json(response)).into_response(),
        Err(err) => (private_cookies, err).into_response(),
    }
}

async fn finish_enrollment(
    state: &AppState,
    device_info: DeviceInfo,
    pending: Result<PendingSignIn, ApiError>,
    data: CallbackData,
) -> Result<EnrollmentCallbackResponse, ApiError> {
    let request = AuthCallbackRequest {
        code: data.code,
        nonce: pending?.binding,
    };
    let rx = state
        .grpc_server
        .send(core_request::Payload::AuthCallback(request), device_info)?;
    match get_core_response(rx, Some(CORE_OPENID_TIMEOUT)).await? {
        core_response::Payload::AuthCallback(response) => {
            info!("Finished an OpenID sign-in on the enrollment portal");
            Ok(EnrollmentCallbackResponse {
                url: response.url,
                token: response.token,
            })
        }
        _ => {
            error!("Received an invalid gRPC response type for the OpenID callback");
            Err(ApiError::InvalidResponseType)
        }
    }
}

/// Finish the OpenID step of a desktop client's MFA.
///
/// The cookie is removed whether or not the sign-in succeeds.
#[instrument(level = "debug", skip_all)]
async fn mfa_callback(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    private_cookies: PrivateCookieJar,
    Json(data): Json<CallbackData>,
) -> Response {
    let (private_cookies, pending) = take_pending(&state, private_cookies, FlowType::Mfa, &data);
    match finish_mfa(&state, device_info, pending, data).await {
        Ok(()) => private_cookies.into_response(),
        Err(err) => (private_cookies, err).into_response(),
    }
}

async fn finish_mfa(
    state: &AppState,
    device_info: DeviceInfo,
    pending: Result<PendingSignIn, ApiError>,
    data: CallbackData,
) -> Result<(), ApiError> {
    let request = ClientMfaOidcAuthenticateRequest {
        code: data.code,
        state: data.state,
        nonce: pending?.binding,
    };
    let rx = state.grpc_server.send(
        core_request::Payload::ClientMfaOidcAuthenticate(request),
        device_info,
    )?;
    match get_core_response(rx, Some(CORE_OPENID_TIMEOUT)).await? {
        core_response::Payload::Empty(()) => {
            info!("Finished the OpenID step of a desktop client's MFA");
            Ok(())
        }
        _ => {
            error!("Received an invalid gRPC response type for the OpenID MFA callback");
            Err(ApiError::InvalidResponseType)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_kinds_for_the_web_ui() {
        let google = "https://accounts.google.com/o/oauth2/auth";
        assert_eq!(
            ProviderKind::new(OpenIdProviderKind::Okta, google),
            ProviderKind::Okta
        );
        assert_eq!(
            ProviderKind::new(OpenIdProviderKind::Zitadel, google),
            ProviderKind::Custom
        );
        assert_eq!(
            ProviderKind::new(OpenIdProviderKind::Unspecified, google),
            ProviderKind::Google
        );
        assert_eq!(
            ProviderKind::new(OpenIdProviderKind::Unspecified, "https://example.okta.com"),
            ProviderKind::Custom
        );
        assert_eq!(
            serde_json::to_value(ProviderKind::JumpCloud).unwrap(),
            "jumpcloud"
        );
    }

    #[test]
    fn mfa_session_references() {
        assert!(valid_mfa_state("abc123"));
        assert!(valid_mfa_state("abc.def"));
        assert!(!valid_mfa_state(""));
        assert!(!valid_mfa_state("a b"));
        assert!(!valid_mfa_state("a/b"));
        assert!(!valid_mfa_state(&"a".repeat(MAX_MFA_STATE_LEN + 1)));
    }

    #[test]
    fn secrets_compare_whole() {
        assert!(constant_time_eq("state", "state"));
        assert!(!constant_time_eq("state", "stat"));
        assert!(!constant_time_eq("state", "statf"));
    }
}
