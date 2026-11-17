//! The OpenID sign-in endpoints against a fake Core: what reaches Core, the cookie that binds a
//! sign-in to the browser that started it, and the checks made before anything reaches Core.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::{
    handlers::openid::{OPENID_COOKIE_NAME, OPENID_COOKIE_PATH},
    proto::{
        AuthCallbackResponse, AuthFlowType, AuthInfoResponse, CoreError, CoreErrorCode,
        OpenIdProviderKind, core_request, core_response,
    },
    tests::support::app_with_fake_core,
};

/// What the fake Core was asked, in order.
#[derive(Debug, PartialEq)]
enum Seen {
    AuthInfo {
        flow: AuthFlowType,
        state: Option<String>,
    },
    Callback {
        code: String,
        binding: String,
    },
    MfaCallback {
        code: String,
        state: String,
        binding: String,
    },
}

const STATE: &str = "state-from-core";
const BINDING: &str = "binding-from-core";

fn fake_core(mfa_error: Option<CoreErrorCode>) -> (Router, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let app = app_with_fake_core(move |payload| match payload {
        core_request::Payload::AuthInfo(request) => {
            log.lock().unwrap().push(Seen::AuthInfo {
                flow: request.auth_flow_type(),
                state: request.state,
            });
            core_response::Payload::AuthInfo(AuthInfoResponse {
                url: "https://accounts.google.com/o/oauth2/auth?state=state-from-core".into(),
                csrf_token: STATE.into(),
                nonce: BINDING.into(),
                button_display_name: Some("Google".into()),
                provider_kind: OpenIdProviderKind::Google as i32,
            })
        }
        core_request::Payload::AuthCallback(request) => {
            log.lock().unwrap().push(Seen::Callback {
                code: request.code,
                binding: request.nonce,
            });
            core_response::Payload::AuthCallback(AuthCallbackResponse {
                url: "https://edge.example.org/".into(),
                token: "enrollment-token".into(),
            })
        }
        core_request::Payload::ClientMfaOidcAuthenticate(request) => {
            log.lock().unwrap().push(Seen::MfaCallback {
                code: request.code,
                state: request.state,
                binding: request.nonce,
            });
            match mfa_error {
                None => core_response::Payload::Empty(()),
                Some(code) => core_response::Payload::CoreError(CoreError {
                    status_code: tonic::Code::Unauthenticated as i32,
                    message: "unauthorized".into(),
                    code: code as i32,
                }),
            }
        }
        _ => panic!("unexpected Core request"),
    });
    (app, seen)
}

struct Reply {
    status: StatusCode,
    body: Value,
    cookies: Vec<Cookie<'static>>,
}

async fn post(app: &Router, path: &str, body: Value, cookie: Option<&Cookie<'_>>) -> Reply {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Forwarded-For", "10.0.0.1");
    if let Some(cookie) = cookie {
        request = request.header(
            header::COOKIE,
            format!("{}={}", cookie.name(), cookie.value()),
        );
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| Cookie::parse(value.to_str().unwrap().to_owned()).unwrap())
        .collect();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Reply {
        status,
        body,
        cookies,
    }
}

fn openid_cookie(reply: &Reply) -> Cookie<'static> {
    reply
        .cookies
        .iter()
        .find(|cookie| cookie.name() == OPENID_COOKIE_NAME)
        .cloned()
        .expect("no OpenID cookie set")
}

fn assert_cookie_removed(reply: &Reply) {
    let cookie = openid_cookie(reply);
    assert_eq!(cookie.max_age(), Some(time::Duration::ZERO));
    assert_eq!(cookie.path(), Some(OPENID_COOKIE_PATH));
}

async fn start(app: &Router, body: Value) -> Cookie<'static> {
    let reply = post(app, "/api/v1/openid/auth_info", body, None).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    openid_cookie(&reply)
}

#[tokio::test]
async fn test_auth_info_sets_an_encrypted_bound_cookie() {
    let (app, seen) = fake_core(None);
    let reply = post(
        &app,
        "/api/v1/openid/auth_info",
        json!({"type": "enrollment"}),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.body,
        json!({
            "url": "https://accounts.google.com/o/oauth2/auth?state=state-from-core",
            "button_display_name": "Google",
            "provider_kind": "google",
        })
    );
    let cookie = openid_cookie(&reply);
    assert_eq!(cookie.path(), Some(OPENID_COOKIE_PATH));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Strict));
    assert_eq!(cookie.max_age(), Some(time::Duration::minutes(10)));
    // The cookie is encrypted: neither the state nor the binding can be read from it.
    assert!(!cookie.value().contains(BINDING));
    assert!(!cookie.value().contains(STATE));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![Seen::AuthInfo {
            flow: AuthFlowType::Enrollment,
            state: None,
        }]
    );
}

#[tokio::test]
async fn test_enrollment_callback_forwards_the_binding_once() {
    let (app, seen) = fake_core(None);
    let cookie = start(&app, json!({"type": "enrollment"})).await;

    let reply = post(
        &app,
        "/api/v1/openid/callback",
        json!({"code": "the-code", "state": STATE, "type": "enrollment"}),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.body,
        json!({"url": "https://edge.example.org/", "token": "enrollment-token"})
    );
    assert_cookie_removed(&reply);
    assert_eq!(
        seen.lock().unwrap().last(),
        Some(&Seen::Callback {
            code: "the-code".into(),
            binding: BINDING.into(),
        })
    );
}

#[tokio::test]
async fn test_callbacks_are_checked_before_reaching_core() {
    let (app, seen) = fake_core(None);
    let cookie = start(&app, json!({"type": "enrollment"})).await;
    let calls = || seen.lock().unwrap().len();
    let before = calls();

    // No cookie: the sign-in was started in another browser.
    let reply = post(
        &app,
        "/api/v1/openid/callback",
        json!({"code": "c", "state": STATE}),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    // A state that is not the one this browser started with.
    let reply = post(
        &app,
        "/api/v1/openid/callback",
        json!({"code": "c", "state": "attacker-state"}),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_cookie_removed(&reply);

    // An enrollment sign-in cannot finish an MFA step.
    let reply = post(
        &app,
        "/api/v1/openid/callback/mfa",
        json!({"code": "c", "state": STATE}),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    // Oversized input is refused.
    let reply = post(
        &app,
        "/api/v1/openid/callback",
        json!({"code": "c".repeat(5000), "state": STATE}),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    // MFA needs a well-formed session reference.
    for body in [
        json!({"type": "mfa"}),
        json!({"type": "mfa", "state": "token/../x"}),
        json!({"type": "mfa", "state": "t".repeat(200)}),
    ] {
        let reply = post(&app, "/api/v1/openid/auth_info", body, None).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    assert_eq!(calls(), before, "nothing reached Core");
}

#[tokio::test]
async fn test_mfa_sign_in_round_trip() {
    let (app, seen) = fake_core(None);
    let cookie = start(&app, json!({"type": "mfa", "state": "token123.attempt456"})).await;
    let reply = post(
        &app,
        "/api/v1/openid/callback/mfa",
        json!({"code": "mfa-code", "state": STATE, "type": "mfa"}),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_cookie_removed(&reply);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            Seen::AuthInfo {
                flow: AuthFlowType::Mfa,
                state: Some("token123.attempt456".into()),
            },
            Seen::MfaCallback {
                code: "mfa-code".into(),
                state: STATE.into(),
                binding: BINDING.into(),
            },
        ]
    );
}

#[tokio::test]
async fn test_mfa_account_mismatch_reaches_the_web_ui() {
    let (app, _seen) = fake_core(Some(CoreErrorCode::OidcAccountMismatch));
    let cookie = start(&app, json!({"type": "mfa", "state": "token123"})).await;
    let reply = post(
        &app,
        "/api/v1/openid/callback/mfa",
        json!({"code": "mfa-code", "state": STATE}),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        reply.body,
        json!({"error": "unauthorized", "code": "oidc_account_mismatch"})
    );
    // The cookie is gone even though the sign-in failed.
    assert_cookie_removed(&reply);
}
