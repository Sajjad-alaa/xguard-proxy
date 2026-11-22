//! Remote enrollment with directory credentials against a fake Core: what reaches Core, what
//! the browser gets back, and the checks made before anything reaches Core.

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use serde_json::json;

use crate::{
    proto::{CoreError, DirectoryEnrollmentResponse, core_request, core_response},
    tests::support::{app_with_fake_core_and_settings, post_json, test_public_settings},
};

const PATH: &str = "/api/v1/enrollment/directory";

fn app(enabled: bool, refuse: bool) -> (axum::Router, Arc<Mutex<Vec<(String, String)>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let mut settings = test_public_settings(Some("https://edge.example.com"));
    settings.directory_enrollment = enabled;
    let app = app_with_fake_core_and_settings(Some(settings), move |payload| match payload {
        core_request::Payload::DirectoryEnrollment(request) => {
            log.lock()
                .unwrap()
                .push((request.username, request.password));
            if refuse {
                core_response::Payload::CoreError(CoreError {
                    status_code: tonic::Code::Unauthenticated as i32,
                    message: "invalid username or password".into(),
                    ..Default::default()
                })
            } else {
                core_response::Payload::DirectoryEnrollment(DirectoryEnrollmentResponse {
                    token: "enrollment-token".into(),
                })
            }
        }
        _ => panic!("unexpected Core request"),
    });
    (app, seen)
}

#[tokio::test]
async fn returns_the_token_core_issued() {
    let (app, seen) = app(true, false);
    let (status, body) = post_json(
        &app,
        PATH,
        &json!({"username": "  jdoe ", "password": "directory secret"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"token": "enrollment-token"}));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![("jdoe".to_owned(), "directory secret".to_owned())]
    );
}

#[tokio::test]
async fn core_refusal_is_unauthorized() {
    let (app, _) = app(true, true);
    let (status, body) = post_json(
        &app,
        PATH,
        &json!({"username": "jdoe", "password": "wrong"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid username or password");
}

#[tokio::test]
async fn disabled_feature_never_reaches_core() {
    let (app, seen) = app(false, false);
    let (status, _) = post_json(
        &app,
        PATH,
        &json!({"username": "jdoe", "password": "secret"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_input_never_reaches_core() {
    let (app, seen) = app(true, false);
    for body in [
        json!({"username": "", "password": "secret"}),
        json!({"username": "   ", "password": "secret"}),
        json!({"username": "jdoe", "password": ""}),
        json!({"username": "x".repeat(257), "password": "secret"}),
        json!({"username": "jdoe", "password": "x".repeat(1025)}),
    ] {
        let (status, _) = post_json(&app, PATH, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    assert!(seen.lock().unwrap().is_empty());
}
