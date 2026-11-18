use axum::http::StatusCode;
use serde_json::json;

use crate::{
    proto::{CoreError, InstanceInfoResponse, core_request, core_response},
    tests::support::{app_with_fake_core, post_json},
};

#[tokio::test]
async fn test_poll_forwards_revision_and_returns_not_modified() {
    let app = app_with_fake_core(|payload| match payload {
        core_request::Payload::InstanceInfo(request) => {
            assert_eq!(request.token, "polling-token");
            assert_eq!(request.config_revision.as_deref(), Some("x1-abc"));
            core_response::Payload::InstanceInfo(InstanceInfoResponse {
                device_config: None,
                config_revision: Some("x1-abc".into()),
                not_modified: Some(true),
                poll_interval_secs: Some(60),
            })
        }
        _ => panic!("unexpected Core request"),
    });

    let (status, body) = post_json(
        &app,
        "/api/v1/poll",
        &json!({"token": "polling-token", "config_revision": "x1-abc"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["not_modified"], true);
    assert_eq!(body["config_revision"], "x1-abc");
    assert_eq!(body["poll_interval_secs"], 60);
    assert!(body["device_config"].is_null());
}

#[tokio::test]
async fn test_poll_without_revision_from_older_clients() {
    let app = app_with_fake_core(|payload| match payload {
        core_request::Payload::InstanceInfo(request) => {
            assert!(request.config_revision.is_none());
            core_response::Payload::InstanceInfo(InstanceInfoResponse::default())
        }
        _ => panic!("unexpected Core request"),
    });
    let (status, _) = post_json(&app, "/api/v1/poll", &json!({"token": "t"})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_poll_refusals_keep_their_status() {
    for (code, expected) in [
        (tonic::Code::Unauthenticated, StatusCode::UNAUTHORIZED),
        (tonic::Code::PermissionDenied, StatusCode::FORBIDDEN),
        (
            tonic::Code::ResourceExhausted,
            StatusCode::TOO_MANY_REQUESTS,
        ),
    ] {
        let app = app_with_fake_core(move |_| {
            core_response::Payload::CoreError(CoreError {
                status_code: code as i32,
                message: "refused".into(),
                ..Default::default()
            })
        });
        let (status, body) = post_json(&app, "/api/v1/poll", &json!({"token": "t"})).await;
        assert_eq!(status, expected, "{code:?}");
        assert_eq!(body["error"], "refused");
    }
}
