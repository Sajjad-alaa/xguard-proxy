use axum::http::StatusCode;
use serde_json::json;

use crate::{
    proto::{
        CoreError, CoreErrorCode, MfaFlowStartRequest, PostureConnectResponse, PostureOs,
        core_request, core_response,
    },
    tests::support::{app_with_fake_core, post_json},
};

#[tokio::test]
async fn test_posture_connect_forwards_facts_and_returns_key() {
    let app = app_with_fake_core(|payload| match payload {
        core_request::Payload::PostureConnect(request) => {
            assert_eq!(request.location_id, 3);
            assert_eq!(request.pubkey, "device-public-key");
            assert_eq!(request.token, "polling-token");
            let facts = request.posture.expect("facts are forwarded");
            assert_eq!(facts.os, PostureOs::Linux as i32);
            assert_eq!(facts.disk_encrypted, Some(true));
            assert_eq!(facts.firewall_enabled, None);
            assert_eq!(facts.kernel_version.as_deref(), Some("6.8.0"));
            core_response::Payload::PostureConnect(PostureConnectResponse {
                preshared_key: "psk".into(),
            })
        }
        _ => panic!("unexpected Core request"),
    });

    // A client that knows nothing about some facts simply leaves them out.
    let (status, body) = post_json(
        &app,
        "/api/v1/posture/connect",
        &json!({
            "location_id": 3,
            "pubkey": "device-public-key",
            "token": "polling-token",
            "posture": {
                "os": PostureOs::Linux as i32,
                "client_version": "2.2.0",
                "kernel_version": "6.8.0",
                "disk_encrypted": true,
            },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"preshared_key": "psk"}));
}

#[tokio::test]
async fn test_posture_rejection_reaches_client_with_code() {
    let rejection = || {
        core_response::Payload::CoreError(CoreError {
            status_code: tonic::Code::PermissionDenied as i32,
            message: "Device posture check failed: disk encryption is required".into(),
            code: CoreErrorCode::PostureRejected as i32,
        })
    };
    let app = app_with_fake_core(move |payload| match payload {
        core_request::Payload::PostureConnect(_) | core_request::Payload::MfaFlowStart(_) => {
            rejection()
        }
        _ => panic!("unexpected Core request"),
    });

    let (status, body) = post_json(
        &app,
        "/api/v1/posture/connect",
        &json!({"location_id": 3, "pubkey": "k", "token": "t"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        json!({
            "error": "Device posture check failed: disk encryption is required",
            "code": "posture_rejected",
        })
    );

    let (status, body) = post_json(
        &app,
        "/api/v1/mfa-flow/start",
        &MfaFlowStartRequest {
            location_id: 3,
            pubkey: "k".into(),
            selected_methods: Vec::new(),
            posture: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "posture_rejected");
}
