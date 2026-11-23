//! The client download links Core sends reach the enrollment pages through `/api/v1/info`.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::{
    client_downloads::{DEFAULT_BASE_URL, DEFAULT_RELEASES_URL},
    proto::{ClientDownloads, core_response},
    tests::support::{app_with_fake_core_and_settings, test_public_settings},
};

async fn info(settings: Option<crate::proto::PublicSettings>) -> Value {
    let app = app_with_fake_core_and_settings(settings, |_| core_response::Payload::Empty(()));
    let response = app
        .oneshot(Request::get("/api/v1/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn info_without_settings_from_core_uses_github_defaults() {
    let body = info(None).await;
    assert_eq!(
        body["client_downloads"],
        json!({
            "base_url": DEFAULT_BASE_URL,
            "releases_url": DEFAULT_RELEASES_URL,
            "android_url": null,
            "ios_url": null,
            "macos_installer": false,
        })
    );
    // An older Core sends PublicSettings without the links: the defaults stay.
    let body = info(Some(test_public_settings(Some("https://edge.example.com")))).await;
    assert_eq!(body["client_downloads"]["base_url"], DEFAULT_BASE_URL);
}

#[tokio::test]
async fn info_serves_links_from_core_and_drops_unsafe_ones() {
    let mut settings = test_public_settings(Some("https://edge.example.com"));
    settings.client_downloads = Some(ClientDownloads {
        base_url: "https://mirror.example.lan/xguard/".into(),
        releases_url: "https://mirror.example.lan/xguard/".into(),
        android_url: Some("https://mirror.example.lan/xguard/xguard.apk".into()),
        ios_url: Some("javascript:alert(1)".into()),
        macos_installer: true,
    });
    let body = info(Some(settings)).await;
    assert_eq!(
        body["client_downloads"],
        json!({
            "base_url": "https://mirror.example.lan/xguard",
            "releases_url": "https://mirror.example.lan/xguard/",
            "android_url": "https://mirror.example.lan/xguard/xguard.apk",
            "ios_url": null,
            "macos_installer": true,
        })
    );
}
