//! XGuard device posture: posture-only connections.
//!
//! For a location with posture policies and no MFA, the desktop client posts its posture facts
//! here. Core checks the device's polling token, evaluates the facts and returns a preshared key
//! for the new session, or refuses with `403` and `code: "posture_rejected"`. Locations with MFA
//! get the facts with the MFA start request instead.

use axum::{Json, Router, extract::State, routing::post};

use crate::{
    error::ApiError,
    handlers::get_core_response,
    http::AppState,
    proto::{
        DeviceInfo, PostureConnectRequest, PostureConnectResponse, core_request,
        core_response::Payload,
    },
};

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/connect", post(posture_connect))
}

#[instrument(level = "debug", skip_all)]
async fn posture_connect(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    Json(request): Json<PostureConnectRequest>,
) -> Result<Json<PostureConnectResponse>, ApiError> {
    let location_id = request.location_id;
    let rx = state
        .grpc_server
        .send(core_request::Payload::PostureConnect(request), device_info)?;
    match get_core_response(rx, None).await? {
        Payload::PostureConnect(response) => {
            info!("Posture-checked connection to location {location_id} authorized");
            Ok(Json(response))
        }
        _ => {
            error!("Received invalid gRPC response type, expected PostureConnect");
            Err(ApiError::InvalidResponseType)
        }
    }
}
