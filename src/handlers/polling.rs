use axum::{Json, extract::State};

use crate::{
    error::ApiError,
    handlers::get_core_response,
    http::AppState,
    proto::{DeviceInfo, InstanceInfoRequest, InstanceInfoResponse, core_request, core_response},
};

/// Desktop client configuration sync: forwards the device's polling token and the revision it
/// applied last; Core answers with the configuration or `not_modified`. Refusals keep their
/// meaning: 401 unknown token, 403 disabled user, 429 polling too often.
#[instrument(level = "debug", skip(state, req))]
pub(crate) async fn info(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    Json(req): Json<InstanceInfoRequest>,
) -> Result<Json<InstanceInfoResponse>, ApiError> {
    debug!("Retrieving info for polling request");
    let rx = state.grpc_server.send(
        core_request::Payload::InstanceInfo(req.clone()),
        device_info,
    )?;
    let payload = get_core_response(rx, None).await?;

    if let core_response::Payload::InstanceInfo(response) = payload {
        debug!("Retrieved info for polling request");
        Ok(Json(response))
    } else {
        error!("Received invalid gRPC response type");
        Err(ApiError::InvalidResponseType)
    }
}
