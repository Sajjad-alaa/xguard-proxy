use axum::{Json, Router, extract::State, routing::post};
use axum_extra::extract::PrivateCookieJar;
use time::OffsetDateTime;

use super::register_mfa::router as register_mfa_router;
use crate::{
    error::ApiError,
    handlers::{get_core_response, mobile_client::register_mobile_auth},
    http::{
        AppState, ENROLLMENT_COOKIE_NAME, ENROLLMENT_COOKIE_PATH, remove_session_cookie,
        session_cookie,
    },
    proto::{
        ActivateUserRequest, DeviceConfigResponse, DeviceInfo, DirectoryEnrollmentRequest,
        EnrollmentStartRequest, EnrollmentStartResponse, ExistingDevice, NewDevice, core_request,
        core_response,
    },
};

/// Longest username or email accepted for directory enrollment (Core applies the same limit).
const MAX_DIRECTORY_USERNAME_LEN: usize = 256;
/// Longest directory password accepted.
const MAX_DIRECTORY_PASSWORD_LEN: usize = 1024;
/// Core checks the password against the directory, which can take a moment.
const CORE_DIRECTORY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);

#[derive(serde::Deserialize)]
pub(crate) struct DirectoryEnrollmentData {
    username: String,
    password: String,
}

#[derive(Debug, PartialEq, serde::Serialize)]
pub(crate) struct DirectoryEnrollmentResult {
    token: String,
}

/// Remote enrollment of a directory (LDAP / Active Directory) user with their directory
/// password. Core checks the password and answers with a fresh enrollment token, which the web
/// UI uses to start enrollment (`/enrollment/start`) or to configure the desktop client.
///
/// The password is only passed on to Core; it is never logged or stored.
#[instrument(level = "debug", skip_all)]
async fn directory_enrollment(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    Json(data): Json<DirectoryEnrollmentData>,
) -> Result<Json<DirectoryEnrollmentResult>, ApiError> {
    if !state
        .grpc_server
        .public_settings
        .directory_enrollment
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err(ApiError::NotFound(
            "Enrollment with directory credentials is not enabled".into(),
        ));
    }
    let username = data.username.trim();
    if username.is_empty()
        || username.len() > MAX_DIRECTORY_USERNAME_LEN
        || data.password.is_empty()
        || data.password.len() > MAX_DIRECTORY_PASSWORD_LEN
    {
        return Err(ApiError::BadRequest(
            "Missing or invalid username or password".into(),
        ));
    }
    let request = DirectoryEnrollmentRequest {
        username: username.to_owned(),
        password: data.password,
    };
    let rx = state.grpc_server.send(
        core_request::Payload::DirectoryEnrollment(request),
        device_info,
    )?;
    match get_core_response(rx, Some(CORE_DIRECTORY_TIMEOUT)).await? {
        core_response::Payload::DirectoryEnrollment(response) => {
            info!("Started a remote enrollment with directory credentials");
            Ok(Json(DirectoryEnrollmentResult {
                token: response.token,
            }))
        }
        _ => {
            error!("Received an invalid gRPC response type for directory enrollment");
            Err(ApiError::InvalidResponseType)
        }
    }
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .nest("/register-mfa", register_mfa_router())
        .route("/start", post(start_enrollment_process))
        .route("/directory", post(directory_enrollment))
        .route("/activate_user", post(activate_user))
        .route("/create_device", post(create_device))
        .route("/network_info", post(get_network_info))
        .route("/register_mobile", post(register_mobile_auth))
}

#[instrument(level = "debug", skip_all)]
async fn start_enrollment_process(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    mut private_cookies: PrivateCookieJar,
    Json(req): Json<EnrollmentStartRequest>,
) -> Result<(PrivateCookieJar, Json<EnrollmentStartResponse>), ApiError> {
    info!("Starting enrollment process");

    // clear session cookies if already populated
    debug!("Trying to remove previous session cookie if it still exists.");
    if private_cookies.get(ENROLLMENT_COOKIE_NAME).is_some() {
        debug!("Removing previous session cookie");
        private_cookies = remove_session_cookie(
            private_cookies,
            ENROLLMENT_COOKIE_NAME,
            ENROLLMENT_COOKIE_PATH,
            state.cookie_secure(),
        );
    }

    let token = req.token.clone();

    debug!("Sending the enrollment process request to core service.");
    let rx = state
        .grpc_server
        .send(core_request::Payload::EnrollmentStart(req), device_info)?;
    let payload = get_core_response(rx, None).await?;
    debug!(
        "Receving payload from the core service. Try to set private cookie for starting enrollment process."
    );
    if let core_response::Payload::EnrollmentStart(response) = payload {
        info!(
            "Started enrollment process for user {:?} by admin {:?}",
            response.user, response.admin
        );
        // set session cookie
        let cookie = session_cookie(
            ENROLLMENT_COOKIE_NAME,
            token,
            ENROLLMENT_COOKIE_PATH,
            state.cookie_secure(),
        )
        .expires(
            OffsetDateTime::from_unix_timestamp(response.deadline_timestamp).map_err(|_| {
                ApiError::Unexpected("Invalid enrollment deadline timestamp".into())
            })?,
        );

        Ok((private_cookies.add(cookie), Json(response)))
    } else {
        error!("Received invalid gRPC response type");
        Err(ApiError::InvalidResponseType)
    }
}

#[instrument(level = "debug", skip_all)]
async fn activate_user(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    mut private_cookies: PrivateCookieJar,
    Json(mut req): Json<ActivateUserRequest>,
) -> Result<PrivateCookieJar, ApiError> {
    let phone = req.phone_number.clone();
    info!("Activating user - phone number {phone:?}");

    // set auth info
    debug!("Set private cookie for the request.");
    req.token = private_cookies
        .get(ENROLLMENT_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string());

    debug!("Sending the activate user request to core service.");
    let rx = state
        .grpc_server
        .send(core_request::Payload::ActivateUser(req), device_info)?;
    let payload = get_core_response(rx, None).await?;
    debug!("Receiving payload from the core service. Trying to remove private cookie...");
    if let core_response::Payload::Empty(()) = payload {
        info!("Activated user - phone number {phone:?}");
        if private_cookies.get(ENROLLMENT_COOKIE_NAME).is_some() {
            debug!("Enrollment finished. Removing session cookie");
            private_cookies = remove_session_cookie(
                private_cookies,
                ENROLLMENT_COOKIE_NAME,
                ENROLLMENT_COOKIE_PATH,
                state.cookie_secure(),
            );
        }
        Ok(private_cookies)
    } else {
        error!("Received invalid gRPC response type");
        Err(ApiError::InvalidResponseType)
    }
}

#[instrument(level = "debug", skip_all)]
async fn create_device(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    private_cookies: PrivateCookieJar,
    Json(mut req): Json<NewDevice>,
) -> Result<Json<DeviceConfigResponse>, ApiError> {
    let (name, pubkey) = (req.name.clone(), req.pubkey.clone());
    info!("Adding new device {name} {pubkey}");

    // set auth info
    req.token = private_cookies
        .get(ENROLLMENT_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string());

    let rx = state
        .grpc_server
        .send(core_request::Payload::NewDevice(req), device_info)?;
    let payload = get_core_response(rx, None).await?;
    if let core_response::Payload::DeviceConfig(response) = payload {
        info!("Added new device {name} {pubkey}");
        Ok(Json(response))
    } else {
        error!("Received invalid gRPC response type");
        Err(ApiError::InvalidResponseType)
    }
}

#[instrument(level = "debug", skip_all)]
async fn get_network_info(
    State(state): State<AppState>,
    device_info: DeviceInfo,
    private_cookies: PrivateCookieJar,
    Json(mut req): Json<ExistingDevice>,
) -> Result<Json<DeviceConfigResponse>, ApiError> {
    let pubkey = req.pubkey.clone();
    info!("Getting network info for device {pubkey}");

    // set auth info
    req.token = private_cookies
        .get(ENROLLMENT_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string());

    let rx = state
        .grpc_server
        .send(core_request::Payload::ExistingDevice(req), device_info)?;
    let payload = get_core_response(rx, None).await?;
    if let core_response::Payload::DeviceConfig(response) = payload {
        info!("Got network info for device {pubkey}");
        Ok(Json(response))
    } else {
        error!("Received invalid gRPC response type");
        Err(ApiError::InvalidResponseType)
    }
}
