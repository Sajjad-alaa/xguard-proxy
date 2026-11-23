use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, HeaderName, header::FORWARDED, request::Parts},
};
use axum_extra::{TypedHeader, extract::PrivateCookieJar, headers::UserAgent};
use tokio::{sync::oneshot::Receiver, time};
use tonic::Code;

use super::proto::DeviceInfo;
use crate::{
    config::IpCidr,
    error::{ApiError, is_oidc_not_completed},
    http::ENROLLMENT_COOKIE_NAME,
    proto::core_response::Payload,
};

pub(crate) mod desktop_client_mfa;
pub(crate) mod enrollment;
pub(crate) mod mfa_config;
pub(crate) mod mfa_flow;
pub(crate) mod mobile_client;
pub(crate) mod openid;
pub(crate) mod password_reset;
pub(crate) mod polling;
pub(crate) mod posture;
pub(crate) mod register_mfa;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

fn parse_ip_token(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Some(sock.ip());
    }
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return inner.parse::<IpAddr>().ok();
    }
    None
}

fn pick_rightmost_untrusted(ips: &[IpAddr], trusted_proxies: &[IpCidr]) -> Option<IpAddr> {
    if ips.is_empty() {
        return None;
    }
    ips.iter()
        .rev()
        .copied()
        .find(|ip| !trusted_proxies.iter().any(|net| net.contains(*ip)))
        .or_else(|| ips.last().copied())
}

fn parse_forwarded_header_ips(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for header_val in headers.get_all(FORWARDED) {
        let Ok(s) = header_val.to_str() else {
            continue;
        };
        for entry in s.split(',') {
            for param in entry.split(';') {
                let param = param.trim();
                let Some((key, value)) = param.split_once('=') else {
                    continue;
                };
                if key.trim().eq_ignore_ascii_case("for")
                    && let Some(ip) = parse_ip_token(value)
                {
                    ips.push(ip);
                }
            }
        }
    }
    ips
}

fn parse_xff_header_ips(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for header_val in headers.get_all(&X_FORWARDED_FOR) {
        let Ok(s) = header_val.to_str() else {
            continue;
        };
        for part in s.split(',') {
            if let Some(ip) = parse_ip_token(part) {
                ips.push(ip);
            }
        }
    }
    ips
}

/// Extract client IP address, honoring `Forwarded` / `X-Forwarded-For` ONLY when the TCP
/// peer IP (`peer_ip`) belongs to `trusted_proxies`.
pub(crate) fn extract_client_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpCidr],
) -> Option<IpAddr> {
    let from_headers = || {
        let forwarded = parse_forwarded_header_ips(headers);
        if let Some(ip) = pick_rightmost_untrusted(&forwarded, trusted_proxies) {
            return Some(ip);
        }
        let xff = parse_xff_header_ips(headers);
        pick_rightmost_untrusted(&xff, trusted_proxies)
    };

    match peer_ip {
        Some(peer) => {
            if trusted_proxies.iter().any(|net| net.contains(peer)) {
                from_headers().or(Some(peer))
            } else {
                Some(peer)
            }
        }
        None => {
            #[cfg(test)]
            {
                from_headers()
            }
            #[cfg(not(test))]
            {
                None
            }
        }
    }
}

/// Extracts client IP address from `ConnectInfo`, honoring forwarding headers only when the peer
/// IP is configured in `trusted_proxies`.
pub struct ClientIpAddr(pub IpAddr);

impl<S> FromRequestParts<S> for ClientIpAddr
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let peer_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        let trusted = parts
            .extensions
            .get::<Arc<Vec<IpCidr>>>()
            .map_or(&[][..], |v| v.as_slice());
        extract_client_ip(&parts.headers, peer_ip, trusted)
            .map(Self)
            .ok_or(ApiError::ClientIpError)
    }
}

// Timeout for awaiting response from XGuard Core.
const CORE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_VERSION_HEADER: &str = "xguard-client-version";
const CLIENT_PLATFORM_HEADER: &str = "xguard-client-platform";

/// Reads the enrollment token from the private cookie set at enrollment start.
pub(super) fn enrollment_token(cookie_jar: &PrivateCookieJar) -> Result<String, ApiError> {
    cookie_jar
        .get(ENROLLMENT_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| ApiError::Unauthorized(String::new()))
}

impl<S> FromRequestParts<S> for DeviceInfo
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ip_address = ClientIpAddr::from_request_parts(parts, state)
            .await
            .map(|v| v.0.to_string())
            .map_err(|_| ApiError::Unexpected("Missing client IP".to_string()))?;
        let user_agent = TypedHeader::<UserAgent>::from_request_parts(parts, state)
            .await
            .map(|v| v.to_string())
            .ok()
            // sanitize user-agent
            .filter(|agent| !ammonia::is_html(agent));

        let version = parts
            .headers
            .get(CLIENT_VERSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let platform = parts
            .headers
            .get(CLIENT_PLATFORM_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        Ok(Self {
            ip_address,
            user_agent,
            version,
            platform,
        })
    }
}

/// Helper which awaits core response
///
/// Waits for core response with a given timeout and returns the response payload.
pub(crate) async fn get_core_response(
    rx: Receiver<Payload>,
    timeout: Option<Duration>,
) -> Result<Payload, ApiError> {
    debug!("Fetching core response.");
    if let Ok(core_response) = time::timeout(timeout.unwrap_or(CORE_RESPONSE_TIMEOUT), rx).await {
        debug!("Got gRPC response from XGuard Core");
        if let Ok(Payload::CoreError(core_error)) = core_response {
            if core_error.status_code == Code::FailedPrecondition as i32
                && core_error.message == "no valid license"
            {
                debug!(
                    "Tried to get response from Core related to an enterprise feature but the \
                    enterprise is not enabled, ignoring it."
                );
                return Err(ApiError::EnterpriseNotEnabled);
            }
            if is_oidc_not_completed(&core_error) {
                debug!("OIDC authentication still pending: {}", core_error.message);
            } else {
                error!(
                    "Received an error response from Core service. | status code: {} message: {}",
                    core_error.status_code, core_error.message
                );
            }
            return Err(core_error.into());
        }
        core_response
            .map_err(|err| ApiError::Unexpected(format!("Failed to receive core response: {err}")))
    } else {
        error!(
            "Did not receive response from Core within {:?}",
            timeout.unwrap_or(CORE_RESPONSE_TIMEOUT)
        );
        Err(ApiError::CoreTimeout)
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};

    use super::*;

    static VALID_USER_AGENTS: &[&str] = &[
        // desktop
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.10 Safari/605.1.1	43.03",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.3	21.05",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3	17.34",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3	3.72",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Trailer/93.3.8652.5	2.48",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.	2.48",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.	2.48",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.	2.48",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.	1.24",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.1958	1.24",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.	1.24",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.3	1.24",
        // mobile
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.3	63.11",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Mobile/15E148 Safari/604.	8.25",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/360.1.737798518 Mobile/15E148 Safari/604.	5.83",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/134.0.6998.99 Mobile/15E148 Safari/604.	4.85",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.3	3.88",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.	3.4",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.	1.94",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.	1.94",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.3	1.46",
        "Mozilla/5.0 (Android 14; Mobile; rv:136.0) Gecko/136.0 Firefox/136.	0.97",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.3	0.97",
        "Mozilla/5.0 (Linux; Android 10; JNY-LX1; HMSCore 6.15.0.302) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.196 HuaweiBrowser/15.0.4.312 Mobile Safari/537.3	0.97",
        "Mozilla/5.0 (Android 15; Mobile; rv:136.0) Gecko/136.0 Firefox/136.	0.49",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) CriOS/56.0.2924.75 Mobile/14E5239e YisouSpider/5.0 Safari/602.	0.49",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.	0.49",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.3	0.49",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.3	0.49",
    ];

    static INVALID_USER_AGENTS: &[&str] = &[
        "<h1><a href=\"//isec.pl\">CLICK HERE</a></h1>",
        "<html><script>alert(\"test\")</script></html>",
        "<h1><a href=\"//isec.pl\">CLICK HERE",
    ];

    struct DummyState;

    #[tokio::test]
    async fn test_user_agent_sanitization_dg25_16() {
        let state = DummyState;

        // valid user agents
        for agent in VALID_USER_AGENTS {
            let req = Request::builder()
                .header("User-Agent", *agent)
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap();
            let (parts, _) = req.into_parts();
            let mut parts = parts;

            let device_info = DeviceInfo::from_request_parts(&mut parts, &state)
                .await
                .expect("should succeed");

            assert_eq!(device_info.user_agent, Some(agent.to_string()));
        }

        // invalid user agents
        for agent in INVALID_USER_AGENTS {
            let req = Request::builder()
                .header("User-Agent", *agent)
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap();
            let (parts, _) = req.into_parts();
            let mut parts = parts;

            let device_info = DeviceInfo::from_request_parts(&mut parts, &state)
                .await
                .expect("should succeed");

            assert!(device_info.user_agent.is_none());
        }

        // no user agent
        let req = Request::builder()
            .header("X-Forwarded-For", "10.0.0.1")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let mut parts = parts;

        let device_info = DeviceInfo::from_request_parts(&mut parts, &state)
            .await
            .expect("should succeed");

        assert!(device_info.user_agent.is_none());
    }

    #[test]
    fn extract_client_ip_ignores_forwarding_headers_from_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED, "for=198.51.100.7".parse().unwrap());
        headers.insert(X_FORWARDED_FOR, "198.51.100.8".parse().unwrap());

        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let trusted: Vec<IpCidr> = vec!["10.0.0.0/8".parse().unwrap()];

        assert_eq!(extract_client_ip(&headers, Some(peer), &[]), Some(peer));
        assert_eq!(
            extract_client_ip(&headers, Some(peer), &trusted),
            Some(peer)
        );
    }

    #[test]
    fn extract_client_ip_honors_rightmost_untrusted_from_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            "1.1.1.1, 198.51.100.42, 10.0.0.5".parse().unwrap(),
        );
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        let trusted: Vec<IpCidr> = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(
            extract_client_ip(&headers, Some(peer), &trusted),
            Some("198.51.100.42".parse().unwrap())
        );

        let mut fwd_headers = HeaderMap::new();
        fwd_headers.insert(
            FORWARDED,
            r#"for=203.0.113.10;proto=https, for="[::ffff:10.0.0.9]""#
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_client_ip(&fwd_headers, Some(peer), &trusted),
            Some("203.0.113.10".parse().unwrap())
        );
    }
}
