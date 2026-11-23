//! Client download links shown on the enrollment pages, set by an admin in Core
//! (Settings -> Client downloads) and sent in `PublicSettings.client_downloads`.
//!
//! Core validates the links before saving them; the Edge checks them again because it serves
//! them to unauthenticated visitors: only `http(s)` URLs with a host and without credentials
//! pass, anything else falls back to the built-in defaults (or hides an optional link).

use serde::Serialize;
use url::Url;

use crate::proto::ClientDownloads;

/// Default installer base URL: the newest GitHub release of the XGuard client.
pub(crate) const DEFAULT_BASE_URL: &str =
    "https://github.com/Sajjad-alaa/xguard-client/releases/latest/download";
/// Default releases page.
pub(crate) const DEFAULT_RELEASES_URL: &str =
    "https://github.com/Sajjad-alaa/xguard-client/releases/latest";
const MAX_URL_LEN: usize = 2048;

/// The links as the web UI receives them in `/api/v1/info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ClientDownloadLinks {
    /// Installers are `<base_url>/<asset name>`.
    pub(crate) base_url: String,
    pub(crate) releases_url: String,
    pub(crate) android_url: Option<String>,
    pub(crate) ios_url: Option<String>,
    pub(crate) macos_installer: bool,
}

impl Default for ClientDownloadLinks {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.into(),
            releases_url: DEFAULT_RELEASES_URL.into(),
            android_url: None,
            ios_url: None,
            macos_installer: false,
        }
    }
}

/// `value` if it is a usable link; `path_only` also refuses a query or fragment (file names are
/// appended to it) and drops trailing slashes.
fn checked_url(value: &str, path_only: bool) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_URL_LEN {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || (path_only && (url.query().is_some() || url.fragment().is_some()))
    {
        return None;
    }
    let mut url = url.to_string();
    if path_only {
        while url.ends_with('/') {
            url.pop();
        }
    }
    Some(url)
}

impl ClientDownloadLinks {
    /// The links Core sent, each one checked; `None` (an older Core) means the defaults.
    pub(crate) fn from_core(downloads: Option<ClientDownloads>) -> Self {
        let Some(downloads) = downloads else {
            return Self::default();
        };
        let required = |value: &str, path_only: bool, default: &str, name: &str| {
            checked_url(value, path_only).unwrap_or_else(|| {
                warn!("Ignoring the invalid client download {name} from Core: {value:?}");
                default.to_owned()
            })
        };
        let optional = |value: Option<&str>, name: &str| {
            let value = value.map(str::trim).filter(|value| !value.is_empty())?;
            let checked = checked_url(value, false);
            if checked.is_none() {
                warn!("Ignoring the invalid client download {name} from Core: {value:?}");
            }
            checked
        };
        Self {
            base_url: required(&downloads.base_url, true, DEFAULT_BASE_URL, "base URL"),
            releases_url: required(
                &downloads.releases_url,
                false,
                DEFAULT_RELEASES_URL,
                "releases URL",
            ),
            android_url: optional(downloads.android_url.as_deref(), "Android URL"),
            ios_url: optional(downloads.ios_url.as_deref(), "iOS URL"),
            macos_installer: downloads.macos_installer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn downloads(base_url: &str) -> ClientDownloads {
        ClientDownloads {
            base_url: base_url.into(),
            releases_url: "https://mirror.example.lan/xguard/".into(),
            android_url: None,
            ios_url: None,
            macos_installer: false,
        }
    }

    #[test]
    fn older_core_gets_defaults() {
        let links = ClientDownloadLinks::from_core(None);
        assert_eq!(links, ClientDownloadLinks::default());
        assert_eq!(links.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn keeps_valid_links() {
        let links = ClientDownloadLinks::from_core(Some(ClientDownloads {
            android_url: Some(" https://mirror.example.lan/xguard/xguard.apk ".into()),
            ios_url: Some(String::new()),
            macos_installer: true,
            ..downloads("http://10.0.0.5/xguard/")
        }));
        assert_eq!(links.base_url, "http://10.0.0.5/xguard");
        assert_eq!(links.releases_url, "https://mirror.example.lan/xguard/");
        assert_eq!(
            links.android_url.as_deref(),
            Some("https://mirror.example.lan/xguard/xguard.apk")
        );
        assert_eq!(links.ios_url, None);
        assert!(links.macos_installer);
    }

    #[test]
    fn replaces_unsafe_links() {
        for bad in [
            "javascript:alert(1)",
            "data:text/html,x",
            "https://user:pw@mirror.example.lan/x",
            "https://mirror.example.lan/x?y=1",
            "mirror.example.lan",
            "",
        ] {
            let links = ClientDownloadLinks::from_core(Some(ClientDownloads {
                releases_url: bad.into(),
                ios_url: Some(bad.into()),
                ..downloads(bad)
            }));
            assert_eq!(links.base_url, DEFAULT_BASE_URL, "{bad}");
            if bad.contains('?') {
                // A query is fine on a page link, just not on the base URL.
                assert_eq!(links.releases_url, bad);
            } else {
                assert_eq!(links.releases_url, DEFAULT_RELEASES_URL, "{bad}");
                assert_eq!(links.ios_url, None, "{bad}");
            }
        }
        let long = format!("https://mirror.example.lan/{}", "a".repeat(MAX_URL_LEN));
        assert_eq!(
            ClientDownloadLinks::from_core(Some(downloads(&long))).base_url,
            DEFAULT_BASE_URL
        );
    }
}
