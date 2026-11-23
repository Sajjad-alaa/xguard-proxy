use std::{
    fmt, fs::read_to_string, net::IpAddr, num::NonZeroU64, path::PathBuf, str::FromStr,
    time::Duration,
};

use clap::Parser;
use log::LevelFilter;
use serde::{Deserialize, Deserializer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpCidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

impl IpCidr {
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (normalize_ip(self.addr), normalize_ip(ip)) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 32_u32.saturating_sub(u32::from(self.prefix_len));
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(candidate) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 128_u32.saturating_sub(u32::from(self.prefix_len));
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(candidate) & mask)
            }
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (s, None),
        };
        let raw_addr = addr_part
            .parse::<IpAddr>()
            .map_err(|err| format!("invalid IP address '{addr_part}': {err}"))?;
        let max_prefix = match raw_addr {
            IpAddr::V4(_) => 32_u8,
            IpAddr::V6(_) => 128_u8,
        };
        let raw_prefix = match prefix_part {
            Some(p) => {
                let parsed = p
                    .parse::<u8>()
                    .map_err(|err| format!("invalid CIDR prefix '{p}': {err}"))?;
                if parsed > max_prefix {
                    return Err(format!("CIDR prefix /{parsed} exceeds /{max_prefix}"));
                }
                parsed
            }
            None => max_prefix,
        };
        let (addr, prefix_len) = match raw_addr {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if raw_prefix >= 96 => (IpAddr::V4(v4), raw_prefix - 96),
                _ => (IpAddr::V6(v6), raw_prefix),
            },
            IpAddr::V4(_) => (raw_addr, raw_prefix),
        };
        Ok(Self { addr, prefix_len })
    }
}

impl<'de> Deserialize<'de> for IpCidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

fn default_http_port() -> u16 {
    8080
}

fn default_grpc_port() -> u16 {
    50051
}

fn default_log_level() -> LevelFilter {
    LevelFilter::Info
}

fn default_cert_dir() -> PathBuf {
    PathBuf::from("/etc/xguard/certs")
}

fn default_https_port() -> u16 {
    443
}

fn default_adoption_timeout() -> u64 {
    10
}

pub(crate) const DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECONDS: NonZeroU64 = NonZeroU64::new(10).unwrap();
pub(crate) const DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECONDS: NonZeroU64 = NonZeroU64::new(20).unwrap();

fn default_grpc_keepalive_interval_seconds() -> NonZeroU64 {
    DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECONDS
}

fn default_grpc_keepalive_timeout_seconds() -> NonZeroU64 {
    DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECONDS
}

fn default_rate_limit_per_second() -> u64 {
    20
}

fn default_rate_limit_burst() -> u32 {
    60
}

#[derive(Parser, Deserialize, Clone)]
#[command(version)]
pub struct EnvConfig {
    // port the API server will listen on
    #[arg(
        long,
        short = 'p',
        env = "XGUARD_PROXY_HTTP_PORT",
        default_value_t = 8080
    )]
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    // port the API server will listen on
    #[arg(long, env = "XGUARD_PROXY_GRPC_PORT", default_value_t = 50051)]
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    /// HTTP/2 keepalive ping interval for the gRPC server, in seconds.
    #[arg(
        long,
        env = "XGUARD_PROXY_GRPC_KEEPALIVE_INTERVAL_SECONDS",
        default_value_t = DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECONDS
    )]
    #[serde(default = "default_grpc_keepalive_interval_seconds")]
    pub grpc_keepalive_interval_seconds: NonZeroU64,

    /// Time to wait for an HTTP/2 keepalive ping acknowledgement, in seconds.
    #[arg(
        long,
        env = "XGUARD_PROXY_GRPC_KEEPALIVE_TIMEOUT_SECONDS",
        default_value_t = DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECONDS
    )]
    #[serde(default = "default_grpc_keepalive_timeout_seconds")]
    pub grpc_keepalive_timeout_seconds: NonZeroU64,

    #[arg(long, env = "XGUARD_PROXY_LOG_LEVEL", default_value_t = LevelFilter::Info)]
    #[serde(default = "default_log_level")]
    pub log_level: LevelFilter,

    #[arg(long, env = "XGUARD_PROXY_RATELIMIT_PERSECOND", default_value_t = 20)]
    #[serde(default = "default_rate_limit_per_second")]
    pub rate_limit_per_second: u64,

    #[arg(long, env = "XGUARD_PROXY_RATELIMIT_BURST", default_value_t = 60)]
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,

    /// Configuration file path
    #[arg(long = "config", short)]
    #[serde(skip)]
    config_path: Option<PathBuf>,

    #[arg(long, env = "XGUARD_HTTP_BIND_ADDRESS")]
    #[serde(default)]
    pub http_bind_address: Option<IpAddr>,

    #[arg(long, env = "XGUARD_GRPC_BIND_ADDRESS")]
    #[serde(default)]
    pub grpc_bind_address: Option<IpAddr>,

    // TODO: On different platforms this may be different
    #[arg(
        long,
        env = "XGUARD_PROXY_CERT_DIR",
        default_value = "/etc/xguard/certs"
    )]
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,

    /// Port for the HTTPS server. When Core sends TLS certificates over gRPC, the HTTP
    /// server is restarted on this port using those certificates.
    #[arg(long, env = "XGUARD_PROXY_HTTPS_PORT", default_value_t = 443)]
    #[serde(default = "default_https_port")]
    pub https_port: u16,

    /// Use Let's Encrypt staging environment for ACME issuance.
    #[arg(long, env = "XGUARD_PROXY_ACME_STAGING", default_value_t = false)]
    #[serde(default)]
    pub acme_staging: bool,

    /// Time limit in minutes for the auto-adoption process.
    /// After this time Edge will reject adoption attempts until restarted.
    #[arg(
        long,
        short = 't',
        env = "XGUARD_ADOPTION_TIMEOUT",
        default_value = "10"
    )]
    #[serde(default = "default_adoption_timeout")]
    pub adoption_timeout: u64,

    /// Comma-separated list of trusted reverse proxy IPs or CIDRs whose forwarding headers
    /// (`Forwarded`, `X-Forwarded-For`) are honored for client IP extraction.
    #[arg(long, env = "XGUARD_PROXY_TRUSTED_PROXIES", value_delimiter = ',')]
    #[serde(default)]
    pub trusted_proxies: Vec<IpCidr>,

    /// Optional shared secret required on the initial gRPC adoption handshake (`ProxySetup::Start`).
    #[arg(long, env = "XGUARD_PROXY_ADOPTION_TOKEN")]
    #[serde(default)]
    pub adoption_token: Option<String>,
}

impl fmt::Debug for EnvConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvConfig")
            .field("http_port", &self.http_port)
            .field("grpc_port", &self.grpc_port)
            .field(
                "grpc_keepalive_interval_seconds",
                &self.grpc_keepalive_interval_seconds,
            )
            .field(
                "grpc_keepalive_timeout_seconds",
                &self.grpc_keepalive_timeout_seconds,
            )
            .field("log_level", &self.log_level)
            .field("rate_limit_per_second", &self.rate_limit_per_second)
            .field("rate_limit_burst", &self.rate_limit_burst)
            .field("config_path", &self.config_path)
            .field("http_bind_address", &self.http_bind_address)
            .field("grpc_bind_address", &self.grpc_bind_address)
            .field("cert_dir", &self.cert_dir)
            .field("https_port", &self.https_port)
            .field("acme_staging", &self.acme_staging)
            .field("adoption_timeout", &self.adoption_timeout)
            .field("trusted_proxies", &self.trusted_proxies)
            .field(
                "adoption_token",
                &self.adoption_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl EnvConfig {
    #[must_use]
    pub fn adoption_timeout(&self) -> Duration {
        Duration::from_secs(self.adoption_timeout * 60)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file")]
    IoError(#[from] std::io::Error),
    #[error("Failed to parse config file")]
    ParseError(#[from] toml::de::Error),
}

pub fn get_env_config() -> Result<EnvConfig, ConfigError> {
    let cli_config = EnvConfig::parse();

    let config = if let Some(config_path) = cli_config.config_path {
        info!("Reading configuration from file: {config_path:?}");
        let config_toml = read_to_string(config_path)?;
        toml::from_str(&config_toml)?
    } else {
        cli_config
    };

    Ok(config)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{
        DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECONDS, DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECONDS, EnvConfig,
    };

    #[test]
    fn keepalive_defaults_and_toml_values_parse() {
        let defaults: EnvConfig = toml::from_str("").expect("empty TOML should use defaults");
        assert_eq!(
            defaults.grpc_keepalive_interval_seconds.get(),
            DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECONDS.get()
        );
        assert_eq!(
            defaults.grpc_keepalive_timeout_seconds.get(),
            DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECONDS.get()
        );

        let configured: EnvConfig = toml::from_str(
            "grpc_keepalive_interval_seconds = 15\ngrpc_keepalive_timeout_seconds = 30",
        )
        .expect("keepalive TOML values should parse");
        assert_eq!(configured.grpc_keepalive_interval_seconds.get(), 15);
        assert_eq!(configured.grpc_keepalive_timeout_seconds.get(), 30);
    }

    #[test]
    fn keepalive_cli_options_parse_seconds() {
        let config = EnvConfig::try_parse_from([
            "edge",
            "--grpc-keepalive-interval-seconds",
            "15",
            "--grpc-keepalive-timeout-seconds",
            "30",
        ])
        .expect("keepalive CLI options should parse");
        assert_eq!(config.grpc_keepalive_interval_seconds.get(), 15);
        assert_eq!(config.grpc_keepalive_timeout_seconds.get(), 30);
    }

    #[test]
    fn keepalive_environment_variables_are_loaded_in_child() {
        let output = std::process::Command::new(
            std::env::current_exe().expect("test executable path should exist"),
        )
        .args([
            "--exact",
            "config::tests::keepalive_environment_variables_child",
            "--nocapture",
        ])
        .env("XGUARD_TEST_KEEPALIVE_ENV_CHILD", "1")
        .env("XGUARD_PROXY_GRPC_KEEPALIVE_INTERVAL_SECONDS", "13")
        .env("XGUARD_PROXY_GRPC_KEEPALIVE_TIMEOUT_SECONDS", "27")
        .output()
        .expect("environment test child should start");
        assert!(
            output.status.success(),
            "child test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn keepalive_environment_variables_child() {
        if std::env::var_os("XGUARD_TEST_KEEPALIVE_ENV_CHILD").is_none() {
            return;
        }

        let config = EnvConfig::try_parse_from(["edge"]).expect("environment values should parse");
        assert_eq!(config.grpc_keepalive_interval_seconds.get(), 13);
        assert_eq!(config.grpc_keepalive_timeout_seconds.get(), 27);
    }

    #[test]
    fn keepalive_parsers_reject_zero() {
        for toml in [
            "grpc_keepalive_interval_seconds = 0",
            "grpc_keepalive_timeout_seconds = 0",
        ] {
            assert!(toml::from_str::<EnvConfig>(toml).is_err());
        }

        for args in [
            ["edge", "--grpc-keepalive-interval-seconds", "0"],
            ["edge", "--grpc-keepalive-timeout-seconds", "0"],
        ] {
            assert!(EnvConfig::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn rate_limit_defaults_and_trusted_proxies_parse() {
        let defaults: EnvConfig = toml::from_str("").expect("empty TOML should parse");
        assert_eq!(defaults.rate_limit_per_second, 20);
        assert_eq!(defaults.rate_limit_burst, 60);
        assert!(defaults.trusted_proxies.is_empty());

        let parsed = EnvConfig::try_parse_from([
            "edge",
            "--trusted-proxies",
            "10.0.0.0/8,192.168.1.5",
            "--adoption-token",
            "top-secret",
        ])
        .expect("trusted proxies and adoption token should parse");
        assert_eq!(parsed.trusted_proxies.len(), 2);
        assert!(parsed.trusted_proxies[0].contains("10.2.3.4".parse().unwrap()));
        assert!(!parsed.trusted_proxies[0].contains("172.16.0.1".parse().unwrap()));
        assert!(parsed.trusted_proxies[1].contains("192.168.1.5".parse().unwrap()));
        assert!(!format!("{parsed:?}").contains("top-secret"));
    }
}
