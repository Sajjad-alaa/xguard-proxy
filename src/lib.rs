use std::sync::Arc;

use tokio::sync::mpsc;
use xguard_version::Version;

use crate::proto::LogEntry;

mod acme;
pub(crate) mod client_downloads;
pub mod assets;
pub mod config;
mod error;
pub mod grpc;
mod handlers;
pub mod http;
pub mod logging;
mod setup;

#[cfg(test)]
mod tests;

pub(crate) mod generated {
    pub(crate) mod xguard {
        pub(crate) mod proxy {
            pub(crate) mod v2 {
                tonic::include_proto!("xguard.proxy.v2");
            }
        }

        pub(crate) mod common {
            pub(crate) mod v2 {
                tonic::include_proto!("xguard.common.v2");
            }
        }

        pub mod client_types {
            tonic::include_proto!("xguard.client_types");
        }
    }
}

pub(crate) mod proto {
    pub(crate) use crate::generated::xguard::{client_types::*, common::v2::*, proxy::v2::*};
}

#[macro_use]
extern crate tracing;

pub static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("VERGEN_GIT_SHA"));
pub const MIN_CORE_VERSION: Version = Version::new(2, 1, 0);

type LogsReceiver = Arc<tokio::sync::Mutex<mpsc::Receiver<LogEntry>>>;
