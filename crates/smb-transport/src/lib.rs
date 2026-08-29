#![forbid(unsafe_code)]

use std::time::Duration;

pub mod config;
pub mod error;
pub mod frame;
pub mod iovec;
pub mod tcp;
pub mod traits;
pub mod utils;

#[cfg(feature = "test-support")]
pub mod test_support;

pub use config::*;
pub use error::TransportError;
pub use frame::{DEFAULT_MAX_FRAME_SIZE, SendFrame, TransportFrame};
pub use iovec::*;

pub use tcp::{SmbTcpMessageHeader, TcpTransport};
pub use traits::*;

#[cfg(feature = "netbios-transport")]
pub mod netbios;
#[cfg(feature = "netbios-transport")]
pub use netbios::*;

#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
pub use quic::*;

#[cfg(feature = "rdma")]
pub mod rdma;
#[cfg(feature = "rdma")]
pub use rdma::*;

/// Creates [`SmbTransport`] out of [`TransportConfig`].
///
/// ## Arguments
/// * `transport` - The transport configuration to make the transport by.
/// * `timeout` - The timeout duration to use for the transport.
pub fn make_transport(
    transport: &TransportConfig,
    timeout: Duration,
) -> Result<Box<dyn SmbTransport>, TransportError> {
    match transport {
        TransportConfig::Tcp => Ok(Box::new(tcp::TcpTransport::new(timeout))),

        #[cfg(feature = "netbios-transport")]
        TransportConfig::NetBios => Ok(Box::new(NetBiosTransport::new(timeout))),

        #[cfg(feature = "quic")]
        TransportConfig::Quic(quic_config) => {
            Ok(Box::new(quic::QuicTransport::new(quic_config, timeout)?))
        }

        #[cfg(feature = "rdma")]
        TransportConfig::Rdma(rdma_config) => {
            Ok(Box::new(RdmaTransport::new(rdma_config, timeout)))
        }
    }
}
