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
    }
}
