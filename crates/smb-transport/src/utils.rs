use std::net::{SocketAddr, ToSocketAddrs};

pub struct TransportUtils;
use crate::TransportError;

impl TransportUtils {
    /// Parses a string endpoint into a [SocketAddr]. If no port is specified, port 0 is used.
    /// Returns [TransportError::InvalidAddress] if the address is invalid or cannot be resolved.
    ///
    /// Supports:
    /// - IPv4: `192.168.1.1`, `192.168.1.1:445`
    /// - IPv6: `::1`, `[::1]:445`, `fe80::1%eth0`
    /// - Hostname: `server.local`, `server.local:445`
    pub fn parse_socket_address(endpoint: &str) -> super::error::Result<SocketAddr> {
        // If it already parses as a SocketAddr (has port), use directly.
        if let Ok(addr) = endpoint.parse::<SocketAddr>() {
            return Ok(addr);
        }

        // Try appending default port 0 with format appropriate for the address type.
        let with_port = if endpoint.starts_with('[') {
            // Bracketed IPv6 without port: [::1] → [::1]:0
            format!("{}:0", endpoint)
        } else if endpoint.contains(':') && endpoint.contains('.') {
            // Likely IPv4:port that failed to parse — return error
            return Err(TransportError::InvalidAddress(endpoint.to_string()));
        } else if endpoint.contains(':') {
            // Bare IPv6 address (no brackets, no port): ::1 → [::1]:0
            format!("[{}]:0", endpoint)
        } else {
            // IPv4 or hostname without port: 192.168.1.1 → 192.168.1.1:0
            format!("{}:0", endpoint)
        };

        let mut socket_addrs = with_port
            .to_socket_addrs()
            .map_err(|_| TransportError::InvalidAddress(endpoint.to_string()))?;
        socket_addrs
            .next()
            .ok_or_else(|| TransportError::InvalidAddress(endpoint.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_with_port() {
        let addr = TransportUtils::parse_socket_address("192.168.1.1:445").unwrap();
        assert_eq!(addr.ip(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addr.port(), 445);
    }

    #[test]
    fn test_ipv4_without_port() {
        let addr = TransportUtils::parse_socket_address("192.168.1.1").unwrap();
        assert_eq!(addr.ip(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn test_ipv6_bracketed_with_port() {
        let addr = TransportUtils::parse_socket_address("[::1]:445").unwrap();
        assert_eq!(addr.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(addr.port(), 445);
    }

    #[test]
    fn test_ipv6_bracketed_without_port() {
        let addr = TransportUtils::parse_socket_address("[::1]").unwrap();
        assert_eq!(addr.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn test_ipv6_bare() {
        let addr = TransportUtils::parse_socket_address("::1").unwrap();
        assert_eq!(addr.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn test_invalid_address() {
        assert!(TransportUtils::parse_socket_address("not_valid:::").is_err());
    }
}
