//! Connection configuration settings.

use std::time::Duration;

use crate::SigningPolicy;
use smb_msg::Dialect;
use smb_transport::config::*;

/// Bounded automatic transport and Connection-generation recovery policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoReconnectConfig {
    pub enabled: bool,
    pub max_attempts: u32,
    pub attempt_timeout: Duration,
    pub total_timeout: Duration,
    pub initial_backoff: Duration,
    pub maximum_backoff: Duration,
    pub maximum_jitter: Duration,
    pub max_waiting_operations: usize,
}

impl Default for AutoReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: 3,
            attempt_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(30),
            initial_backoff: Duration::from_millis(100),
            maximum_backoff: Duration::from_secs(2),
            maximum_jitter: Duration::from_millis(100),
            max_waiting_operations: 1024,
        }
    }
}

impl AutoReconnectConfig {
    pub(crate) fn runtime_policy(self) -> crate::runtime::RecoveryPolicy {
        if !self.enabled {
            return crate::runtime::RecoveryPolicy::disabled();
        }
        crate::runtime::RecoveryPolicy {
            max_attempts: self.max_attempts,
            attempt_timeout: self.attempt_timeout,
            total_timeout: self.total_timeout,
            initial_backoff: self.initial_backoff,
            maximum_backoff: self.maximum_backoff,
            maximum_jitter: self.maximum_jitter,
            max_waiting_operations: self.max_waiting_operations,
        }
    }
}

/// Specifies the encryption mode for the connection.
/// Use this as part of the [ConnectionConfig] to specify the encryption mode for the connection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncryptionMode {
    /// Encryption is allowed but not required, it's up to the server to decide.
    #[default]
    Allowed,
    /// Encryption is required, and connection will fail if the server does not support it.
    Required,
    /// Encryption is disabled, server might fail the connection if it requires encryption.
    Disabled,
}

/// Configures whether and how SMB Multi-Channel will be used for a connection.
///
/// # Semantics
///
/// SMB Multi-Channel is a *negotiated* capability — both client and server must
/// declare support, and the server must additionally expose reachable alternate
/// network interfaces. As a result, no client-side setting can truly force
/// "always-on" Multi-Channel; the most we can do is *announce* support in
/// NEGOTIATE so the server reports its own capability honestly, then let
/// [`crate::Client`] discover the alternate interfaces and bind them.
///
/// Use [`Auto`](Self::Auto) for that "announce + discover" behavior — it is the
/// recommended setting for normal use and the name that most accurately
/// describes what happens at runtime.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum MultiChannelConfig {
    /// Multi-channel is disabled — NEGOTIATE will not advertise the capability.
    #[default]
    Disabled,
    /// Announce Multi-Channel support and let the protocol decide whether to
    /// actually use it based on the server's reply and discovered network
    /// interfaces. This is the recommended default for code that wants
    /// Multi-Channel where it is available.
    Auto,
}

impl MultiChannelConfig {
    /// Returns whether multichannel of any form is enabled.
    pub fn is_enabled(&self) -> bool {
        match self {
            MultiChannelConfig::Auto => true,
            MultiChannelConfig::Disabled => false,
        }
    }
}

impl EncryptionMode {
    /// Returns true if encryption is required.
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Required)
    }

    /// Returns true if encryption is disabled.
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

/// Specifies the authentication methods (SSPs) to be used for the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMethodsConfig {
    /// Whether to try using NTLM authentication.
    /// This is enabled by default.
    pub ntlm: bool,

    /// Whether to try using Kerberos authentication.
    /// This is supported only if the `kerberos` feature is enabled,
    /// and if so, enabled by default.
    pub kerberos: bool,
}

impl Default for AuthMethodsConfig {
    fn default() -> Self {
        Self {
            ntlm: true,
            kerberos: cfg!(feature = "kerberos"),
        }
    }
}

/// Specifies the configuration for a connection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// Specifies the server port to connect to.
    /// If unset, defaults to the default port for the selected transport protocol.
    pub port: Option<u16>,

    /// Specifies the timeout for the connection.
    /// If unset, defaults to [`ConnectionConfig::DEFAULT_TIMEOUT`].
    /// 0 means wait forever.
    /// Access the timeout using the [`ConnectionConfig::timeout()`] method.
    pub timeout: Option<Duration>,

    /// Controls automatic recovery after unplanned transport loss.
    pub auto_reconnect: AutoReconnectConfig,

    /// Specifies the minimum and maximum dialects to be used in the connection.
    ///
    /// Note, that if set, the minimum dialect must be less than or equal to the maximum dialect.
    pub min_dialect: Option<Dialect>,

    /// Specifies the minimum and maximum dialects to be used in the connection.
    ///
    /// Note, that if set, the minimum dialect must be less than or equal to the maximum dialect.
    pub max_dialect: Option<Dialect>,

    /// Sets the encryption mode for the connection.
    /// See [EncryptionMode] for more information.
    pub encryption_mode: EncryptionMode,

    /// Client policy combined with the server signing requirement.
    pub signing_policy: SigningPolicy,

    /// Sets whether signing may be skipped for guest or anonymous access.
    pub allow_unsigned_guest_access: bool,

    /// Whether this client requires signing for the connection.
    ///
    /// Signing capability is still advertised when signing algorithms are
    /// compiled in. `false` means that the client does not require signing; it
    /// does not disable signing. Messages are still signed when the server or
    /// established session requires it. Defaults to `false`.
    pub signing_required: bool,

    /// Whether to enable compression, if supported by the server and specified connection dialects.
    ///
    /// Note: you must also have compression features enabled when building the crate, otherwise compression
    /// would not be available. Compression is disabled in the default build.
    pub compression_enabled: bool,

    /// Multi-channel configuration
    pub multichannel: MultiChannelConfig,

    /// Specifies the client host name to be used in the SMB2 negotiation & session setup.
    pub client_name: Option<String>,

    /// Specifies whether to disable support for Server-to-client notifications.
    /// If set to true, the client will NOT support notifications.
    pub disable_notifications: bool,

    /// Whether to avoid multi-protocol negotiation,
    /// and perform smb2-only negotiation. This results in a
    /// faster negotiation process, but it might fail with some servers,
    pub smb2_only_negotiate: bool,

    /// Specifies the transport protocol to be used for the connection.
    pub transport: TransportConfig,

    /// Configures valid authentication methods (SSPs) for the connection.
    /// See [`AuthMethodsConfig`] for more information.
    pub auth_methods: AuthMethodsConfig,

    /// The number of SMB2 credits to request for the connection.
    /// If not configured, uses [`ConnectionConfig::DEFAULT_CREDITS_BACKLOG`].
    ///
    /// The higher number of credits, the more concurrent requests can be sent on the connection.
    /// However, some servers may not issue such high number of credits.
    ///
    /// This is the somewhat similar to the [`-Smb2MaxCredits`](<https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=windowsserver2025-ps#-smb2creditsmax>)
    /// parameter in the `Set-SmbServerConfiguration` PowerShell cmdlet, but from the client's side.
    pub credits_backlog: Option<u16>,

    /// The default size, in bytes, of the buffer that can be used for
    /// [`ResourceHandle::query_info`][crate::ResourceHandle::query_info], [`ResourceHandle::query_fs_info`][crate::ResourceHandle::query_fs_info],
    /// [`ResourceHandle::query_security_info`][crate::ResourceHandle::query_security_info], [`Directory::query_quota_info`][crate::Directory::query_quota_info],
    /// their respective `set_*_info` counterparts (such as [`ResourceHandle::set_info`][crate::ResourceHandle::set_info]),
    /// [`Directory::query`][crate::Directory::query] and [`Directory::watch`][crate::Directory::watch] operations.
    pub default_transaction_size: Option<u32>,
}

impl ConnectionConfig {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Default target for the number of SMB2 credits maintained by a connection.
    pub const DEFAULT_CREDITS_BACKLOG: u16 = 1024;

    /// Validates common configuration settings.
    pub fn validate(&self) -> crate::Result<()> {
        // Make sure dialects min <= max.
        if let (Some(min), Some(max)) = (self.min_dialect, self.max_dialect)
            && min > max
        {
            return Err(crate::Error::InvalidConfiguration(
                "Minimum dialect is greater than maximum dialect".to_string(),
            ));
        }
        if let Some(default_transaction_size) = self.default_transaction_size
            && default_transaction_size == 0
        {
            return Err(crate::Error::InvalidConfiguration(
                "Default transaction size cannot be zero".to_string(),
            ));
        }
        if self.signing_required && crate::crypto::SIGNING_ALGOS.is_empty() {
            return Err(crate::Error::InvalidConfiguration(
                "Signing is required, but no signing algorithms are enabled".to_string(),
            ));
        }
        if self.auto_reconnect.enabled {
            if self.auto_reconnect.max_attempts == 0
                || self.auto_reconnect.attempt_timeout.is_zero()
                || self.auto_reconnect.total_timeout.is_zero()
                || self.auto_reconnect.max_waiting_operations == 0
            {
                return Err(crate::Error::InvalidConfiguration(
                    "Enabled auto reconnect requires attempts and non-zero deadlines".to_string(),
                ));
            }
            if self.auto_reconnect.initial_backoff > self.auto_reconnect.maximum_backoff {
                return Err(crate::Error::InvalidConfiguration(
                    "Initial reconnect backoff exceeds maximum backoff".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Returns the effective timeout to be used if [`timeout`][`Self::timeout`] is not set.
    pub fn timeout(&self) -> Duration {
        self.timeout.unwrap_or(Self::DEFAULT_TIMEOUT)
    }

    pub(crate) fn effective_credits_backlog(&self) -> u16 {
        self.credits_backlog
            .unwrap_or(Self::DEFAULT_CREDITS_BACKLOG)
    }

    pub const DEFAULT_TRANSACTION_SIZE: u32 = 0x10_000;

    /// Returns the effective value to be used if [`default_transaction_size`][`Self::default_transaction_size`] is not set.
    pub fn default_transaction_size(&self) -> u32 {
        self.default_transaction_size
            .unwrap_or(Self::DEFAULT_TRANSACTION_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_backlog_uses_documented_default_and_preserves_override() {
        assert_eq!(
            ConnectionConfig::default().effective_credits_backlog(),
            ConnectionConfig::DEFAULT_CREDITS_BACKLOG
        );
        assert_eq!(
            ConnectionConfig {
                credits_backlog: Some(128),
                ..Default::default()
            }
            .effective_credits_backlog(),
            128
        );
    }

    #[test]
    #[cfg(not(any(
        feature = "sign_hmac",
        feature = "sign_cmac_rustcrypto",
        feature = "sign_gmac"
    )))]
    fn required_signing_is_rejected_when_no_algorithm_is_compiled() {
        let config = ConnectionConfig {
            signing_required: true,
            ..Default::default()
        };

        assert!(matches!(
            config.validate(),
            Err(crate::Error::InvalidConfiguration(_))
        ));
    }

    #[test]
    #[cfg(any(
        feature = "sign_hmac",
        feature = "sign_cmac_rustcrypto",
        feature = "sign_gmac"
    ))]
    fn required_signing_is_valid_when_an_algorithm_is_compiled() {
        let config = ConnectionConfig {
            signing_required: true,
            ..Default::default()
        };

        assert!(config.validate().is_ok());
    }
}
