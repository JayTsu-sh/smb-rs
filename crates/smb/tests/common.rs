#![allow(dead_code)]
use std::env::var;
use std::fs;
use std::sync::OnceLock;
use zeroize::Zeroizing;

static SERVER_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();
static USER_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();
static PASSWORD_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();
static SHARE_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();

pub struct TestEnv;

impl TestEnv {
    pub const SERVER: &'static str = "SMB_RUST_TESTS_SERVER";
    pub const SERVER_FD: &'static str = "SMB_RUST_TESTS_SERVER_FD";
    pub const USER: &'static str = "SMB_RUST_TESTS_USER_NAME";
    pub const USER_FD: &'static str = "SMB_RUST_TESTS_USER_NAME_FD";
    pub const DEFAULT_USER: &'static str = "LocalAdmin";
    pub const PASSWORD: &'static str = "SMB_RUST_TESTS_PASSWORD";
    pub const PASSWORD_FD: &'static str = "SMB_RUST_TESTS_PASSWORD_FD";
    pub const DEFAULT_PASSWORD: &'static str = "123456";
    /// Optional override for the share name used by integration tests
    /// (e.g. when pointing at a real lease-capable server with a non-default
    /// share). Falls back to [`TestConstants::DEFAULT_SHARE`] when unset.
    pub const SHARE: &'static str = "SMB_RUST_TESTS_SHARE";
    pub const SHARE_FD: &'static str = "SMB_RUST_TESTS_SHARE_FD";

    pub const GUEST_USER: &'static str = "/GUEST";
    pub const GUEST_PASSWORD: &'static str = "";
}

pub struct TestConstants;

impl TestConstants {
    pub const DEFAULT_SHARE: &'static str = "MyShare";
    pub const PUBLIC_GUEST_SHARE: &'static str = "PublicShare";
}

/// Reads the share name from `SMB_RUST_TESTS_SHARE`, falling back to
/// [`TestConstants::DEFAULT_SHARE`] when unset.
pub fn smb_tests_share() -> String {
    var(TestEnv::SHARE)
        .ok()
        .or_else(|| from_secret_fd(TestEnv::SHARE_FD, &SHARE_FROM_FD))
        .unwrap_or_else(|| TestConstants::DEFAULT_SHARE.to_string())
}

/// Returns the server address for the tests connection.
pub fn smb_tests_server() -> String {
    var(TestEnv::SERVER)
        .ok()
        .or_else(|| from_secret_fd(TestEnv::SERVER_FD, &SERVER_FROM_FD))
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

pub fn smb_test_credentials() -> smb::Credentials {
    let user = var(TestEnv::USER)
        .ok()
        .or_else(|| from_secret_fd(TestEnv::USER_FD, &USER_FROM_FD))
        .unwrap_or_else(|| TestEnv::DEFAULT_USER.to_string());
    let password = var(TestEnv::PASSWORD)
        .ok()
        .or_else(|| from_secret_fd(TestEnv::PASSWORD_FD, &PASSWORD_FROM_FD))
        .unwrap_or_else(|| TestEnv::DEFAULT_PASSWORD.to_string());
    smb::Credentials::ntlm(user, password)
}

fn from_secret_fd(name: &str, cache: &'static OnceLock<Zeroizing<String>>) -> Option<String> {
    let descriptor = var(name).ok()?;
    let descriptor = descriptor
        .parse::<i32>()
        .unwrap_or_else(|_| panic!("{name} must contain a descriptor number"));
    assert!(descriptor >= 3, "{name} descriptor must be at least 3");
    let value = cache.get_or_init(|| {
        let value = fs::read_to_string(format!("/proc/self/fd/{descriptor}"))
            .unwrap_or_else(|error| panic!("failed reading {name}: {error}"));
        let value = value.trim_end_matches(['\r', '\n']).to_owned();
        assert!(!value.is_empty(), "{name} descriptor was empty");
        Zeroizing::new(value)
    });
    Some(value.to_string())
}

#[macro_export]
macro_rules! with_temp_env {
    (
        [
            $(
                ($name:expr, $value:expr),
            )*
        ],
        $body:expr
    ) => {
        temp_env::async_with_vars(
            [
                $(($name, $value)),*
            ],
            $body
        ).await
    };
}
