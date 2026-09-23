#![allow(dead_code)]
use std::env::var;
use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;
use zeroize::Zeroizing;

static SERVER_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();
static USER_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();
static PASSWORD_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();
static SHARE_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();
static MANAGEMENT_TARGET_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();
static MANAGEMENT_USER_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();
static MANAGEMENT_PASSWORD_FROM_FD: OnceLock<Zeroizing<String>> = OnceLock::new();

#[derive(Default)]
struct SessionRecord {
    connection_id: Option<String>,
    session_id: Option<String>,
    node: Option<String>,
    windows_user: Option<String>,
    client_ip: Option<String>,
}

impl SessionRecord {
    fn matches(&self, username: &str, client_ip: &str) -> bool {
        self.windows_user.as_deref().is_some_and(|value| {
            (value == username || value.ends_with(&format!("\\{username}")))
                && self.client_ip.as_deref() == Some(client_ip)
        })
    }
}

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

pub fn smb_test_username() -> String {
    var(TestEnv::USER)
        .ok()
        .or_else(|| from_secret_fd(TestEnv::USER_FD, &USER_FROM_FD))
        .unwrap_or_else(|| TestEnv::DEFAULT_USER.to_string())
}

pub fn close_exact_ontap_session(share: &str) -> Result<(), String> {
    let svm = var("SMB_ONTAP_TEST_SVM").map_err(|_| "missing SMB_ONTAP_TEST_SVM")?;
    let username = smb_test_username();
    let client_ip =
        var("SMB_ONTAP_TEST_CLIENT_IP").map_err(|_| "missing SMB_ONTAP_TEST_CLIENT_IP")?;
    let output = management_command(&[
        "vserver",
        "cifs",
        "session",
        "show",
        "-vserver",
        &svm,
        "-share-names",
        share,
        "-instance",
    ])?;
    let mut matches = Vec::new();
    let mut record = SessionRecord::default();
    for line in output.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if line.is_empty() {
            if record.matches(&username, &client_ip) {
                matches.push(std::mem::take(&mut record));
            } else {
                record = SessionRecord::default();
            }
            continue;
        }
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let label = label
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        let value = value.trim();
        if label == "connectionid" {
            record.connection_id = Some(value.to_owned());
        } else if label == "sessionid" {
            record.session_id = Some(value.to_owned());
        } else if label == "node" {
            record.node = Some(value.to_owned());
        } else if label == "windowsuser" {
            record.windows_user = Some(value.to_owned());
        } else if label == "workstationipaddress" {
            record.client_ip = Some(value.to_owned());
        }
    }
    if matches.len() != 1 {
        return Err(format!(
            "management preflight found {} exact test-share sessions",
            matches.len()
        ));
    }
    let record = matches
        .pop()
        .ok_or("management preflight lost the exact test-share session")?;
    let connection_id = record
        .connection_id
        .ok_or("management preflight omitted connection ID")?;
    let session_id = record
        .session_id
        .ok_or("management preflight omitted session ID")?;
    let node = record.node.ok_or("management preflight omitted node")?;
    let close_arguments = [
        "vserver",
        "cifs",
        "session",
        "close",
        "-node",
        &node,
        "-vserver",
        &svm,
        "-session-id",
        &session_id,
        "-connection-id",
        &connection_id,
    ];
    let output = run_management_command(&close_arguments)?;
    if output.status.success() {
        return Ok(());
    }
    if output.status.code() != Some(255) || !output.stderr.is_empty() {
        return Err(management_failure(&output));
    }

    for attempt in 0..20 {
        let remaining = management_command(&[
            "vserver",
            "cifs",
            "session",
            "show",
            "-vserver",
            &svm,
            "-share-names",
            share,
            "-instance",
        ])?;
        let old_session_remains = remaining.lines().any(|line| {
            let Some((label, value)) = line.split_once(':') else {
                return false;
            };
            label
                .chars()
                .filter(|character| !character.is_ascii_whitespace())
                .collect::<String>()
                .eq_ignore_ascii_case("sessionid")
                && value.trim() == session_id
        });
        if !old_session_remains {
            return Ok(());
        }
        if attempt < 19 {
            thread::sleep(Duration::from_millis(250));
        }
    }
    Err(format!(
        "management session close disconnected but the exact session remains: {}",
        management_failure(&output)
    ))
}

fn management_command(arguments: &[&str]) -> Result<String, String> {
    let output = run_management_command(arguments)?;
    if !output.status.success() {
        return Err(management_failure(&output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_management_command(arguments: &[&str]) -> Result<Output, String> {
    let descriptor = |name: &str| {
        var(name)
            .map_err(|_| format!("missing {name}"))?
            .parse::<i32>()
            .map_err(|_| format!("invalid {name}"))
    };
    let target = from_secret_fd("SMB_ONTAP_MANAGEMENT_TARGET_FD", &MANAGEMENT_TARGET_FROM_FD)
        .ok_or("missing management target")?;
    let user = from_secret_fd("SMB_ONTAP_MANAGEMENT_USER_FD", &MANAGEMENT_USER_FROM_FD)
        .ok_or("missing management user")?;
    let password = from_secret_fd(
        "SMB_ONTAP_MANAGEMENT_PASSWORD_FD",
        &MANAGEMENT_PASSWORD_FROM_FD,
    )
    .ok_or("missing management password")?;
    let _ = descriptor("SMB_ONTAP_MANAGEMENT_PASSWORD_FD")?;
    if arguments.iter().any(|value| {
        value.is_empty()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'\\' | b':' | b'@' | b',')
            })
    }) {
        return Err("management command contains an invalid token".into());
    }
    let remote = arguments.join(" ");
    let mut child = Command::new("sshpass")
        .arg("-d0")
        .arg("ssh")
        .args(["-o", "BatchMode=no", "-o", "PasswordAuthentication=yes"])
        .args([
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
        ])
        .arg(format!("{user}@{target}"))
        .arg(remote)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start management command: {error}"))?;
    let mut input = child
        .stdin
        .take()
        .ok_or("management password pipe unavailable")?;
    input
        .write_all(format!("{password}\n").as_bytes())
        .map_err(|error| format!("write management password: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait management command: {error}"))?;
    Ok(output)
}

fn management_failure(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let diagnostic = stderr
        .lines()
        .chain(stdout.lines())
        .find(|line| {
            let line = line.trim();
            !line.is_empty()
                && line.chars().any(|character| !character.is_control())
                && !line.starts_with("Last login time:")
                && !line.starts_with("Unsuccessful login attempts")
        })
        .unwrap_or("no diagnostic")
        .trim();
    format!("management command failed: {}; {diagnostic}", output.status)
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
