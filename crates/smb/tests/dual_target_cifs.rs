//! Explicit real-device acceptance for the two distinct CIFS identity modes.
//!
//! Each ignored test accepts only profile-specific descriptor variables. It
//! never falls back to the generic real-server test configuration.

#![cfg(feature = "real-server-tests")]

use bytes::Bytes;
use rand::RngCore;
use smb::{Client, Credentials, Error, FileOpenOptions, SharePath};
use smb_tests::cifs_acceptance::{
    CifsAcceptanceEvidence, CifsAcceptanceProfile, CifsAcceptanceStatus, CifsCleanupEvidence,
};
use std::{env, fs, io::ErrorKind, path::PathBuf, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use zeroize::Zeroizing;

const COMMIT_ENV: &str = "SMB_CIFS_ACCEPTANCE_COMMIT";
const PAYLOAD: &[u8] = b"smb-rs dual-target CIFS acceptance";

#[derive(Clone, Copy)]
struct Profile {
    evidence: CifsAcceptanceProfile,
    prefix: &'static str,
}

impl Profile {
    const DXN_AD: Self = Self {
        evidence: CifsAcceptanceProfile::DxnAd,
        prefix: "DXN_AD",
    };
    const FAS_LOCAL: Self = Self {
        evidence: CifsAcceptanceProfile::FasLocal,
        prefix: "FAS_LOCAL",
    };

    const fn name(self) -> &'static str {
        match self.evidence {
            CifsAcceptanceProfile::DxnAd => "dxn-ad",
            CifsAcceptanceProfile::FasLocal => "fas-local",
        }
    }

    fn variable(self, suffix: &str) -> String {
        format!("SMB_CIFS_ACCEPTANCE_{}_{}", self.prefix, suffix)
    }
}

struct ProfileConfig {
    server: Zeroizing<String>,
    share: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    reject_password: Option<Zeroizing<String>>,
    commit: String,
    evidence_path: PathBuf,
    account_lockout_attested: Option<bool>,
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires explicit DXN AD profile descriptors on a controlled runner"]
async fn cifs_positive_dxn_ad() {
    execute_positive_and_assert(Profile::DXN_AD).await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires explicit FAS local-CIFS profile descriptors on a controlled runner"]
async fn cifs_positive_fas_local() {
    execute_positive_and_assert(Profile::FAS_LOCAL).await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires explicit DXN AD profile descriptors on a controlled runner"]
async fn cifs_acceptance_dxn_ad() {
    execute_acceptance_and_assert(Profile::DXN_AD).await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires explicit FAS local-CIFS profile descriptors on a controlled runner"]
async fn cifs_acceptance_fas_local() {
    execute_acceptance_and_assert(Profile::FAS_LOCAL).await;
}

async fn execute_positive_and_assert(profile: Profile) {
    let config = ProfileConfig::load(profile, false).unwrap_or_else(|error| {
        panic!(
            "{} acceptance configuration failed: {error}",
            profile.name()
        )
    });
    let evidence_path = config.evidence_path.clone();
    let evidence = execute_profile(profile, config, false).await;
    write_evidence(&evidence_path, &evidence)
        .unwrap_or_else(|error| panic!("{} acceptance evidence failed: {error}", profile.name()));
    assert!(
        evidence.positive_path_is_passed(),
        "{} CIFS positive validation did not pass: {:?}",
        profile.name(),
        evidence.result
    );
}

async fn execute_acceptance_and_assert(profile: Profile) {
    let config = ProfileConfig::load(profile, true).unwrap_or_else(|error| {
        panic!(
            "{} acceptance configuration failed: {error}",
            profile.name()
        )
    });
    let evidence_path = config.evidence_path.clone();
    let evidence = execute_profile(profile, config, true).await;
    write_evidence(&evidence_path, &evidence)
        .unwrap_or_else(|error| panic!("{} acceptance evidence failed: {error}", profile.name()));
    assert!(
        evidence.is_passed(),
        "{} CIFS acceptance did not pass: {:?}",
        profile.name(),
        evidence.result
    );
}

impl ProfileConfig {
    fn load(profile: Profile, rejected_authentication: bool) -> Result<Self, String> {
        let password = descriptor_value(profile, "PASSWORD_FD")?;
        let (reject_password, account_lockout_attested) = if rejected_authentication {
            let reject_password = descriptor_value(profile, "REJECT_PASSWORD_FD")?;
            if password == reject_password {
                return Err("reject password must differ from the valid password".into());
            }
            let attestation = required_value(&profile.variable("ACCOUNT_LOCKOUT_ATTESTED"))?;
            let account_lockout_attested = match attestation.as_str() {
                "yes" => true,
                "no" => false,
                _ => return Err("account-lockout attestation must be yes or no".into()),
            };
            (Some(reject_password), Some(account_lockout_attested))
        } else {
            (None, None)
        };
        Ok(Self {
            server: descriptor_value(profile, "SERVER_FD")?,
            share: descriptor_value(profile, "SHARE_FD")?,
            username: descriptor_value(profile, "USERNAME_FD")?,
            password,
            reject_password,
            commit: required_value(COMMIT_ENV)?,
            evidence_path: PathBuf::from(required_value(&profile.variable("EVIDENCE_PATH"))?),
            account_lockout_attested,
        })
    }
}

async fn execute_profile(
    profile: Profile,
    config: ProfileConfig,
    rejected_authentication: bool,
) -> CifsAcceptanceEvidence {
    let run_id = random_run_id();
    let mut evidence = CifsAcceptanceEvidence::new(profile.evidence, &config.commit, &run_id);
    if rejected_authentication && config.account_lockout_attested != Some(true) {
        evidence.valid_authentication = CifsAcceptanceStatus::blocked("account-lockout-policy");
        evidence.rejected_authentication = CifsAcceptanceStatus::blocked("account-lockout-policy");
        evidence.share_roundtrip = CifsAcceptanceStatus::blocked("account-lockout-policy");
        evidence.cleanup = CifsCleanupEvidence::not_started("account-lockout-policy");
        evidence.finalize();
        return evidence;
    }

    if !target_reachable(config.server.as_str()).await {
        evidence.valid_authentication = CifsAcceptanceStatus::blocked("target-unavailable");
        evidence.rejected_authentication = CifsAcceptanceStatus::blocked("target-unavailable");
        evidence.share_roundtrip = CifsAcceptanceStatus::blocked("target-unavailable");
        evidence.cleanup = CifsCleanupEvidence::not_started("target-unavailable");
        evidence.finalize();
        return evidence;
    }

    evidence.rejected_authentication = if rejected_authentication {
        rejected_authentication_probe(&config).await
    } else {
        CifsAcceptanceStatus::blocked("not-requested")
    };
    positive_roundtrip(&config, &run_id, &mut evidence).await;
    evidence.finalize();
    evidence
}

async fn target_reachable(server: &str) -> bool {
    matches!(
        timeout(Duration::from_secs(10), TcpStream::connect((server, 445))).await,
        Ok(Ok(_))
    )
}

async fn rejected_authentication_probe(config: &ProfileConfig) -> CifsAcceptanceStatus {
    let client = Client::new();
    let reject_password = config
        .reject_password
        .as_ref()
        .expect("rejected-authentication configuration includes a password");
    match client
        .authenticate(
            config.server.as_str(),
            Credentials::ntlm(config.username.as_str(), reject_password.as_str()),
        )
        .await
    {
        Ok(session) => {
            let _ = session.close().await;
            let _ = client.close().await;
            CifsAcceptanceStatus::failed("unexpected-auth-success")
        }
        Err(error) if is_explicit_auth_rejection(&error) => CifsAcceptanceStatus::passed(),
        Err(error) => classify_error(&error),
    }
}

async fn positive_roundtrip(
    config: &ProfileConfig,
    run_id: &str,
    evidence: &mut CifsAcceptanceEvidence,
) {
    let client = Client::new();
    let session = match client
        .authenticate(
            config.server.as_str(),
            Credentials::ntlm(config.username.as_str(), config.password.as_str()),
        )
        .await
    {
        Ok(session) => {
            evidence.valid_authentication = CifsAcceptanceStatus::passed();
            session
        }
        Err(error) => {
            evidence.valid_authentication = classify_error(&error);
            evidence.share_roundtrip =
                CifsAcceptanceStatus::blocked("authentication-not-established");
            evidence.cleanup = CifsCleanupEvidence::not_started("authentication-not-established");
            let _ = client.close().await;
            return;
        }
    };
    let share = match session.connect_share(config.share.as_str()).await {
        Ok(share) => share,
        Err(error) => {
            tracing::warn!(error = %error, "CIFS share connection failed");
            evidence.share_roundtrip = if is_access_denied(&error) {
                CifsAcceptanceStatus::failed("share-access-denied")
            } else {
                classify_error(&error)
            };
            evidence.cleanup = CifsCleanupEvidence::not_started("share-not-connected");
            let _ = session.close().await;
            let _ = client.close().await;
            return;
        }
    };

    let path = SharePath::new(format!("smb-rs-acceptance-{run_id}-roundtrip.bin"))
        .expect("run-owned path is valid");
    let file = match share.open_file(&path, FileOpenOptions::create_new()).await {
        Ok(file) => file,
        Err(error) => {
            evidence.share_roundtrip = if is_object_collision(&error) {
                CifsAcceptanceStatus::blocked("ownership-conflict")
            } else {
                classify_error(&error)
            };
            evidence.cleanup = CifsCleanupEvidence::not_started("file-not-owned");
            let _ = share.close().await;
            let _ = session.close().await;
            let _ = client.close().await;
            return;
        }
    };

    let roundtrip = async {
        file.write_all_at(0, Bytes::from_static(PAYLOAD)).await?;
        file.flush().await?;
        let read = file
            .read_exact_at(
                0,
                u32::try_from(PAYLOAD.len()).expect("payload fits in u32"),
            )
            .await?;
        if read.as_ref() != PAYLOAD {
            return Err(Error::InvalidMessage("roundtrip payload mismatch".into()));
        }
        Ok::<(), Error>(())
    }
    .await;
    evidence.share_roundtrip = match roundtrip {
        Ok(()) => CifsAcceptanceStatus::passed(),
        Err(error) => classify_error(&error),
    };

    let delete = file.delete().await;
    let close = file.close().await;
    let delete_status = delete
        .as_ref()
        .map(|_| CifsAcceptanceStatus::passed())
        .unwrap_or_else(|_| CifsAcceptanceStatus::failed("cleanup-failed"));
    let close_status = close
        .as_ref()
        .map(|_| CifsAcceptanceStatus::passed())
        .unwrap_or_else(|_| CifsAcceptanceStatus::failed("cleanup-failed"));
    evidence.cleanup = CifsCleanupEvidence {
        created: true,
        residual_object: !delete_status.is_passed() || !close_status.is_passed(),
        delete: delete_status,
        close: close_status,
    };

    let _ = share.close().await;
    let _ = session.close().await;
    let _ = client.close().await;
}

fn classify_error(error: &Error) -> CifsAcceptanceStatus {
    if is_target_unavailable(error) {
        CifsAcceptanceStatus::blocked("target-unavailable")
    } else if matches!(error, Error::OutcomeUnknown) {
        // The request reached the wire but the client cannot determine
        // whether the server completed it. This is distinct from a failed
        // connection and prevents a caller from assuming the operation was
        // safely rolled back.
        CifsAcceptanceStatus::failed("request-outcome-unknown")
    } else if matches!(
        error,
        Error::OperationTimeout(smb::error::TimedOutTask::ReceiveNextMessage, _)
    ) {
        // The TCP target was reachable and the operation was submitted, but
        // the server did not return an SMB response before the request timer.
        // Keep this distinct from a connection failure: it is the evidence
        // needed to diagnose a share-side VFS stall.
        CifsAcceptanceStatus::failed("request-timeout")
    } else {
        CifsAcceptanceStatus::failed("io-failed")
    }
}

fn is_explicit_auth_rejection(error: &Error) -> bool {
    status_code(error).is_some_and(|status| {
        status == smb::protocol::Status::LogonFailure as u32
            || status == smb::protocol::Status::WrongPassword as u32
            || status == smb::protocol::Status::AccessDenied as u32
    })
}

fn is_access_denied(error: &Error) -> bool {
    status_code(error) == Some(smb::protocol::Status::AccessDenied as u32)
}

fn is_object_collision(error: &Error) -> bool {
    status_code(error) == Some(smb::protocol::Status::ObjectNameCollision as u32)
}

fn status_code(error: &Error) -> Option<u32> {
    match error {
        Error::UnexpectedMessageStatus(status) | Error::ReceivedErrorMessage(status, _) => {
            Some(*status)
        }
        _ => None,
    }
}

fn is_target_unavailable(error: &Error) -> bool {
    match error {
        Error::IoError(error) => matches!(
            error.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionAborted
                | ErrorKind::ConnectionReset
                | ErrorKind::NotConnected
                | ErrorKind::TimedOut
                | ErrorKind::HostUnreachable
                | ErrorKind::NetworkUnreachable
        ),
        Error::TransportError(smb::transport::TransportError::Timeout(_)) => true,
        Error::TransportError(smb::transport::TransportError::IoError(error)) => matches!(
            error.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionAborted
                | ErrorKind::ConnectionReset
                | ErrorKind::NotConnected
                | ErrorKind::TimedOut
                | ErrorKind::HostUnreachable
                | ErrorKind::NetworkUnreachable
        ),
        _ => false,
    }
}

fn descriptor_value(profile: Profile, suffix: &str) -> Result<Zeroizing<String>, String> {
    let name = profile.variable(suffix);
    let descriptor = required_value(&name)?;
    let descriptor = descriptor
        .parse::<i32>()
        .map_err(|_| format!("{name} must be a descriptor number"))?;
    if descriptor < 3 {
        return Err(format!("{name} must be at least 3"));
    }
    let value = fs::read_to_string(format!("/proc/self/fd/{descriptor}"))
        .map_err(|_| format!("failed to read {name}"))?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(format!("{name} is empty or invalid"));
    }
    Ok(Zeroizing::new(value))
}

fn required_value(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing {name}"))
}

fn write_evidence(path: &PathBuf, evidence: &CifsAcceptanceEvidence) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(evidence).map_err(|_| "encode evidence".to_string())?;
    fs::write(path, bytes).map_err(|_| "write evidence".to_string())
}

fn random_run_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn generated_run_id_is_128_bit_lowercase_hex() {
    let run_id = random_run_id();
    assert_eq!(run_id.len(), 32);
    assert!(
        run_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[test]
fn receive_timeout_is_recorded_as_a_request_timeout() {
    let error = Error::OperationTimeout(
        smb::error::TimedOutTask::ReceiveNextMessage,
        Duration::from_secs(20),
    );
    assert_eq!(
        classify_error(&error),
        CifsAcceptanceStatus::failed("request-timeout")
    );
}

#[test]
fn unknown_request_outcome_is_recorded_explicitly() {
    assert_eq!(
        classify_error(&Error::OutcomeUnknown),
        CifsAcceptanceStatus::failed("request-outcome-unknown")
    );
}
