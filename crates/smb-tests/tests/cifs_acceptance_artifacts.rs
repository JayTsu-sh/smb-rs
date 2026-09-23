//! Controlled-runner aggregation of two secret-free CIFS acceptance artifacts.

use smb_tests::cifs_acceptance::{
    CifsAcceptanceEvidence, CifsAcceptanceStatus, aggregate_cifs_acceptance,
};
use std::{env, fs, path::PathBuf};

const DXN_EVIDENCE_ENV: &str = "SMB_CIFS_ACCEPTANCE_DXN_AD_EVIDENCE_PATH";
const FAS_EVIDENCE_ENV: &str = "SMB_CIFS_ACCEPTANCE_FAS_LOCAL_EVIDENCE_PATH";
const AGGREGATE_EVIDENCE_ENV: &str = "SMB_CIFS_ACCEPTANCE_AGGREGATE_EVIDENCE_PATH";
const CHECKPOINT_SUMMARY_ENV: &str = "SMB_CIFS_ACCEPTANCE_CHECKPOINT_SUMMARY_PATH";

#[test]
#[ignore = "requires two controlled-runner CIFS acceptance evidence artifacts"]
fn aggregate_dual_target_cifs_evidence() {
    let dxn = read_evidence(DXN_EVIDENCE_ENV).expect("read DXN acceptance evidence");
    let fas = read_evidence(FAS_EVIDENCE_ENV).expect("read FAS acceptance evidence");
    let aggregate = aggregate_cifs_acceptance(&dxn, &fas).expect("validate acceptance evidence");
    write_json(AGGREGATE_EVIDENCE_ENV, &aggregate).expect("write aggregate acceptance evidence");

    assert!(
        aggregate.result.is_passed(),
        "dual-target CIFS acceptance did not pass: {:?}",
        aggregate.result
    );
    write_summary(CHECKPOINT_SUMMARY_ENV, &aggregate.commit).expect("write checkpoint summary");
}

fn read_evidence(name: &str) -> Result<CifsAcceptanceEvidence, String> {
    let path = required_path(name)?;
    let bytes = fs::read(path).map_err(|_| format!("read {name}"))?;
    serde_json::from_slice(&bytes).map_err(|_| format!("decode {name}"))
}

fn write_json<T: serde::Serialize>(name: &str, value: &T) -> Result<(), String> {
    let path = required_path(name)?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| format!("encode {name}"))?;
    fs::write(path, bytes).map_err(|_| format!("write {name}"))
}

fn write_summary(name: &str, commit: &str) -> Result<(), String> {
    let path = required_path(name)?;
    let summary = format!(
        "# Dual-target CIFS acceptance checkpoint\n\nCommit: `{commit}`\n\n- dxn-ad: passed\n- fas-local: passed\n"
    );
    fs::write(path, summary).map_err(|_| format!("write {name}"))
}

fn required_path(name: &str) -> Result<PathBuf, String> {
    let value = env::var(name).map_err(|_| format!("missing {name}"))?;
    if value.is_empty() {
        return Err(format!("empty {name}"));
    }
    Ok(PathBuf::from(value))
}

#[test]
fn status_type_stays_secret_free_in_debug_output() {
    let status = CifsAcceptanceStatus::failed("io-failed");
    assert_eq!(
        format!("{status:?}"),
        "Failed { reason_code: \"io-failed\" }"
    );
}
