//! Secret-free evidence for dual-target CIFS acceptance integration tests.

use serde::{Deserialize, Serialize};

pub const CIFS_ACCEPTANCE_SCHEMA_VERSION: u32 = 1;

/// The fixed identity and storage binding selected by one integration test.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CifsAcceptanceProfile {
    DxnAd,
    FasLocal,
}

/// A stable, secret-free result for one phase of an acceptance test.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CifsAcceptanceStatus {
    Passed,
    Failed { reason_code: String },
    Blocked { reason_code: String },
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum CifsAcceptanceStatusWire {
    Passed {},
    Failed { reason_code: String },
    Blocked { reason_code: String },
}

impl<'de> Deserialize<'de> for CifsAcceptanceStatus {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        Ok(match CifsAcceptanceStatusWire::deserialize(deserializer)? {
            CifsAcceptanceStatusWire::Passed {} => Self::Passed,
            CifsAcceptanceStatusWire::Failed { reason_code } => Self::Failed { reason_code },
            CifsAcceptanceStatusWire::Blocked { reason_code } => Self::Blocked { reason_code },
        })
    }
}

impl CifsAcceptanceStatus {
    pub const fn passed() -> Self {
        Self::Passed
    }

    pub fn failed(reason_code: impl Into<String>) -> Self {
        Self::Failed {
            reason_code: reason_code.into(),
        }
    }

    pub fn blocked(reason_code: impl Into<String>) -> Self {
        Self::Blocked {
            reason_code: reason_code.into(),
        }
    }

    pub const fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Cleanup observations for one exact run-owned object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CifsCleanupEvidence {
    pub created: bool,
    pub delete: CifsAcceptanceStatus,
    pub close: CifsAcceptanceStatus,
    pub residual_object: bool,
}

impl CifsCleanupEvidence {
    pub fn not_started(reason_code: impl Into<String>) -> Self {
        let reason_code = reason_code.into();
        Self {
            created: false,
            delete: CifsAcceptanceStatus::blocked(reason_code.clone()),
            close: CifsAcceptanceStatus::blocked(reason_code),
            residual_object: false,
        }
    }

    pub const fn is_passed(&self) -> bool {
        self.created && self.delete.is_passed() && self.close.is_passed() && !self.residual_object
    }
}

/// The complete evidence document emitted by exactly one profile test.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CifsAcceptanceEvidence {
    pub schema_version: u32,
    pub profile: CifsAcceptanceProfile,
    pub commit: String,
    pub run_id: String,
    pub valid_authentication: CifsAcceptanceStatus,
    pub rejected_authentication: CifsAcceptanceStatus,
    pub share_roundtrip: CifsAcceptanceStatus,
    pub cleanup: CifsCleanupEvidence,
    pub result: CifsAcceptanceStatus,
}

impl CifsAcceptanceEvidence {
    pub fn new(
        profile: CifsAcceptanceProfile,
        commit: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: CIFS_ACCEPTANCE_SCHEMA_VERSION,
            profile,
            commit: commit.into(),
            run_id: run_id.into(),
            valid_authentication: CifsAcceptanceStatus::blocked("not-started"),
            rejected_authentication: CifsAcceptanceStatus::blocked("not-started"),
            share_roundtrip: CifsAcceptanceStatus::blocked("not-started"),
            cleanup: CifsCleanupEvidence::not_started("not-started"),
            result: CifsAcceptanceStatus::blocked("not-started"),
        }
    }

    pub fn finalize(&mut self) {
        self.result = if self.valid_authentication.is_passed()
            && self.rejected_authentication.is_passed()
            && self.share_roundtrip.is_passed()
            && self.cleanup.is_passed()
        {
            CifsAcceptanceStatus::passed()
        } else if matches!(
            self.valid_authentication,
            CifsAcceptanceStatus::Failed { .. }
        ) || matches!(
            self.rejected_authentication,
            CifsAcceptanceStatus::Failed { .. }
        ) || matches!(self.share_roundtrip, CifsAcceptanceStatus::Failed { .. })
            || matches!(self.cleanup.delete, CifsAcceptanceStatus::Failed { .. })
            || matches!(self.cleanup.close, CifsAcceptanceStatus::Failed { .. })
        {
            CifsAcceptanceStatus::failed("profile-failed")
        } else if matches!(
            self.valid_authentication,
            CifsAcceptanceStatus::Blocked { .. }
        ) || matches!(
            self.rejected_authentication,
            CifsAcceptanceStatus::Blocked { .. }
        ) || matches!(self.share_roundtrip, CifsAcceptanceStatus::Blocked { .. })
            || matches!(self.cleanup.delete, CifsAcceptanceStatus::Blocked { .. })
            || matches!(self.cleanup.close, CifsAcceptanceStatus::Blocked { .. })
        {
            CifsAcceptanceStatus::blocked("profile-blocked")
        } else {
            CifsAcceptanceStatus::failed("invalid-profile-state")
        };
    }

    pub const fn is_passed(&self) -> bool {
        self.result.is_passed()
    }

    /// True when the valid-authentication and file-I/O portion passed, even if
    /// the separately authorized rejected-credential probe was not requested.
    pub const fn positive_path_is_passed(&self) -> bool {
        self.valid_authentication.is_passed()
            && self.share_roundtrip.is_passed()
            && self.cleanup.is_passed()
    }

    pub fn validate(&self) -> Result<(), CifsEvidenceError> {
        if self.schema_version != CIFS_ACCEPTANCE_SCHEMA_VERSION {
            return Err(CifsEvidenceError::new("unsupported-schema-version"));
        }
        if !is_hex(&self.commit, 7, 40) {
            return Err(CifsEvidenceError::new("invalid-commit"));
        }
        if !is_hex(&self.run_id, 32, 32) {
            return Err(CifsEvidenceError::new("invalid-run-id"));
        }
        for status in [
            &self.valid_authentication,
            &self.rejected_authentication,
            &self.share_roundtrip,
            &self.cleanup.delete,
            &self.cleanup.close,
            &self.result,
        ] {
            validate_status(status)?;
        }
        let expected = self.expected_result();
        if self.result != expected {
            return Err(CifsEvidenceError::new("inconsistent-result"));
        }
        Ok(())
    }

    fn expected_result(&self) -> CifsAcceptanceStatus {
        let mut evidence = self.clone();
        evidence.result = CifsAcceptanceStatus::blocked("not-started");
        evidence.finalize();
        evidence.result
    }
}

/// A secret-free same-commit result over both required profiles.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CifsAcceptanceAggregate {
    pub schema_version: u32,
    pub commit: String,
    pub dxn_ad: CifsAcceptanceStatus,
    pub fas_local: CifsAcceptanceStatus,
    pub result: CifsAcceptanceStatus,
}

/// Validation failure for an acceptance document or pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CifsEvidenceError {
    code: &'static str,
}

impl CifsEvidenceError {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl std::fmt::Display for CifsEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for CifsEvidenceError {}

/// Validates and combines the two required, independently executed profiles.
pub fn aggregate_cifs_acceptance(
    first: &CifsAcceptanceEvidence,
    second: &CifsAcceptanceEvidence,
) -> Result<CifsAcceptanceAggregate, CifsEvidenceError> {
    first.validate()?;
    second.validate()?;
    if first.profile == second.profile {
        return Err(CifsEvidenceError::new("duplicate-profile"));
    }
    if first.commit != second.commit {
        return Err(CifsEvidenceError::new("commit-mismatch"));
    }
    let (dxn_ad, fas_local) = match (first.profile, second.profile) {
        (CifsAcceptanceProfile::DxnAd, CifsAcceptanceProfile::FasLocal) => {
            (first.result.clone(), second.result.clone())
        }
        (CifsAcceptanceProfile::FasLocal, CifsAcceptanceProfile::DxnAd) => {
            (second.result.clone(), first.result.clone())
        }
        _ => return Err(CifsEvidenceError::new("missing-required-profile")),
    };
    let result = combined_result(&dxn_ad, &fas_local);
    Ok(CifsAcceptanceAggregate {
        schema_version: CIFS_ACCEPTANCE_SCHEMA_VERSION,
        commit: first.commit.clone(),
        dxn_ad,
        fas_local,
        result,
    })
}

fn combined_result(
    dxn_ad: &CifsAcceptanceStatus,
    fas_local: &CifsAcceptanceStatus,
) -> CifsAcceptanceStatus {
    if dxn_ad.is_passed() && fas_local.is_passed() {
        CifsAcceptanceStatus::passed()
    } else if matches!(dxn_ad, CifsAcceptanceStatus::Blocked { .. })
        || matches!(fas_local, CifsAcceptanceStatus::Blocked { .. })
    {
        CifsAcceptanceStatus::blocked("profile-blocked")
    } else {
        CifsAcceptanceStatus::failed("profile-failed")
    }
}

fn validate_status(status: &CifsAcceptanceStatus) -> Result<(), CifsEvidenceError> {
    let reason_code = match status {
        CifsAcceptanceStatus::Passed => return Ok(()),
        CifsAcceptanceStatus::Failed { reason_code }
        | CifsAcceptanceStatus::Blocked { reason_code } => reason_code,
    };
    if reason_code.is_empty()
        || reason_code.len() > 64
        || !reason_code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(CifsEvidenceError::new("invalid-reason-code"));
    }
    Ok(())
}

fn is_hex(value: &str, minimum: usize, maximum: usize) -> bool {
    value.len() >= minimum
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing(profile: CifsAcceptanceProfile) -> CifsAcceptanceEvidence {
        let mut evidence = CifsAcceptanceEvidence::new(profile, "abc1234", "a".repeat(32));
        evidence.valid_authentication = CifsAcceptanceStatus::passed();
        evidence.rejected_authentication = CifsAcceptanceStatus::passed();
        evidence.share_roundtrip = CifsAcceptanceStatus::passed();
        evidence.cleanup = CifsCleanupEvidence {
            created: true,
            delete: CifsAcceptanceStatus::passed(),
            close: CifsAcceptanceStatus::passed(),
            residual_object: false,
        };
        evidence.finalize();
        evidence
    }

    #[test]
    fn accepts_one_passing_evidence_per_profile_from_same_commit() {
        let aggregate = aggregate_cifs_acceptance(
            &passing(CifsAcceptanceProfile::DxnAd),
            &passing(CifsAcceptanceProfile::FasLocal),
        )
        .unwrap();
        assert!(aggregate.result.is_passed());
    }

    #[test]
    fn rejects_duplicate_profiles_and_commit_mismatches() {
        let first = passing(CifsAcceptanceProfile::DxnAd);
        let duplicate = passing(CifsAcceptanceProfile::DxnAd);
        assert_eq!(
            aggregate_cifs_acceptance(&first, &duplicate)
                .unwrap_err()
                .code(),
            "duplicate-profile"
        );

        let mut second = passing(CifsAcceptanceProfile::FasLocal);
        second.commit = "def5678".into();
        assert_eq!(
            aggregate_cifs_acceptance(&first, &second)
                .unwrap_err()
                .code(),
            "commit-mismatch"
        );
    }

    #[test]
    fn blocked_profile_blocks_the_aggregate() {
        let first = passing(CifsAcceptanceProfile::DxnAd);
        let mut second = passing(CifsAcceptanceProfile::FasLocal);
        second.rejected_authentication = CifsAcceptanceStatus::blocked("account-lockout-policy");
        second.finalize();

        let aggregate = aggregate_cifs_acceptance(&first, &second).unwrap();
        assert!(matches!(
            aggregate.result,
            CifsAcceptanceStatus::Blocked { .. }
        ));
    }

    #[test]
    fn evidence_rejects_unknown_fields_at_every_secret_free_boundary() {
        let evidence = passing(CifsAcceptanceProfile::DxnAd);

        let mut document = serde_json::to_value(&evidence).unwrap();
        document
            .as_object_mut()
            .unwrap()
            .insert("password".into(), serde_json::json!("must-not-be-accepted"));
        assert!(serde_json::from_value::<CifsAcceptanceEvidence>(document).is_err());

        let mut cleanup = serde_json::to_value(&evidence).unwrap();
        cleanup["cleanup"]
            .as_object_mut()
            .unwrap()
            .insert("endpoint".into(), serde_json::json!("must-not-be-accepted"));
        assert!(serde_json::from_value::<CifsAcceptanceEvidence>(cleanup).is_err());

        let mut status = serde_json::to_value(&evidence).unwrap();
        status["valid_authentication"]
            .as_object_mut()
            .unwrap()
            .insert(
                "raw_diagnostic".into(),
                serde_json::json!("must-not-be-accepted"),
            );
        assert!(serde_json::from_value::<CifsAcceptanceEvidence>(status).is_err());

        let aggregate = aggregate_cifs_acceptance(
            &passing(CifsAcceptanceProfile::DxnAd),
            &passing(CifsAcceptanceProfile::FasLocal),
        )
        .unwrap();
        let mut aggregate_document = serde_json::to_value(aggregate).unwrap();
        aggregate_document
            .as_object_mut()
            .unwrap()
            .insert("username".into(), serde_json::json!("must-not-be-accepted"));
        assert!(serde_json::from_value::<CifsAcceptanceAggregate>(aggregate_document).is_err());
    }
}
