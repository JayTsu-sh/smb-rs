//! Secret-free, machine-readable architecture wave evidence.

use crate::architecture::{Activation, Wave};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateDefinition {
    pub id: String,
    pub owner_wave: Wave,
    pub activation: Activation,
    pub hard: bool,
    pub conditional: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateEvidence {
    pub id: String,
    pub status: CaseStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CaseStatus {
    Passed,
    Failed { reason_code: String },
    Blocked { reason_code: String },
    NotApplicable { reason_code: String },
    NotYetActivated { owner_wave: Wave },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandEvidence {
    pub category: String,
    pub passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetEvidence {
    pub anonymous_id: String,
    pub platform_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CleanupEvidence {
    pub inventory_empty: bool,
    pub preexisting_state_unchanged: bool,
    pub retained_resources: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WaveEvidence {
    pub schema_version: u32,
    pub wave: Wave,
    pub commit: String,
    pub gates: Vec<GateEvidence>,
    pub commands: Vec<CommandEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<CleanupEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceViolation {
    pub code: String,
    pub subject: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EvidenceValidation {
    pub checkpoint_passed: bool,
    pub violations: Vec<EvidenceViolation>,
}

impl EvidenceValidation {
    fn violation(&mut self, code: &str, subject: impl Into<String>) {
        self.violations.push(EvidenceViolation {
            code: code.to_string(),
            subject: subject.into(),
        });
    }
}

pub fn validate_evidence(
    evidence: &WaveEvidence,
    definitions: &[GateDefinition],
) -> EvidenceValidation {
    let mut validation = EvidenceValidation::default();
    if evidence.schema_version != 1 {
        validation.violation("unsupported-schema-version", "schema-version");
    }
    if evidence.commit.len() < 7
        || evidence.commit.len() > 40
        || !evidence.commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        validation.violation("invalid-commit", "commit");
    }

    let definitions_by_id: BTreeMap<_, _> = definitions
        .iter()
        .map(|definition| (definition.id.as_str(), definition))
        .collect();
    if definitions_by_id.len() != definitions.len() {
        validation.violation("duplicate-gate-definition", "gate-definitions");
    }
    for definition in definitions {
        validate_identifier(&definition.id, "gate-definition", &mut validation);
        if definition.conditional && !definition.hard {
            validation.violation("conditional-gate-not-hard", &definition.id);
        }
    }

    let mut seen = BTreeSet::new();
    for gate in &evidence.gates {
        validate_identifier(&gate.id, "gate", &mut validation);
        if !seen.insert(gate.id.as_str()) {
            validation.violation("duplicate-gate", &gate.id);
            continue;
        }
        let Some(definition) = definitions_by_id.get(gate.id.as_str()) else {
            validation.violation("unknown-gate", &gate.id);
            continue;
        };
        validate_gate_status(evidence.wave, gate, definition, &mut validation);
    }
    for definition in definitions {
        if !seen.contains(definition.id.as_str()) {
            validation.violation("missing-gate", &definition.id);
        }
    }

    let mut command_categories = BTreeSet::new();
    for command in &evidence.commands {
        validate_identifier(&command.category, "command-category", &mut validation);
        if !command_categories.insert(command.category.as_str()) {
            validation.violation("duplicate-command-category", &command.category);
        }
    }
    if let Some(target) = &evidence.target {
        validate_identifier(&target.anonymous_id, "target-id", &mut validation);
        validate_identifier(
            &target.platform_version,
            "platform-version",
            &mut validation,
        );
    }

    validation
        .violations
        .sort_by(|left, right| (&left.code, &left.subject).cmp(&(&right.code, &right.subject)));
    validation.violations.dedup();
    validation.checkpoint_passed = validation.violations.is_empty()
        && evidence.commands.iter().all(|command| command.passed)
        && evidence.cleanup.as_ref().is_none_or(|cleanup| {
            cleanup.inventory_empty
                && cleanup.preexisting_state_unchanged
                && cleanup.retained_resources == 0
        })
        && definitions.iter().all(|definition| {
            if definition.activation != Activation::Activated || !definition.hard {
                return true;
            }
            evidence
                .gates
                .iter()
                .find(|gate| gate.id == definition.id)
                .is_some_and(|gate| match gate.status {
                    CaseStatus::Passed => true,
                    CaseStatus::NotApplicable { .. } => definition.conditional,
                    _ => false,
                })
        });
    validation
}

fn validate_gate_status(
    wave: Wave,
    gate: &GateEvidence,
    definition: &GateDefinition,
    validation: &mut EvidenceValidation,
) {
    match &gate.status {
        CaseStatus::Failed { reason_code }
        | CaseStatus::Blocked { reason_code }
        | CaseStatus::NotApplicable { reason_code } => {
            validate_identifier(reason_code, "reason-code", validation)
        }
        CaseStatus::Passed | CaseStatus::NotYetActivated { .. } => {}
    }

    match definition.activation {
        Activation::Activated => {
            if matches!(gate.status, CaseStatus::NotYetActivated { .. }) {
                validation.violation("activation-overdue", &gate.id);
            }
        }
        Activation::NotYetActivated => {
            if definition.owner_wave <= wave {
                validation.violation("activation-overdue", &gate.id);
            } else if !matches!(gate.status, CaseStatus::NotYetActivated { .. }) {
                validation.violation("activation-too-early", &gate.id);
            }
        }
    }
    if let CaseStatus::NotYetActivated { owner_wave } = gate.status {
        if owner_wave != definition.owner_wave {
            validation.violation("activation-owner-mismatch", &gate.id);
        }
        if owner_wave <= wave {
            validation.violation("activation-overdue", &gate.id);
        }
    }
    if matches!(gate.status, CaseStatus::NotApplicable { .. }) && !definition.conditional {
        validation.violation("not-applicable-hard-gate", &gate.id);
    }
}

fn validate_identifier(value: &str, subject: &str, validation: &mut EvidenceValidation) {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        validation.violation("invalid-identifier", subject);
    }
}
