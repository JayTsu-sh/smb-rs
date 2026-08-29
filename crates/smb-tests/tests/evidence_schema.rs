use smb_tests::architecture::{Activation, Wave};
use smb_tests::evidence::{
    CaseStatus, CleanupEvidence, CommandEvidence, EvidenceValidation, GateDefinition, GateEvidence,
    TargetEvidence, WaveEvidence, validate_evidence,
};

fn definitions() -> Vec<GateDefinition> {
    vec![
        GateDefinition {
            id: "workspace-check".to_string(),
            owner_wave: Wave::W0,
            activation: Activation::Activated,
            hard: true,
            conditional: false,
        },
        GateDefinition {
            id: "conditional-ca".to_string(),
            owner_wave: Wave::W4,
            activation: Activation::NotYetActivated,
            hard: true,
            conditional: true,
        },
    ]
}

fn valid_evidence() -> WaveEvidence {
    WaveEvidence {
        schema_version: 1,
        wave: Wave::W1,
        commit: "f02188b".to_string(),
        gates: vec![
            GateEvidence {
                id: "workspace-check".to_string(),
                status: CaseStatus::Passed,
            },
            GateEvidence {
                id: "conditional-ca".to_string(),
                status: CaseStatus::NotYetActivated {
                    owner_wave: Wave::W4,
                },
            },
        ],
        commands: vec![CommandEvidence {
            category: "workspace-check".to_string(),
            passed: true,
        }],
        target: Some(TargetEvidence {
            anonymous_id: "fas2750-validation-target".to_string(),
            platform_version: "ontap-9-19-1".to_string(),
        }),
        cleanup: Some(CleanupEvidence {
            inventory_empty: true,
            preexisting_state_unchanged: true,
            retained_resources: 0,
        }),
    }
}

fn violation_codes(validation: &EvidenceValidation) -> Vec<&str> {
    validation
        .violations
        .iter()
        .map(|violation| violation.code.as_str())
        .collect()
}

#[test]
fn valid_evidence_serializes_without_command_or_secret_fields() {
    let evidence = valid_evidence();
    let validation = validate_evidence(&evidence, &definitions());
    let json = serde_json::to_string_pretty(&evidence).expect("evidence serializes");

    assert!(validation.violations.is_empty());
    assert!(validation.checkpoint_passed);
    assert!(!json.contains("password"));
    assert!(!json.contains("username"));
    assert!(!json.contains("command_line"));
    assert!(!json.contains("payload"));
}

#[test]
fn missing_or_duplicate_hard_gate_is_rejected() {
    let mut missing = valid_evidence();
    missing.gates.retain(|gate| gate.id != "workspace-check");
    let missing_validation = validate_evidence(&missing, &definitions());
    assert!(violation_codes(&missing_validation).contains(&"missing-gate"));
    assert!(!missing_validation.checkpoint_passed);

    let mut duplicate = valid_evidence();
    duplicate.gates.push(duplicate.gates[0].clone());
    let duplicate_validation = validate_evidence(&duplicate, &definitions());
    assert!(violation_codes(&duplicate_validation).contains(&"duplicate-gate"));
}

#[test]
fn not_applicable_requires_a_conditional_gate_and_stable_reason() {
    let mut invalid = valid_evidence();
    invalid.gates[0].status = CaseStatus::NotApplicable {
        reason_code: "not-supported".to_string(),
    };
    let invalid_validation = validate_evidence(&invalid, &definitions());
    assert!(violation_codes(&invalid_validation).contains(&"not-applicable-hard-gate"));

    let definitions = vec![GateDefinition {
        id: "conditional-ca".to_string(),
        owner_wave: Wave::W1,
        activation: Activation::Activated,
        hard: true,
        conditional: true,
    }];
    let mut conditional = valid_evidence();
    conditional.gates = vec![GateEvidence {
        id: "conditional-ca".to_string(),
        status: CaseStatus::NotApplicable {
            reason_code: "platform-prerequisite-absent".to_string(),
        },
    }];
    let conditional_validation = validate_evidence(&conditional, &definitions);
    assert!(conditional_validation.violations.is_empty());
    assert!(conditional_validation.checkpoint_passed);
}

#[test]
fn not_yet_activated_must_belong_to_a_future_wave() {
    let mut evidence = valid_evidence();
    evidence.gates[0].status = CaseStatus::NotYetActivated {
        owner_wave: Wave::W1,
    };

    let validation = validate_evidence(&evidence, &definitions());

    assert!(violation_codes(&validation).contains(&"activation-overdue"));
    assert!(!validation.checkpoint_passed);
}

#[test]
fn failed_and_blocked_hard_gates_are_valid_evidence_but_fail_checkpoint() {
    for status in [
        CaseStatus::Failed {
            reason_code: "assertion-failed".to_string(),
        },
        CaseStatus::Blocked {
            reason_code: "infrastructure-unavailable".to_string(),
        },
    ] {
        let mut evidence = valid_evidence();
        evidence.gates[0].status = status;
        let validation = validate_evidence(&evidence, &definitions());
        assert!(validation.violations.is_empty());
        assert!(!validation.checkpoint_passed);
    }
}

#[test]
fn payload_like_identifiers_and_non_hex_commit_are_rejected() {
    let mut evidence = valid_evidence();
    evidence.commit = "main branch".to_string();
    evidence.commands[0].category = "run with password".to_string();
    evidence.target.as_mut().expect("target").anonymous_id = "10.0.0.1".to_string();

    let validation = validate_evidence(&evidence, &definitions());
    let codes = violation_codes(&validation);

    assert!(codes.contains(&"invalid-commit"));
    assert!(codes.contains(&"invalid-identifier"));
    assert!(!validation.checkpoint_passed);
}

#[test]
fn failed_command_or_incomplete_cleanup_prevents_checkpoint_acceptance() {
    let mut failed_command = valid_evidence();
    failed_command.commands[0].passed = false;
    let command_validation = validate_evidence(&failed_command, &definitions());
    assert!(command_validation.violations.is_empty());
    assert!(!command_validation.checkpoint_passed);

    let mut incomplete_cleanup = valid_evidence();
    incomplete_cleanup
        .cleanup
        .as_mut()
        .expect("cleanup")
        .inventory_empty = false;
    let cleanup_validation = validate_evidence(&incomplete_cleanup, &definitions());
    assert!(cleanup_validation.violations.is_empty());
    assert!(!cleanup_validation.checkpoint_passed);
}
