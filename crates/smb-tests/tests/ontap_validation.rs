use smb_tests::ontap::{
    ApplyAuthorization, Inventory, Lifecycle, Mutation, OntapAdapter, Plan, ProvisioningRun,
    ResourceKind, RunManifest,
};
use std::fs;
use std::path::PathBuf;

fn fixture() -> Plan {
    Plan::new(
        "0123456789abcdef0123456789abcdef",
        "validation-svm",
        "data-aggr",
        "DOMAIN\\test-user",
    )
    .unwrap()
}

fn temp_manifest(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "smb-rs-ontap-{name}-{}-{}.json",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = fs::remove_file(&path);
    path
}

#[test]
fn plan_uses_exact_run_owned_names_and_secret_free_commands() {
    let plan = fixture();
    assert_eq!(
        plan.volume_name(),
        "smbrs_0123456789abcdef0123456789abcdef_functional"
    );
    assert_eq!(
        plan.share_name(),
        "smbrs_0123456789abcdef0123456789abcdef_plain"
    );
    let rendered = plan.render_redacted();
    assert!(rendered.contains("volume create"));
    assert!(rendered.contains("access-control delete"));
    assert!(rendered.contains("<test-identity>"));
    assert!(!serde_json::to_string(&plan).unwrap().contains("test-user"));
    assert!(!rendered.to_ascii_lowercase().contains("password"));
}

#[test]
fn apply_is_bound_to_the_exact_plan_hash() {
    let plan = fixture();
    assert!(ApplyAuthorization::new(&plan, &plan.hash()).is_ok());
    assert!(ApplyAuthorization::new(&plan, "not-the-plan-hash").is_err());
}

#[test]
fn rejects_non_128_bit_lowercase_hex_run_ids() {
    assert!(Plan::new("short", "svm", "aggr", "user").is_err());
    assert!(Plan::new("0123456789ABCDEF0123456789ABCDEF", "svm", "aggr", "user").is_err());
}

#[test]
fn preflight_and_runtime_identity_are_cryptographically_bound_without_cleartext() {
    let unbound = fixture();
    let unbound_hash = unbound.hash();
    let plan = unbound.bind_preflight(&"a".repeat(64)).unwrap();
    assert_ne!(plan.hash(), unbound_hash);
    assert_eq!(plan.preflight_state_hash(), Some("a".repeat(64).as_str()));
    assert!(plan.matches_test_identity("DOMAIN\\test-user"));
    assert!(!plan.matches_test_identity("DOMAIN\\other-user"));
    let json = serde_json::to_string(&plan).unwrap();
    assert!(!json.contains("test-user"));
}

#[test]
fn inventory_is_the_only_cleanup_authority_and_cleanup_is_reversed() {
    let plan = fixture();
    let mut inventory = Inventory::new(&plan);
    inventory.record_created(ResourceKind::Volume).unwrap();
    inventory.record_created(ResourceKind::Share).unwrap();
    assert_eq!(
        inventory.cleanup_order(),
        vec![ResourceKind::Share, ResourceKind::Volume]
    );
}

#[test]
fn ownership_mismatch_blocks_parent_deletion() {
    let plan = fixture();
    let mut inventory = Inventory::new(&plan);
    inventory.record_created(ResourceKind::Volume).unwrap();
    inventory.record_created(ResourceKind::Share).unwrap();
    inventory
        .record_ownership_mismatch(ResourceKind::Share)
        .unwrap();
    assert!(inventory.may_delete(ResourceKind::Share).is_err());
    assert!(inventory.may_delete(ResourceKind::Volume).is_err());
}

#[test]
fn lifecycle_cannot_skip_ready_or_claim_deleted_without_creation() {
    let plan = fixture();
    let mut inventory = Inventory::new(&plan);
    assert!(inventory.record_deleted(ResourceKind::Volume).is_err());
    inventory.record_created(ResourceKind::Volume).unwrap();
    assert_eq!(
        inventory.state(ResourceKind::Volume),
        Some(Lifecycle::Created)
    );
    inventory.record_ready(ResourceKind::Volume).unwrap();
    inventory.record_deleted(ResourceKind::Volume).unwrap();
    assert_eq!(
        inventory.state(ResourceKind::Volume),
        Some(Lifecycle::Deleted)
    );
}

#[test]
fn manifest_persists_each_transition_and_recovers_without_discovery() {
    let path = temp_manifest("recover");
    let mut manifest = RunManifest::create(&path, fixture()).unwrap();
    manifest.record_created(ResourceKind::Volume).unwrap();

    let recovered = RunManifest::load(&path).unwrap();
    assert_eq!(
        recovered.state(ResourceKind::Volume),
        Some(Lifecycle::Created)
    );
    assert_eq!(recovered.cleanup_order(), vec![ResourceKind::Volume]);
    assert_eq!(recovered.path(), path.as_path());
    fs::remove_file(path).unwrap();
}

#[test]
fn failed_atomic_write_does_not_advance_in_memory_or_durable_state() {
    let path = temp_manifest("rollback");
    let mut manifest = RunManifest::create(&path, fixture()).unwrap();
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();

    assert!(manifest.record_created(ResourceKind::Volume).is_err());
    assert_eq!(
        manifest.state(ResourceKind::Volume),
        Some(Lifecycle::Planned)
    );
    fs::remove_dir(path).unwrap();
}

#[test]
fn tampered_manifest_is_rejected_before_cleanup_authority_is_granted() {
    let path = temp_manifest("tamper");
    let manifest = RunManifest::create(&path, fixture()).unwrap();
    drop(manifest);
    let original = fs::read_to_string(&path).unwrap();
    fs::write(&path, original.replace("data-aggr", "other-aggr")).unwrap();

    assert!(RunManifest::load(&path).is_err());
    fs::remove_file(path).unwrap();
}

#[derive(Default)]
struct ScriptedOntap {
    calls: Vec<&'static str>,
    fail_at: Option<&'static str>,
    mismatch: Option<ResourceKind>,
}

impl ScriptedOntap {
    fn action(&mut self, name: &'static str) -> Result<(), String> {
        self.calls.push(name);
        if self.fail_at == Some(name) {
            Err(format!("scripted failure at {name}"))
        } else {
            Ok(())
        }
    }
}

impl OntapAdapter for ScriptedOntap {
    fn create_volume(&mut self, _: &Plan) -> Result<(), String> {
        self.action("create-volume")
    }
    fn create_share(&mut self, _: &Plan) -> Result<(), String> {
        self.action("create-share")
    }
    fn remove_everyone_acl(&mut self, _: &Plan) -> Result<(), String> {
        self.action("remove-everyone-acl")
    }
    fn grant_test_acl(&mut self, _: &Plan) -> Result<(), String> {
        self.action("grant-test-acl")
    }
    fn verify_ready(&mut self, _: &Plan, kind: ResourceKind) -> Result<bool, String> {
        self.calls.push(match kind {
            ResourceKind::Volume => "verify-volume-ready",
            ResourceKind::Share => "verify-share-ready",
        });
        Ok(self.mismatch != Some(kind))
    }
    fn verify_owned(&mut self, _: &Plan, kind: ResourceKind) -> Result<bool, String> {
        self.calls.push(match kind {
            ResourceKind::Volume => "verify-volume-owned",
            ResourceKind::Share => "verify-share-owned",
        });
        Ok(self.mismatch != Some(kind))
    }
    fn delete_share(&mut self, _: &Plan) -> Result<(), String> {
        self.action("delete-share")
    }
    fn offline_volume(&mut self, _: &Plan) -> Result<(), String> {
        self.action("offline-volume")
    }
    fn delete_volume(&mut self, _: &Plan) -> Result<(), String> {
        self.action("delete-volume")
    }
}

#[test]
fn provisioning_persists_ready_resources_in_dependency_order() {
    let path = temp_manifest("provision");
    let plan = fixture();
    let authorization = ApplyAuthorization::new(&plan, &plan.hash()).unwrap();
    let manifest = RunManifest::create(&path, plan).unwrap();
    let mut adapter = ScriptedOntap::default();

    ProvisioningRun::new(manifest, &mut adapter)
        .apply(&authorization)
        .unwrap();
    let recovered = RunManifest::load(&path).unwrap();
    assert_eq!(
        recovered.state(ResourceKind::Volume),
        Some(Lifecycle::Ready)
    );
    assert_eq!(recovered.state(ResourceKind::Share), Some(Lifecycle::Ready));
    assert_eq!(
        adapter.calls,
        vec![
            "create-volume",
            "create-share",
            "remove-everyone-acl",
            "grant-test-acl",
            "verify-volume-ready",
            "verify-share-ready",
        ]
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn provisioning_failure_runs_owned_reverse_cleanup_and_persists_it() {
    let path = temp_manifest("provision-fail");
    let plan = fixture();
    let authorization = ApplyAuthorization::new(&plan, &plan.hash()).unwrap();
    let manifest = RunManifest::create(&path, plan).unwrap();
    let mut adapter = ScriptedOntap {
        fail_at: Some("grant-test-acl"),
        ..Default::default()
    };

    assert!(
        ProvisioningRun::new(manifest, &mut adapter)
            .apply(&authorization)
            .is_err()
    );
    let recovered = RunManifest::load(&path).unwrap();
    assert_eq!(
        recovered.state(ResourceKind::Share),
        Some(Lifecycle::Deleted)
    );
    assert_eq!(
        recovered.state(ResourceKind::Volume),
        Some(Lifecycle::Deleted)
    );
    assert_eq!(
        recovered.mutations(),
        &[Mutation::EveryoneAclRemoved, Mutation::VolumeOfflined]
    );
    assert_eq!(
        adapter.calls,
        vec![
            "create-volume",
            "create-share",
            "remove-everyone-acl",
            "grant-test-acl",
            "verify-share-owned",
            "delete-share",
            "verify-volume-owned",
            "offline-volume",
            "delete-volume",
        ]
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn recovered_manifest_can_resume_exact_cleanup() {
    let path = temp_manifest("resume-cleanup");
    let mut manifest = RunManifest::create(&path, fixture()).unwrap();
    manifest.record_created(ResourceKind::Volume).unwrap();
    manifest.record_created(ResourceKind::Share).unwrap();
    drop(manifest);

    let recovered = RunManifest::load(&path).unwrap();
    let mut adapter = ScriptedOntap::default();
    ProvisioningRun::new(recovered, &mut adapter)
        .cleanup()
        .unwrap();
    let final_manifest = RunManifest::load(&path).unwrap();
    assert_eq!(
        final_manifest.state(ResourceKind::Share),
        Some(Lifecycle::Deleted)
    );
    assert_eq!(
        final_manifest.state(ResourceKind::Volume),
        Some(Lifecycle::Deleted)
    );
    assert_eq!(
        adapter.calls,
        vec![
            "verify-share-owned",
            "delete-share",
            "verify-volume-owned",
            "offline-volume",
            "delete-volume",
        ]
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn ownership_mismatch_stops_that_object_and_parent_cleanup() {
    let path = temp_manifest("provision-mismatch");
    let plan = fixture();
    let authorization = ApplyAuthorization::new(&plan, &plan.hash()).unwrap();
    let manifest = RunManifest::create(&path, plan).unwrap();
    let mut adapter = ScriptedOntap {
        fail_at: Some("grant-test-acl"),
        mismatch: Some(ResourceKind::Share),
        ..Default::default()
    };

    assert!(
        ProvisioningRun::new(manifest, &mut adapter)
            .apply(&authorization)
            .is_err()
    );
    let recovered = RunManifest::load(&path).unwrap();
    assert_eq!(
        recovered.state(ResourceKind::Share),
        Some(Lifecycle::OwnershipMismatch)
    );
    assert_eq!(
        recovered.state(ResourceKind::Volume),
        Some(Lifecycle::Created)
    );
    assert!(!adapter.calls.contains(&"delete-share"));
    assert!(!adapter.calls.contains(&"delete-volume"));
    fs::remove_file(path).unwrap();
}
