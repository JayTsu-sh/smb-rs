use smb_tests::ontap::{ApplyAuthorization, Inventory, Lifecycle, Plan, ResourceKind};

fn fixture() -> Plan {
    Plan::new(
        "0123456789abcdef0123456789abcdef",
        "validation-svm",
        "data-aggr",
        "DOMAIN\\test-user",
    )
    .unwrap()
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
