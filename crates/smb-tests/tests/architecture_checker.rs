use smb_tests::architecture::{
    Activation, ArchitectureRules, CrateRule, DependencyGraph, ModuleRule, TemporaryAdapter, Wave,
    check_architecture, check_workspace,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "smb-rs-architecture-check-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("unique fixture root");
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture file parent"))
            .expect("fixture parent exists");
        fs::write(path, contents).expect("fixture source writes");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("fixture cleanup");
    }
}

fn module(name: &str, allowed: &[&str]) -> ModuleRule {
    ModuleRule {
        name: name.to_string(),
        root: format!("src/{name}"),
        import_prefix: format!("crate::{name}"),
        allowed_modules: allowed.iter().map(|name| (*name).to_string()).collect(),
        allowed_crate_prefixes: vec![],
        deny_unclassified_crate_imports: true,
        owner_wave: Wave::W2,
        activation: Activation::Activated,
    }
}

fn rules(modules: Vec<ModuleRule>) -> ArchitectureRules {
    ArchitectureRules {
        current_wave: Wave::W3,
        crate_rules: vec![],
        module_rules: modules,
        temporary_adapters: vec![],
    }
}

fn codes(report: &smb_tests::architecture::ArchitectureReport) -> BTreeSet<&str> {
    report
        .violations
        .iter()
        .map(|violation| violation.code.as_str())
        .collect()
}

#[test]
fn accepted_one_way_module_dependencies_pass() {
    let fixture = Fixture::new();
    fixture.write("src/facade/mod.rs", "use crate::domain::Session;");
    fixture.write("src/domain/mod.rs", "use crate::runtime::Operation;");
    fixture.write("src/runtime/mod.rs", "pub struct Operation;");
    let rules = rules(vec![
        module("facade", &["domain"]),
        module("domain", &["runtime"]),
        module("runtime", &[]),
    ]);

    let report = check_architecture(&fixture.root, &rules, &DependencyGraph::default());

    assert!(report.violations.is_empty(), "{:?}", report.violations);
    assert_eq!(
        report.activated_modules,
        vec!["domain", "facade", "runtime"]
    );
}

#[test]
fn reverse_and_skipped_layer_imports_fail() {
    let fixture = Fixture::new();
    fixture.write("src/facade/mod.rs", "use crate::runtime::Operation;");
    fixture.write("src/domain/mod.rs", "pub struct Session;");
    fixture.write("src/runtime/mod.rs", "use crate::domain::Session;");
    let rules = rules(vec![
        module("facade", &["domain"]),
        module("domain", &["runtime"]),
        module("runtime", &[]),
    ]);

    let report = check_architecture(&fixture.root, &rules, &DependencyGraph::default());

    assert!(codes(&report).contains("forbidden-module-dependency"));
    assert_eq!(
        report
            .violations
            .iter()
            .filter(|violation| violation.code == "forbidden-module-dependency")
            .count(),
        2
    );
}

#[test]
fn unknown_modules_and_unclassified_crate_imports_fail() {
    let fixture = Fixture::new();
    fixture.write("src/facade/mod.rs", "use crate::legacy::Worker;");
    let rules = rules(vec![module("facade", &["missing-module"])]);

    let report = check_architecture(&fixture.root, &rules, &DependencyGraph::default());

    assert!(codes(&report).contains("unknown-allowed-module"));
    assert!(codes(&report).contains("unclassified-crate-import"));
}

#[test]
fn rule_roots_cannot_escape_the_workspace() {
    let fixture = Fixture::new();
    let mut escaping = module("facade", &[]);
    escaping.root = "../outside".to_string();

    let report = check_architecture(
        &fixture.root,
        &rules(vec![escaping]),
        &DependencyGraph::default(),
    );

    assert!(codes(&report).contains("module-root-escape"));
}

#[test]
fn future_module_is_not_yet_activated_until_its_root_exists() {
    let fixture = Fixture::new();
    let mut future = module("wire", &[]);
    future.owner_wave = Wave::W4;
    future.activation = Activation::NotYetActivated;
    let rules = ArchitectureRules {
        current_wave: Wave::W1,
        module_rules: vec![future],
        ..rules(vec![])
    };

    let before = check_architecture(&fixture.root, &rules, &DependencyGraph::default());
    assert_eq!(before.not_yet_activated_modules, vec!["wire"]);
    assert!(before.violations.is_empty());

    fixture.write("src/wire/mod.rs", "pub struct Frame;");
    let early = check_architecture(&fixture.root, &rules, &DependencyGraph::default());
    assert!(codes(&early).contains("activation-too-early"));

    let current_rules = ArchitectureRules {
        current_wave: Wave::W4,
        ..rules
    };
    let after = check_architecture(&fixture.root, &current_rules, &DependencyGraph::default());
    assert_eq!(after.activated_modules, vec!["wire"]);
    assert!(after.not_yet_activated_modules.is_empty());
}

#[test]
fn overdue_gate_and_expired_temporary_adapter_fail() {
    let fixture = Fixture::new();
    fixture.write("src/adapter.rs", "pub struct LegacyAdapter;");
    let mut overdue = module("runtime", &[]);
    overdue.owner_wave = Wave::W1;
    overdue.activation = Activation::NotYetActivated;
    let rules = ArchitectureRules {
        current_wave: Wave::W3,
        module_rules: vec![overdue],
        temporary_adapters: vec![TemporaryAdapter {
            path: "src/adapter.rs".to_string(),
            owner_wave: Wave::W2,
            remove_by: Wave::W3,
        }],
        ..rules(vec![])
    };

    let report = check_architecture(&fixture.root, &rules, &DependencyGraph::default());

    assert!(codes(&report).contains("activation-overdue"));
    assert!(codes(&report).contains("temporary-adapter-expired"));
}

#[test]
fn forbidden_crate_dependency_fails_from_metadata_graph() {
    let fixture = Fixture::new();
    let graph = BTreeMap::from([(
        "smb-msg".to_string(),
        BTreeSet::from(["smb".to_string(), "smb-dtyp".to_string()]),
    )]);
    let rules = ArchitectureRules {
        crate_rules: vec![CrateRule {
            name: "smb-msg".to_string(),
            forbidden_dependencies: vec!["smb".to_string()],
            owner_wave: Wave::W1,
            activation: Activation::Activated,
        }],
        ..rules(vec![])
    };

    let report = check_architecture(&fixture.root, &rules, &graph);

    assert!(codes(&report).contains("forbidden-crate-dependency"));
}

#[test]
fn fixture_paths_are_always_scoped_to_the_unique_temp_root() {
    let fixture = Fixture::new();
    assert!(fixture.root.starts_with(std::env::temp_dir()));
    assert!(!Path::new(&fixture.root).is_symlink());
}

#[test]
fn repository_rules_pass_through_the_same_cli_seam() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("smb-tests is under workspace/crates");
    let rules_path = workspace_root.join("docs/architecture/dependency-rules.json");

    let report = check_workspace(workspace_root, &rules_path).expect("repository rules load");

    assert!(report.passed(), "{:?}", report.violations);
    assert_eq!(
        report.activated_modules,
        vec!["domain", "facade", "runtime"]
    );
    assert!(report.not_yet_activated_modules.is_empty());
}
