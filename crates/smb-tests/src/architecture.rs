//! Executable architecture dependency and activation rules.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use syn::visit::Visit;

pub type DependencyGraph = BTreeMap<String, BTreeSet<String>>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Wave {
    W0,
    W1,
    W2,
    W3,
    W4,
    W5,
    W6,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Activation {
    Activated,
    NotYetActivated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArchitectureRules {
    pub current_wave: Wave,
    #[serde(default)]
    pub crate_rules: Vec<CrateRule>,
    #[serde(default)]
    pub module_rules: Vec<ModuleRule>,
    #[serde(default)]
    pub temporary_adapters: Vec<TemporaryAdapter>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrateRule {
    pub name: String,
    #[serde(default)]
    pub forbidden_dependencies: Vec<String>,
    pub owner_wave: Wave,
    pub activation: Activation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModuleRule {
    pub name: String,
    pub root: String,
    pub import_prefix: String,
    #[serde(default)]
    pub allowed_modules: Vec<String>,
    #[serde(default)]
    pub allowed_crate_prefixes: Vec<String>,
    #[serde(default)]
    pub deny_unclassified_crate_imports: bool,
    pub owner_wave: Wave,
    pub activation: Activation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TemporaryAdapter {
    pub path: String,
    pub owner_wave: Wave,
    pub remove_by: Wave,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArchitectureViolation {
    pub code: String,
    pub subject: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ArchitectureReport {
    pub activated_crates: Vec<String>,
    pub not_yet_activated_crates: Vec<String>,
    pub activated_modules: Vec<String>,
    pub not_yet_activated_modules: Vec<String>,
    pub violations: Vec<ArchitectureViolation>,
}

impl ArchitectureReport {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }

    fn violation(&mut self, code: &str, subject: impl Into<String>, detail: impl Into<String>) {
        self.violations.push(ArchitectureViolation {
            code: code.to_string(),
            subject: subject.into(),
            detail: detail.into(),
        });
    }

    fn sort(&mut self) {
        self.activated_crates.sort();
        self.not_yet_activated_crates.sort();
        self.activated_modules.sort();
        self.not_yet_activated_modules.sort();
        self.violations.sort_by(|left, right| {
            (&left.code, &left.subject, &left.detail).cmp(&(
                &right.code,
                &right.subject,
                &right.detail,
            ))
        });
    }
}

pub fn load_rules(path: &Path) -> Result<ArchitectureRules, String> {
    let bytes = fs::read(path).map_err(|error| format!("failed to read rules: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("failed to parse rules: {error}"))
}

pub fn cargo_dependency_graph(workspace_root: &Path) -> Result<DependencyGraph, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(workspace_root)
        .output()
        .map_err(|error| format!("failed to execute cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err("cargo metadata failed".to_string());
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("invalid cargo metadata: {error}"))?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "cargo metadata omitted packages".to_string())?;
    let mut graph = DependencyGraph::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "cargo package omitted name".to_string())?;
        let dependencies = package
            .get("dependencies")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("cargo package {name} omitted dependencies"))?;
        graph.insert(
            name.to_string(),
            dependencies
                .iter()
                .filter_map(|dependency| dependency.get("name"))
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect(),
        );
    }
    Ok(graph)
}

pub fn check_workspace(
    workspace_root: &Path,
    rules_path: &Path,
) -> Result<ArchitectureReport, String> {
    let rules = load_rules(rules_path)?;
    let dependencies = cargo_dependency_graph(workspace_root)?;
    Ok(check_architecture(workspace_root, &rules, &dependencies))
}

pub fn check_architecture(
    workspace_root: &Path,
    rules: &ArchitectureRules,
    dependencies: &DependencyGraph,
) -> ArchitectureReport {
    let mut report = ArchitectureReport::default();
    check_rule_identity(rules, &mut report);
    check_crates(rules, dependencies, &mut report);
    check_modules(workspace_root, rules, &mut report);
    check_temporary_adapters(workspace_root, rules, &mut report);
    report.sort();
    report
}

fn check_rule_identity(rules: &ArchitectureRules, report: &mut ArchitectureReport) {
    let names: BTreeSet<_> = rules
        .module_rules
        .iter()
        .map(|rule| rule.name.as_str())
        .collect();
    if names.len() != rules.module_rules.len() {
        report.violation(
            "duplicate-module-rule",
            "module-rules",
            "module rule names must be unique",
        );
    }
    for rule in &rules.module_rules {
        for allowed in &rule.allowed_modules {
            if !names.contains(allowed.as_str()) {
                report.violation(
                    "unknown-allowed-module",
                    &rule.name,
                    format!("allowed module {allowed} has no rule"),
                );
            }
        }
    }
}

fn check_crates(
    rules: &ArchitectureRules,
    dependencies: &DependencyGraph,
    report: &mut ArchitectureReport,
) {
    for rule in &rules.crate_rules {
        let present = dependencies.get(&rule.name);
        let active = present.is_some();
        if active && rule.owner_wave > rules.current_wave {
            report.violation(
                "activation-too-early",
                &rule.name,
                format!("crate gate belongs to {:?}", rule.owner_wave),
            );
        }
        match (rule.activation, active) {
            (Activation::Activated, false) => report.violation(
                "activated-crate-missing",
                &rule.name,
                "activated crate is absent from cargo metadata",
            ),
            (Activation::NotYetActivated, false) if rule.owner_wave <= rules.current_wave => report
                .violation(
                    "activation-overdue",
                    &rule.name,
                    format!("crate gate {:?} is due", rule.owner_wave),
                ),
            (Activation::NotYetActivated, false) => {
                report.not_yet_activated_crates.push(rule.name.clone())
            }
            _ => report.activated_crates.push(rule.name.clone()),
        }
        if let Some(actual) = present {
            for forbidden in &rule.forbidden_dependencies {
                if actual.contains(forbidden) {
                    report.violation(
                        "forbidden-crate-dependency",
                        &rule.name,
                        format!("depends on forbidden crate {forbidden}"),
                    );
                }
            }
        }
    }
}

fn check_modules(
    workspace_root: &Path,
    rules: &ArchitectureRules,
    report: &mut ArchitectureReport,
) {
    let workspace_root = match workspace_root.canonicalize() {
        Ok(root) => root,
        Err(error) => {
            report.violation(
                "workspace-root-unavailable",
                ".",
                format!("cannot canonicalize workspace root: {error}"),
            );
            return;
        }
    };
    for rule in &rules.module_rules {
        let Some(root) = checked_rule_path(&workspace_root, &rule.root, &rule.name, report) else {
            continue;
        };
        let present = root.exists();
        if present && rule.owner_wave > rules.current_wave {
            report.violation(
                "activation-too-early",
                &rule.name,
                format!("module gate belongs to {:?}", rule.owner_wave),
            );
        }
        match (rule.activation, present) {
            (Activation::Activated, false) => report.violation(
                "activated-module-missing",
                &rule.name,
                format!("activated module root {} is absent", rule.root),
            ),
            (Activation::NotYetActivated, false) if rule.owner_wave <= rules.current_wave => report
                .violation(
                    "activation-overdue",
                    &rule.name,
                    format!("module gate {:?} is due", rule.owner_wave),
                ),
            (Activation::NotYetActivated, false) => {
                report.not_yet_activated_modules.push(rule.name.clone())
            }
            _ => {
                report.activated_modules.push(rule.name.clone());
                check_module_sources(&workspace_root, &root, rule, rules, report);
            }
        }
    }
}

fn check_temporary_adapters(
    workspace_root: &Path,
    rules: &ArchitectureRules,
    report: &mut ArchitectureReport,
) {
    let Ok(workspace_root) = workspace_root.canonicalize() else {
        return;
    };
    for adapter in &rules.temporary_adapters {
        let Some(path) = checked_rule_path(&workspace_root, &adapter.path, &adapter.path, report)
        else {
            continue;
        };
        if adapter.remove_by <= adapter.owner_wave {
            report.violation(
                "invalid-adapter-lifetime",
                &adapter.path,
                "remove_by must be later than owner_wave",
            );
        }
        if path.exists() && rules.current_wave >= adapter.remove_by {
            report.violation(
                "temporary-adapter-expired",
                &adapter.path,
                format!("adapter expired at {:?}", adapter.remove_by),
            );
        }
    }
}

fn checked_rule_path(
    workspace_root: &Path,
    relative: &str,
    subject: &str,
    report: &mut ArchitectureReport,
) -> Option<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        report.violation(
            "module-root-escape",
            subject,
            format!("rule path {relative} escapes the workspace"),
        );
        return None;
    }
    let joined = workspace_root.join(path);
    if joined.exists() {
        match joined.canonicalize() {
            Ok(canonical) if canonical.starts_with(workspace_root) => {}
            Ok(_) => {
                report.violation(
                    "module-root-escape",
                    subject,
                    format!("rule path {relative} resolves outside the workspace"),
                );
                return None;
            }
            Err(error) => {
                report.violation(
                    "module-root-unavailable",
                    subject,
                    format!("cannot canonicalize {relative}: {error}"),
                );
                return None;
            }
        }
    }
    Some(joined)
}

fn check_module_sources(
    workspace_root: &Path,
    module_root: &Path,
    rule: &ModuleRule,
    rules: &ArchitectureRules,
    report: &mut ArchitectureReport,
) {
    let mut files = Vec::new();
    collect_rust_files(module_root, &mut files, report, &rule.name);
    files.sort();
    for file in files {
        let relative_file = file
            .strip_prefix(workspace_root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let source = match fs::read_to_string(&file) {
            Ok(source) => source,
            Err(error) => {
                report.violation(
                    "source-read-failed",
                    &relative_file,
                    format!("cannot read source: {error}"),
                );
                continue;
            }
        };
        let syntax = match syn::parse_file(&source) {
            Ok(syntax) => syntax,
            Err(error) => {
                report.violation("rust-parse-error", &relative_file, error.to_string());
                continue;
            }
        };
        let current_module = current_module_prefix(module_root, &file, &rule.import_prefix);
        let mut visitor = CratePathVisitor::default();
        visitor.visit_file(&syntax);
        for raw in visitor.paths {
            if let Some(path) = normalize_crate_path(&raw, &current_module) {
                check_crate_path(&path, rule, rules, report, &relative_file);
            }
        }
    }
}

fn collect_rust_files(
    path: &Path,
    files: &mut Vec<PathBuf>,
    report: &mut ArchitectureReport,
    subject: &str,
) {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.to_path_buf());
        }
        return;
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            report.violation(
                "module-root-unavailable",
                subject,
                format!("cannot read module root: {error}"),
            );
            return;
        }
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() {
            collect_rust_files(&child, files, report, subject);
        } else if child.extension().is_some_and(|extension| extension == "rs") {
            files.push(child);
        }
    }
}

fn current_module_prefix(module_root: &Path, file: &Path, import_prefix: &str) -> Vec<String> {
    let mut prefix: Vec<_> = import_prefix.split("::").map(str::to_string).collect();
    let relative = file.strip_prefix(module_root).unwrap_or(file);
    if let Some(parent) = relative.parent() {
        prefix.extend(parent.components().filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        }));
    }
    if relative.file_name().is_some_and(|name| name != "mod.rs")
        && let Some(stem) = relative.file_stem()
    {
        prefix.push(stem.to_string_lossy().into_owned());
    }
    prefix
}

fn normalize_crate_path(raw: &[String], current_module: &[String]) -> Option<String> {
    let first = raw.first()?;
    let mut normalized = match first.as_str() {
        "crate" => vec!["crate".to_string()],
        "self" => current_module.to_vec(),
        "super" => {
            let mut base = current_module.to_vec();
            let mut index = 0;
            while raw.get(index).is_some_and(|segment| segment == "super") {
                if base.len() <= 1 {
                    return None;
                }
                base.pop();
                index += 1;
            }
            base.extend_from_slice(&raw[index..]);
            return Some(base.join("::"));
        }
        _ => return None,
    };
    normalized.extend_from_slice(&raw[1..]);
    Some(normalized.join("::"))
}

fn check_crate_path(
    path: &str,
    rule: &ModuleRule,
    rules: &ArchitectureRules,
    report: &mut ArchitectureReport,
    source: &str,
) {
    if path == "crate" || prefix_matches(path, &rule.import_prefix) {
        return;
    }
    if rule
        .allowed_crate_prefixes
        .iter()
        .any(|prefix| prefix_matches(path, prefix))
    {
        return;
    }
    let target = rules
        .module_rules
        .iter()
        .filter(|candidate| prefix_matches(path, &candidate.import_prefix))
        .max_by_key(|candidate| candidate.import_prefix.len());
    if let Some(target) = target {
        if !rule.allowed_modules.contains(&target.name) {
            report.violation(
                "forbidden-module-dependency",
                source,
                format!(
                    "module {} imports {} through {path}",
                    rule.name, target.name
                ),
            );
        }
    } else if rule.deny_unclassified_crate_imports {
        report.violation(
            "unclassified-crate-import",
            source,
            format!("module {} imports unclassified path {path}", rule.name),
        );
    }
}

fn prefix_matches(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with("::"))
}

#[derive(Default)]
struct CratePathVisitor {
    paths: BTreeSet<Vec<String>>,
}

impl<'ast> Visit<'ast> for CratePathVisitor {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_use_tree(Vec::new(), &item.tree, &mut self.paths);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.paths.insert(
            path.segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect(),
        );
        syn::visit::visit_path(self, path);
    }
}

fn collect_use_tree(prefix: Vec<String>, tree: &syn::UseTree, paths: &mut BTreeSet<Vec<String>>) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut next = prefix;
            next.push(path.ident.to_string());
            collect_use_tree(next, &path.tree, paths);
        }
        syn::UseTree::Name(name) => {
            let mut path = prefix;
            path.push(name.ident.to_string());
            paths.insert(path);
        }
        syn::UseTree::Rename(rename) => {
            let mut path = prefix;
            path.push(rename.ident.to_string());
            paths.insert(path);
        }
        syn::UseTree::Glob(_) => {
            paths.insert(prefix);
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(prefix.clone(), item, paths);
            }
        }
    }
}
