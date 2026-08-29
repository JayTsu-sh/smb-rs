//! Secret-free planning and exact-inventory rules for isolated ONTAP validation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PREFIX: &str = "smbrs";

mod ssh;
pub use ssh::{PreflightEvidence, SshOntapAdapter};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    run_id: String,
    svm: String,
    aggregate: String,
    test_identity_digest: String,
    volume: String,
    share: String,
    junction: String,
    owner_comment: String,
    preflight_state_hash: Option<String>,
}

impl Plan {
    pub fn new(
        run_id: &str,
        svm: &str,
        aggregate: &str,
        test_identity: &str,
    ) -> Result<Self, String> {
        if run_id.len() != 32
            || !run_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("run ID must be exactly 128-bit lowercase hexadecimal".into());
        }
        for (name, value) in [
            ("SVM", svm),
            ("aggregate", aggregate),
            ("test identity", test_identity),
        ] {
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(format!("{name} is empty or contains control characters"));
            }
        }
        let stem = format!("{PREFIX}_{run_id}");
        let test_identity_digest = hex::encode(Sha256::digest(
            [run_id.as_bytes(), b":", test_identity.as_bytes()].concat(),
        ));
        Ok(Self {
            run_id: run_id.into(),
            svm: svm.into(),
            aggregate: aggregate.into(),
            test_identity_digest,
            volume: format!("{stem}_functional"),
            share: format!("{stem}_plain"),
            junction: format!("/{stem}_functional"),
            owner_comment: format!("smb-rs-validation:{run_id}"),
            preflight_state_hash: None,
        })
    }

    pub fn volume_name(&self) -> &str {
        &self.volume
    }
    pub fn share_name(&self) -> &str {
        &self.share
    }

    pub fn matches_test_identity(&self, identity: &str) -> bool {
        let digest = hex::encode(Sha256::digest(
            [self.run_id.as_bytes(), b":", identity.as_bytes()].concat(),
        ));
        digest == self.test_identity_digest
    }

    pub fn anonymous_target_id(&self, target: &str) -> String {
        hex::encode(Sha256::digest(
            [self.run_id.as_bytes(), b":target:", target.as_bytes()].concat(),
        ))
    }

    pub fn bind_preflight(mut self, state_hash: &str) -> Result<Self, String> {
        if state_hash.len() != 64
            || !state_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("preflight state hash must be lowercase SHA-256 hexadecimal".into());
        }
        self.preflight_state_hash = Some(state_hash.to_owned());
        Ok(self)
    }

    pub fn preflight_state_hash(&self) -> Option<&str> {
        self.preflight_state_hash.as_deref()
    }

    pub fn hash(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("Plan serialization cannot fail");
        hex::encode(Sha256::digest(bytes))
    }

    pub fn provision_commands(&self) -> Vec<Vec<String>> {
        vec![
            args(&[
                "volume",
                "create",
                "-vserver",
                &self.svm,
                "-volume",
                &self.volume,
                "-aggregate",
                &self.aggregate,
                "-size",
                "2GB",
                "-security-style",
                "unix",
                "-unix-permissions",
                "0770",
                "-junction-path",
                &self.junction,
                "-comment",
                &self.owner_comment,
                "-autosize-mode",
                "off",
                "-space-guarantee",
                "none",
                "-snapshot-policy",
                "none",
            ]),
            args(&[
                "vserver",
                "cifs",
                "share",
                "create",
                "-vserver",
                &self.svm,
                "-share-name",
                &self.share,
                "-path",
                &self.junction,
                "-share-properties",
                "oplocks,browsable,changenotify,show-previous-versions",
                "-comment",
                &self.owner_comment,
            ]),
            args(&[
                "vserver",
                "cifs",
                "share",
                "access-control",
                "delete",
                "-vserver",
                &self.svm,
                "-share",
                &self.share,
                "-user-or-group",
                "Everyone",
            ]),
            args(&[
                "vserver",
                "cifs",
                "share",
                "access-control",
                "create",
                "-vserver",
                &self.svm,
                "-share",
                &self.share,
                "-user-or-group",
                "<test-identity>",
                "-permission",
                "Full_Control",
            ]),
        ]
    }

    pub fn render_redacted(&self) -> String {
        self.provision_commands()
            .into_iter()
            .map(|command| command.join(" "))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyAuthorization {
    plan_hash: String,
}

impl ApplyAuthorization {
    pub fn new(plan: &Plan, supplied_hash: &str) -> Result<Self, String> {
        if plan.hash() != supplied_hash {
            return Err("apply authorization does not match the exact plan".into());
        }
        Ok(Self {
            plan_hash: supplied_hash.to_owned(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ResourceKind {
    Volume,
    Share,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lifecycle {
    Planned,
    Created,
    Ready,
    OwnershipMismatch,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mutation {
    EveryoneAclRemoved,
    TestIdentityAclGranted,
    VolumeOfflined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    plan_hash: String,
    resources: BTreeMap<ResourceKind, Lifecycle>,
}

impl Inventory {
    pub fn new(plan: &Plan) -> Self {
        Self {
            plan_hash: plan.hash(),
            resources: BTreeMap::from([
                (ResourceKind::Volume, Lifecycle::Planned),
                (ResourceKind::Share, Lifecycle::Planned),
            ]),
        }
    }

    pub fn state(&self, kind: ResourceKind) -> Option<Lifecycle> {
        self.resources.get(&kind).copied()
    }

    pub fn record_created(&mut self, kind: ResourceKind) -> Result<(), String> {
        self.transition(kind, Lifecycle::Planned, Lifecycle::Created)
    }

    pub fn record_ready(&mut self, kind: ResourceKind) -> Result<(), String> {
        self.transition(kind, Lifecycle::Created, Lifecycle::Ready)
    }

    pub fn record_deleted(&mut self, kind: ResourceKind) -> Result<(), String> {
        match self.state(kind) {
            Some(Lifecycle::Created | Lifecycle::Ready) => {
                self.resources.insert(kind, Lifecycle::Deleted);
                Ok(())
            }
            _ => Err("resource was not created by this inventory".into()),
        }
    }

    pub fn record_ownership_mismatch(&mut self, kind: ResourceKind) -> Result<(), String> {
        match self.state(kind) {
            Some(Lifecycle::Created | Lifecycle::Ready) => {
                self.resources.insert(kind, Lifecycle::OwnershipMismatch);
                Ok(())
            }
            _ => Err("cannot mismatch an uncreated resource".into()),
        }
    }

    pub fn cleanup_order(&self) -> Vec<ResourceKind> {
        [ResourceKind::Share, ResourceKind::Volume]
            .into_iter()
            .filter(|kind| {
                matches!(
                    self.state(*kind),
                    Some(Lifecycle::Created | Lifecycle::Ready)
                )
            })
            .collect()
    }

    pub fn may_delete(&self, kind: ResourceKind) -> Result<(), String> {
        if self.state(kind) == Some(Lifecycle::OwnershipMismatch) {
            return Err("resource ownership does not match the manifest".into());
        }
        if kind == ResourceKind::Volume
            && self.state(ResourceKind::Share) == Some(Lifecycle::OwnershipMismatch)
        {
            return Err("child ownership mismatch blocks parent deletion".into());
        }
        if !matches!(
            self.state(kind),
            Some(Lifecycle::Created | Lifecycle::Ready)
        ) {
            return Err("resource is not cleanup-authorized by the inventory".into());
        }
        Ok(())
    }

    fn transition(
        &mut self,
        kind: ResourceKind,
        from: Lifecycle,
        to: Lifecycle,
    ) -> Result<(), String> {
        if self.state(kind) != Some(from) {
            return Err(format!("invalid resource lifecycle transition to {to:?}"));
        }
        self.resources.insert(kind, to);
        Ok(())
    }

    fn validate(&self, plan: &Plan) -> Result<(), String> {
        if self.plan_hash != plan.hash() {
            return Err("manifest plan hash does not match its inventory".into());
        }
        let expected = [ResourceKind::Volume, ResourceKind::Share];
        if self.resources.len() != expected.len()
            || expected
                .iter()
                .any(|kind| !self.resources.contains_key(kind))
        {
            return Err("manifest inventory has missing or unknown resources".into());
        }
        Ok(())
    }
}

/// A durable Validation run whose transition methods persist before they
/// expose the new state to callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    schema_version: u32,
    metadata: RunMetadata,
    plan: Plan,
    inventory: Inventory,
    mutations: Vec<Mutation>,
    #[serde(skip)]
    path: PathBuf,
}

impl RunManifest {
    pub fn create(path: impl AsRef<Path>, plan: Plan) -> Result<Self, String> {
        Self::create_with_metadata(path, plan, RunMetadata::test_fixture())
    }

    pub fn create_with_metadata(
        path: impl AsRef<Path>,
        plan: Plan,
        metadata: RunMetadata,
    ) -> Result<Self, String> {
        let path = path.as_ref();
        if path.exists() {
            return Err(format!("manifest already exists: {}", path.display()));
        }
        let manifest = Self {
            schema_version: 1,
            metadata,
            inventory: Inventory::new(&plan),
            mutations: Vec::new(),
            plan,
            path: path.to_owned(),
        };
        manifest.persist()?;
        Ok(manifest)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(io_error("read manifest"))?;
        let mut manifest: Self =
            serde_json::from_slice(&bytes).map_err(|error| format!("decode manifest: {error}"))?;
        if manifest.schema_version != 1 {
            return Err(format!(
                "unsupported manifest schema version {}",
                manifest.schema_version
            ));
        }
        manifest.inventory.validate(&manifest.plan)?;
        manifest.metadata.validate()?;
        manifest.path = path.to_owned();
        Ok(manifest)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn metadata(&self) -> &RunMetadata {
        &self.metadata
    }

    pub fn state(&self, kind: ResourceKind) -> Option<Lifecycle> {
        self.inventory.state(kind)
    }

    pub fn cleanup_order(&self) -> Vec<ResourceKind> {
        self.inventory.cleanup_order()
    }

    pub fn record_created(&mut self, kind: ResourceKind) -> Result<(), String> {
        self.update(|inventory| inventory.record_created(kind))
    }

    pub fn record_ready(&mut self, kind: ResourceKind) -> Result<(), String> {
        self.update(|inventory| inventory.record_ready(kind))
    }

    pub fn record_deleted(&mut self, kind: ResourceKind) -> Result<(), String> {
        self.update(|inventory| inventory.record_deleted(kind))
    }

    pub fn record_ownership_mismatch(&mut self, kind: ResourceKind) -> Result<(), String> {
        self.update(|inventory| inventory.record_ownership_mismatch(kind))
    }

    pub fn may_delete(&self, kind: ResourceKind) -> Result<(), String> {
        self.inventory.may_delete(kind)
    }

    pub fn mutations(&self) -> &[Mutation] {
        &self.mutations
    }

    pub fn record_mutation(&mut self, mutation: Mutation) -> Result<(), String> {
        let mut next = self.clone();
        if next.mutations.contains(&mutation) {
            return Err("mutation is already recorded".into());
        }
        next.mutations.push(mutation);
        next.persist()?;
        self.mutations = next.mutations;
        Ok(())
    }

    fn update(
        &mut self,
        transition: impl FnOnce(&mut Inventory) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut next = self.clone();
        transition(&mut next.inventory)?;
        next.persist()?;
        self.inventory = next.inventory;
        Ok(())
    }

    fn persist(&self) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "manifest path requires a UTF-8 file name".to_string())?;
        let temporary = parent.join(format!(".{file_name}.{:016x}.tmp", rand::random::<u64>()));
        let result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(io_error("create temporary manifest"))?;
            let bytes = serde_json::to_vec_pretty(self)
                .map_err(|error| format!("encode manifest: {error}"))?;
            file.write_all(&bytes)
                .map_err(io_error("write temporary manifest"))?;
            file.write_all(b"\n")
                .map_err(io_error("terminate temporary manifest"))?;
            file.sync_all()
                .map_err(io_error("fsync temporary manifest"))?;
            fs::rename(&temporary, &self.path).map_err(io_error("replace manifest"))?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(io_error("fsync manifest directory"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMetadata {
    pub code_commit: String,
    pub toolchain: String,
    pub runner_version: String,
    pub anonymous_target_id: String,
    pub created_unix_seconds: u64,
}

impl RunMetadata {
    pub fn new(
        code_commit: String,
        toolchain: String,
        runner_version: String,
        anonymous_target_id: String,
    ) -> Result<Self, String> {
        let metadata = Self {
            code_commit,
            toolchain,
            runner_version,
            anonymous_target_id,
            created_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
                .as_secs(),
        };
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<(), String> {
        if self.code_commit.len() != 40
            || !self
                .code_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("metadata code commit must be a 40-digit Git object ID".into());
        }
        if self.anonymous_target_id.len() != 64
            || !self
                .anonymous_target_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("metadata target ID must be a SHA-256 digest".into());
        }
        if self.toolchain.is_empty()
            || self.runner_version.is_empty()
            || self.toolchain.chars().any(char::is_control)
            || self.runner_version.chars().any(char::is_control)
        {
            return Err("metadata tool versions are empty or invalid".into());
        }
        Ok(())
    }

    fn test_fixture() -> Self {
        Self {
            code_commit: "0".repeat(40),
            toolchain: "test-toolchain".into(),
            runner_version: env!("CARGO_PKG_VERSION").into(),
            anonymous_target_id: "0".repeat(64),
            created_unix_seconds: 0,
        }
    }
}

fn io_error(operation: &'static str) -> impl FnOnce(io::Error) -> String {
    move |error| format!("{operation}: {error}")
}

/// Adapter at the true-external ONTAP seam. Implementations perform one exact
/// appliance mutation or verification per method.
pub trait OntapAdapter {
    fn create_volume(&mut self, plan: &Plan) -> Result<(), String>;
    fn create_share(&mut self, plan: &Plan) -> Result<(), String>;
    fn remove_everyone_acl(&mut self, plan: &Plan) -> Result<(), String>;
    fn grant_test_acl(&mut self, plan: &Plan) -> Result<(), String>;
    fn verify_ready(&mut self, plan: &Plan, kind: ResourceKind) -> Result<bool, String>;
    fn verify_owned(&mut self, plan: &Plan, kind: ResourceKind) -> Result<bool, String>;
    fn delete_share(&mut self, plan: &Plan) -> Result<(), String>;
    fn offline_volume(&mut self, plan: &Plan) -> Result<(), String>;
    fn delete_volume(&mut self, plan: &Plan) -> Result<(), String>;
}

/// Transactional provisioning and cleanup orchestration over an ONTAP Adapter.
pub struct ProvisioningRun<'a, A> {
    manifest: RunManifest,
    adapter: &'a mut A,
}

impl<'a, A: OntapAdapter> ProvisioningRun<'a, A> {
    pub fn new(manifest: RunManifest, adapter: &'a mut A) -> Self {
        Self { manifest, adapter }
    }

    pub fn apply(mut self, authorization: &ApplyAuthorization) -> Result<RunManifest, String> {
        if self.manifest.plan.hash() != authorization.plan_hash {
            return Err("apply authorization is for a different manifest".into());
        }
        let result = self.provision();
        if let Err(provision_error) = result {
            let cleanup_errors = self.cleanup_resources();
            return Err(if cleanup_errors.is_empty() {
                provision_error
            } else {
                format!(
                    "{provision_error}; cleanup failed: {}",
                    cleanup_errors.join("; ")
                )
            });
        }
        Ok(self.manifest)
    }

    pub fn cleanup(mut self) -> Result<RunManifest, String> {
        let errors = self.cleanup_resources();
        if errors.is_empty() {
            Ok(self.manifest)
        } else {
            Err(errors.join("; "))
        }
    }

    fn provision(&mut self) -> Result<(), String> {
        let plan = self.manifest.plan.clone();
        self.adapter.create_volume(&plan)?;
        self.manifest.record_created(ResourceKind::Volume)?;
        self.adapter.create_share(&plan)?;
        self.manifest.record_created(ResourceKind::Share)?;
        self.adapter.remove_everyone_acl(&plan)?;
        self.manifest
            .record_mutation(Mutation::EveryoneAclRemoved)?;
        self.adapter.grant_test_acl(&plan)?;
        self.manifest
            .record_mutation(Mutation::TestIdentityAclGranted)?;
        for kind in [ResourceKind::Volume, ResourceKind::Share] {
            if !self.adapter.verify_ready(&plan, kind)? {
                return Err(format!("{kind:?} did not match the ready plan"));
            }
            self.manifest.record_ready(kind)?;
        }
        Ok(())
    }

    fn cleanup_resources(&mut self) -> Vec<String> {
        let plan = self.manifest.plan.clone();
        let mut errors = Vec::new();
        for kind in self.manifest.cleanup_order() {
            if let Err(error) = self.manifest.may_delete(kind) {
                errors.push(error);
                continue;
            }
            match self.adapter.verify_owned(&plan, kind) {
                Ok(true) => {}
                Ok(false) => {
                    if let Err(error) = self.manifest.record_ownership_mismatch(kind) {
                        errors.push(error);
                    }
                    errors.push(format!("{kind:?} ownership mismatch"));
                    continue;
                }
                Err(error) => {
                    errors.push(error);
                    continue;
                }
            }
            let deletion = match kind {
                ResourceKind::Share => self.adapter.delete_share(&plan),
                ResourceKind::Volume => {
                    if !self.manifest.mutations.contains(&Mutation::VolumeOfflined) {
                        if let Err(error) = self.adapter.offline_volume(&plan) {
                            errors.push(error);
                            continue;
                        }
                        if let Err(error) = self.manifest.record_mutation(Mutation::VolumeOfflined)
                        {
                            errors.push(error);
                            continue;
                        }
                    }
                    self.adapter.delete_volume(&plan)
                }
            };
            match deletion {
                Ok(()) => {
                    if let Err(error) = self.manifest.record_deleted(kind) {
                        errors.push(error);
                    }
                }
                Err(error) => errors.push(error),
            }
        }
        errors
    }
}
