//! Secret-free planning and exact-inventory rules for isolated ONTAP validation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const PREFIX: &str = "smbrs";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    run_id: String,
    svm: String,
    aggregate: String,
    test_identity: String,
    volume: String,
    share: String,
    junction: String,
    owner_comment: String,
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
        Ok(Self {
            run_id: run_id.into(),
            svm: svm.into(),
            aggregate: aggregate.into(),
            test_identity: test_identity.into(),
            volume: format!("{stem}_functional"),
            share: format!("{stem}_plain"),
            junction: format!("/{stem}_functional"),
            owner_comment: format!("smb-rs-validation:{run_id}"),
        })
    }

    pub fn volume_name(&self) -> &str {
        &self.volume
    }
    pub fn share_name(&self) -> &str {
        &self.share
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
                &self.test_identity,
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

#[derive(Debug)]
pub struct ApplyAuthorization<'a> {
    pub plan: &'a Plan,
}

impl<'a> ApplyAuthorization<'a> {
    pub fn new(plan: &'a Plan, supplied_hash: &str) -> Result<Self, String> {
        if plan.hash() != supplied_hash {
            return Err("apply authorization does not match the exact plan".into());
        }
        Ok(Self { plan })
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
}
