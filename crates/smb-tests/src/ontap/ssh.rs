use super::{OntapAdapter, Plan, ResourceKind, ShareRole, VolumeRole};
use std::io::Write;
use std::process::{Command, Output, Stdio};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightEvidence {
    pub state_hash: String,
    pub ontap_version: String,
}

/// Production Adapter for the ONTAP CLI over SSH. The management password is
/// consumed by `sshpass` from an inherited descriptor and is never an argument
/// or environment value.
pub struct SshOntapAdapter {
    target: String,
    user: Zeroizing<String>,
    test_identity: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl SshOntapAdapter {
    pub fn new(
        target: &str,
        user: &str,
        test_identity: &str,
        password: &str,
    ) -> Result<Self, String> {
        if target.is_empty()
            || user.is_empty()
            || test_identity.is_empty()
            || password.is_empty()
            || target.chars().any(char::is_control)
            || user.chars().any(char::is_control)
            || test_identity.chars().any(char::is_control)
            || user.contains('@')
        {
            return Err("invalid SSH target or user".into());
        }
        Ok(Self {
            target: target.to_owned(),
            user: Zeroizing::new(user.to_owned()),
            test_identity: Zeroizing::new(test_identity.to_owned()),
            password: Zeroizing::new(password.to_owned()),
        })
    }

    pub fn preflight(&self, plan: &Plan) -> Result<PreflightEvidence, String> {
        use sha2::{Digest, Sha256};

        let version = self.run(&["version"])?;
        let cifs = self.run(&["vserver", "cifs", "show", "-vserver", &plan.svm])?;
        if !has_exact_token(&cifs, &plan.svm) {
            return Err("preflight did not find the configured CIFS SVM".into());
        }
        let aggregate = self.run(&[
            "storage",
            "aggregate",
            "show",
            "-aggregate",
            &plan.aggregate,
            "-state",
            "online",
            "-fields",
            "aggregate",
        ])?;
        if !has_exact_token(&aggregate, &plan.aggregate) {
            return Err("preflight did not find the configured online aggregate".into());
        }
        if self.volume_owned(plan, false)?
            || self.performance_volume_owned(plan, false)?
            || self.ca_volume_owned(plan, false)?
            || self.share_owned(plan, ShareRole::Plain, false)?
            || self.share_owned(plan, ShareRole::Encrypted, false)?
            || self.share_owned(plan, ShareRole::PerformancePlain, false)?
            || self.share_owned(plan, ShareRole::PerformanceEncrypted, false)?
            || self.share_owned(plan, ShareRole::Ca, false)?
        {
            return Err("preflight run-owned resource names are not absent".into());
        }
        let normalized = normalize_preflight(&[&version, &cifs, &aggregate]);
        let state_hash = hex::encode(Sha256::digest(normalized.as_bytes()));
        let ontap_version = version
            .lines()
            .find(|line| line.contains("Release"))
            .unwrap_or("version-detected")
            .trim()
            .to_owned();
        Ok(PreflightEvidence {
            state_hash,
            ontap_version,
        })
    }

    fn run(&self, args: &[&str]) -> Result<String, String> {
        let remote_command = args
            .iter()
            .map(|argument| ontap_token(argument))
            .collect::<Result<Vec<_>, _>>()?
            .join(" ");
        let mut child = Command::new("sshpass")
            .arg("-d0")
            .arg("ssh")
            .arg("-o")
            .arg("BatchMode=no")
            .arg("-o")
            .arg("PasswordAuthentication=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg(format!("{}@{}", self.user.as_str(), self.target))
            .arg(remote_command)
            .env_remove("SSHPASS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("start management SSH command: {error}"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "management SSH password pipe is unavailable".to_string())?;
        stdin
            .write_all(self.password.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|error| format!("write management SSH password pipe: {error}"))?;
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|error| format!("wait for management SSH command: {error}"))?;
        decode_output(output)
    }

    fn volume_owned(&self, plan: &Plan, ready: bool) -> Result<bool, String> {
        self.volume_role_owned(plan, VolumeRole::Functional, ready)
    }

    fn performance_volume_owned(&self, plan: &Plan, ready: bool) -> Result<bool, String> {
        self.volume_role_owned(plan, VolumeRole::Performance, ready)
    }

    fn ca_volume_owned(&self, plan: &Plan, ready: bool) -> Result<bool, String> {
        self.volume_role_owned(plan, VolumeRole::Ca, ready)
    }

    fn volume_role_owned(
        &self,
        plan: &Plan,
        role: VolumeRole,
        ready: bool,
    ) -> Result<bool, String> {
        let volume = plan.volume_name(role);
        let mut args = vec![
            "volume",
            "show",
            "-vserver",
            &plan.svm,
            "-volume",
            volume,
            "-comment",
            &plan.owner_comment,
        ];
        if ready {
            args.extend([
                "-aggregate",
                &plan.aggregate,
                "-state",
                "online",
                "-security-style",
                role.security_style(),
                "-junction-path",
                plan.junction(role),
            ]);
        }
        args.extend(["-fields", "volume"]);
        self.run(&args)
            .map(|output| has_exact_token(&output, volume))
    }

    fn share_owned(&self, plan: &Plan, role: ShareRole, ready: bool) -> Result<bool, String> {
        let share = plan.share_name(role);
        let mut args = vec![
            "vserver",
            "cifs",
            "share",
            "show",
            "-vserver",
            &plan.svm,
            "-share-name",
            share,
            "-comment",
            &plan.owner_comment,
        ];
        if ready {
            args.extend(["-path", plan.junction(role.volume_role())]);
        }
        args.extend([
            "-fields",
            if ready {
                "share-name,share-properties"
            } else {
                "share-name"
            },
        ]);
        let share_output = self.run(&args)?;
        let share_matches = has_exact_token(&share_output, share);
        if !ready || !share_matches {
            return Ok(share_matches);
        }
        let required_properties = ["oplocks", "browsable", "changenotify"];
        if required_properties
            .into_iter()
            .any(|property| !has_list_item(&share_output, property))
            || (role != ShareRole::Ca && !has_list_item(&share_output, "show-previous-versions"))
            || (role == ShareRole::Ca && !has_list_item(&share_output, "continuously-available"))
            || (matches!(role, ShareRole::Encrypted | ShareRole::PerformanceEncrypted)
                && !has_list_item(&share_output, "encrypt-data"))
            || (matches!(role, ShareRole::Plain | ShareRole::PerformancePlain)
                && has_list_item(&share_output, "encrypt-data"))
        {
            return Ok(false);
        }

        let granted = self.run(&[
            "vserver",
            "cifs",
            "share",
            "access-control",
            "show",
            "-vserver",
            &plan.svm,
            "-share",
            share,
            "-user-or-group",
            self.test_identity.as_str(),
            "-permission",
            "Full_Control",
        ])?;
        let everyone = self.run(&[
            "vserver",
            "cifs",
            "share",
            "access-control",
            "show",
            "-vserver",
            &plan.svm,
            "-share",
            share,
            "-user-or-group",
            "Everyone",
        ])?;
        Ok(has_exact_token(&granted, self.test_identity.as_str())
            && !has_exact_token(&everyone, "Everyone"))
    }

    fn snapshot_owned(&self, plan: &Plan) -> Result<bool, String> {
        let output = self.run(&[
            "volume",
            "snapshot",
            "show",
            "-vserver",
            &plan.svm,
            "-volume",
            &plan.volume,
            "-snapshot",
            &plan.snapshot,
            "-comment",
            &plan.owner_comment,
            "-fields",
            "snapshot",
        ])?;
        Ok(has_exact_token(&output, &plan.snapshot))
    }
}

impl OntapAdapter for SshOntapAdapter {
    fn create_volume(&mut self, plan: &Plan, role: VolumeRole) -> Result<(), String> {
        let mut args = vec![
            "volume",
            "create",
            "-vserver",
            &plan.svm,
            "-volume",
            plan.volume_name(role),
            "-aggregate",
            &plan.aggregate,
            "-size",
            role.size(),
            "-security-style",
            role.security_style(),
        ];
        if role != VolumeRole::Ca {
            args.extend(["-unix-permissions", "0770"]);
        }
        args.extend([
            "-junction-path",
            plan.junction(role),
            "-comment",
            &plan.owner_comment,
            "-autosize-mode",
            "off",
            "-space-guarantee",
            "none",
            "-snapshot-policy",
            "none",
        ]);
        self.run(&args).map(drop)
    }

    fn create_share(&mut self, plan: &Plan, role: ShareRole) -> Result<(), String> {
        self.run(&[
            "vserver",
            "cifs",
            "share",
            "create",
            "-vserver",
            &plan.svm,
            "-share-name",
            plan.share_name(role),
            "-path",
            plan.junction(role.volume_role()),
            "-share-properties",
            role.properties(),
            "-comment",
            &plan.owner_comment,
        ])
        .map(drop)
    }

    fn remove_everyone_acl(&mut self, plan: &Plan, role: ShareRole) -> Result<(), String> {
        self.run(&[
            "vserver",
            "cifs",
            "share",
            "access-control",
            "delete",
            "-vserver",
            &plan.svm,
            "-share",
            plan.share_name(role),
            "-user-or-group",
            "Everyone",
        ])
        .map(drop)
    }

    fn grant_test_acl(&mut self, plan: &Plan, role: ShareRole) -> Result<(), String> {
        let share = plan.share_name(role);
        self.run(&[
            "vserver",
            "cifs",
            "share",
            "access-control",
            "create",
            "-vserver",
            &plan.svm,
            "-share",
            share,
            "-user-or-group",
            self.test_identity.as_str(),
            "-permission",
            "Full_Control",
        ])
        .map(drop)
    }

    fn verify_ready(&mut self, plan: &Plan, kind: ResourceKind) -> Result<bool, String> {
        match kind {
            ResourceKind::Volume => self.volume_owned(plan, true),
            ResourceKind::PlainShare => self.share_owned(plan, ShareRole::Plain, true),
            ResourceKind::EncryptedShare => self.share_owned(plan, ShareRole::Encrypted, true),
            ResourceKind::PerformanceVolume => self.performance_volume_owned(plan, true),
            ResourceKind::PerformancePlainShare => {
                self.share_owned(plan, ShareRole::PerformancePlain, true)
            }
            ResourceKind::PerformanceEncryptedShare => {
                self.share_owned(plan, ShareRole::PerformanceEncrypted, true)
            }
            ResourceKind::Snapshot => self.snapshot_owned(plan),
            ResourceKind::CaVolume => self.ca_volume_owned(plan, true),
            ResourceKind::CaShare => self.share_owned(plan, ShareRole::Ca, true),
        }
    }

    fn verify_owned(&mut self, plan: &Plan, kind: ResourceKind) -> Result<bool, String> {
        match kind {
            ResourceKind::Volume => self.volume_owned(plan, false),
            ResourceKind::PlainShare => self.share_owned(plan, ShareRole::Plain, false),
            ResourceKind::EncryptedShare => self.share_owned(plan, ShareRole::Encrypted, false),
            ResourceKind::PerformanceVolume => self.performance_volume_owned(plan, false),
            ResourceKind::PerformancePlainShare => {
                self.share_owned(plan, ShareRole::PerformancePlain, false)
            }
            ResourceKind::PerformanceEncryptedShare => {
                self.share_owned(plan, ShareRole::PerformanceEncrypted, false)
            }
            ResourceKind::Snapshot => self.snapshot_owned(plan),
            ResourceKind::CaVolume => self.ca_volume_owned(plan, false),
            ResourceKind::CaShare => self.share_owned(plan, ShareRole::Ca, false),
        }
    }

    fn delete_share(&mut self, plan: &Plan, role: ShareRole) -> Result<(), String> {
        self.run(&[
            "vserver",
            "cifs",
            "share",
            "delete",
            "-vserver",
            &plan.svm,
            "-share-name",
            plan.share_name(role),
        ])
        .map(drop)
    }

    fn unmount_volume(&mut self, plan: &Plan, role: VolumeRole) -> Result<(), String> {
        self.run(&[
            "volume",
            "unmount",
            "-vserver",
            &plan.svm,
            "-volume",
            plan.volume_name(role),
        ])
        .map(drop)
    }

    fn offline_volume(&mut self, plan: &Plan, role: VolumeRole) -> Result<(), String> {
        self.run(&[
            "volume",
            "offline",
            "-vserver",
            &plan.svm,
            "-volume",
            plan.volume_name(role),
            "-foreground",
            "true",
        ])
        .map(drop)
    }

    fn delete_volume(&mut self, plan: &Plan, role: VolumeRole) -> Result<(), String> {
        self.run(&[
            "volume",
            "delete",
            &plan.svm,
            "-volume",
            plan.volume_name(role),
            "-foreground",
            "true",
        ])
        .map(drop)
    }
    fn create_snapshot(&mut self, plan: &Plan) -> Result<(), String> {
        self.run(&[
            "volume",
            "snapshot",
            "create",
            "-vserver",
            &plan.svm,
            "-volume",
            &plan.volume,
            "-snapshot",
            &plan.snapshot,
            "-comment",
            &plan.owner_comment,
        ])
        .map(drop)
    }

    fn delete_snapshot(&mut self, plan: &Plan) -> Result<(), String> {
        self.run(&[
            "volume",
            "snapshot",
            "delete",
            "-vserver",
            &plan.svm,
            "-volume",
            &plan.volume,
            "-snapshot",
            &plan.snapshot,
            "-foreground",
            "true",
        ])
        .map(drop)
    }
}

fn ontap_token(value: &str) -> Result<String, String> {
    if !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'-' | b'.' | b'/' | b'\\' | b':' | b'@' | b',' | b'<' | b'>'
                )
        })
    {
        Ok(value.to_owned())
    } else {
        Err("ONTAP command contains a non-whitelisted token".into())
    }
}

fn decode_output(output: Output) -> Result<String, String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let empty_query = stdout.contains("There are no entries matching your query.");
    if (!output.status.success() && !empty_query)
        || stdout.lines().any(is_cli_error)
        || stderr.lines().any(is_cli_error)
    {
        return Err(format!(
            "management command failed with status {}",
            output.status
        ));
    }
    Ok(stdout.into_owned())
}

fn is_cli_error(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("Error:") || line.starts_with("command failed:")
}

fn has_exact_token(output: &str, expected: &str) -> bool {
    output
        .split_ascii_whitespace()
        .any(|token| token == expected)
}

fn has_list_item(output: &str, expected: &str) -> bool {
    output
        .split_ascii_whitespace()
        .flat_map(|token| token.split(','))
        .any(|item| item == expected)
}

fn normalize_preflight(outputs: &[&str]) -> String {
    outputs
        .iter()
        .flat_map(|output| output.lines())
        .map(|line| line.trim_matches(char::is_control).trim())
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("Last login time:")
                && !line.starts_with("Unsuccessful login attempts since last login:")
        })
        .flat_map(str::split_ascii_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_tokens_reject_whitespace_and_metacharacters() {
        assert_eq!(ontap_token("DOMAIN\\user").unwrap(), "DOMAIN\\user");
        assert_eq!(
            ontap_token("oplocks,browsable").unwrap(),
            "oplocks,browsable"
        );
        assert!(ontap_token("a b").is_err());
        assert!(ontap_token("a;$c").is_err());
        assert!(ontap_token("a'b").is_err());
    }

    #[test]
    fn exact_token_matching_does_not_accept_prefixes() {
        assert!(has_exact_token(
            "svm name comment\nsvm exact owned",
            "exact"
        ));
        assert!(!has_exact_token("svm exact-suffix owned", "exact"));
    }

    #[test]
    fn share_properties_are_matched_as_exact_list_items() {
        let output = "share share-properties\nname oplocks,browsable,encrypt-data";
        assert!(has_list_item(output, "encrypt-data"));
        assert!(!has_list_item(output, "encrypt"));
    }

    #[test]
    fn rejects_empty_runtime_secrets() {
        assert!(SshOntapAdapter::new("", "admin", "identity", "secret").is_err());
        assert!(SshOntapAdapter::new("target", "", "identity", "secret").is_err());
        assert!(SshOntapAdapter::new("target", "admin", "", "secret").is_err());
        assert!(SshOntapAdapter::new("target", "admin", "identity", "").is_err());
    }

    #[test]
    fn preflight_hash_input_ignores_dynamic_login_banner() {
        let first = "Last login time: 8/29/2026 09:00:00\nNetApp Release stable\n";
        let second = "Last login time: 8/29/2026 09:01:00\nNetApp Release stable\n";
        assert_eq!(
            normalize_preflight(&[first]),
            normalize_preflight(&[second])
        );
        assert_eq!(normalize_preflight(&[first]), "NetApp Release stable");
    }
}
