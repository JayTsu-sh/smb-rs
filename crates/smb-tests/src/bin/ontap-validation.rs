use rand::RngCore;
use smb_tests::ontap::{ApplyAuthorization, Plan, ProvisioningRun, RunManifest, SshOntapAdapter};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run() {
        eprintln!("validation command failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next().ok_or_else(usage)?;
    let options = parse_options(arguments)?;
    let manifest_path = PathBuf::from(required(&options, "--manifest")?);
    let target = read_secret_fd(required_fd(&options, "--target-fd")?)?;
    let management_user = read_secret_fd(required_fd(&options, "--management-user-fd")?)?;
    let test_identity = read_secret_fd(required_fd(&options, "--test-identity-fd")?)?;
    let password_fd = required_fd(&options, "--management-password-fd")?;
    let management_password = read_secret_fd(password_fd)?;
    let mut adapter = SshOntapAdapter::new(
        target.as_str(),
        management_user.as_str(),
        test_identity.as_str(),
        management_password.as_str(),
    )?;

    match mode.as_str() {
        "plan" => {
            let run_id = random_run_id();
            let plan = Plan::new(
                &run_id,
                required(&options, "--svm")?,
                required(&options, "--aggregate")?,
                test_identity.as_str(),
            )?;
            let preflight = adapter.preflight(&plan)?;
            let plan = plan.bind_preflight(&preflight.state_hash)?;
            let manifest = RunManifest::create(&manifest_path, plan)?;
            println!("dry-run plan hash: {}", manifest.plan().hash());
            println!("ONTAP capability: {}", preflight.ontap_version);
            println!("{}", manifest.plan().render_redacted());
            println!("No appliance resources were changed.");
        }
        "apply" => {
            let manifest = RunManifest::load(&manifest_path)?;
            ensure_identity(&manifest, test_identity.as_str())?;
            let supplied_hash = required(&options, "--apply")?;
            let authorization = ApplyAuthorization::new(manifest.plan(), supplied_hash)?;
            let preflight = adapter.preflight(manifest.plan())?;
            if manifest.plan().preflight_state_hash() != Some(preflight.state_hash.as_str()) {
                return Err("preflight drift invalidated the plan".into());
            }
            ProvisioningRun::new(manifest, &mut adapter).apply(&authorization)?;
            println!("isolated functional resources are Ready");
        }
        "cleanup" => {
            let manifest = RunManifest::load(&manifest_path)?;
            ensure_identity(&manifest, test_identity.as_str())?;
            let supplied_hash = required(&options, "--apply")?;
            ApplyAuthorization::new(manifest.plan(), supplied_hash)?;
            let expected_state_hash = manifest
                .plan()
                .preflight_state_hash()
                .ok_or_else(|| "manifest has no preflight state binding".to_string())?
                .to_owned();
            let cleaned = ProvisioningRun::new(manifest, &mut adapter).cleanup()?;
            let final_preflight = adapter.preflight(cleaned.plan())?;
            if final_preflight.state_hash != expected_state_hash {
                return Err("cleanup completed but pre-existing state hash changed".into());
            }
            println!("manifest-owned resources are cleaned");
        }
        _ => return Err(usage()),
    }
    Ok(())
}

fn ensure_identity(manifest: &RunManifest, identity: &str) -> Result<(), String> {
    if manifest.plan().matches_test_identity(identity) {
        Ok(())
    } else {
        Err("test identity does not match the plan binding".into())
    }
}

fn parse_options(
    arguments: impl Iterator<Item = String>,
) -> Result<BTreeMap<String, String>, String> {
    let values = arguments.collect::<Vec<_>>();
    if values.len() % 2 != 0 {
        return Err(usage());
    }
    let mut options = BTreeMap::new();
    for pair in values.chunks_exact(2) {
        if !pair[0].starts_with("--") || options.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err("options must be unique --name value pairs".into());
        }
    }
    Ok(options)
}

fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn required_fd(options: &BTreeMap<String, String>, name: &str) -> Result<i32, String> {
    let fd = required(options, name)?
        .parse::<i32>()
        .map_err(|_| format!("{name} must be a descriptor number"))?;
    if fd < 3 {
        return Err(format!("{name} must be at least 3"));
    }
    Ok(fd)
}

fn read_secret_fd(fd: i32) -> Result<Zeroizing<String>, String> {
    let value = fs::read_to_string(format!("/proc/self/fd/{fd}"))
        .map_err(|error| format!("read secret descriptor {fd}: {error}"))?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(format!("secret descriptor {fd} is empty or invalid"));
    }
    Ok(Zeroizing::new(value))
}

fn random_run_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn usage() -> String {
    "usage: ontap-validation <plan|apply|cleanup> --manifest PATH --target-fd N --management-user-fd N --test-identity-fd N --management-password-fd N [--svm NAME --aggregate NAME] [--apply PLAN_HASH]".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_parser_rejects_duplicates_and_dangling_values() {
        assert!(
            parse_options(["--a".into(), "1".into(), "--a".into(), "2".into()].into_iter())
                .is_err()
        );
        assert!(parse_options(["--a".into()].into_iter()).is_err());
    }

    #[test]
    fn generated_run_id_is_exactly_128_bit_lowercase_hex() {
        let run_id = random_run_id();
        assert_eq!(run_id.len(), 32);
        assert!(
            run_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}
