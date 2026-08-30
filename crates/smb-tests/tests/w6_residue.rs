use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("smb-tests lives under workspace/crates")
        .to_owned()
}

fn read(relative: &str) -> String {
    fs::read_to_string(workspace_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

#[test]
fn legacy_public_spine_and_temporary_adapter_cannot_return() {
    let lib = read("crates/smb/src/lib.rs");
    for declaration in [
        "pub mod client;",
        "pub mod command;",
        "pub mod connection;",
        "pub mod resource;",
        "pub mod session;",
        "pub mod tree;",
    ] {
        assert!(
            !lib.contains(declaration),
            "legacy API returned: {declaration}"
        );
    }

    for path in [
        "crates/smb/src/runtime/domain_bridge.rs",
        "crates/smb/src/connection/worker.rs",
        "crates/smb/src/connection/worker/runtime_worker.rs",
        "docs/architecture/current-architecture-audit.md",
    ] {
        assert!(
            !workspace_root().join(path).exists(),
            "residue returned: {path}"
        );
    }
}

#[test]
fn activation_ledger_is_at_w6_without_temporary_adapters() {
    let rules: serde_json::Value =
        serde_json::from_str(&read("docs/architecture/dependency-rules.json"))
            .expect("dependency rules remain valid JSON");
    assert_eq!(rules["current_wave"], "W6");
    assert_eq!(
        rules["temporary_adapters"].as_array().map(Vec::len),
        Some(0)
    );
}

#[test]
fn removed_dead_features_cannot_return() {
    let smb_manifest = read("crates/smb/Cargo.toml");
    for feature in [
        "test-multichannel",
        "test-quic",
        "test-rdma",
        "quic =",
        "rdma =",
        "std-fs-impls",
        "test-ndr64",
        "__debug-dump-keys",
    ] {
        assert!(
            !smb_manifest.contains(feature),
            "dead feature returned: {feature}"
        );
    }

    let default_features = smb_manifest
        .lines()
        .find(|line| line.starts_with("default ="))
        .expect("smb default feature declaration exists");
    assert!(
        !default_features.contains("compress"),
        "compression returned to the default FAS-oriented build"
    );

    let cli_manifest = read("smb-cli/Cargo.toml");
    for feature in ["profiling =", "quic =", "rdma =", "netbios-transport ="] {
        assert!(
            !cli_manifest.contains(feature),
            "dead CLI feature returned: {feature}"
        );
    }

    for path in [
        "crates/smb-transport/src/quic.rs",
        "crates/smb-transport/src/quic",
        "crates/smb-transport/src/rdma.rs",
        "crates/smb-transport/src/rdma",
        "crates/smb-transport/README.rdma.md",
    ] {
        assert!(
            !workspace_root().join(path).exists(),
            "dead transport returned: {path}"
        );
    }
}

#[test]
fn post_acceptance_internal_residue_cannot_return() {
    for path in [
        "crates/smb/src/resource/file_util.rs",
        "crates/smb/src/runtime/session_recovery.rs",
        "crates/smb/src/runtime/share_recovery.rs",
        "crates/smb/src/runtime/durable_recovery.rs",
        "crates/smb/src/runtime/event_authority.rs",
        "crates/smb/src/tree/dfs_tree.rs",
        "crates/smb/src/tree/ipc_tree.rs",
    ] {
        assert!(
            !workspace_root().join(path).exists(),
            "obsolete internal layer returned: {path}"
        );
    }

    let wire = read("crates/smb/src/runtime/wire.rs");
    assert!(
        !wire.contains("compatibility branch") && !wire.contains("legacy `encrypt: bool`"),
        "wire protection compatibility fallback returned"
    );
    assert!(
        wire.contains("wire protection policy is not sealed"),
        "wire seam must reject unsealed protection policy"
    );
}

#[test]
fn drop_implementations_cannot_spawn_unowned_cleanup_tasks() {
    for path in [
        "crates/smb/src/connection.rs",
        "crates/smb/src/session.rs",
        "crates/smb/src/tree.rs",
        "crates/smb/src/resource.rs",
    ] {
        let source = read(path);
        let syntax =
            syn::parse_file(&source).unwrap_or_else(|error| panic!("parse {path}: {error}"));
        for item in syntax.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            let is_drop = item
                .trait_
                .as_ref()
                .and_then(|(_, path, _)| path.segments.last())
                .is_some_and(|segment| segment.ident == "Drop");
            if is_drop {
                let rendered = quote::quote!(#item).to_string();
                assert!(
                    !rendered.contains("tokio ::") && !rendered.contains("spawn"),
                    "Drop must not start unowned async cleanup in {path}"
                );
            }
        }
    }
}
