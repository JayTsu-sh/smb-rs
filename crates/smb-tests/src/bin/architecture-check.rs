use smb_tests::architecture::check_workspace;
use std::path::PathBuf;

fn main() {
    let workspace_root = std::env::current_dir().unwrap_or_else(|error| {
        eprintln!("architecture-check: current directory unavailable: {error}");
        std::process::exit(2);
    });
    let rules_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("docs/architecture/dependency-rules.json"));
    let report = check_workspace(&workspace_root, &rules_path).unwrap_or_else(|error| {
        eprintln!("architecture-check: {error}");
        std::process::exit(2);
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("architecture report is serializable")
    );
    if !report.passed() {
        std::process::exit(1);
    }
}
