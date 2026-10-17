//! The policy scanner is a SECURITY CONTROL (architecture.md D19): the
//! counting-allocator exception is safe only because `remora-testkit` can never
//! be a normal dependency. These tests run it over the real workspace AND over a
//! planted-violation workspace, so a scanner that silently scans nothing fails.

use std::fs;
use std::path::{Path, PathBuf};

use remora_testkit::policy::check_workspace;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn real_workspace_obeys_unsafe_dependency_and_boundary_policies() {
    let scan = check_workspace(&workspace_root());
    // An empty violation list means nothing unless the files were read.
    for must_scan in [
        "crates/remora-capture/src/sys/macos.rs",
        "crates/remora-crypto/Cargo.toml",
        "crates/remora-host/src/main.rs",
        "crates/remora-testkit/src/sys/count_alloc.rs",
        "spikes/windows-spike/src/win.rs",
    ] {
        assert!(
            scan.scanned.iter().any(|p| p == must_scan),
            "scanner did not read {must_scan}"
        );
    }
    assert!(
        scan.scanned.len() >= 30,
        "only {} files scanned",
        scan.scanned.len()
    );
    assert!(
        scan.violations.is_empty(),
        "policy violations:\n{}",
        scan.violations
            .iter()
            .map(|v| format!("  [{}] {}:{}  {}", v.rule, v.path, v.line, v.text))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Builds a throwaway workspace with one violation of every rule, plus the same
/// violations inside `target/` and a hidden folder (which must be skipped).
fn planted_workspace() -> std::io::Result<PathBuf> {
    let root = std::env::temp_dir().join(format!("remora-policy-fixture-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let files: &[(&str, &str)] = &[
        (
            "crates/remora-net/src/lib.rs",
            "fn f() { unsafe {} }\nuse snow::Builder;\n",
        ),
        (
            "crates/remora-net/Cargo.toml",
            "[dependencies]\nspake2 = \"0.4\"\nremora-testkit = { path = \"x\" }\n",
        ),
        (
            "crates/remora-crypto/src/pake/spake2.rs",
            "use spake2::Spake2;\n",
        ), // allowed
        (
            "crates/remora-capture/src/sys/macos.rs",
            "fn g() { unsafe {} }\n",
        ), // allowed
        (
            "crates/remora-net/target/debug/gen.rs",
            "fn h() { unsafe {} }\n",
        ), // skipped
        ("crates/remora-net/.hidden/x.rs", "fn i() { unsafe {} }\n"), // skipped
        ("crates/remora-net/README.md", "unsafe snow:: spake2::\n"),  // not code
    ];
    for (path, content) in files {
        let p = root.join(path);
        if let Some(dir) = p.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(p, content)?;
    }
    Ok(root)
}

#[test]
fn planted_violations_are_all_found_and_nothing_else() {
    let root = planted_workspace().expect("create fixture workspace");
    let scan = check_workspace(&root);
    let mut found: Vec<(String, usize, &str)> = scan
        .violations
        .iter()
        .map(|v| (v.path.clone(), v.line, v.rule))
        .collect();
    found.sort();
    let _ = fs::remove_dir_all(&root);
    assert_eq!(
        found,
        vec![
            (
                "crates/remora-net/Cargo.toml".to_owned(),
                2,
                "spake2/snow dependency outside remora-crypto"
            ),
            (
                "crates/remora-net/Cargo.toml".to_owned(),
                3,
                "remora-testkit as a non-dev dependency"
            ),
            (
                "crates/remora-net/src/lib.rs".to_owned(),
                1,
                "unsafe outside src/sys"
            ),
            (
                "crates/remora-net/src/lib.rs".to_owned(),
                2,
                "spake2/snow outside remora-crypto wrapper modules"
            ),
        ]
    );
    assert!(
        !scan
            .scanned
            .iter()
            .any(|p| p.contains("/target/") || p.contains("/.hidden/")),
        "target/ and hidden folders must be skipped: {:?}",
        scan.scanned
    );
    assert!(
        !scan.scanned.iter().any(|p| p.ends_with(".md")),
        "only .rs and Cargo.toml are code"
    );
}
