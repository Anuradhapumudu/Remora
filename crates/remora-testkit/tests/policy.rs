//! Runs the policy scanner over the real workspace (A31, A35). Fails the build
//! if any rule is broken anywhere.

use std::path::Path;

#[test]
fn workspace_obeys_unsafe_dependency_and_boundary_policies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let violations = remora_testkit::policy::check_workspace(&root);
    assert!(
        violations.is_empty(),
        "policy violations:\n{}",
        violations
            .iter()
            .map(|v| format!("  [{}] {}:{}  {}", v.rule, v.path, v.line, v.text))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
