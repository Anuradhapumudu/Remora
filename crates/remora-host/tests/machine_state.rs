//! `remora-host machine-state` prints the lines `scripts/macos/measuring.py`
//! parses (R9, phase4.5-criteria §15). If the format changes, the helper would
//! silently read "unknown"; this test fails first.
#![cfg(target_os = "macos")]

use std::process::Command;

#[test]
fn machine_state_prints_the_lines_the_measuring_helper_parses() {
    let out = Command::new(env!("CARGO_BIN_EXE_remora-host"))
        .args(["machine-state", "--when", "start"])
        .output()
        .expect("run remora-host");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("utf-8");
    let lines: Vec<&str> = text.lines().collect();
    let thermal = lines[0]
        .strip_prefix("machine state (start): thermal state ")
        .expect("first line");
    assert!(
        ["nominal", "fair", "serious", "critical"].contains(&thermal),
        "thermal state {thermal:?}"
    );
    assert!(lines[1].starts_with("  power: "), "{:?}", lines[1]);
    assert!(lines[1].contains(" | low power mode: "), "{:?}", lines[1]);
    assert!(
        lines[2].starts_with("  thermal/performance: "),
        "{:?}",
        lines[2]
    );
    assert!(lines[3].starts_with("  load averages: "), "{:?}", lines[3]);
}
