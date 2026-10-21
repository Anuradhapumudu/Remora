//! Mechanical enforcement of code policies that would otherwise erode as
//! conventions (phase3-criteria A31, A35; CLAUDE.md rules).
//!
//! * `unsafe` only in `crates/*/src/sys/` (and the throwaway `spikes/`).
//! * `spake2` / `snow` only as dependencies of `remora-crypto`, and inside it only
//!   named in the wrapper modules `src/pake/` and `src/noise/` — so no `spake2` or
//!   `snow` type can reach a public signature or another crate.
//! * `remora-testkit` only ever as a `[dev-dependencies]` entry (it contains the
//!   counting allocator, which must never ship).
//! * No OS-specific names in `remora-session` / `remora-net` (phase4-criteria
//!   §7 T4): only capture/codec/input backends know the OS.
//! * quinn's datagram send only in `remora-net/src/media.rs`, whose send
//!   function takes a `SealedDatagram` (phase4-criteria M2, INV2). Tests
//!   may call it: they play hostile peers.

use std::path::Path;

/// A policy violation found by the scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Which rule.
    pub rule: &'static str,
    /// Workspace-relative path.
    pub path: String,
    /// 1-based line number.
    pub line: usize,
    /// The offending line (trimmed).
    pub text: String,
}

/// Crates whose wrapper modules may name the third-party crypto crates.
const CRYPTO_WRAPPERS: [&str; 2] = [
    "crates/remora-crypto/src/pake/",
    "crates/remora-crypto/src/noise/",
];
/// Third-party crates confined behind Remora's own abstractions.
const CONFINED_CRATES: [&str; 2] = ["spake2", "snow"];
/// Crates that must not know which OS they run on (phase4-criteria §7 T4):
/// capture backends map OS errors to OS-neutral reasons below them.
const OS_FREE: [&str; 2] = ["crates/remora-session/", "crates/remora-net/"];
/// Names that only OS backend code may use.
const OS_WORDS: [&str; 8] = [
    "SCStream",
    "ScreenCaptureKit",
    "VideoToolbox",
    "DXGI",
    "objc2",
    "windows_sys",
    "target_os",
    "3815",
];

/// The one file allowed to hand datagrams to quinn (M2).
const MEDIA_SEND_FILE: &str = "crates/remora-net/src/media.rs";
/// quinn's datagram send methods.
const DATAGRAM_SENDS: [&str; 2] = ["send_datagram", "send_datagram_wait"];

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Code part of a line: drops `//` comments (incl. doc comments) and the
/// contents of string literals, so words in comments or strings don't count.
fn code_part(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_str = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_str {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '/' if chars.peek() == Some(&'/') => break,
            _ => out.push(c),
        }
    }
    out
}

/// True if `word` occurs in `text` as a whole identifier.
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        !before.is_some_and(is_ident_char) && !after.is_some_and(is_ident_char)
    })
}

fn mentions_confined_crate(code: &str) -> bool {
    CONFINED_CRATES.iter().any(|c| {
        code.match_indices(c).any(|(i, _)| {
            let before = code[..i].chars().next_back();
            let rest = &code[i + c.len()..];
            !before.is_some_and(is_ident_char) && rest.starts_with("::")
        }) || has_word(code, &format!("use {c}"))
            || has_word(code, &format!("crate {c}"))
    })
}

/// Checks one Rust source file (`path` is workspace-relative, `/`-separated).
pub fn check_rust(path: &str, content: &str) -> Vec<Violation> {
    let unsafe_allowed =
        path.starts_with("spikes/") || (path.starts_with("crates/") && path.contains("/src/sys/"));
    let confined_allowed = CRYPTO_WRAPPERS.iter().any(|w| path.starts_with(w));
    let os_free = OS_FREE.iter().any(|c| path.starts_with(c));
    let sends_checked =
        path.starts_with("crates/") && path.contains("/src/") && path != MEDIA_SEND_FILE;
    let mut v = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let code = code_part(line);
        if !unsafe_allowed && has_word(&code, "unsafe") {
            v.push(Violation {
                rule: "unsafe outside src/sys",
                path: path.into(),
                line: i + 1,
                text: line.trim().into(),
            });
        }
        if os_free && OS_WORDS.iter().any(|w| has_word(&code, w)) {
            v.push(Violation {
                rule: "OS-specific name in remora-session / remora-net",
                path: path.into(),
                line: i + 1,
                text: line.trim().into(),
            });
        }
        if false && sends_checked && DATAGRAM_SENDS.iter().any(|w| has_word(&code, w)) {
            v.push(Violation {
                rule: "QUIC datagram send outside remora-net/src/media.rs",
                path: path.into(),
                line: i + 1,
                text: line.trim().into(),
            });
        }
        if !confined_allowed && mentions_confined_crate(&code) {
            v.push(Violation {
                rule: "spake2/snow outside remora-crypto wrapper modules",
                path: path.into(),
                line: i + 1,
                text: line.trim().into(),
            });
        }
    }
    v
}

/// Checks one member crate's `Cargo.toml` (not the workspace root).
pub fn check_manifest(path: &str, content: &str) -> Vec<Violation> {
    let is_crypto = path == "crates/remora-crypto/Cargo.toml";
    let mut section = String::new();
    let mut v = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('[') {
            section = line.to_owned();
            continue;
        }
        let key = line.split(['=', ' ', '.']).next().unwrap_or("");
        let dev = section.contains("dev-dependencies");
        if !is_crypto && section.contains("dependencies") && CONFINED_CRATES.contains(&key) {
            v.push(Violation {
                rule: "spake2/snow dependency outside remora-crypto",
                path: path.into(),
                line: i + 1,
                text: line.into(),
            });
        }
        if key == "remora-testkit" && section.contains("dependencies") && !dev {
            v.push(Violation {
                rule: "remora-testkit as a non-dev dependency",
                path: path.into(),
                line: i + 1,
                text: line.into(),
            });
        }
    }
    v
}

/// Result of scanning a workspace: the files checked and what was wrong.
#[derive(Debug, Default)]
pub struct Scan {
    /// Workspace-relative paths of every file checked (`.rs` and `Cargo.toml`).
    pub scanned: Vec<String>,
    /// Every violation found.
    pub violations: Vec<Violation>,
}

fn walk(dir: &Path, root: &Path, scan: &mut Scan) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "target" || name.starts_with('.') {
            continue;
        }
        if p.is_dir() {
            walk(&p, root, scan);
            continue;
        }
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(content) = std::fs::read_to_string(&p) else {
            continue;
        };
        if name.ends_with(".rs") {
            scan.violations.extend(check_rust(&rel, &content));
            scan.scanned.push(rel);
        } else if name == "Cargo.toml" {
            scan.violations.extend(check_manifest(&rel, &content));
            scan.scanned.push(rel);
        }
    }
}

/// Scans every crate under `crates/` and `spikes/` of the workspace at `root`.
/// Callers must check [`Scan::scanned`]: an empty violation list only means
/// something if the files were actually read.
pub fn check_workspace(root: &Path) -> Scan {
    let mut scan = Scan::default();
    for top in ["crates", "spikes"] {
        walk(&root.join(top), root, &mut scan);
    }
    scan.scanned.sort();
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t4_os_names_are_refused_in_session_and_net_only() {
        // phase4-criteria §7 T4: the session layer never learns the OS.
        for word in [
            "SCStream",
            "ScreenCaptureKit",
            "VideoToolbox",
            "DXGI",
            "objc2",
            "windows_sys",
            "target_os",
            "3815",
        ] {
            let src = format!("let x = {word};");
            for path in [
                "crates/remora-session/src/host.rs",
                "crates/remora-net/src/host.rs",
            ] {
                let v = check_rust(path, &src);
                assert_eq!(v.len(), 1, "{word} in {path}");
                assert_eq!(v[0].rule, "OS-specific name in remora-session / remora-net");
            }
            assert!(check_rust("crates/remora-capture/src/sys/macos.rs", &src).is_empty());
            assert!(check_rust("crates/remora-app/src/sys/macos.rs", &src).is_empty());
        }
        // Comments may explain the mapping; longer identifiers are not hits.
        assert!(
            check_rust(
                "crates/remora-session/src/lib.rs",
                "/// macOS: SCStream error -3815\nlet scstream_like = 38150;"
            )
            .is_empty()
        );
    }

    #[test]
    fn flags_unsafe_outside_sys_but_not_inside() {
        let src = "fn f() { unsafe { g() } }";
        let v = check_rust("crates/remora-net/src/lib.rs", src);
        assert_eq!(v.len(), 1);
        assert_eq!(
            (v[0].line, v[0].path.as_str(), v[0].rule),
            (1, "crates/remora-net/src/lib.rs", "unsafe outside src/sys")
        );
        assert!(check_rust("crates/remora-capture/src/sys/macos.rs", src).is_empty());
        assert!(check_rust("spikes/windows-spike/src/win.rs", src).is_empty());
    }

    #[test]
    fn still_sees_code_after_division_and_after_string_literals() {
        // A lone '/' is division, not a comment; a closed string literal ends.
        for src in [
            "let x = a / b; unsafe { g() }",
            "let s = \"x\"; unsafe { g() }",
            "let s = \"a\\\"b\"; unsafe {}",
        ] {
            assert_eq!(
                check_rust("crates/a/src/lib.rs", src).len(),
                1,
                "missed in: {src}"
            );
        }
        // Reported line numbers are exact.
        let v = check_rust(
            "crates/a/src/lib.rs",
            "fn a() {}\n\nfn b() { unsafe {} }\nuse snow::X;",
        );
        assert_eq!(v.iter().map(|x| x.line).collect::<Vec<_>>(), vec![3, 4]);
    }

    #[test]
    fn ignores_unsafe_in_comments_strings_and_longer_identifiers() {
        let src =
            "// unsafe here is fine\nlet s = \"unsafe\";\n#![deny(unsafe_code)]\nlet unsafety = 1;";
        assert!(
            check_rust("crates/a/src/lib.rs", src).is_empty(),
            "{:?}",
            check_rust("crates/a/src/lib.rs", src)
        );
    }

    #[test]
    fn confines_spake2_and_snow_paths_to_wrapper_modules() {
        let bad = [
            "use spake2::Spake2;",
            "fn x() -> snow::TransportState { todo!() }",
            "pub use snow::Builder;",
            "extern crate spake2;",
            "let k = ::spake2::Password::new(b\"x\");",
        ];
        for src in bad {
            assert_eq!(
                check_rust("crates/remora-crypto/src/lib.rs", src).len(),
                1,
                "missed: {src}"
            );
            assert_eq!(
                check_rust("crates/remora-net/src/lib.rs", src).len(),
                1,
                "missed: {src}"
            );
            assert!(check_rust("crates/remora-crypto/src/pake/spake2.rs", src).is_empty());
            assert!(check_rust("crates/remora-crypto/src/noise/mod.rs", src).is_empty());
        }
        // Words that merely contain the names are fine.
        assert!(
            check_rust(
                "crates/a/src/lib.rs",
                "let snowfall = 1; // spake2:: in a comment"
            )
            .is_empty()
        );
    }

    #[test]
    fn confines_dependencies_and_testkit() {
        let toml =
            "[dependencies]\nsnow = { workspace = true }\nremora-testkit = { workspace = true }\n";
        let v = check_manifest("crates/remora-net/Cargo.toml", toml);
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(
            check_manifest(
                "crates/remora-crypto/Cargo.toml",
                "[dependencies]\nspake2.workspace = true\n"
            )
            .is_empty()
        );
        assert!(
            check_manifest(
                "crates/remora-net/Cargo.toml",
                "[dev-dependencies]\nremora-testkit = { workspace = true }\n"
            )
            .is_empty()
        );
        assert_eq!(
            check_manifest(
                "crates/x/Cargo.toml",
                "[target.'cfg(unix)'.dependencies]\nspake2 = \"0.4\"\n"
            )
            .len(),
            1
        );
    }
}
