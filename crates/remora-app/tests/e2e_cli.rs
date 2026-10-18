//! End to end through the real binaries (phase3-criteria §7b step "host /
//! viewer CLI"): F1, A16, A19, A22 and the INV11 indicator. Each test
//! spawns `remora-host` and `remora-viewer` on 127.0.0.1 and talks to them
//! through stdin/stdout. Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use rand_core::RngCore;

/// Builds both apps once (they are other packages' binaries, so cargo does
/// not build them for this test on its own) and returns their paths.
fn bins() -> &'static (PathBuf, PathBuf) {
    static BINS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
    static BUILD: Mutex<()> = Mutex::new(());
    BINS.get_or_init(|| {
        let _guard = BUILD.lock().unwrap();
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let status = Command::new(cargo)
            .args([
                "build",
                "-p",
                "remora-host",
                "-p",
                "remora-viewer",
                "--bins",
            ])
            .status()
            .unwrap();
        assert!(status.success(), "building the apps failed");
        // target/<profile>/deps/<this test> -> target/<profile>/
        let dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let exe = |n: &str| dir.join(format!("{n}{}", std::env::consts::EXE_SUFFIX));
        (exe("remora-host"), exe("remora-viewer"))
    })
}

fn tmp_dir() -> PathBuf {
    let mut r = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut r);
    let d = std::env::temp_dir().join(format!("remora-e2e-{}", u64::from_le_bytes(r)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A running app: its stdout lines arrive on a channel.
struct App {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl App {
    fn spawn(exe: &Path, args: &[&str]) -> App {
        let mut child = Command::new(exe)
            .args(args)
            .env("RUST_LOG", "warn")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take();
        App {
            child,
            stdin,
            lines: rx,
            seen: Vec::new(),
        }
    }

    /// The first new line starting with `prefix` (≤ `secs`), or panic with
    /// everything seen so far.
    fn expect(&mut self, prefix: &str, secs: u64) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(l) => {
                    self.seen.push(l.clone());
                    if l.starts_with(prefix) {
                        return l;
                    }
                }
                Err(_) => panic!(
                    "no line starting with {prefix:?} within {secs} s; saw:\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    /// Whether a line starting with `prefix` arrives within `ms`.
    fn sees_within(&mut self, prefix: &str, ms: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_millis(ms);
        while let Ok(l) = self
            .lines
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
        {
            self.seen.push(l.clone());
            if l.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    fn wait_exit(&mut self, secs: u64) -> i32 {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "did not exit within {secs} s; saw:\n{}",
                self.seen.join("\n")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn value(line: &str) -> String {
    line.split_once(": ")
        .map(|(_, v)| v.trim().to_owned())
        .unwrap()
}

/// A host started with a fresh identity file: (app, code, password, identity hex, short code).
struct Host {
    app: App,
    code: String,
    password: String,
    identity: String,
    device: String,
}

fn start_host(dir: &Path, extra: &[&str]) -> Host {
    let key = dir.join("host.key");
    let mut args = vec![
        "serve",
        "--identity-file",
        key.to_str().unwrap(),
        "--name",
        "e2e host",
    ];
    args.extend_from_slice(extra);
    let mut app = App::spawn(&bins().0, &args);
    let device = value(&app.expect("device:", 10));
    let identity = value(&app.expect("identity:", 10));
    let _ = app.expect("listening:", 10);
    let code = value(&app.expect("code:", 10));
    let password = value(&app.expect("password:", 10));
    Host {
        app,
        code,
        password,
        identity,
        device,
    }
}

fn viewer_identity(dir: &Path) -> (String, String) {
    let key = dir.join("viewer.key");
    let mut app = App::spawn(
        &bins().1,
        &["identity", "--identity-file", key.to_str().unwrap()],
    );
    let identity = value(&app.expect("identity:", 10));
    let device = value(&app.expect("device:", 10));
    assert_eq!(app.wait_exit(10), 0);
    (identity, device)
}

fn connect_viewer(dir: &Path, code: &str, extra: &[&str]) -> App {
    let key = dir.join("viewer.key");
    let mut args = vec![
        "connect",
        code,
        "--identity-file",
        key.to_str().unwrap(),
        "--name",
        "e2e viewer",
    ];
    args.extend_from_slice(extra);
    App::spawn(&bins().1, &args)
}

/// `prompt <id>: ... safety code 123 456 ...` -> (id, "123 456")
fn parse_prompt(line: &str) -> (String, String) {
    let id = line
        .trim_start_matches("prompt ")
        .split(':')
        .next()
        .unwrap()
        .to_owned();
    let sas = line.split("safety code ").nth(1).unwrap()[..7].to_owned();
    (id, sas)
}

// ------------------------------------------------------------------- F1 --

#[test]
fn f1_password_mode_accept_makes_both_active_with_the_same_code() {
    let dir = tmp_dir();
    let mut host = start_host(&dir, &[]);
    let mut viewer = connect_viewer(&dir, &host.code, &["--password", &host.password]);
    let (id, host_sas) = parse_prompt(&host.app.expect("prompt ", 15));
    let viewer_sas = value(&viewer.expect("safety code:", 15));
    assert_eq!(
        &viewer_sas[..7],
        host_sas,
        "both screens show the same code"
    );
    host.app.send(&format!("accept {id}"));
    // INV11: the host prints the indicator for the whole session.
    host.app.expect(&format!("SESSION ACTIVE {id}"), 10);
    viewer.expect("SESSION ACTIVE", 10);
    host.app.send(&format!("disconnect {id}"));
    host.app.expect(&format!("session ended {id}"), 10);
    assert_eq!(viewer.wait_exit(10), 0);
}

#[test]
fn f1_deny_rejects_and_the_viewer_exits_2() {
    let dir = tmp_dir();
    let mut host = start_host(&dir, &[]);
    let mut viewer = connect_viewer(&dir, &host.code, &["--password", &host.password]);
    let (id, _) = parse_prompt(&host.app.expect("prompt ", 15));
    host.app.send(&format!("deny {id}"));
    viewer.expect("rejected", 10);
    assert_eq!(viewer.wait_exit(10), 2);
    assert!(
        !host
            .app
            .seen
            .iter()
            .any(|l| l.starts_with("SESSION ACTIVE"))
    );
}

#[test]
fn f1_trusted_mode_with_pinned_keys() {
    let dir = tmp_dir();
    let (viewer_key, _) = viewer_identity(&dir);
    let mut host = start_host(&dir, &["--trust", &viewer_key]);
    let mut viewer = connect_viewer(&dir, &host.code, &["--pin", &host.identity]);
    let (id, host_sas) = parse_prompt(&host.app.expect("prompt ", 15));
    let viewer_sas = value(&viewer.expect("safety code:", 15));
    assert_eq!(&viewer_sas[..7], host_sas);
    host.app.send(&format!("accept {id}"));
    viewer.expect("SESSION ACTIVE", 10);
}

#[test]
fn wrong_password_fails_with_auth_exit_code() {
    let dir = tmp_dir();
    let host = start_host(&dir, &[]);
    let wrong = format!(
        "{:06}",
        (host.password.parse::<u32>().unwrap() + 1) % 1_000_000
    );
    let mut viewer = connect_viewer(&dir, &host.code, &["--password", &wrong]);
    viewer.expect("failed:", 15);
    assert_eq!(viewer.wait_exit(10), 4);
}

// ------------------------------------------------------------------ A16 --

#[test]
fn a16_viewer_asking_for_device_x_refuses_a_code_for_device_y() {
    let dir = tmp_dir();
    let mut host = start_host(&dir, &[]);
    // The device the user asked for is some other machine.
    let other = tmp_dir();
    let (_, other_device) = viewer_identity(&other);
    let mut viewer = connect_viewer(
        &dir,
        &host.code,
        &["--password", &host.password, "--device", &other_device],
    );
    viewer.expect("identity mismatch", 15);
    assert_eq!(viewer.wait_exit(10), 3);
    assert!(
        !viewer.seen.iter().any(|l| l.starts_with("safety code")),
        "no SAS shown"
    );
    assert!(
        !host.app.sees_within("prompt ", 1000),
        "never reaches the host's prompt"
    );
}

#[test]
fn a16_the_right_device_code_is_accepted() {
    let dir = tmp_dir();
    let mut host = start_host(&dir, &[]);
    let device = host.device.clone();
    let mut viewer = connect_viewer(
        &dir,
        &host.code,
        &["--password", &host.password, "--device", &device],
    );
    host.app.expect("prompt ", 15);
    viewer.expect("safety code:", 15);
}

// ------------------------------------------------------------------ A19 --

#[test]
fn a19_pinned_host_whose_key_changed_is_a_hard_failure() {
    let dir = tmp_dir();
    let (viewer_key, _) = viewer_identity(&dir);
    let old = start_host(&dir, &["--trust", &viewer_key]);
    let old_identity = old.identity.clone();
    drop(old);
    // The host's key file is replaced (reinstall, or an impostor).
    std::fs::remove_file(dir.join("host.key")).unwrap();
    let host = start_host(&dir, &["--trust", &viewer_key]);
    assert_ne!(host.identity, old_identity);
    let mut viewer = connect_viewer(&dir, &host.code, &["--pin", &old_identity]);
    let line = viewer.expect("this device's identity changed", 15);
    assert!(!line.is_empty());
    assert_eq!(viewer.wait_exit(10), 3);
    assert!(!viewer.seen.iter().any(|l| l.starts_with("safety code")));
    assert!(
        !viewer.seen.iter().any(|l| l.contains("password")),
        "never falls back to a password"
    );
}

// ------------------------------------------------------------------ A22 --

/// Two viewers pending on one host; returns (host, [(viewer, id)] x 2).
fn two_pending() -> (Host, Vec<(App, String)>) {
    let dir = tmp_dir();
    let mut host = start_host(&dir, &[]);
    let mut a = connect_viewer(&dir, &host.code, &["--password", &host.password]);
    let (id_a, _) = parse_prompt(&host.app.expect("prompt ", 15));
    a.expect("safety code:", 15);
    // The host printed a fresh code and password for the next connection.
    let code_b = value(&host.app.expect("code:", 10));
    let password_b = value(&host.app.expect("password:", 10));
    let dir_b = tmp_dir();
    let mut b = connect_viewer(&dir_b, &code_b, &["--password", &password_b]);
    let (id_b, _) = parse_prompt(&host.app.expect("prompt ", 15));
    b.expect("safety code:", 15);
    assert_ne!(id_a, id_b);
    (host, vec![(a, id_a), (b, id_b)])
}

#[test]
fn a22_two_pending_sessions_accepting_one_activates_only_it() {
    // Chosen ADVERSARIALLY: once the session with the smaller id, once the
    // larger. A bug that approves by order (largest / smallest / first /
    // last) instead of by the id typed is then caught every time; with
    // random ids a single fixed choice would let such a bug pass whenever
    // its pick happened to coincide (found by planting exactly that bug).
    for pick_larger in [false, true] {
        let (mut host, mut viewers) = two_pending();
        let larger = usize::from(
            viewers[1].1.parse::<u64>().unwrap() > viewers[0].1.parse::<u64>().unwrap(),
        );
        let chosen = if pick_larger { larger } else { 1 - larger };
        let other = 1 - chosen;
        let chosen_id = viewers[chosen].1.clone();
        let other_id = viewers[other].1.clone();
        host.app.send(&format!("accept {chosen_id}"));
        host.app.expect(&format!("SESSION ACTIVE {chosen_id}"), 10);
        viewers[chosen].0.expect("SESSION ACTIVE", 10);
        assert!(
            !viewers[other].0.sees_within("SESSION ACTIVE", 1500),
            "the other session must stay pending"
        );
        assert!(
            !host
                .app
                .seen
                .iter()
                .any(|l| l.starts_with(&format!("SESSION ACTIVE {other_id}")))
        );
    }
}

#[test]
fn unknown_command_or_session_id_changes_nothing() {
    let dir = tmp_dir();
    let mut host = start_host(&dir, &[]);
    let mut viewer = connect_viewer(&dir, &host.code, &["--password", &host.password]);
    let (id, _) = parse_prompt(&host.app.expect("prompt ", 15));
    host.app.send("accept 999999");
    host.app.expect("no pending session 999999", 10);
    host.app.send("launch-rockets");
    host.app.expect("unknown command", 10);
    assert!(!viewer.sees_within("SESSION ACTIVE", 1000));
    host.app.send(&format!("accept {id}"));
    viewer.expect("SESSION ACTIVE", 10);
}
