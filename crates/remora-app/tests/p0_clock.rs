//! P0 (phase4-criteria §4): host and viewer are two processes; end-to-end
//! latency is only valid if both read the same clock. Measured, not assumed:
//! this test starts ITSELF as a second process and exchanges timestamps over
//! pipes, NTP style (quality.md §2): offset = ((t2 - t1) + (t3 - t4)) / 2,
//! round trip = (t4 - t1) - (t3 - t2). PASS: |offset| <= 50 us and round trip
//! <= 200 us (the best of 1000 rounds), and the median |offset| <= 50 us.
//!
//! What would this still pass with if the property were removed? A child
//! whose clock is shifted: the planted 1 ms skew (REMORA_P0_SKEW_NS, read
//! only by this test's own child) must fail it - see
//! `p0_detects_a_planted_one_millisecond_skew`.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use remora_app::clock::monotonic_ns;

const CHILD: &str = "REMORA_P0_CHILD";
const SKEW: &str = "REMORA_P0_SKEW_NS";
const ROUNDS: usize = 1000;

/// The child side: for every line from the parent, answer with t2 and t3
/// (receive and send times on the child's clock, plus any planted skew).
fn child() {
    let skew: u64 = std::env::var(SKEW)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let stdin = std::io::stdin();
    // Replies go to STDERR with a marker: the test harness writes its own
    // text to stdout (e.g. "test p0_child_entry ... " with no newline, which
    // the first reply would be glued onto).
    let mut out = std::io::stderr().lock();
    for line in stdin.lock().lines() {
        let t2 = monotonic_ns().unwrap() + skew;
        if line.unwrap().is_empty() {
            break;
        }
        let t3 = monotonic_ns().unwrap() + skew;
        writeln!(out, "@@ {t2} {t3}").unwrap();
        out.flush().unwrap();
    }
}

struct Result {
    best_offset_ns: i64,
    best_rtt_ns: i64,
    median_abs_offset_ns: i64,
}

fn measure(skew_ns: u64) -> Result {
    let mut c = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "p0_child_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env(SKEW, skew_ns.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut to = c.stdin.take().unwrap();
    let mut from = BufReader::new(c.stderr.take().unwrap());
    let mut samples = Vec::with_capacity(ROUNDS);
    let mut line = String::new();
    while samples.len() < ROUNDS {
        let t1 = monotonic_ns().unwrap() as i64;
        writeln!(to, "x").unwrap();
        to.flush().unwrap();
        // Only "@@ <t2> <t3>" lines are replies. Anything else is skipped
        // WITHOUT sending again: every request must be paired with its own
        // reply (a first version re-sent here, paired replies with the wrong
        // requests and reported an impossible 166 ns round trip).
        let (t2, t3, t4) = loop {
            line.clear();
            assert!(from.read_line(&mut line).unwrap() > 0, "child exited");
            let t4 = monotonic_ns().unwrap() as i64;
            let Some(rest) = line.trim_end().strip_prefix("@@ ") else {
                continue;
            };
            let mut it = rest.split(' ').map(str::parse::<i64>);
            if let (Some(Ok(t2)), Some(Ok(t3)), None) = (it.next(), it.next(), it.next()) {
                break (t2, t3, t4);
            }
        };
        let offset = ((t2 - t1) + (t3 - t4)) / 2;
        let rtt = (t4 - t1) - (t3 - t2);
        samples.push((rtt, offset));
    }
    writeln!(to).unwrap();
    drop(to);
    let _ = c.wait();
    let &(best_rtt_ns, best_offset_ns) = samples.iter().min_by_key(|s| s.0).unwrap();
    let mut abs: Vec<i64> = samples.iter().map(|s| s.1.abs()).collect();
    abs.sort_unstable();
    Result {
        best_offset_ns,
        best_rtt_ns,
        median_abs_offset_ns: abs[abs.len() / 2],
    }
}

/// A pipe round trip between processes takes microseconds; anything under
/// 1 us means requests and replies were mispaired, so the result is invalid.
fn plausible(r: &Result) -> bool {
    r.best_rtt_ns >= 1_000
}

fn passes(r: &Result) -> bool {
    r.best_offset_ns.abs() <= 50_000 && r.best_rtt_ns <= 200_000 && r.median_abs_offset_ns <= 50_000
}

/// Entry point of the child process (does nothing in a normal test run).
#[test]
fn p0_child_entry() {
    if std::env::var(CHILD).is_ok() {
        child();
    }
}

#[test]
#[cfg(target_os = "macos")]
fn p0_two_processes_read_the_same_clock() {
    let r = measure(0);
    println!(
        "P0: best offset {} ns at round trip {} ns; median |offset| {} ns",
        r.best_offset_ns, r.best_rtt_ns, r.median_abs_offset_ns
    );
    assert!(
        plausible(&r),
        "round trip {} ns is impossible: samples mispaired",
        r.best_rtt_ns
    );
    assert!(passes(&r), "clocks disagree across processes");
}

#[test]
#[cfg(target_os = "macos")]
fn p0_detects_a_planted_one_millisecond_skew() {
    let r = measure(1_000_000);
    println!(
        "P0 plant: best offset {} ns at round trip {} ns",
        r.best_offset_ns, r.best_rtt_ns
    );
    assert!(
        plausible(&r),
        "round trip {} ns is impossible: samples mispaired",
        r.best_rtt_ns
    );
    assert!(!passes(&r), "a 1 ms skew must fail P0");
    assert!(
        (900_000..=1_100_000).contains(&r.best_offset_ns),
        "skew measured as {} ns",
        r.best_offset_ns
    );
}

#[test]
#[cfg(not(target_os = "macos"))]
fn p0_no_backend_yet_says_so() {
    assert_eq!(monotonic_ns(), None);
}
