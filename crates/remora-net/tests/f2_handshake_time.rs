//! phase3-criteria F2 (information only): handshake time on loopback over
//! real QUIC, p50/p95 over 100 runs - from `connect()` until the viewer
//! shows the safety code (the full handshake, before the human prompt).
//! The internet budget is set in Phase 5; nothing is asserted beyond
//! every run completing.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use remora_net::{ViewerEvent, connect};

#[tokio::test(flavor = "multi_thread")]
async fn f2_handshake_time_on_loopback() {
    let (h, v) = (device("host"), device("viewer"));
    let mut ms = Vec::new();
    for _ in 0..100 {
        // A fresh host each time: the password is one-time (INV15) and the
        // per-IP limit allows 10 connections a minute.
        let host = start_host(&h, vec![]).await;
        let nonce = host.server.issue_nonce(Duration::from_secs(300));
        let started = tokio::time::Instant::now();
        let (_c, mut ev) = connect(
            host.addr,
            viewer_cfg(&v, password(&host.server.otp())),
            nonce,
        )
        .await
        .unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), ev.recv())
                .await
                .unwrap()
            {
                Some(ViewerEvent::ShowSas { .. }) => break,
                Some(_) => continue,
                None => panic!("connection ended before the SAS"),
            }
        }
        ms.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    ms.sort_by(|a, b| a.total_cmp(b));
    let p = |q: f64| ms[((ms.len() as f64 - 1.0) * q).round() as usize];
    eprintln!(
        "F2 handshake (connect -> SAS shown), n=100: p50 {:.2} ms, p95 {:.2} ms, max {:.2} ms",
        p(0.5),
        p(0.95),
        ms[ms.len() - 1]
    );
}
