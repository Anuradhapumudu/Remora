//! phase4.7-criteria CU2 / C5 with real mDNS on this machine's network.
//! Ignored in CI (runners often block multicast). Run:
//!     REMORA_MDNS_IP=<this machine's LAN address> cargo test -p remora-net \
//!         --test cu2_discovery -- --ignored
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use std::time::{Duration, Instant};

use rand_core::OsRng;
use remora_crypto::identity::{DeviceId, IdentityKeypair};
use remora_net::discovery::{Announcement, Announcer, find};

fn ip() -> std::net::IpAddr {
    std::env::var("REMORA_MDNS_IP")
        .expect("set REMORA_MDNS_IP to this machine's LAN address")
        .parse()
        .expect("an IP address")
}

#[test]
#[ignore = "needs a network that passes mDNS"]
fn cu2_a_host_is_found_by_its_code_and_c5_not_after_it_withdraws() {
    let id = DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public());
    let a = Announcement {
        id,
        nonce: [9; 16],
        port: 40001,
    };
    let mut ann = Announcer::new(ip()).expect("announcer");
    ann.announce(&a).expect("announce");
    std::thread::sleep(Duration::from_secs(3)); // the host is up before anyone looks
    let t = Instant::now();
    let (addrs, got) = find(&id.short_code(), Duration::from_secs(5))
        .expect("browse")
        .expect("found by its code");
    eprintln!("found in {:?} at {addrs:?}", t.elapsed());
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "CU2: {:?}",
        t.elapsed()
    );
    assert_eq!(got, a);
    assert!(addrs.contains(&ip()));
    // C5: withdrawn means not found any more.
    ann.withdraw();
    std::thread::sleep(Duration::from_secs(2));
    let gone = find(&id.short_code(), Duration::from_secs(3)).expect("browse");
    assert!(gone.is_none(), "still announced after withdraw: {gone:?}");
}
