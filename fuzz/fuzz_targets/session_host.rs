//! Arbitrary frame / datagram / tick sequences into one host session: the
//! state machine never panics, never delivers an application message and
//! never reaches Active without an approval (none is given here).
#![no_main]
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use rand_core::OsRng;
use remora_crypto::identity::IdentityKeypair;
use remora_crypto::noise::NoiseStaticKeypair;
use remora_crypto::secret::Exporter;
use remora_session::{Host, HostAction, HostConfig, Identity, Millis, State};

fuzz_target!(|data: &[u8]| {
    let key = IdentityKeypair::generate(&mut OsRng);
    let noise = NoiseStaticKeypair::generate(&mut OsRng);
    let Ok(cert) = key.sign_cert(noise.public(), "fuzz host", 1) else {
        return;
    };
    let config = HostConfig {
        identity: Arc::new(Identity { noise, cert }),
        password_enabled: true,
        trusted: vec![key.public()],
    };
    let mut host = Host::new(config, &mut OsRng);
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let Ok(id) = host.accept_connection(ip, Exporter::from_bytes([1; 32]), Millis(0), &mut OsRng) else {
        return;
    };
    // data = sequence of (op, len_hi, len_lo, bytes…)
    let mut rest = data;
    let mut now = 0u64;
    while let [op, hi, lo, tail @ ..] = rest {
        let len = (usize::from(*hi) << 8 | usize::from(*lo)).min(tail.len());
        let (chunk, next) = tail.split_at(len);
        rest = next;
        let acts = match op % 3 {
            0 => host.on_frame(id, chunk, Millis(now), &mut OsRng),
            1 => host.on_datagram(id, chunk),
            _ => {
                now += u64::from(*hi) * 1000;
                host.tick(Millis(now))
            }
        };
        for a in &acts {
            assert!(!matches!(a, HostAction::Deliver { .. } | HostAction::Active { .. }));
        }
        assert_ne!(host.state(id), Some(State::Active));
    }
});
