//! Remora signaling server and STUN responder. Never sees keys, passwords or video.
//!
//! Pre-alpha skeleton: prints its version and exits.

#![forbid(unsafe_code)]

fn main() {
    println!(
        "{} {} (pre-alpha skeleton, nothing to run yet)",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
}
