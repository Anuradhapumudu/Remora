//! Remora viewer: views and controls a remote Remora host.
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
