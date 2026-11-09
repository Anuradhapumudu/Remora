//! Spike S-C1 (throwaway): announce / find a Remora host by device code
//! on the home network with mdns-sd 0.21.6.
//!
//!   sc1-mdns announce <code> <ip>   announce `_remora._udp` with TXT
//!                                   {code, nonce, v} (no computer name)
//!   sc1-mdns find <code>            browse, print how long until an
//!                                   instance with that code is resolved
//!
//! The instance name is the code itself, the "host name" a fixed
//! `remora-host.local.`, so the computer's name is never announced.

use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

const TYPE: &str = "_remora._udp.local.";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let daemon = ServiceDaemon::new()?;
    match args.get(1).map(String::as_str) {
        Some("announce") => {
            let code = args.get(2).ok_or("code")?;
            let ip = args.get(3).ok_or("ip")?;
            let nonce = format!("{:032x}", rand_u128());
            let props = [("code", code.as_str()), ("nonce", nonce.as_str()), ("v", "1")];
            let info = ServiceInfo::new(TYPE, code, "remora-host.local.", ip.as_str(), 4242, &props[..])?;
            daemon.register(info)?;
            eprintln!("announcing {code} at {ip}:4242 for 120 s (TXT: code, nonce, v)");
            std::thread::sleep(Duration::from_secs(120));
        }
        Some("find") => {
            let want = args.get(2).ok_or("code")?;
            let rx = daemon.browse(TYPE)?;
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(20) {
                let Ok(ev) = rx.recv_timeout(Duration::from_secs(1)) else { continue };
                if let ServiceEvent::ServiceResolved(s) = ev {
                    let code = s.get_property_val_str("code").unwrap_or("?");
                    let nonce = s.get_property_val_str("nonce").map_or(0, str::len);
                    println!(
                        "resolved after {:?}: {} code={code} nonce_len={nonce} addrs={:?} port={}",
                        t.elapsed(),
                        s.get_fullname(),
                        s.get_addresses_v4(),
                        s.get_port()
                    );
                    if code == want {
                        println!("FOUND {want} in {:?}", t.elapsed());
                        break;
                    }
                }
            }
        }
        _ => eprintln!("usage: sc1-mdns announce <code> <ip> | find <code>"),
    }
    let _ = daemon.shutdown();
    Ok(())
}

/// Spike only: a random-enough nonce from the clock and the process id.
fn rand_u128() -> u128 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    t ^ (u128::from(std::process::id()) << 64)
}
