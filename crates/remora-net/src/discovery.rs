//! Finding a host on the home network by its device code (phase4.7-criteria
//! step 5, C4, C5; spike S-C1).
//!
//! * **What the host announces** (mDNS service [`SERVICE`]), and only while
//!   it is ready for a connection:
//!   - the instance name is its short device code;
//!   - TXT `id` is its full 80-bit device ID (the long form the code is
//!     computed from, which every host sends in its hello anyway);
//!   - TXT `nonce` is a fresh single-use connection nonce (replay
//!     protection, not a secret: protocol.md §2);
//!   - `v` is this format's version, plus the port.
//!
//!   **Never the computer's name**: the mDNS host name is a fixed
//!   `remora-host.local.` (owner, 2026-11-02).
//! * **What the viewer trusts: nothing it hears.** An answer is parsed with
//!   limits ([`parse`], fuzzed: `mdns_record`). It is used only if its full
//!   ID gives the code the person typed. The viewer then connects
//!   *expecting that full ID*, so the handshake refuses any host whose key
//!   does not hash to it (A16). A short code is an address, not a
//!   credential (`remora_crypto::identity::ShortCode`): the password, the
//!   safety code and the host's Accept are the security.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use remora_crypto::identity::{DEVICE_ID_LEN, DeviceId, ShortCode};

/// The mDNS service type.
pub const SERVICE: &str = "_remora._udp.local.";
/// The fixed mDNS host name (the computer's own name is never announced).
pub const HOST_NAME: &str = "remora-host.local.";
/// This announcement format.
const VERSION: &str = "1";
/// Most TXT entries looked at in one answer.
const MAX_PROPS: usize = 8;
/// Longest TXT value looked at.
const MAX_VALUE: usize = 64;

/// What a host announces, as the viewer reads it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announcement {
    /// The host's full device ID.
    pub id: DeviceId,
    /// A single-use connection nonce.
    pub nonce: [u8; 16],
    /// The port it listens on.
    pub port: u16,
}

/// Why an answer was not used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    /// More entries or longer values than an announcement has.
    #[error("announcement too large")]
    TooLarge,
    /// A field is missing or malformed, or another format version.
    #[error("not a Remora announcement: {0}")]
    Malformed(&'static str),
    /// The instance name is not the code of the announced ID.
    #[error("announced name and device ID disagree")]
    NameMismatch,
    /// The mDNS service failed.
    #[error("home-network discovery: {0}")]
    Mdns(String),
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The instance name for a device ID: its short code without spaces.
pub fn instance_name(id: &DeviceId) -> String {
    id.short_code().to_string().replace(' ', "")
}

/// The TXT entries a host announces.
pub fn txt(a: &Announcement) -> Vec<(String, String)> {
    vec![
        ("v".into(), VERSION.into()),
        ("id".into(), hex(a.id.as_bytes())),
        ("nonce".into(), hex(&a.nonce)),
    ]
}

/// Reads one answer (untrusted): limits first, then each field. The
/// instance name must be the announced ID's code.
pub fn parse(
    instance: &str,
    props: &[(&str, &str)],
    port: u16,
) -> Result<Announcement, DiscoveryError> {
    if props.len() > MAX_PROPS
        || instance.len() > MAX_VALUE
        || props
            .iter()
            .any(|(k, v)| k.len() > MAX_VALUE || v.len() > MAX_VALUE)
    {
        return Err(DiscoveryError::TooLarge);
    }
    let get = |key: &str| props.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    if get("v") != Some(VERSION) {
        return Err(DiscoveryError::Malformed("version"));
    }
    let id = get("id")
        .and_then(unhex::<DEVICE_ID_LEN>)
        .map(DeviceId::from_bytes)
        .ok_or(DiscoveryError::Malformed("id"))?;
    let nonce = get("nonce")
        .and_then(unhex::<16>)
        .ok_or(DiscoveryError::Malformed("nonce"))?;
    if port == 0 {
        return Err(DiscoveryError::Malformed("port"));
    }
    if instance != instance_name(&id) {
        return Err(DiscoveryError::NameMismatch);
    }
    Ok(Announcement { id, nonce, port })
}

/// A host's announcement on the home network; stops when dropped.
pub struct Announcer {
    daemon: mdns_sd::ServiceDaemon,
    ip: IpAddr,
    current: Option<String>,
}

impl std::fmt::Debug for Announcer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Announcer")
            .field("announcing", &self.current.is_some())
            .finish_non_exhaustive()
    }
}

fn mdns(e: impl std::fmt::Display) -> DiscoveryError {
    DiscoveryError::Mdns(e.to_string())
}

impl Announcer {
    /// An announcer for the address `ip` (the one the host listens on).
    /// Announces nothing until [`announce`](Self::announce).
    pub fn new(ip: IpAddr) -> Result<Self, DiscoveryError> {
        Ok(Self {
            daemon: mdns_sd::ServiceDaemon::new().map_err(mdns)?,
            ip,
            current: None,
        })
    }

    /// Announces (or replaces the announcement with) `a`.
    pub fn announce(&mut self, a: &Announcement) -> Result<(), DiscoveryError> {
        self.withdraw();
        let props = txt(a);
        let props: Vec<(&str, &str)> = props
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let info = mdns_sd::ServiceInfo::new(
            SERVICE,
            &instance_name(&a.id),
            HOST_NAME,
            self.ip,
            a.port,
            &props[..],
        )
        .map_err(mdns)?;
        let name = info.get_fullname().to_owned();
        self.daemon.register(info).map_err(mdns)?;
        self.current = Some(name);
        Ok(())
    }

    /// Stops announcing (e.g. while a session is Active, C5).
    pub fn withdraw(&mut self) {
        if let Some(name) = self.current.take() {
            let _ = self.daemon.unregister(&name);
        }
    }

    /// Whether something is being announced.
    pub fn is_announcing(&self) -> bool {
        self.current.is_some()
    }
}

impl Drop for Announcer {
    fn drop(&mut self) {
        self.withdraw();
        let _ = self.daemon.shutdown();
    }
}

/// Looks for the host whose code is `code` for up to `wait`; its addresses
/// and announcement. Answers that do not parse, or are for another code,
/// are ignored.
pub fn find(
    code: &ShortCode,
    wait: Duration,
) -> Result<Option<(Vec<IpAddr>, Announcement)>, DiscoveryError> {
    let daemon = mdns_sd::ServiceDaemon::new().map_err(mdns)?;
    let rx = daemon.browse(SERVICE).map_err(mdns)?;
    let deadline = Instant::now() + wait;
    let mut found = None;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Ok(ev) = rx.recv_timeout(left.min(Duration::from_millis(200))) else {
            continue;
        };
        let mdns_sd::ServiceEvent::ServiceResolved(s) = ev else {
            continue;
        };
        let instance = s
            .get_fullname()
            .strip_suffix(&format!(".{SERVICE}"))
            .unwrap_or_default()
            .to_owned();
        let props: Vec<(String, String)> = s
            .get_properties()
            .iter()
            .take(MAX_PROPS + 1)
            .map(|p| (p.key().to_owned(), p.val_str().to_owned()))
            .collect();
        let props: Vec<(&str, &str)> = props
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let Ok(a) = parse(&instance, &props, s.get_port()) else {
            continue;
        };
        if a.id.short_code() == *code {
            let addrs = s.get_addresses_v4().into_iter().map(IpAddr::V4).collect();
            found = Some((addrs, a));
            break;
        }
    }
    let _ = daemon.shutdown();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use remora_crypto::identity::IdentityKeypair;

    use super::*;

    fn announcement() -> Announcement {
        Announcement {
            id: DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public()),
            nonce: [7; 16],
            port: 46248,
        }
    }

    fn props(t: &[(String, String)]) -> Vec<(&str, &str)> {
        t.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    #[test]
    fn an_announcement_reads_back_and_carries_no_name() {
        let a = announcement();
        let t = txt(&a);
        assert_eq!(parse(&instance_name(&a.id), &props(&t), a.port), Ok(a));
        let keys: Vec<&str> = t.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["v", "id", "nonce"], "nothing else, no name");
    }

    #[test]
    fn c4_malformed_or_oversized_answers_are_refused() {
        let a = announcement();
        let t = txt(&a);
        let name = instance_name(&a.id);
        let p = props(&t);
        let with = |key: &str, val: &str| -> Vec<(String, String)> {
            t.iter()
                .map(|(k, v)| (k.clone(), if k == key { val.into() } else { v.clone() }))
                .collect()
        };
        for (what, bad) in [
            ("version", with("v", "2")),
            ("id short", with("id", "00")),
            ("id not hex", with("id", &"zz".repeat(10))),
            ("nonce short", with("nonce", "00")),
        ] {
            assert!(parse(&name, &props(&bad), a.port).is_err(), "{what}");
        }
        assert_eq!(parse(&name, &p, 0), Err(DiscoveryError::Malformed("port")));
        let many: Vec<(String, String)> = (0..9).map(|i| (format!("k{i}"), "v".into())).collect();
        assert_eq!(
            parse(&name, &props(&many), 1),
            Err(DiscoveryError::TooLarge)
        );
        let long = with("nonce", &"0".repeat(65));
        assert_eq!(
            parse(&name, &props(&long), 1),
            Err(DiscoveryError::TooLarge)
        );
    }

    #[test]
    fn c4_a_name_that_is_not_the_ids_code_is_refused() {
        let (a, other) = (announcement(), announcement());
        let t = txt(&a);
        assert_eq!(
            parse(&instance_name(&other.id), &props(&t), a.port),
            Err(DiscoveryError::NameMismatch)
        );
    }
}
