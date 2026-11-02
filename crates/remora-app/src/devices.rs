//! Remembered devices (phase4.7-criteria C6, C8): the viewer's saved
//! computers and the host's known viewers, one owner-only file each.
//!
//! * **What a remembered entry means.** On the viewer: "I connect to this
//!   key without a password, and refuse it if the key changes" (C1). On the
//!   host: "this viewer may connect without a password; I still approve
//!   every connection" (C2, C3). Public keys are not secret, but who talks
//!   to whom is private, so the files get the key file's protection: created
//!   0600 in a 0700 folder, refused if anyone else can read them.
//! * **Format** (plain text, one device per line, written by us only):
//!
//!   ```text
//!   remora-devices 1
//!   <identity key, 64 hex> <last address or -> <name as hex of its UTF-8>
//!   ```
//!
//!   The name is stored as hex so no character in it can break a line.
//!   It is untrusted text (the device chose it). It is kept raw and must be
//!   shown through `remora_proto::display_text::display_name` (H6, C8).
//! * **Limits, checked before anything is kept:** the file is at most
//!   [`MAX_FILE`] bytes, [`MAX_DEVICES`] entries, names [`MAX_NAME`] bytes;
//!   a key appears once.

use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;

use remora_crypto::identity::{IdentityPublic, ShortCode};

/// First line of every file.
const HEADER: &str = "remora-devices 1";
/// Largest file read (256 entries × ~260 bytes fit with room to spare).
pub const MAX_FILE: usize = 96 * 1024;
/// Most devices kept in one list.
pub const MAX_DEVICES: usize = 256;
/// Longest name kept, bytes (the certificate's limit).
pub const MAX_NAME: usize = 64;

/// One remembered device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Its identity key: what it must present to match this entry.
    pub key: IdentityPublic,
    /// Its name as it gave it (untrusted; escape when shown).
    pub name: String,
    /// Where it was last reached (viewer's list only).
    pub addr: Option<SocketAddr>,
}

impl Device {
    /// Its device code (what a person reads and types).
    pub fn code(&self) -> ShortCode {
        remora_crypto::identity::DeviceId::of(&self.key).short_code()
    }
}

/// Why a device list was refused.
#[derive(Debug, thiserror::Error)]
pub enum DevicesError {
    /// Reading or writing failed.
    #[error("device list: {0}")]
    Io(#[from] std::io::Error),
    /// Group or others can read it (Unix).
    #[error("device list is accessible by other users (mode {0:o}); refusing to use it")]
    Permissions(u32),
    /// Larger than [`MAX_FILE`].
    #[error("device list is too large")]
    TooLarge,
    /// Not a device list, or a malformed line.
    #[error("device list: line {0} is not valid")]
    Format(usize),
    /// More than [`MAX_DEVICES`] entries.
    #[error("device list holds more than {MAX_DEVICES} devices")]
    TooMany,
    /// The same key twice.
    #[error("device list: a device is listed twice (line {0})")]
    Duplicate(usize),
    /// A name longer than [`MAX_NAME`] bytes.
    #[error("device name longer than {MAX_NAME} bytes")]
    NameTooLong,
}

/// A list of remembered devices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceList {
    devices: Vec<Device>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl DeviceList {
    /// No devices.
    pub fn new() -> Self {
        Self::default()
    }

    /// The devices, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter()
    }

    /// How many.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// None at all.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// The entry for `key`.
    pub fn get(&self, key: &IdentityPublic) -> Option<&Device> {
        self.devices.iter().find(|d| d.key == *key)
    }

    /// The entry whose device code is `code`.
    pub fn find_code(&self, code: &ShortCode) -> Option<&Device> {
        self.devices.iter().find(|d| d.code() == *code)
    }

    /// Adds `device`, or updates the entry with the same key (name, address).
    pub fn remember(&mut self, device: Device) -> Result<(), DevicesError> {
        if device.name.len() > MAX_NAME {
            return Err(DevicesError::NameTooLong);
        }
        if let Some(d) = self.devices.iter_mut().find(|d| d.key == device.key) {
            *d = device;
            return Ok(());
        }
        if self.devices.len() >= MAX_DEVICES {
            return Err(DevicesError::TooMany);
        }
        self.devices.push(device);
        Ok(())
    }

    /// Removes the entry for `key`; whether there was one.
    pub fn forget(&mut self, key: &IdentityPublic) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.key != *key);
        self.devices.len() != before
    }

    /// Parses a file's text (all limits checked; fuzzed: `device_list`).
    pub fn parse(text: &str) -> Result<Self, DevicesError> {
        if text.len() > MAX_FILE {
            return Err(DevicesError::TooLarge);
        }
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(DevicesError::Format(1));
        }
        let mut list = Self::new();
        for (i, line) in lines.enumerate() {
            let n = i + 2;
            if line.is_empty() {
                continue;
            }
            let mut f = line.split(' ');
            let (Some(key), Some(addr), Some(name), None) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                return Err(DevicesError::Format(n));
            };
            let key = crate::cli::parse_identity(key).map_err(|_| DevicesError::Format(n))?;
            let addr = match addr {
                "-" => None,
                a => Some(a.parse().map_err(|_| DevicesError::Format(n))?),
            };
            let name = unhex(name)
                .filter(|b| b.len() <= MAX_NAME)
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or(DevicesError::Format(n))?;
            if list.get(&key).is_some() {
                return Err(DevicesError::Duplicate(n));
            }
            if list.devices.len() >= MAX_DEVICES {
                return Err(DevicesError::TooMany);
            }
            list.devices.push(Device { key, name, addr });
        }
        Ok(list)
    }

    /// The file's text.
    pub fn render(&self) -> String {
        let mut s = format!("{HEADER}\n");
        for d in &self.devices {
            let addr = d.addr.map_or_else(|| "-".to_owned(), |a| a.to_string());
            s.push_str(&format!(
                "{} {addr} {}\n",
                crate::cli::identity_hex(&d.key),
                hex(d.name.as_bytes())
            ));
        }
        s
    }

    /// Loads `path`; a missing file is an empty list. Refused if others
    /// can read it, or if it is too large (checked before reading).
    pub fn load(path: &Path) -> Result<Self, DevicesError> {
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => return Err(e.into()),
        };
        check_permissions(&meta)?;
        if meta.len() > MAX_FILE as u64 {
            return Err(DevicesError::TooLarge);
        }
        let mut text = String::new();
        fs::File::open(path)?
            .take(MAX_FILE as u64 + 1)
            .read_to_string(&mut text)
            .map_err(|_| DevicesError::Format(0))?;
        Self::parse(&text)
    }

    /// Writes the list to `path` (0600, folder 0700): a new file is written
    /// next to it and renamed over it, so a crash never leaves half a list.
    pub fn save(&self, path: &Path) -> Result<(), DevicesError> {
        if let Some(dir) = path.parent() {
            let mut b = fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir)?;
        }
        let tmp = path.with_extension("new");
        let _ = fs::remove_file(&tmp);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(self.render().as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(unix)]
fn check_permissions(meta: &fs::Metadata) -> Result<(), DevicesError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(DevicesError::Permissions(mode & 0o777));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_meta: &fs::Metadata) -> Result<(), DevicesError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use remora_crypto::identity::IdentityKeypair;

    use super::*;

    fn device(name: &str) -> Device {
        Device {
            key: IdentityKeypair::generate(&mut OsRng).public(),
            name: name.into(),
            addr: Some("192.168.8.100:46248".parse().expect("addr")),
        }
    }

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("remora-devices-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_list_round_trips_through_its_file_text() {
        let mut l = DeviceList::new();
        l.remember(device("Fedora laptop")).expect("add");
        // Hostile name: spaces, newline, control and bidi characters.
        l.remember(device("evil\nname \u{202e}x\u{0}"))
            .expect("add");
        let mut no_addr = device("viewer");
        no_addr.addr = None;
        l.remember(no_addr).expect("add");
        assert_eq!(DeviceList::parse(&l.render()).expect("parse"), l);
        assert_eq!(
            l.render().lines().count(),
            4,
            "the newline in a name cannot add a line"
        );
    }

    #[test]
    fn remember_updates_by_key_and_forget_removes() {
        let mut l = DeviceList::new();
        let mut d = device("old name");
        l.remember(d.clone()).expect("add");
        d.name = "new name".into();
        l.remember(d.clone()).expect("update");
        assert_eq!(l.len(), 1);
        assert_eq!(l.get(&d.key).map(|x| x.name.as_str()), Some("new name"));
        assert_eq!(l.find_code(&d.code()).map(|x| x.key), Some(d.key));
        assert!(l.forget(&d.key));
        assert!(!l.forget(&d.key), "already gone");
        assert!(l.is_empty());
    }

    #[test]
    fn c6_limits_and_malformed_lines_are_refused() {
        let good = device("x");
        let line = |k: &str, a: &str, n: &str| format!("{HEADER}\n{k} {a} {n}\n");
        let key = crate::cli::identity_hex(&good.key);
        assert!(DeviceList::parse(&line(&key, "-", "78")).is_ok());
        for bad in [
            "not a device list\n".to_owned(),
            line(&key, "-", "7"),              // odd hex
            line(&key, "-", "zz"),             // not hex
            line(&key, "nowhere", "78"),       // not an address
            line(&key[..63], "-", "78"),       // short key
            line(&key, "-", "ff"),             // not UTF-8
            line(&key, "-", &"78".repeat(65)), // name too long
            format!("{HEADER}\n{key} - 78 extra\n"),
        ] {
            assert!(DeviceList::parse(&bad).is_err(), "{bad:?}");
        }
        let twice = format!("{HEADER}\n{key} - 78\n{key} - 79\n");
        assert!(matches!(
            DeviceList::parse(&twice),
            Err(DevicesError::Duplicate(3))
        ));
        assert!(matches!(
            DeviceList::parse(&"x".repeat(MAX_FILE + 1)),
            Err(DevicesError::TooLarge)
        ));
        let mut l = DeviceList::new();
        for _ in 0..MAX_DEVICES {
            l.remember(device("d")).expect("room");
        }
        assert!(matches!(
            l.remember(device("d")),
            Err(DevicesError::TooMany)
        ));
        assert!(matches!(
            DeviceList::new().remember(device(&"n".repeat(MAX_NAME + 1))),
            Err(DevicesError::NameTooLong)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn c6_the_file_is_owner_only_and_refused_when_others_can_read_it() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("mode");
        let path = d.join("saved-devices");
        assert_eq!(
            DeviceList::load(&path).expect("missing = empty"),
            DeviceList::new()
        );
        let mut l = DeviceList::new();
        l.remember(device("Fedora laptop")).expect("add");
        l.save(&path).expect("save");
        let mode = fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "file mode {mode:o}");
        let dmode = fs::metadata(&d).expect("meta").permissions().mode();
        assert_eq!(dmode & 0o777, 0o700, "folder mode {dmode:o}");
        assert_eq!(DeviceList::load(&path).expect("load"), l);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            DeviceList::load(&path),
            Err(DevicesError::Permissions(0o644))
        ));
        let _ = fs::remove_dir_all(d);
    }
}
