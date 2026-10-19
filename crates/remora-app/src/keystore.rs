//! Device keys on disk (Phase 3; replaced by the OS keychain before v0.1).
//!
//! * Created **once**, never overwritten (`create_new`), with mode 0600 on
//!   Unix (owner read/write only).
//! * Refused on load if group or others have any permission on Unix — a
//!   key file someone else can read is treated as compromised, not fixed
//!   silently.
//! * Size checked before reading: anything but the exact encoded length is
//!   refused without reading it.
//! * On Windows the file lives in the user's profile (`%APPDATA%`), whose
//!   ACL is per-user by default; the permission check is Unix-only and that
//!   gap is listed in the roadmap.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use remora_crypto::identity::DEVICE_KEYS_LEN;
use zeroize::Zeroizing;

use remora_crypto::identity::{DeviceKeys, DeviceKeysError};

/// Which app the keys belong to (separate files, separate identities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `remora-host`.
    Host,
    /// `remora-viewer`.
    Viewer,
}

/// Why the key file could not be used.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// Reading or writing failed.
    #[error("key file: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not exactly the encoded length.
    #[error("key file has the wrong size ({0} bytes)")]
    WrongSize(u64),
    /// Group or others have permissions on it (Unix).
    #[error("key file is accessible by other users (mode {0:o}); refusing to use it")]
    Permissions(u32),
    /// The file grew between the size check and the read.
    #[error("key file changed while it was being read")]
    ChangedWhileReading,
    /// Not a valid key file.
    #[error("key file: {0}")]
    Format(#[from] DeviceKeysError),
    /// No home / config directory could be determined.
    #[error("cannot determine the configuration directory")]
    NoConfigDir,
}

/// The default key file: `<config dir>/Remora/<role>-identity.key`, where
/// the config dir is `~/Library/Application Support` (macOS),
/// `$XDG_CONFIG_HOME` or `~/.config` (Linux), `%APPDATA%` (Windows).
pub fn default_path(role: Role) -> Result<PathBuf, KeyStoreError> {
    let file = match role {
        Role::Host => "host-identity.key",
        Role::Viewer => "viewer-identity.key",
    };
    let dir =
        config_dir_for(Os::current(), |k| std::env::var_os(k)).ok_or(KeyStoreError::NoConfigDir)?;
    Ok(dir.join("Remora").join(file))
}

/// Operating-system families with different config-directory conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// `~/Library/Application Support`.
    MacOs,
    /// `%APPDATA%`.
    Windows,
    /// `$XDG_CONFIG_HOME`, else `~/.config`.
    OtherUnix,
}

impl Os {
    /// The OS this binary was built for.
    pub fn current() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(windows) {
            Os::Windows
        } else {
            Os::OtherUnix
        }
    }
}

/// The per-user configuration directory for `os`, from the environment
/// (`env` looks a variable up). Pure, so every OS's rule is tested on any
/// machine. Empty or relative values are ignored: a key file must never
/// land relative to the current directory.
pub fn config_dir_for(os: Os, env: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<PathBuf> {
    let get = |name: &str| env(name).map(PathBuf::from).filter(|p| p.is_absolute());
    match os {
        Os::MacOs => get("HOME").map(|h| h.join("Library").join("Application Support")),
        Os::Windows => get("APPDATA"),
        Os::OtherUnix => get("XDG_CONFIG_HOME").or_else(|| get("HOME").map(|h| h.join(".config"))),
    }
}

/// Loads the keys at `path`, creating them first if the file does not
/// exist. Returns the keys and whether they were just created.
///
/// Creation is exclusive (`create_new`): if the file exists - or another
/// process creates it at the same moment - the existing file is loaded and
/// never replaced.
pub fn load_or_create(path: &Path) -> Result<(DeviceKeys, bool), KeyStoreError> {
    if let Some(dir) = path.parent() {
        create_private_dir(dir)?;
    }
    match create_owner_only(path) {
        Ok(mut f) => {
            let keys = DeviceKeys::generate(&mut rand_core::OsRng);
            f.write_all(&keys.encode())?;
            f.sync_all()?;
            Ok((keys, true))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok((load(path)?, false)),
        Err(e) => Err(e.into()),
    }
}

/// Opens a new file for writing, owner-only (0600) on Unix; fails if it
/// already exists.
fn create_owner_only(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Creates the key directory (0700 on Unix) if missing.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Loads existing keys (permissions and size checked first).
pub fn load(path: &Path) -> Result<DeviceKeys, KeyStoreError> {
    let meta = fs::metadata(path)?;
    check_permissions(&meta)?;
    if meta.len() != DEVICE_KEYS_LEN as u64 {
        return Err(KeyStoreError::WrongSize(meta.len()));
    }
    let mut file = File::open(path)?;
    let mut buf = Zeroizing::new([0u8; DEVICE_KEYS_LEN]);
    file.read_exact(&mut buf[..])?;
    // The file may have grown since the size check: refuse, do not read on.
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(KeyStoreError::ChangedWhileReading);
    }
    Ok(DeviceKeys::decode(&buf[..])?)
}

#[cfg(unix)]
fn check_permissions(meta: &fs::Metadata) -> Result<(), KeyStoreError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(KeyStoreError::Permissions(mode & 0o777));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_meta: &fs::Metadata) -> Result<(), KeyStoreError> {
    Ok(())
}
