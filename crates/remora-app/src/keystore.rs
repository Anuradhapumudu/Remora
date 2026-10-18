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

use std::path::{Path, PathBuf};

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
    let _ = role;
    todo!()
}

/// Loads the keys at `path`, creating them first if the file does not
/// exist. Returns the keys and whether they were just created.
pub fn load_or_create(path: &Path) -> Result<(DeviceKeys, bool), KeyStoreError> {
    let _ = path;
    todo!()
}

/// Loads existing keys (permissions and size checked first).
pub fn load(path: &Path) -> Result<DeviceKeys, KeyStoreError> {
    let _ = path;
    todo!()
}
