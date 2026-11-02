//! A short secret kept in an owner-only file: the desktop portal's restore
//! token on Linux (phase4.6-criteria Q5, L8). The token lets the next
//! session share the screen and take control without asking the person at
//! the computer, so it is a capability: created 0600, never logged, and
//! only its length-checked text leaves this module.
//!
//! The file is written here, not in `remora-capture`: crates that handle
//! screen content may not write files at all (remora-testkit's policy
//! scanner enforces it), so no picture can ever reach the disk from them.

use std::io::Write;
use std::path::Path;

/// Longest token accepted from the file (GNOME's are UUIDs, 36 bytes).
pub const MAX_LEN: usize = 256;

/// The token in `path`, if the file holds one plausible token: printable
/// ASCII without spaces, at most [`MAX_LEN`] bytes (checked before it is
/// kept).
pub fn load(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_LEN as u64 + 2 {
        return None;
    }
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    (!s.is_empty() && s.len() <= MAX_LEN && s.bytes().all(|b| b.is_ascii_graphic()))
        .then(|| s.to_owned())
}

/// Replaces the file with `token`, readable by this user only: a new file
/// is created 0600 next to it and renamed over it, so a reader never sees
/// half a token and the old one is never left world-readable.
pub fn save(path: &Path, token: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("new");
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(&tmp)?;
    #[cfg(unix)]
    {
        // The mode above is masked by the umask, which can only remove bits;
        // set it explicitly anyway.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(token.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("remora-token-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[cfg(unix)]
    #[test]
    fn l8_the_token_file_is_owner_only_and_round_trips() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("mode");
        let path = d.join("portal-restore-token");
        save(&path, "secret-capability").expect("save");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "token file mode {mode:o}");
        assert_eq!(load(&path).as_deref(), Some("secret-capability"));
        // Replacing keeps it owner-only.
        save(&path, "newer").expect("save again");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(load(&path).as_deref(), Some("newer"));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn junk_in_the_file_is_not_a_token() {
        let d = dir("junk");
        std::fs::create_dir_all(&d).expect("dir");
        let path = d.join("t");
        for bad in ["", "two words", "tab\there", &"x".repeat(MAX_LEN + 1)] {
            std::fs::write(&path, bad).expect("write");
            assert_eq!(load(&path), None, "{bad:?}");
        }
        assert_eq!(load(&d.join("missing")), None);
        let _ = std::fs::remove_dir_all(d);
    }
}
