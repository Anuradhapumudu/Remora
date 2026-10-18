//! Device key file. Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use std::path::PathBuf;

use rand_core::RngCore;
use remora_app::keystore::{KeyStoreError, Role, default_path, load, load_or_create};
use remora_testkit::{CountingAlloc, count_allocations};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// A fresh, unique directory under the system temp dir.
fn tmp_dir() -> PathBuf {
    let mut r = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut r);
    let d = std::env::temp_dir().join(format!("remora-keystore-{}", u64::from_le_bytes(r)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn first_run_creates_then_later_runs_load_the_same_keys() {
    let path = tmp_dir().join("Remora").join("host-identity.key");
    let (a, created) = load_or_create(&path).unwrap();
    assert!(created);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 72);
    let (b, created) = load_or_create(&path).unwrap();
    assert!(!created, "an existing file is loaded, never replaced");
    assert_eq!(a.identity.public(), b.identity.public());
    assert_eq!(a.noise.public(), b.noise.public());
    assert_eq!(load(&path).unwrap().identity.public(), a.identity.public());
}

#[cfg(unix)]
#[test]
fn the_file_is_created_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let path = tmp_dir().join("k.key");
    load_or_create(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[test]
fn a_file_others_can_access_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let path = tmp_dir().join("k.key");
    load_or_create(&path).unwrap();
    for mode in [0o640, 0o604, 0o644, 0o660, 0o666, 0o601] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        match load(&path) {
            Err(KeyStoreError::Permissions(m)) => assert_eq!(m & 0o777, mode),
            other => panic!("mode {mode:o}: {other:?}"),
        }
        assert!(
            matches!(load_or_create(&path), Err(KeyStoreError::Permissions(_))),
            "never 'fixed' by recreating"
        );
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(load(&path).is_ok(), "owner read-only is fine");
}

#[test]
fn wrong_size_or_corrupt_files_are_refused() {
    let dir = tmp_dir();
    for (name, bytes) in [
        ("empty", vec![]),
        ("short", vec![0u8; 71]),
        ("long", vec![0u8; 73]),
    ] {
        let p = dir.join(name);
        write_owner_only(&p, &bytes);
        assert!(
            matches!(load(&p), Err(KeyStoreError::WrongSize(_))),
            "{name}"
        );
    }
    let p = dir.join("magic");
    let mut b = vec![0u8; 72];
    b[..8].copy_from_slice(b"NOTREMOR");
    write_owner_only(&p, &b);
    assert!(matches!(load(&p), Err(KeyStoreError::Format(_))));
}

#[test]
fn a_huge_file_is_refused_without_reading_it() {
    let p = tmp_dir().join("huge");
    write_owner_only(&p, &vec![0u8; 8 << 20]);
    let (r, stats) = count_allocations(|| load(&p).map(|_| ()));
    assert!(matches!(r, Err(KeyStoreError::WrongSize(n)) if n == 8 << 20));
    assert!(stats.peak_bytes < 64 * 1024, "{stats:?}");
}

#[test]
fn a_missing_file_is_an_error_for_load() {
    let p = tmp_dir().join("absent.key");
    assert!(matches!(load(&p), Err(KeyStoreError::Io(_))));
}

#[test]
fn default_paths_are_per_role_and_under_a_remora_dir() {
    let h = default_path(Role::Host).unwrap();
    let v = default_path(Role::Viewer).unwrap();
    assert_ne!(h, v);
    assert!(
        h.ends_with("Remora/host-identity.key") || h.ends_with("Remora\\host-identity.key"),
        "{h:?}"
    );
    assert!(
        v.ends_with("Remora/viewer-identity.key") || v.ends_with("Remora\\viewer-identity.key"),
        "{v:?}"
    );
}

fn write_owner_only(p: &std::path::Path, bytes: &[u8]) {
    std::fs::write(p, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
