//! Remora input injection: normalised mouse and keyboard events with per-OS backends.
//!
//! Part of Remora; see `docs/architecture.md` in the repository.
//! Pre-alpha: injection is Phase 6. Today it holds one window setting the
//! GUI toolkit cannot make ([`window`], I3, architecture D46).

// `unsafe_code` is denied workspace-wide. Only the OS FFI modules under
// `src/sys/` may opt in with `#[allow(unsafe_code)]`, and every unsafe block
// needs a `// SAFETY:` comment (architecture.md §4).

#![deny(unsafe_code)]

mod sys;
pub mod window;
