//! Remora video codecs: hardware-first encoder and decoder backends with a software fallback.
//!
//! Part of Remora; see `docs/architecture.md` in the repository.
//! Pre-alpha skeleton: no functionality yet.

// `unsafe_code` is denied workspace-wide. Only the OS FFI modules under
// `src/sys/` may opt in with `#[allow(unsafe_code)]`, and every unsafe block
// needs a `// SAFETY:` comment (architecture.md §4).
