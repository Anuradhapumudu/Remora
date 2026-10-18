//! Unattended-access password policy (phase3-criteria A30, threat model INV13).
//!
//! Rules, applied to the **NFKC-normalised** text (so look-alike forms such as
//! full-width letters count as the letters they represent):
//!
//! * length counted in characters that are **not combining marks** — so
//!   `"a\u{301}"` (a + combining acute) counts once, and padding a short
//!   password with invisible combining characters does not lengthen it;
//! * at least [`MIN_CHARS`], at most [`MAX_CHARS`];
//! * no control characters;
//! * not on the embedded list of obvious passwords (case-insensitive).
//!
//! Input longer than [`MAX_INPUT_BYTES`] is refused **before** normalising
//! (NFKC can expand text, so it must not run on unbounded input — INV7).

use crate::secret::UnattendedPassword;

/// Minimum length in non-combining characters.
pub const MIN_CHARS: usize = 12;
/// Maximum length in non-combining characters.
pub const MAX_CHARS: usize = 128;
/// Raw input limit, checked before any normalisation.
pub const MAX_INPUT_BYTES: usize = 1024;

/// Why a password was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    /// Raw input above [`MAX_INPUT_BYTES`].
    #[error("password input is too large")]
    InputTooLarge,
    /// Fewer than [`MIN_CHARS`] characters after normalisation.
    #[error("password needs at least {MIN_CHARS} characters (has {chars})")]
    TooShort {
        /// Characters counted.
        chars: usize,
    },
    /// More than [`MAX_CHARS`] characters after normalisation.
    #[error("password may have at most {MAX_CHARS} characters (has {chars})")]
    TooLong {
        /// Characters counted.
        chars: usize,
    },
    /// Contains a control character.
    #[error("password contains a control character")]
    ControlCharacter,
    /// On the list of obvious passwords.
    #[error("password is too common")]
    Common,
}

/// Obvious passwords of 12+ characters. Hand-written (not a published breach
/// corpus); it catches the laziest choices, the length rule does the rest.
/// Compared after NFKC + lower-casing.
pub(crate) const COMMON: &[&str] = &[
    "123456789012",
    "1234567890123",
    "12345678901234",
    "123123123123",
    "111111111111",
    "000000000000",
    "abcdefghijkl",
    "abc123abc123",
    "password1234",
    "password12345",
    "password123456",
    "passwordpassword",
    "qwertyuiop12",
    "qwertyuiop123",
    "qwertyuiopasdf",
    "qwerty123456",
    "1q2w3e4r5t6y",
    "asdfghjkl123",
    "iloveyou1234",
    "letmein12345",
    "welcome12345",
    "administrator",
    "remoteaccess",
    "remora123456",
    "remorapassword",
    "changeme1234",
    "trustno1trustno1",
];

/// Checks an unattended-access password against the policy and returns it
/// normalised (NFKC).
pub fn validate_unattended_password(input: &str) -> Result<UnattendedPassword, PasswordError> {
    let _ = input;
    todo!()
}
