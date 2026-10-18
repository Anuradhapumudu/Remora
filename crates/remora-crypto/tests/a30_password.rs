//! phase3-criteria A30 / threat model INV13: unattended-password policy.
//! Written before the implementation.

use remora_crypto::password::{
    MAX_CHARS, MAX_INPUT_BYTES, MIN_CHARS, PasswordError, validate_unattended_password,
};
use remora_testkit::{CountingAlloc, count_allocations};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn chars(n: usize) -> String {
    // Avoid anything on the common list: cycle through a mixed alphabet.
    "Kq7#mZ2!pW9@xL4$".chars().cycle().take(n).collect()
}

#[test]
fn length_boundaries() {
    assert_eq!(
        validate_unattended_password(&chars(MIN_CHARS - 1)).unwrap_err(),
        PasswordError::TooShort {
            chars: MIN_CHARS - 1
        }
    );
    assert!(validate_unattended_password(&chars(MIN_CHARS)).is_ok());
    assert!(validate_unattended_password(&chars(MAX_CHARS)).is_ok());
    assert_eq!(
        validate_unattended_password(&chars(MAX_CHARS + 1)).unwrap_err(),
        PasswordError::TooLong {
            chars: MAX_CHARS + 1
        }
    );
    assert_eq!(
        validate_unattended_password("").unwrap_err(),
        PasswordError::TooShort { chars: 0 }
    );
}

#[test]
fn combining_marks_do_not_count() {
    // 11 base letters + 11 combining marks (U+0301 COMBINING ACUTE). Some
    // pairs have a precomposed form (c → ć) and some don't (b + ́ stays two
    // code points); either way only 11 characters may count.
    let tricky: String = "bcdfghjklmn".chars().flat_map(|c| [c, '\u{301}']).collect();
    assert_eq!(tricky.chars().count(), 22);
    assert_eq!(
        validate_unattended_password(&tricky).unwrap_err(),
        PasswordError::TooShort { chars: 11 }
    );
    // Invisible padding with a run of combining marks after a short password.
    let padded = format!("Kq7#mZ2!pW9{}", "\u{300}".repeat(30));
    assert_eq!(
        validate_unattended_password(&padded).unwrap_err(),
        PasswordError::TooShort { chars: 11 }
    );
}

#[test]
fn nfkc_is_applied_before_counting_and_comparing() {
    // Full-width "password1234" is NFKC-equal to the common password.
    let fullwidth = "ｐａｓｓｗｏｒｄ１２３４";
    assert_eq!(
        validate_unattended_password(fullwidth).unwrap_err(),
        PasswordError::Common
    );
    // Ligature "ﬀ" (U+FB00) normalises to "ff" — two characters.
    let lig = "ﬀKq7#mZ2!pW"; // 1 + 10 code points, NFKC → 12 characters
    let ok = validate_unattended_password(lig).unwrap();
    assert_eq!(ok.reveal(), "ffKq7#mZ2!pW", "stored normalised");
    // Precomposed é and e + U+0301 are the same password after NFKC.
    let a = validate_unattended_password("caf\u{e9}Kq7#mZ2!pW").unwrap();
    let b = validate_unattended_password("cafe\u{301}Kq7#mZ2!pW").unwrap();
    assert_eq!(a.reveal(), b.reveal());
}

#[test]
fn common_passwords_rejected_case_insensitively() {
    for p in [
        "password1234",
        "PASSWORD1234",
        "Password1234",
        "123456789012",
        "qwertyuiop123",
    ] {
        assert_eq!(
            validate_unattended_password(p).unwrap_err(),
            PasswordError::Common,
            "{p}"
        );
    }
}

#[test]
fn control_characters_rejected() {
    for p in [
        "Kq7#mZ2!pW9@\u{0}",
        "Kq7#mZ2!pW9@\n",
        "Kq7#mZ2!\u{1b}pW9@",
        "Kq7#mZ2!pW9@\u{7f}",
    ] {
        assert_eq!(
            validate_unattended_password(p).unwrap_err(),
            PasswordError::ControlCharacter,
            "{p:?}"
        );
    }
}

#[test]
fn huge_input_refused_before_normalising() {
    // NFKC can expand text, so it must never run on unbounded input (INV7).
    let big = "a".repeat(1 << 20);
    let (r, stats) = count_allocations(|| validate_unattended_password(&big).map(|_| ()));
    assert_eq!(r.unwrap_err(), PasswordError::InputTooLarge);
    assert!(
        stats.peak_bytes <= 256,
        "allocated before the size check: {stats:?}"
    );
    let over = "a".repeat(MAX_INPUT_BYTES + 1);
    assert_eq!(
        validate_unattended_password(&over).unwrap_err(),
        PasswordError::InputTooLarge
    );
    // Exactly at the byte limit the length rule decides instead.
    let at = "Kq7#mZ2!".repeat(MAX_INPUT_BYTES / 8);
    assert_eq!(at.len(), MAX_INPUT_BYTES);
    assert!(matches!(
        validate_unattended_password(&at).unwrap_err(),
        PasswordError::TooLong { .. }
    ));
}

#[test]
fn good_passwords_accepted() {
    for p in [
        "correct horse battery staple",
        "Kq7#mZ2!pW9@",
        "パスワードは十二文字以上です",
        "ñandú-ñandú-ñandú",
    ] {
        assert!(validate_unattended_password(p).is_ok(), "{p}");
    }
}
