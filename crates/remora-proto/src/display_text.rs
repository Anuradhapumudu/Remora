//! Untrusted names made safe to show (phase4.5-criteria H6): a peer's
//! device name cannot fake the host's Accept/Deny dialog. The name is chosen by the other computer (untrusted text, at most
//! 64 bytes (`DEVICE_NAME_MAX`), checked when the
//! certificate is parsed). Before it is shown, every character that could
//! move, hide or reorder text is replaced by a visible escape:
//!
//! * control characters (C0, DEL, C1): a newline could push a fake line;
//! * bidirectional controls (U+061C, U+200E, U+200F, U+202A-U+202E,
//!   U+2066-U+2069): an override can make "tpeccA" read as "Accept";
//! * invisible and zero-width characters (U+00AD, U+034F, U+115F, U+1160,
//!   U+17B4, U+17B5, U+180B-U+180F, U+200B-U+200D, U+2028, U+2029,
//!   U+2060-U+2064, U+206A-U+206F, U+3164, U+FE00-U+FE0F, U+FEFF, U+FFA0,
//!   U+FFF9-U+FFFB, U+1D173-U+1D17A, U+E0000-U+E0FFF): two names that look
//!   the same must not be different names in secret.
//!
//! The escape is `\u{XXXX}`, and a backslash itself becomes `\\`, so a name
//! that *types* `\u{202E}` is shown as `\\u{202E}` and can never pass for an
//! escaped character. Everything else (letters of any script, emoji) is
//! shown as it is. Look-alike letters from other scripts (Cyrillic "а" for
//! Latin "a") are **not** changed: the dialog labels the name "chosen by the
//! other computer, not checked", and the device ID and safety code are what
//! identify the viewer (H1).

/// Whether `c` is shown as an escape instead of itself.
pub fn is_escaped(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{00AD}'
                | '\u{034F}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{17B4}'
                | '\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200D}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{2060}'..='\u{2064}'
                | '\u{206A}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

/// The name as the dialog shows it: every [`is_escaped`] character as
/// `\u{XXXX}` and `\` as `\\`.
pub fn display_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if is_escaped(c) {
            out.push_str(&format!("\\u{{{:04X}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// Reverses [`display_name`] (tests and the fuzz target: the escaping must
/// lose nothing, so two different names never look the same).
pub fn undo_display_name(shown: &str) -> Option<String> {
    let mut out = String::new();
    let mut it = shown.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next()? {
            '\\' => out.push('\\'),
            'u' => {
                if it.next()? != '{' {
                    return None;
                }
                let mut hex = String::new();
                loop {
                    match it.next()? {
                        '}' => break,
                        h if hex.len() < 6 => hex.push(h),
                        _ => return None,
                    }
                }
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h6_newline_cannot_start_a_fake_line() {
        let shown = display_name("Bob\nAccept only if the code is 000 000");
        assert!(!shown.contains('\n'));
        assert_eq!(shown, "Bob\\u{000A}Accept only if the code is 000 000");
    }

    #[test]
    fn h6_bidi_override_is_visible() {
        // RLO + "tpeccA" renders as "Accept" if passed through.
        let shown = display_name("\u{202E}tpeccA");
        assert_eq!(shown, "\\u{202E}tpeccA");
        for c in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{2066}', '\u{2069}',
        ] {
            assert!(!display_name(&format!("x{c}y")).contains(c), "{c:?}");
        }
    }

    #[test]
    fn h6_zero_width_characters_are_visible() {
        let shown = display_name("Al\u{200D}ice\u{FEFF}");
        assert_eq!(shown, "Al\\u{200D}ice\\u{FEFF}");
        assert_ne!(display_name("Alice"), display_name("Al\u{200B}ice"));
    }

    #[test]
    fn h6_a_typed_escape_cannot_pass_for_a_real_one() {
        assert_eq!(display_name("\\u{202E}"), "\\\\u{202E}");
        assert_ne!(display_name("\\u{202E}"), display_name("\u{202E}"));
    }

    #[test]
    fn h6_ordinary_names_are_unchanged() {
        for name in ["MacBook Air", "Ünïcødé", "東京のMac", "Café ☕", "Олег"] {
            assert_eq!(display_name(name), name);
        }
    }

    #[test]
    fn h6_undo_refuses_what_display_name_never_writes() {
        assert_eq!(undo_display_name("\\u{0000041}"), None, "7 hex digits");
        assert_eq!(undo_display_name("\\u{41"), None);
        assert_eq!(undo_display_name("\\x"), None);
        assert_eq!(undo_display_name("\\u{110000}"), None, "not a char");
        assert_eq!(undo_display_name("\\u{000041}").as_deref(), Some("A"));
    }

    #[test]
    fn h6_escaping_loses_nothing() {
        for name in [
            "",
            "a\\b",
            "\u{202E}x\u{E0001}\u{1D173}",
            "\u{0}\u{7F}\u{9F}",
            "\\u{41}",
        ] {
            let shown = display_name(name);
            assert!(!shown.chars().any(is_escaped), "{shown:?}");
            assert_eq!(undo_display_name(&shown).as_deref(), Some(name));
        }
    }
}
