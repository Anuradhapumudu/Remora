//! Canary secrets and log capture (phase3-criteria A28, threat model INV8).
//!
//! A test plants distinctive secret values ("canaries"), runs the code, captures
//! every log line and `Debug`/error string, and asserts no canary appears in any
//! encoding someone might accidentally log it in.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn hex(bytes: &[u8], table: &[u8; 16]) -> String {
    bytes
        .iter()
        .flat_map(|b| [table[usize::from(b >> 4)], table[usize::from(b & 0xf)]])
        .map(char::from)
        .collect()
}

fn base64(bytes: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(char::from(table[((n >> (18 - 6 * i)) & 63) as usize]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// A planted secret value.
#[derive(Debug, Clone)]
pub struct Canary {
    /// What it stands for (e.g. "otp", "identity key").
    pub name: &'static str,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

impl Canary {
    /// A canary for `bytes`. Use distinctive values (≥ 6 bytes) so a match can't
    /// be a coincidence.
    pub fn new(name: &'static str, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            name,
            bytes: bytes.into(),
        }
    }

    /// Every textual form the secret could leak in: raw UTF-8 (if valid), hex
    /// (both cases), base64 (standard and URL-safe, padded and unpadded) and the
    /// Rust `Debug` form of a byte slice.
    pub fn encodings(&self) -> Vec<String> {
        let b = &self.bytes;
        let mut v = vec![
            hex(b, HEX_LOWER),
            hex(b, HEX_UPPER),
            base64(b, B64_STD, true),
            base64(b, B64_STD, false),
            base64(b, B64_URL, true),
            base64(b, B64_URL, false),
            format!("{b:?}").trim_end_matches(']').to_owned(),
        ];
        if let Ok(s) = std::str::from_utf8(b) {
            v.push(s.to_owned());
        }
        v.retain(|e| !e.is_empty());
        v.sort();
        v.dedup();
        v
    }
}

/// A canary found in captured text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leak {
    /// Which canary.
    pub canary: &'static str,
    /// The encoding that matched.
    pub encoding: String,
    /// The line it appeared in (truncated to 200 chars).
    pub line: String,
}

/// Every occurrence of any canary, in any encoding, in `text`.
pub fn find_leaks(text: &str, canaries: &[Canary]) -> Vec<Leak> {
    let mut leaks = Vec::new();
    for c in canaries {
        for enc in c.encodings() {
            for line in text.lines().filter(|l| l.contains(enc.as_str())) {
                leaks.push(Leak {
                    canary: c.name,
                    encoding: enc.clone(),
                    line: line.chars().take(200).collect(),
                });
            }
        }
    }
    leaks
}

/// Every place in `text` where some `window`-byte run of `data` appears as
/// a `Debug` byte list (`12, 200, 7, …`, inside a longer list too), as hex
/// (either case) or as raw text. For content that is not one short secret
/// but a frame (phase4-criteria N1, N4: "no 16-byte window of any encoded
/// frame"). Base64 is not searched: it depends on the run's alignment.
pub fn find_windows(text: &str, name: &'static str, data: &[u8], window: usize) -> Vec<Leak> {
    let mut leaks = Vec::new();
    if window == 0 {
        return leaks; // `windows(0)` would panic
    }
    for run in data.windows(window) {
        let list = run.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
        let mut forms = vec![list, hex(run, HEX_LOWER), hex(run, HEX_UPPER)];
        if let Ok(s) = std::str::from_utf8(run) {
            forms.push(s.to_owned());
        }
        for enc in forms {
            if let Some(line) = text.lines().find(|l| l.contains(enc.as_str())) {
                leaks.push(Leak {
                    canary: name,
                    encoding: enc,
                    line: line.chars().take(200).collect(),
                });
                return leaks; // one is enough to fail; keeps big inputs fast
            }
        }
    }
    leaks
}

/// Every 16-byte run of some content (encoded frames, pixel rows), to find
/// a piece of it in logs or files (phase4-criteria M1b, N1, N2: "no 16-byte
/// window of any encoded frame"). A set, so megabytes of logs are checked
/// quickly against megabytes of video.
#[derive(Debug, Default)]
pub struct Windows16 {
    set: std::collections::HashSet<u128>,
}

impl Windows16 {
    /// No content yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds every 16-byte run of `data`.
    pub fn add(&mut self, data: &[u8]) {
        for w in data.windows(16) {
            self.set.insert(Self::key(w));
        }
    }

    /// How many distinct runs are known.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether no content was added.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    fn key(w: &[u8]) -> u128 {
        let mut b = [0u8; 16];
        b.copy_from_slice(w);
        u128::from_be_bytes(b)
    }

    /// The offset of the first 16 bytes of `bytes` that are content.
    pub fn find_in_bytes(&self, bytes: &[u8]) -> Option<usize> {
        bytes
            .windows(16)
            .position(|w| self.set.contains(&Self::key(w)))
    }

    /// The first line of `text` holding content: as raw bytes, as a run of
    /// hex digits (either case, either alignment) or as a decimal byte list
    /// (`Debug` of a slice). Base64 is not searched (alignment-dependent).
    pub fn find_in_text(&self, text: &str) -> Option<String> {
        text.lines()
            .find(|line| {
                self.find_in_bytes(line.as_bytes()).is_some()
                    || hex_runs(line)
                        .iter()
                        .any(|b| self.find_in_bytes(b).is_some())
                    || decimal_lists(line)
                        .iter()
                        .any(|b| self.find_in_bytes(b).is_some())
            })
            .map(|l| l.chars().take(200).collect())
    }
}

/// Runs of at least 32 hex digits, decoded from both alignments.
fn hex_runs(line: &str) -> Vec<Vec<u8>> {
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::new();
    for run in line
        .as_bytes()
        .split(|c| !c.is_ascii_hexdigit())
        .filter(|r| r.len() >= 32)
    {
        for start in 0..2 {
            let bytes = run[start..]
                .as_chunks::<2>()
                .0
                .iter()
                .filter_map(|[hi, lo]| Some(digit(*hi)? << 4 | digit(*lo)?))
                .collect();
            out.push(bytes);
        }
    }
    out
}

/// Sequences of at least 16 numbers 0..=255 separated by commas (and
/// spaces), as `{:?}` prints a byte slice.
fn decimal_lists(line: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let flush = |cur: &mut Vec<u8>, out: &mut Vec<Vec<u8>>| {
        if cur.len() >= 16 {
            out.push(std::mem::take(cur));
        }
        cur.clear();
    };
    for token in line.split(',') {
        let t = token.trim();
        // The first and last numbers of a list carry the brackets.
        let t = t.trim_start_matches('[').trim_end_matches(']');
        match t.parse::<u8>() {
            Ok(b) if !token.trim().is_empty() => cur.push(b),
            _ => {
                // A token like "body: [12" starts a new list with 12.
                flush(&mut cur, &mut out);
                if let Some(b) = t.rsplit(['[', ' ']).next().and_then(|n| n.parse().ok()) {
                    cur.push(b);
                }
            }
        }
    }
    flush(&mut cur, &mut out);
    out
}

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
    type Writer = Buffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Captures every `tracing` event (all levels, all fields, span context) on the
/// current thread while alive.
pub struct LogCapture {
    buffer: Buffer,
    _guard: Option<tracing::subscriber::DefaultGuard>,
}

impl LogCapture {
    /// Starts capturing on this thread.
    pub fn start() -> Self {
        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_target(true)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        Self {
            buffer,
            _guard: Some(guard),
        }
    }

    /// Starts capturing in **every** thread of this process (the encoder's,
    /// the decoder's, a multi-threaded runtime's). A process has one global
    /// subscriber: use it in a test binary with a single test.
    pub fn global() -> Self {
        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_target(true)
            .finish();
        if tracing::subscriber::set_global_default(subscriber).is_err() {
            panic!("LogCapture::global: this process already has a global subscriber");
        }
        Self {
            buffer,
            _guard: None,
        }
    }

    /// Everything captured so far.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.buffer.0.lock().unwrap_or_else(PoisonError::into_inner))
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn windows16_finds_content_in_bytes_hex_and_debug_lists() {
        let frame: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(101))
            .collect();
        let mut w = super::Windows16::new();
        w.add(&frame);
        assert_eq!(w.len(), 49);
        // Raw bytes inside a packet.
        let mut packet = vec![9u8; 30];
        packet.extend_from_slice(&frame[20..40]);
        assert_eq!(w.find_in_bytes(&packet), Some(30));
        // A Debug list inside a longer one, behind a field name.
        let mut around = vec![1u8, 2];
        around.extend_from_slice(&frame[3..23]);
        let line = format!("x\nFragment {{ body: {around:?} }}");
        assert!(w.find_in_text(&line).unwrap().starts_with("Fragment"));
        // Hex, upper case, odd alignment.
        let hexed = format!("id=7{}", super::hex(&frame[10..30], super::HEX_UPPER));
        assert!(w.find_in_text(&hexed).is_some());
        // 15 bytes, other bytes, sizes: nothing.
        assert!(w.find_in_text(&format!("{:?}", &frame[0..15])).is_none());
        assert!(w.find_in_text("bytes: 64, frame_id: 3").is_none());
        assert!(w.find_in_bytes(&[0u8; 100]).is_none());
    }

    #[test]
    fn finds_a_window_inside_a_longer_debug_list_and_in_hex() {
        let frame: Vec<u8> = (0..40u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(101))
            .collect();
        // The middle 16 bytes, inside a Debug list with other bytes around.
        let mut around = vec![1u8, 2, 3];
        around.extend_from_slice(&frame[10..30]);
        let dbg = format!("Fragment {{ body: {around:?} }}");
        assert_eq!(find_windows(&dbg, "frame", &frame, 16).len(), 1, "{dbg}");
        let hexed = format!("x {}", hex(&frame[5..25], HEX_UPPER));
        assert_eq!(find_windows(&hexed, "frame", &frame, 16).len(), 1);
        // 15 bytes is below the window: not a finding.
        let short = format!("{:?}", &frame[0..15]);
        assert!(find_windows(&short, "frame", &frame, 16).is_empty());
        assert!(find_windows("bytes: 40", "frame", &frame, 16).is_empty());
        // A frame exactly one window long; a zero window finds nothing.
        let exact = format!("{:?}", &frame[..16]);
        assert_eq!(find_windows(&exact, "frame", &frame[..16], 16).len(), 1);
        assert!(find_windows(&exact, "frame", &frame, 0).is_empty());
    }

    use super::*;

    #[test]
    fn encoders_match_known_values() {
        // RFC 4648 test vectors.
        assert_eq!(base64(b"foobar", B64_STD, true), "Zm9vYmFy");
        assert_eq!(base64(b"fo", B64_STD, true), "Zm8=");
        assert_eq!(base64(b"f", B64_STD, false), "Zg");
        assert_eq!(base64(&[0xfb, 0xff], B64_URL, false), "-_8");
        assert_eq!(hex(&[0xde, 0xad], HEX_LOWER), "dead");
        assert_eq!(hex(&[0xde, 0xad], HEX_UPPER), "DEAD");
    }

    #[test]
    fn finds_secret_in_every_encoding() {
        let c = Canary::new("key", vec![0xde, 0xad, 0xbe, 0xef, 0x13, 0x37]);
        for enc in c.encodings() {
            let leaks = find_leaks(&format!("blah {enc} blah"), std::slice::from_ref(&c));
            assert!(!leaks.is_empty(), "missed encoding {enc}");
        }
        assert!(find_leaks("nothing here", &[c]).is_empty());
    }

    #[test]
    fn debug_byte_slice_form_is_detected() {
        let secret = vec![201u8, 202, 203, 204, 205, 206];
        let c = Canary::new("k", secret.clone());
        assert!(!find_leaks(&format!("{secret:?}"), &[c]).is_empty());
    }

    #[test]
    fn captures_events_and_fields_on_this_thread() {
        let cap = LogCapture::start();
        let otp = "424242";
        tracing::warn!(reason = "test", password = otp, "handshake_failed");
        let text = cap.text();
        assert!(text.contains("handshake_failed"));
        let leaks = find_leaks(&text, &[Canary::new("otp", otp)]);
        assert_eq!(
            leaks.len(),
            1,
            "the scanner must catch a deliberately logged secret"
        );
    }
}
