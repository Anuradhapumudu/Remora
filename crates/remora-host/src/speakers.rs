//! `serve --mute-speakers` (phase4.8-criteria A7, owner 2026-11-03): the
//! host's own speakers are silent while sound is being sent, and restored
//! afterwards to how they were.
//!
//! * Why muting the speakers does not silence the viewer: PipeWire records
//!   the default output's copy **before** the output's mute and volume
//!   (spike, phase4.8-criteria step 5b: the same 0.02 peak normal, muted
//!   and at volume 0).
//! * [`mute_speakers`] remembers which output it muted (its PipeWire
//!   id), so the same one is restored even if the default changes during
//!   the session. An output the person had muted is left alone and never
//!   un-muted at the end.
//! * The guard restores on drop: when the last session ends, on Ctrl-C,
//!   on a panic that unwinds. A host killed outright (`kill -9`, power
//!   loss) cannot restore: the speakers then stay muted until someone
//!   unmutes them (GNOME's volume icon shows it). Stated, not hidden.
//! * Linux: WirePlumber's own tool `/usr/bin/wpctl` (absolute path, as
//!   `sysmon.rs` runs macOS's tools), which handles the per-device volume
//!   routes correctly; its output is size-capped and parsed strictly.

/// Mutes and reads one output (a fake in tests).
pub(crate) trait Mixer: Send {
    /// The default output's id.
    fn default_output(&mut self) -> anyhow::Result<u32>;
    /// Whether output `id` is muted.
    fn muted(&mut self, id: u32) -> anyhow::Result<bool>;
    /// Mutes or unmutes output `id`.
    fn set_muted(&mut self, id: u32, muted: bool) -> anyhow::Result<()>;
}

/// The speakers are muted while this lives; dropping it restores them.
pub(crate) struct SpeakersMuted {
    mixer: Box<dyn Mixer>,
    id: u32,
}

impl std::fmt::Debug for SpeakersMuted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SpeakersMuted({})", self.id)
    }
}

impl Drop for SpeakersMuted {
    fn drop(&mut self) {
        match self.mixer.set_muted(self.id, false) {
            Ok(()) => println!("speakers: restored"),
            Err(e) => println!("speakers: could not restore them ({e:#}) - unmute them by hand"),
        }
    }
}

/// Mutes the default output. `Ok(None)`: it was already muted (left as
/// it is). Checks the mute took effect.
pub(crate) fn mute_speakers(mut mixer: Box<dyn Mixer>) -> anyhow::Result<Option<SpeakersMuted>> {
    let id = mixer.default_output()?;
    if mixer.muted(id)? {
        return Ok(None);
    }
    mixer.set_muted(id, true)?;
    // From here on the guard restores, even if the check below fails.
    let mut guard = SpeakersMuted { mixer, id };
    if !guard.mixer.muted(id)? {
        anyhow::bail!("the output did not mute");
    }
    Ok(Some(guard))
}

/// Most output read from the tool (its answers are a line or two).
#[cfg(target_os = "linux")]
const MAX_OUTPUT: usize = 4096;

/// `wpctl inspect @DEFAULT_AUDIO_SINK@`'s first line: `id 62, type ...`.
pub(crate) fn parse_inspect_id(out: &str) -> Option<u32> {
    let first = out.lines().next()?.trim();
    let rest = first.strip_prefix("id ")?;
    let digits = rest.split(',').next()?;
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// `wpctl get-volume <id>`: `Volume: 1.00` or `Volume: 0.40 [MUTED]`.
pub(crate) fn parse_muted(out: &str) -> Option<bool> {
    let line = out.lines().next()?.trim();
    let rest = line.strip_prefix("Volume: ")?;
    let mut words = rest.split(' ');
    let level = words.next()?;
    level.parse::<f32>().ok().filter(|v| v.is_finite())?;
    match (words.next(), words.next()) {
        (None, _) => Some(false),
        (Some("[MUTED]"), None) => Some(true),
        _ => None,
    }
}

/// WirePlumber's `wpctl` (Linux).
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub(crate) struct Wpctl;

#[cfg(target_os = "linux")]
impl Wpctl {
    fn run(args: &[&str]) -> anyhow::Result<String> {
        let out = std::process::Command::new("/usr/bin/wpctl")
            .args(args)
            .output()
            .map_err(|e| anyhow::anyhow!("wpctl: {e}"))?;
        if !out.status.success() {
            anyhow::bail!(
                "wpctl {} failed ({})",
                args.first().unwrap_or(&""),
                out.status
            );
        }
        let n = out.stdout.len().min(MAX_OUTPUT);
        Ok(String::from_utf8_lossy(&out.stdout[..n]).into_owned())
    }
}

#[cfg(target_os = "linux")]
impl Mixer for Wpctl {
    fn default_output(&mut self) -> anyhow::Result<u32> {
        parse_inspect_id(&Self::run(&["inspect", "@DEFAULT_AUDIO_SINK@"])?)
            .ok_or_else(|| anyhow::anyhow!("no default sound output"))
    }

    fn muted(&mut self, id: u32) -> anyhow::Result<bool> {
        parse_muted(&Self::run(&["get-volume", &id.to_string()])?)
            .ok_or_else(|| anyhow::anyhow!("unexpected wpctl answer"))
    }

    fn set_muted(&mut self, id: u32, muted: bool) -> anyhow::Result<()> {
        Self::run(&["set-mute", &id.to_string(), if muted { "1" } else { "0" }]).map(|_| ())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Outputs by id: muted or not; `refuse`: set_muted does nothing.
    #[derive(Debug, Default)]
    pub(crate) struct Fake {
        pub(crate) muted: HashMap<u32, bool>,
        pub(crate) default: u32,
        pub(crate) refuse: bool,
        /// Every set_muted call, in order.
        pub(crate) changes: Vec<(u32, bool)>,
    }

    pub(crate) struct FakeMixer(pub(crate) Arc<Mutex<Fake>>);

    impl Mixer for FakeMixer {
        fn default_output(&mut self) -> anyhow::Result<u32> {
            Ok(self.0.lock().expect("fake").default)
        }
        fn muted(&mut self, id: u32) -> anyhow::Result<bool> {
            Ok(*self
                .0
                .lock()
                .expect("fake")
                .muted
                .get(&id)
                .unwrap_or(&false))
        }
        fn set_muted(&mut self, id: u32, muted: bool) -> anyhow::Result<()> {
            let mut f = self.0.lock().expect("fake");
            f.changes.push((id, muted));
            if !f.refuse {
                f.muted.insert(id, muted);
            }
            Ok(())
        }
    }

    pub(crate) fn fake(default: u32, muted: bool) -> Arc<Mutex<Fake>> {
        let mut f = Fake {
            default,
            ..Fake::default()
        };
        f.muted.insert(default, muted);
        Arc::new(Mutex::new(f))
    }

    fn is_muted(f: &Arc<Mutex<Fake>>, id: u32) -> bool {
        f.lock().expect("fake").muted[&id]
    }

    #[test]
    fn a7_mutes_then_restores_the_same_output() {
        let f = fake(62, false);
        let guard = mute_speakers(Box::new(FakeMixer(Arc::clone(&f)))).expect("mute");
        assert!(guard.is_some());
        assert!(is_muted(&f, 62), "speakers still playing");
        // The person switches the default output mid-session.
        f.lock().expect("fake").default = 45;
        drop(guard);
        assert!(!is_muted(&f, 62), "the muted output was not restored");
    }

    #[test]
    fn a7_an_output_muted_by_the_person_stays_muted() {
        let f = fake(62, true);
        let guard = mute_speakers(Box::new(FakeMixer(Arc::clone(&f)))).expect("mute");
        assert!(guard.is_none());
        drop(guard);
        assert!(is_muted(&f, 62), "un-muted what the person had muted");
        assert!(
            f.lock().expect("fake").changes.is_empty(),
            "touched it at all"
        );
    }

    #[test]
    fn a7_a_mute_that_does_not_take_is_an_error() {
        let f = fake(62, false);
        f.lock().expect("fake").refuse = true;
        assert!(mute_speakers(Box::new(FakeMixer(Arc::clone(&f)))).is_err());
        assert!(!is_muted(&f, 62));
    }

    /// The real tool on a Linux desktop (mutes the speakers for a moment):
    /// `cargo test -p remora-host --bin remora-host -- --ignored a7_live`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a logged-in Linux desktop with WirePlumber"]
    fn a7_live_wpctl_mutes_and_restores() {
        let mut probe = Wpctl;
        let id = probe.default_output().expect("default output");
        let before = probe.muted(id).expect("read");
        assert!(!before, "start with the speakers unmuted");
        let guard = mute_speakers(Box::new(Wpctl))
            .expect("mute")
            .expect("guard");
        assert!(probe.muted(id).expect("read"), "not muted");
        drop(guard);
        assert!(!probe.muted(id).expect("read"), "not restored");
    }

    #[test]
    fn wpctl_answers_are_parsed_strictly() {
        assert_eq!(
            parse_inspect_id("id 62, type PipeWire:Interface:Node\n  x"),
            Some(62)
        );
        for bad in [
            "",
            "id , type",
            "id 6x2, type",
            "62, type",
            "id 99999999999, t",
            "id -1, t",
        ] {
            assert_eq!(parse_inspect_id(bad), None, "{bad:?}");
        }
        assert_eq!(parse_muted("Volume: 1.00\n"), Some(false));
        assert_eq!(parse_muted("Volume: 0.40 [MUTED]"), Some(true));
        for bad in [
            "",
            "Volume: ",
            "Volume: x",
            "Volume: 1.00 [MUTED] x",
            "Volume: 1.00 MUTED",
            "Vol: 1.00",
            "Volume: NaN",
        ] {
            assert_eq!(parse_muted(bad), None, "{bad:?}");
        }
    }
}
