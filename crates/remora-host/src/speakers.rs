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
//! * The guard restores on drop (the last session ends, Ctrl-C, a panic
//!   that unwinds) and **checks** the restore, retrying once. Before
//!   muting, a [`Note`] records which output (id and PipeWire name); it is
//!   cleared only after a verified restore. A host killed outright, or a
//!   restore that did not take (seen live, 2026-11-03: the laptop was
//!   left muted), leaves the note, and the next `serve` repairs it
//!   ([`repair_left_muted`]) — only on an output with the same name, so a
//!   number reused after a reboot is never touched.
//! * GNOME's own volume slider fights this mute (gnome-shell 50.4
//!   `ui/status/volume.js`, read from `libshell-18.so`): a muted output
//!   shows the slider at 0, dragging it up unmutes, and dragging it below
//!   the first step mutes and sets the volume to 0. Moving it during a
//!   session is the person's choice and wins.
//! * Linux: WirePlumber's own tool `/usr/bin/wpctl` (absolute path, as
//!   `sysmon.rs` runs macOS's tools), which handles the per-device volume
//!   routes correctly; its output is size-capped and parsed strictly.

/// Mutes and reads one output (a fake in tests).
pub(crate) trait Mixer: Send {
    /// The default output's id.
    fn default_output(&mut self) -> anyhow::Result<u32>;
    /// Output `id`'s PipeWire name (stable across restarts; ids are not).
    fn name(&mut self, id: u32) -> anyhow::Result<String>;
    /// Whether output `id` is muted.
    fn muted(&mut self, id: u32) -> anyhow::Result<bool>;
    /// Mutes or unmutes output `id`.
    fn set_muted(&mut self, id: u32, muted: bool) -> anyhow::Result<()>;
}

/// Where the output Remora muted is noted until a verified restore.
pub(crate) trait Note: Send {
    /// Notes output `id` called `name` (before muting it).
    fn write(&mut self, id: u32, name: &str) -> anyhow::Result<()>;
    /// The noted output, if any.
    fn read(&mut self) -> Option<(u32, String)>;
    /// Forgets it (after a verified restore).
    fn clear(&mut self);
}

/// Wait before the one retry of a restore that did not take.
const RETRY_AFTER: std::time::Duration = std::time::Duration::from_millis(200);

/// Unmutes `id` and checks it, retrying once; `true` when it is unmuted.
fn restore(mixer: &mut dyn Mixer, id: u32) -> bool {
    for attempt in 0..2 {
        if attempt > 0 {
            std::thread::sleep(RETRY_AFTER);
        }
        let _ = mixer.set_muted(id, false);
        if matches!(mixer.muted(id), Ok(false)) {
            return true;
        }
    }
    false
}

/// The speakers are muted while this lives; dropping it restores them.
pub(crate) struct SpeakersMuted {
    mixer: Box<dyn Mixer>,
    note: Box<dyn Note>,
    id: u32,
}

impl std::fmt::Debug for SpeakersMuted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SpeakersMuted({})", self.id)
    }
}

impl Drop for SpeakersMuted {
    fn drop(&mut self) {
        if restore(&mut *self.mixer, self.id) {
            self.note.clear();
            println!("speakers: restored");
        } else {
            println!(
                "speakers: could not restore them - they stay muted; the next 'remora-host serve' unmutes them, or unmute them by hand"
            );
        }
    }
}

/// Mutes the default output. `Ok(None)`: it was already muted (left as
/// it is). Notes it first (no note, no mute), then checks the mute took.
pub(crate) fn mute_speakers(
    mut mixer: Box<dyn Mixer>,
    mut note: Box<dyn Note>,
) -> anyhow::Result<Option<SpeakersMuted>> {
    let id = mixer.default_output()?;
    if mixer.muted(id)? {
        return Ok(None);
    }
    let name = mixer.name(id)?;
    note.write(id, &name)?;
    if let Err(e) = mixer.set_muted(id, true) {
        note.clear();
        return Err(e);
    }
    // From here on the guard restores, even if the check below fails.
    let mut guard = SpeakersMuted { mixer, note, id };
    if !guard.mixer.muted(id)? {
        anyhow::bail!("the output did not mute");
    }
    Ok(Some(guard))
}

/// At host start: unmutes an output an earlier run muted and did not
/// restore (its note is still there). Only the output with the noted
/// name: the noted id if it still has that name, else the default output
/// if it does; anything else is left alone. Returns what to tell the
/// person, if anything happened.
pub(crate) fn repair_left_muted(mixer: &mut dyn Mixer, note: &mut dyn Note) -> Option<String> {
    let (noted, name) = note.read()?;
    let same = |m: &mut dyn Mixer, id: u32| m.name(id).ok().as_deref() == Some(name.as_str());
    let id = if same(mixer, noted) {
        Some(noted)
    } else {
        mixer.default_output().ok().filter(|&d| same(mixer, d))
    };
    let Some(id) = id else {
        note.clear();
        return Some(format!(
            "speakers: an earlier Remora run had muted \"{name}\", which is not here now - nothing changed"
        ));
    };
    match mixer.muted(id) {
        Ok(false) => {
            note.clear();
            None
        }
        Ok(true) if restore(mixer, id) => {
            note.clear();
            Some("speakers: unmuted - an earlier Remora run had muted them and did not restore them".into())
        }
        _ => Some(
            "speakers: an earlier Remora run left them muted and they could not be unmuted - unmute them by hand".into(),
        ),
    }
}

/// A PipeWire node name as `wpctl inspect` prints it
/// (`  * node.name = "alsa_output.pci-0000_00_1f.3.analog-stereo"`):
/// letters, digits and `._:-` only, at most [`MAX_NAME`] bytes.
pub(crate) fn parse_node_name(out: &str) -> Option<String> {
    let line = out.lines().map(str::trim).find_map(|l| {
        l.strip_prefix("* node.name = \"")
            .or_else(|| l.strip_prefix("node.name = \""))
    })?;
    let name = line.strip_suffix('"')?;
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b));
    ok.then(|| name.to_owned())
}

/// Longest node name accepted.
pub(crate) const MAX_NAME: usize = 200;

/// The note's text: `<id>|<name>` (a `token_file`: printable, no spaces).
pub(crate) fn note_text(id: u32, name: &str) -> String {
    format!("{id}|{name}")
}

/// Reads [`note_text`] back, as strictly as [`parse_node_name`].
pub(crate) fn parse_note(text: &str) -> Option<(u32, String)> {
    let (id, name) = text.split_once('|')?;
    if !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let id = id.parse().ok()?;
    let name = parse_node_name(&format!("node.name = \"{name}\""))?;
    Some((id, name))
}

/// The note as an owner-only file next to the host's key
/// (`remora_app::token_file`: this crate may not write files itself).
#[cfg(target_os = "linux")]
pub(crate) struct FileNote(pub(crate) std::path::PathBuf);

#[cfg(target_os = "linux")]
impl Note for FileNote {
    fn write(&mut self, id: u32, name: &str) -> anyhow::Result<()> {
        remora_app::token_file::save(&self.0, &note_text(id, name))?;
        Ok(())
    }
    fn read(&mut self) -> Option<(u32, String)> {
        parse_note(&remora_app::token_file::load(&self.0)?)
    }
    fn clear(&mut self) {
        remora_app::token_file::remove(&self.0);
    }
}

/// Most output read from the tool (its answers are a line or two).
#[cfg(target_os = "linux")]
const MAX_OUTPUT: usize = 4096;

/// `wpctl inspect @DEFAULT_AUDIO_SINK@`'s first line: `id 62, type ...`.
pub(crate) fn parse_inspect_id(out: &str) -> Option<u32> {
    let first = out.lines().next()?.trim();
    let rest = first.strip_prefix("id ")?;
    let digits = rest.split(',').next()?;
    // `parse` alone would accept "+5"; empty and too-long ids fail it.
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
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

    fn name(&mut self, id: u32) -> anyhow::Result<String> {
        parse_node_name(&Self::run(&["inspect", &id.to_string()])?)
            .ok_or_else(|| anyhow::anyhow!("no usable name for output {id}"))
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

    /// Outputs by id: muted or not, and their names.
    #[derive(Debug, Default)]
    pub(crate) struct Fake {
        pub(crate) muted: HashMap<u32, bool>,
        pub(crate) names: HashMap<u32, String>,
        pub(crate) default: u32,
        /// set_muted(true) does nothing.
        pub(crate) refuse: bool,
        /// The next this many set_muted(false) do nothing (a restore that
        /// does not take, as seen live).
        pub(crate) ignore_unmutes: usize,
        /// Every set_muted call, in order.
        pub(crate) changes: Vec<(u32, bool)>,
    }

    pub(crate) struct FakeMixer(pub(crate) Arc<Mutex<Fake>>);

    impl Mixer for FakeMixer {
        fn default_output(&mut self) -> anyhow::Result<u32> {
            Ok(self.0.lock().expect("fake").default)
        }
        fn name(&mut self, id: u32) -> anyhow::Result<String> {
            self.0
                .lock()
                .expect("fake")
                .names
                .get(&id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no output {id}"))
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
            if muted && f.refuse {
                return Ok(());
            }
            if !muted && f.ignore_unmutes > 0 {
                f.ignore_unmutes -= 1;
                return Ok(());
            }
            f.muted.insert(id, muted);
            Ok(())
        }
    }

    /// The note in memory; `fail`: writing it fails.
    #[derive(Debug, Default)]
    pub(crate) struct Noted {
        pub(crate) note: Option<(u32, String)>,
        pub(crate) fail: bool,
    }

    pub(crate) struct FakeNote(pub(crate) Arc<Mutex<Noted>>);

    impl Note for FakeNote {
        fn write(&mut self, id: u32, name: &str) -> anyhow::Result<()> {
            let mut n = self.0.lock().expect("note");
            anyhow::ensure!(!n.fail, "disk full");
            n.note = Some((id, name.to_owned()));
            Ok(())
        }
        fn read(&mut self) -> Option<(u32, String)> {
            self.0.lock().expect("note").note.clone()
        }
        fn clear(&mut self) {
            self.0.lock().expect("note").note = None;
        }
    }

    pub(crate) const SPEAKERS: &str = "alsa_output.pci-0000_00_1f.3.analog-stereo";

    pub(crate) fn fake(default: u32, muted: bool) -> Arc<Mutex<Fake>> {
        let mut f = Fake {
            default,
            ..Fake::default()
        };
        f.muted.insert(default, muted);
        f.names.insert(default, SPEAKERS.into());
        Arc::new(Mutex::new(f))
    }

    pub(crate) fn note() -> Arc<Mutex<Noted>> {
        Arc::new(Mutex::new(Noted::default()))
    }

    /// Mutes through fakes.
    pub(crate) fn mute(
        f: &Arc<Mutex<Fake>>,
        n: &Arc<Mutex<Noted>>,
    ) -> anyhow::Result<Option<SpeakersMuted>> {
        mute_speakers(
            Box::new(FakeMixer(Arc::clone(f))),
            Box::new(FakeNote(Arc::clone(n))),
        )
    }

    fn is_muted(f: &Arc<Mutex<Fake>>, id: u32) -> bool {
        f.lock().expect("fake").muted[&id]
    }

    fn noted(n: &Arc<Mutex<Noted>>) -> Option<(u32, String)> {
        n.lock().expect("note").note.clone()
    }

    #[test]
    fn a7_mutes_then_restores_the_same_output() {
        let (f, n) = (fake(62, false), note());
        let guard = mute(&f, &n).expect("mute");
        assert!(guard.is_some());
        assert!(is_muted(&f, 62), "speakers still playing");
        assert_eq!(
            noted(&n),
            Some((62, SPEAKERS.into())),
            "muted without a note"
        );
        // The person switches the default output mid-session.
        f.lock().expect("fake").default = 45;
        drop(guard);
        assert!(!is_muted(&f, 62), "the muted output was not restored");
        assert_eq!(noted(&n), None, "note kept after a verified restore");
    }

    #[test]
    fn a7_an_output_muted_by_the_person_stays_muted() {
        let (f, n) = (fake(62, true), note());
        let guard = mute(&f, &n).expect("mute");
        assert!(guard.is_none());
        drop(guard);
        assert!(is_muted(&f, 62), "un-muted what the person had muted");
        assert!(
            f.lock().expect("fake").changes.is_empty(),
            "touched it at all"
        );
        assert_eq!(noted(&n), None);
    }

    #[test]
    fn a7_a_mute_that_does_not_take_is_an_error() {
        let (f, n) = (fake(62, false), note());
        f.lock().expect("fake").refuse = true;
        assert!(mute(&f, &n).is_err());
        assert!(!is_muted(&f, 62));
        assert_eq!(noted(&n), None, "note left for a mute that never was");
    }

    #[test]
    fn a7_no_note_no_mute() {
        let (f, n) = (fake(62, false), note());
        n.lock().expect("note").fail = true;
        assert!(mute(&f, &n).is_err());
        assert!(
            f.lock().expect("fake").changes.is_empty(),
            "muted with nothing to repair it"
        );
    }

    #[test]
    fn a7_a_restore_that_does_not_take_is_retried() {
        let (f, n) = (fake(62, false), note());
        let guard = mute(&f, &n).expect("mute");
        f.lock().expect("fake").ignore_unmutes = 1;
        drop(guard);
        assert!(!is_muted(&f, 62), "one lost unmute left it muted");
        assert_eq!(noted(&n), None);
    }

    #[test]
    fn a7_a_restore_that_never_takes_keeps_the_note_and_the_next_start_repairs_it() {
        let (f, n) = (fake(62, false), note());
        let guard = mute(&f, &n).expect("mute");
        f.lock().expect("fake").ignore_unmutes = 2;
        drop(guard);
        assert!(is_muted(&f, 62));
        assert_eq!(
            noted(&n),
            Some((62, SPEAKERS.into())),
            "note lost: nothing can repair it"
        );
        // The next `serve`.
        let msg = repair_left_muted(
            &mut FakeMixer(Arc::clone(&f)),
            &mut FakeNote(Arc::clone(&n)),
        );
        assert!(msg.is_some_and(|m| m.contains("unmuted")));
        assert!(!is_muted(&f, 62), "not repaired");
        assert_eq!(noted(&n), None);
    }

    #[test]
    fn a7_repair_finds_the_output_by_name_after_a_restart() {
        // After a reboot the speakers have a new id (70); 62 is now
        // something else and must not be touched.
        let (f, n) = (fake(70, true), note());
        {
            let mut g = f.lock().expect("fake");
            g.names
                .insert(62, "bluez_output.68_52_10_93_BD_A4.1".into());
            g.muted.insert(62, true);
        }
        n.lock().expect("note").note = Some((62, SPEAKERS.into()));
        let msg = repair_left_muted(
            &mut FakeMixer(Arc::clone(&f)),
            &mut FakeNote(Arc::clone(&n)),
        );
        assert!(msg.is_some());
        assert!(
            !is_muted(&f, 70),
            "the speakers (by name) were not repaired"
        );
        assert!(
            is_muted(&f, 62),
            "unmuted another output that reused the number"
        );
    }

    #[test]
    fn a7_repair_leaves_alone_what_it_cannot_identify_or_what_plays() {
        // The noted output is gone and the default is something else.
        let (f, n) = (fake(70, true), note());
        f.lock().expect("fake").names.insert(70, "other".into());
        n.lock().expect("note").note = Some((62, SPEAKERS.into()));
        let msg = repair_left_muted(
            &mut FakeMixer(Arc::clone(&f)),
            &mut FakeNote(Arc::clone(&n)),
        );
        assert!(msg.is_some_and(|m| m.contains("nothing changed")));
        assert!(f.lock().expect("fake").changes.is_empty());
        assert_eq!(noted(&n), None, "a stale note is dropped");
        // Not muted any more (someone unmuted it): quietly forget.
        let (f, n) = (fake(62, false), note());
        n.lock().expect("note").note = Some((62, SPEAKERS.into()));
        assert_eq!(
            repair_left_muted(
                &mut FakeMixer(Arc::clone(&f)),
                &mut FakeNote(Arc::clone(&n))
            ),
            None
        );
        assert!(f.lock().expect("fake").changes.is_empty());
        assert_eq!(noted(&n), None);
        // No note: nothing at all.
        let (f, n) = (fake(62, true), note());
        assert_eq!(
            repair_left_muted(
                &mut FakeMixer(Arc::clone(&f)),
                &mut FakeNote(Arc::clone(&n))
            ),
            None
        );
        assert!(f.lock().expect("fake").changes.is_empty());
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
        let n = note();
        let guard = mute_speakers(Box::new(Wpctl), Box::new(FakeNote(Arc::clone(&n))))
            .expect("mute")
            .expect("guard");
        assert!(probe.muted(id).expect("read"), "not muted");
        drop(guard);
        assert!(!probe.muted(id).expect("read"), "not restored");
        assert_eq!(noted(&n), None);
    }

    #[test]
    fn a4_the_guard_prints_only_the_output_id() {
        let g = SpeakersMuted {
            mixer: Box::new(FakeMixer(fake(62, false))),
            note: Box::new(FakeNote(note())),
            id: 62,
        };
        assert_eq!(format!("{g:?}"), "SpeakersMuted(62)");
    }

    #[test]
    fn wpctl_answers_are_parsed_strictly() {
        assert_eq!(
            parse_inspect_id("id 62, type PipeWire:Interface:Node\n  x"),
            Some(62)
        );
        assert_eq!(parse_inspect_id("id 4000000000, type"), Some(4_000_000_000));
        for bad in [
            "",
            "id , type",
            "id 6x2, type",
            "62, type",
            "id 99999999999, t",
            "id -1, t",
            "id +5, t",
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

    #[test]
    fn node_names_and_notes_are_parsed_strictly() {
        let inspect = "id 62, type PipeWire:Interface:Node\n    media.class = \"Audio/Sink\"\n  * node.name = \"alsa_output.pci-0000_00_1f.3.analog-stereo\"\n";
        assert_eq!(parse_node_name(inspect).as_deref(), Some(SPEAKERS));
        let long = format!("node.name = \"{}\"", "a".repeat(MAX_NAME + 1));
        for bad in [
            "",
            "node.name = \"\"",
            "node.name = \"a b\"",
            "node.name = \"a|b\"",
            "node.name = \"a\"x",
            "node.name = a",
            long.as_str(),
        ] {
            assert_eq!(parse_node_name(bad), None, "{bad:?}");
        }
        assert_eq!(
            parse_note(&note_text(62, SPEAKERS)),
            Some((62, SPEAKERS.into()))
        );
        for bad in ["", "62", "|x", "x|y", "+6|y", "62|a b", "62|"] {
            assert_eq!(parse_note(bad), None, "{bad:?}");
        }
    }
}
