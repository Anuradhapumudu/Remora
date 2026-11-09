//! Spike S-L2 (throwaway, D-50): can Remora inject input on GNOME Wayland
//! through the RemoteDesktop portal, and can the person's permission be
//! saved (restore token) so later sessions need no click at the laptop?
//!
//! Local only: nothing from the network drives input here. It moves the
//! pointer in a small square and taps Left Shift (harmless: no clicks, no
//! characters), and measures how long each portal call takes.
//!
//! Proof that the input arrived: GNOME's idle monitor (read by the run
//! script with `gdbus`) drops to ~0 after the moves.

use std::time::Instant;

use ashpd::desktop::PersistMode;
use ashpd::desktop::remote_desktop::{DeviceType, KeyState, RemoteDesktop, SelectDevicesOptions};
use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};

/// evdev KEY_LEFTSHIFT (linux/input-event-codes.h).
const KEY_LEFTSHIFT: i32 = 42;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token_path = std::path::PathBuf::from("rd-restore-token");
    let token = std::fs::read_to_string(&token_path).ok().map(|s| s.trim().to_owned());
    eprintln!(
        "portal: restore token {}",
        if token.is_some() { "present" } else { "absent (GNOME will ask)" }
    );

    let rd = RemoteDesktop::new().await?;
    let sc = Screencast::new().await?;
    eprintln!("portal: RemoteDesktop version {}", rd.version());
    eprintln!("portal: device types offered {:?}", rd.available_device_types().await?);
    let session = rd.create_session(Default::default()).await?;
    rd.select_devices(
        &session,
        SelectDevicesOptions::default()
            .set_devices(DeviceType::Keyboard | DeviceType::Pointer)
            .set_persist_mode(PersistMode::ExplicitlyRevoked)
            .set_restore_token(token.as_deref()),
    )
    .await?;
    // Absolute pointer motion is relative to a screen-cast stream, so the
    // same session also selects the monitor (as the real host will).
    sc.select_sources(
        &session,
        SelectSourcesOptions::default()
            .set_cursor_mode(CursorMode::Embedded)
            .set_sources(ashpd::enumflags2::BitFlags::from_flag(SourceType::Monitor))
            .set_multiple(false),
    )
    .await?;
    let asked = Instant::now();
    let started = rd.start(&session, None, Default::default()).await?.response()?;
    eprintln!("portal: answered in {:.1} s", asked.elapsed().as_secs_f64());
    eprintln!("portal: devices granted {:?}", started.devices());
    match started.restore_token() {
        Some(new) => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&token_path)?;
            f.write_all(new.as_bytes())?;
            eprintln!("portal: restore token saved");
        }
        None => eprintln!("portal: NO restore token returned (permission not saved)"),
    }
    let stream = started.streams().first().ok_or("no stream")?;
    let node = stream.pipe_wire_node_id();
    let (w, h) = stream.size().map(|(w, h)| (w as f64, h as f64)).unwrap_or((1920.0, 1080.0));
    eprintln!("portal: stream node {node}, size {w}x{h}");

    // A small square around the centre, 4 rounds, 10 ms apart.
    let mut call_us = Vec::new();
    let (cx, cy, r) = (w / 2.0, h / 2.0, 100.0);
    for round in 0..4 {
        for (x, y) in [(cx - r, cy - r), (cx + r, cy - r), (cx + r, cy + r), (cx - r, cy + r)] {
            let t = Instant::now();
            rd.notify_pointer_motion_absolute(&session, node, x, y, Default::default()).await?;
            call_us.push(t.elapsed().as_micros() as u64);
            tokio::time::sleep(std::time::Duration::from_millis(10 + round)).await;
        }
    }
    let t = Instant::now();
    rd.notify_keyboard_keycode(&session, KEY_LEFTSHIFT, KeyState::Pressed, Default::default()).await?;
    rd.notify_keyboard_keycode(&session, KEY_LEFTSHIFT, KeyState::Released, Default::default()).await?;
    let key_us = t.elapsed().as_micros();
    call_us.sort_unstable();
    let p = |q: f64| call_us[((call_us.len() - 1) as f64 * q) as usize];
    println!(
        "RESULT sl2: {} pointer moves, call p50 {} us p95 {} us max {} us; shift press+release {} us",
        call_us.len(),
        p(0.5),
        p(0.95),
        call_us[call_us.len() - 1],
        key_us
    );
    session.close().await?;
    Ok(())
}
