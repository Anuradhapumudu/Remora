# Notes: the Fedora laptop as a Remora host (Phase 4.6)

A guide to read later. It explains what was built on 2026-11-02, how to
run it, where everything lives, and every surprise we hit, with the
reason for each. The formal records are `docs/phase4.6-criteria.md` (§8
is the report), `results/phase4.6/` (plants and measurements), and the
decision log in `docs/architecture.md` (D47, D48). This page links them
together in plain words.

---

## 1. What works today

- The **Mac** runs `remora-viewer gui`, and the **Fedora 44 laptop**
  (GNOME 50 on Wayland, attached to the TV) runs `remora-host serve`.
- You see the laptop's screen in a window on the Mac at about 30–40 fps
  while something moves, and your mouse, keyboard and trackpad
  scrolling control it.
- Everything is end-to-end encrypted, the same way the Mac-to-Mac
  version is: password (SPAKE2), Noise handshake, safety code, and
  Accept/Deny at the host.
- GNOME shows its own orange "screen is shared" icon in the top bar.
  One click on it ends the session at once.
- **Not yet:** sound (D-51), a short connection code and saved devices
  (D-52), Mac volume keys (D-53), and the GNOME icon is hidden in
  full-screen apps (D-54).

## 2. How a session runs (step by step)

1. **Laptop:** the host starts and prints a long `code:` and a six-digit
   `password:`. The code holds the laptop's address, its identity key and
   a one-time number. **It expires after 5 minutes** and works once.
2. **Mac:** `remora-viewer gui`. Paste the code and type the password.
3. **Both sides show a six-digit safety code.** Compare them. If they
   match, nobody is in the middle. Only then type `accept <n>` at the
   host. **The host waits only 60 seconds** after the code appears; after
   that it refuses the viewer (shown as "the host declined").
4. **The first time ever,** GNOME asks on the laptop's screen to share
   the screen and allow remote control. Tick "remember". GNOME then gives
   Remora a *restore token* (a saved permission), so later sessions start
   with no dialog.
5. Click inside the video window to control the laptop. On the Mac,
   **⌘ is the laptop's Super (Windows) key**. Keys are sent by physical
   position, not by letter.
6. To end: close the window, type `disconnect <n>` at the host, or click
   GNOME's orange icon.

## 3. The laptop, practically

| Thing | Where / what |
|---|---|
| Address | Changes with the router. It has been 192.168.8.103 and 192.168.8.100. Check that the SSH fingerprint matches (`SHA256:zqGhmaAdmvxF6ONAN8Lc8hfvu+Vpund/UYSL11iDU58`) before trusting a new address |
| SSH without retyping the password | You open one shared connection yourself: `ssh -M -S ~/.ssh/remora-laptop -o ControlPersist=12h -fN pumudu@<ip>`. Commands then use `ssh -S ~/.ssh/remora-laptop pumudu@<ip> '…'`. Close it with `ssh -S ~/.ssh/remora-laptop -O exit pumudu@<ip>` |
| Source copy | `~/remora-src` (copied from the Mac with rsync, **never with `--delete` blind**: see §5) |
| Running files | `~/remora-run`: `remora-host` (the binary), `start.sh` and `start-timing.sh` (start the host in the GNOME session), `in` (a pipe: write `accept 1` into it to accept), `host.log`, `timing.log` |
| Start / stop / code from the Mac | `scripts/dev/laptop-host.sh start` (prints code and password), `code`, `status`, `stop` |
| Accept from the Mac | `scripts/dev/laptop-accept.sh 855732`: type the safety code **your viewer** shows. It accepts only if the laptop shows the same code and the viewer is still waiting; otherwise it refuses and does nothing. Developer tool for now (owner, 2026-11-02); the real answer for an unattended host is open in D-52 |
| Host identity key | `~/.config/Remora/host-identity.key` (0600, unencrypted for now: D-5) |
| Saved screen/control permission | `~/.config/Remora/portal-restore-token` (0600, never printed). Delete with `remora-host forget-permission`, or revoke in GNOME Settings → Privacy |
| Environment for GNOME | A host started over SSH needs `XDG_RUNTIME_DIR=/run/user/1000`, `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus` and `WAYLAND_DISPLAY=wayland-0` (`start.sh` sets them) |
| Wi-Fi | 2.4 GHz with **power saving on**, which made the round trip 54 ms typical and up to 277 ms (it should be 2–5 ms). Turning it off needs admin rights: `sudo iw dev wlo1 set power_save off` (now) and `sudo nmcli connection modify SLT-LTE-WiFi-E07A 802-11-wireless.powersave 2` (permanent; `0` undoes it) |

## 4. How it is built (the short version)

- **Input path (D47).** The viewer turns mouse and keys into `Input`
  messages: keys as USB HID usages, pointer as 0..1 fractions. These are
  sealed by Noise and checked on arrival (`decode_envelope`). One
  **`Guard` per Active session** on the host then:
  - remembers what is held and releases it when dropped (INV10);
  - drops keys outside our table;
  - ends the session on floods (2000 events/s, 32 held).

  `control.rs` creates the guard at Active and drops it on every way a
  session ends.
- **Linux screen + input (D48).** On GNOME Wayland an app may not grab
  the screen or inject input directly. It asks the **desktop portal**
  (xdg-desktop-portal over D-Bus):
  - ScreenCast gives a PipeWire stream of the monitor;
  - RemoteDesktop takes pointer and key events;
  - both are **one portal session**, because GNOME measures pointer
    positions against the screen-cast stream.

  This lives in `remora-capture/src/sys/linux.rs`. `remora-input`'s
  `PortalBackend` only converts units (HID → evdev, 0..1 → pixels).
- **Encoding.** openh264 in software (`remora-codec/src/sys/linux.rs`):
  pictures are converted BGRx → YUV 4:2:0 (BT.709, `yuv.rs`), then
  encoded at 4 Mbit/s with QP 20–34, the setting chosen by measurement
  (§6).
- **Recovery.** If a picture is lost, the viewer asks for a full
  picture (keyframe). GNOME sends nothing while the screen is still, so
  the host re-encodes the last picture as the keyframe after 40 ms
  (`stream.rs`, `repeat_when_still`).
- **Clock.** `remora_app::clock` reads `CLOCK_MONOTONIC` on Linux
  through `rustix`, with no unsafe code, so `--timing` works on the
  laptop.

## 5. Surprises we hit, and why (read these before changing things)

| What happened | Why | What we do now |
|---|---|---|
| The second viewer of a host run hung 120 s with no dialog | `ashpd` keeps **one D-Bus connection per process**, and zbus reads it on the tokio runtime it was created on. Each session had its own runtime; when the first ended, nobody read replies any more | One portal runtime for the whole process (`portal_runtime()`), with a test that opens three sessions in a row |
| Trackpad scrolling did nothing | Every scroll was sent with `finish = true` ("last event of the gesture"), so GNOME ignored the movement | `finish = false` while scrolling, and one closing event 150 ms after the last |
| Two mouse pointers | The laptop's pointer is drawn into the video, and the Mac's sat on top | The viewer hides the Mac pointer over the video window while it controls |
| Soft, blurry text | openh264's built-in default target is **120 kbit/s** | 4 Mbit/s, QP 20–34 (measured, §6) |
| Greys looked slightly yellow | The spike's colour coefficients (−26, −87, 112) summed to −1 | −86; a test checks every grey is exactly neutral |
| A dark/stale band while scrolling | A lost picture leaves the viewer waiting for a keyframe; on a still screen none came | Repeat the last picture as a keyframe (LP4: typical recovery 68 ms) |
| GNOME's Stop ended the session only on the next mouse move | Nobody watched the portal's "Closed" signal | The portal task tells the capture thread at once |
| The first GNOME dialog made the connection fail | Accepting opened the portal; the person's click took longer than the 60 s accept window | With the saved permission it no longer happens on this laptop. A proper fix comes with the GUI (D-52) |
| The saved permission was deleted | `rsync --delete` removed files on the laptop that the Mac doesn't have, including the token | Runtime files live in `~/remora-run`, outside the source copy. Dry-run (`rsync -n`) any sync that deletes |
| The policy test refused the token file code | Crates that handle screen content may not write files (so no picture can reach the disk) | `remora-capture` passes the token as a value; `remora_app::token_file` writes it |
| `pkill -f "tail -f in"` killed my own command | `pkill -f` matches its own shell's command line | Start and stop through small scripts, or `pkill -x <exact name>` |
| "cannot stream: … Could not activate remote peer 'org.freedesktop.portal.Desktop': startup job failed" (2026-11-03) | The laptop had restarted and sat at the **login screen**: only GDM's greeter on the display, no GNOME session for the user, so no Wayland socket and the portal's user service fails its dependencies (`systemctl --user status xdg-desktop-portal`: "Dependency failed") | Log in at the laptop, then restart the host. Remora (through the portals) can only share a **logged-in** desktop; reaching a login screen remotely is not possible today and would need GNOME's own remote-login service — not planned yet |
| A failing check was "committed anyway" twice | `check; git commit` and `check \| tail` hide the check's exit code | `if check; then commit; fi` |
| openh264 sent every test picture as a keyframe | Changing the whole picture is a "scene change", and openh264 answers it with an IDR | Test pictures change one pixel, as a still desktop does |
| Mutation testing broke source files for a while | `cargo mutants --in-place` edits the real files while it runs | Don't stop it mid-run; prefer a copy (`-o <dir>` without `--in-place`) |
| A test binary was stale after restoring a file | `mv` keeps the old modification time, so cargo didn't rebuild | `touch` the file after restoring it |

## 6. The numbers (2026-11-02)

| Target | Result |
|---|---|
| LP1: capture to encoded ≤ 20 ms (p95) | **34 ms**, not met. Software encoding while the laptop also plays video. The real fix is the Intel GPU encoder (VA-API needs RPM Fusion: owner's decision) |
| LP2: ≥ 30 fps | Met while the screen moves (30–44 fps). A still screen sends nothing, so idle seconds show low fps |
| LP3: input ≤ 2 ms per event | Met, about 0.5–1 ms (one D-Bus call) |
| LP4: recovery ≤ 200 ms | Typical (p50) 68 ms; worst 324 ms |
| Encoder bench (YouTube, 30 s) | 8 Mbit/s QP 10–36: up to 135 KB pictures. **4 Mbit/s QP 20–34: half the size**, about the same speed. The spike's 120 kbit/s: small but blurry |
| Wi-Fi round trip Mac → laptop | 54 ms typical, 277 ms worst (power saving on). This is most of the control lag you felt |

## 7. Security, in one table

| Rule | How it is enforced |
|---|---|
| Input only from an approved (Active) session | Session layer (A20/A21) **and** `control.rs`, which creates a guard only at Active |
| Every held key is released however a session ends | The guard releases on drop; tests cover each end path |
| Unknown keys never reach the OS | The generated key table (`scripts/dev/gen-keymap.py` from Apple's and Linux's header files) |
| Input is never sent unencrypted | `remora-net/tests/l7_input_sealed.rs` scans every frame for the plaintext |
| The saved permission stays secret | 0600 file, redacted `Debug`, never logged |
| "Someone is connected" is visible, and one click ends it | GNOME's orange icon; **hidden in full-screen apps (D-54)** |

Every one of these was tested by planting the real bug first and
seeing the test fail (`results/phase4.6/plants.md`).

## 8. Open questions and next steps

- **Who approves when nobody is at the laptop?** You want the host to
  always approve, but the laptop is in another room. Today the safety
  codes are compared and `accept` is typed over SSH. A proper answer
  (approve from a phone, an "unattended" mode with a strong password,
  or always needing a person there) is a decision for the "Connect
  simply" criteria.
- **Next phase, "Connect simply" (D-52):**
  - saved devices: reconnect without a password, the host still
    approves;
  - a short code found on the home Wi-Fi (mDNS, announcing only the
    device code, only while ready);
  - one app for sharing and connecting.

  Across the internet the short code needs the signalling server
  (Phase 8).
- **Then sound (D-51)**, then Mac volume keys (D-53).
- **Before a Linux host is released:** an indicator that stays visible
  in full-screen apps (D-54); a hardware encoder for LP1.
