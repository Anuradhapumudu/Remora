# Phase 4.7 (D-52): Connect simply — saved devices, a short code at home, one app — criteria

**Status: APPROVED by the owner, 2026-11-02**, with the recommended
answer to every decision in §2: Q1 "Person approves; script for now",
Q2 "Announce it with the code", Q3 "Mac first", and Q4 as drafted
("Approve 4.7 + accept 4.6"). Building may start with spike S-C1.
Decisions taken earlier the same day (roadmap D-52) are marked *(decided)*.
Sound (D-51) moves to Phase 4.8, after this one, as the owner chose.

## 0. What exists, and what is not verified yet

**Exists and is tested** (no new security mechanism is needed for the
core of this phase):

- **Device code**: every device has one, e.g. `7266 055 4675-2`. It is
  a truncated hash of the device's identity key, with a check digit
  (`remora_app::cli::short_code_of`). A viewer that asks for a device
  code refuses a host whose key does not hash to it (A16,
  `FailReason::IdentityMismatch`).
- **Trusted mode**: a viewer whose key the host lists connects without a
  password, by Noise with the pinned keys (A1). The host still prompts
  for every connection (threat model §4 item 6). Today the list is the
  host's `--trust` flag and is not saved.
- **Pinning**: a viewer that connects in trusted mode refuses a host
  whose key changed (A19, hard failure).
- **The GUI** (macOS, Phase 4.5) shows "known device" or "new device" in
  the host's Accept dialog.

**Not verified (spike S-C1, step 1, before any criteria item depends on it):**

- that mDNS works between the owner's Mac and the Fedora laptop on the
  home Wi-Fi. Some routers block multicast between Wi-Fi clients, and
  Fedora's firewall must allow UDP 5353 (expected in the Workstation
  zone, not checked);
- `mdns-sd`'s dependency tree and its `unsafe` (it is a pure-Rust mDNS
  crate: 7 M downloads, MIT/Apache; version 0.21.6 of 2026-10-19 is the
  newest that passes the 14-day rule today). All claims about it are to
  be read from its source;
- what macOS asks for: macOS 15+ shows a "Local Network" permission
  prompt the first time an app uses multicast. Expected, not checked.

## 1. Scope

**In:**

1. **Saved devices (viewer).** After a successful session the viewer
   offers "Save this computer". A saved entry holds:
   - the host's name (as the host announced it, untrusted text, shown
     escaped);
   - its device code and identity key;
   - its last address.

   A "Recent / Saved" list then reconnects with one click, in trusted
   mode: no password. The host still shows Accept/Deny every time
   *(decided)*.
2. **Known viewers (host).** A viewer can only reconnect without a
   password if **the host** remembers it too. So after the person at the
   host accepts a password session, the host offers "Remember this
   viewer (no password next time; you still approve each connection)".
   This is the host side of trusted mode, saved to a file. Forgetting
   is one action on each side.
3. **Short code on the home network.**
   - The host, **only while it is ready for a connection**, announces
     itself by mDNS with its **device code and a fresh connection nonce,
     never the computer's name** *(decided)*.
   - The viewer types the device code (or picks a saved device); it
     finds the address on the home network and connects.
   - The device code check (A16) refuses an impostor that answers mDNS
     with someone else's code.
   - Across the internet a short code needs remora-signal (Phase 8);
     this phase is the home network only.
4. **One app.** One Remora app with two sides, "Share this computer"
   and "Connect to a computer", replaces today's two apps on the Mac
   (§2 Q3 for Linux).

**Out:** internet connections without the long code (Phase 8),
unattended access with no person at the host (§2 Q1 decides only the
interim), a Linux GUI unless Q3 chooses it, sound (Phase 4.8).

## 2. Decisions for the owner (recommendation first)

| # | Question | Recommendation | Why |
|---|---|---|---|
| Q1 | **Who approves when nobody is at the host?** (the laptop is in another room) | **Keep "a person approves" as the rule.** For your own two computers, the interim is `scripts/dev/laptop-accept.sh`: it compares safety codes and accepts over your SSH. That is a developer tool, not a feature. A real "approve from my phone/Mac" feature is designed with Phase 8's server | Approval by the person at the host is what stops a stolen password from being enough (INV1). Moving approval elsewhere is a new security design, not a shortcut |
| Q2 | Where does the connection nonce come from for a short-code connection? | **Announced with the device code**, replaced after each use (it is not secret: today it travels inside the copy-paste code) | Keeps the protocol unchanged (protocol.md §2: nonce single-use on the host, 5-minute life). Anyone on the Wi-Fi can read it, but it protects against replay, not secrecy; the password and approval still decide |
| Q3 | One app on Linux too? | **Mac first**: one Remora.app (share + connect). The Linux host stays a terminal app this phase, gaining "remember viewer" / "forget viewer" commands | A Linux GUI means Slint on Wayland plus a Linux video window: a phase of its own. The owner's own setup (Mac views, laptop shares) is fully covered |
| Q4 | Saved-device files | **`saved-devices` (viewer) and `known-viewers` (host)** in the Remora config folder, owner-only (0600), next to the key file | Public keys are not secret, but who connects to whom is private. Same protections as the key file (D-5 keychain move covers all three later) |

## 3. Security requirements (each gets a test seen failing)

| ID | Requirement | Test |
|---|---|---|
| C1 | A saved device reconnects **only** in trusted mode against the **saved key**. A changed key is a hard failure that says so (A19), never a silent re-save | integration; plant: re-save on mismatch |
| C2 | The host's known-viewers list changes only by an action of the person at the host (accept + "remember", or forget). A viewer can never add itself | unit + integration; plant: auto-add on accept |
| C3 | A remembered viewer still gets the Accept/Deny prompt, every time | integration; plant: auto-approve known viewers |
| C4 | mDNS answers are untrusted input: size-limited before parsing, fuzzed. An answer for the asked code whose host key does not hash to that code is refused (A16) | unit + fuzz target `mdns_record`; integration with a fake announcer using another key |
| C5 | The host announces **only** while ready for a connection, only `{device code, nonce, port}`, never the name; it stops on close and while a session is Active (H9) | unit on the announced record; manual `dns-sd -B` check |
| C6 | Saved-device and known-viewer files: 0600 created, refused if others can read them (like the key file), size-limited | unit; plant: 0644 |
| C7 | Forgetting works on both sides and is immediate: a forgotten viewer gets AUTH_FAILED in trusted mode (it may still use a password + approval) | integration |
| C8 | Names in the lists are untrusted text, escaped where shown (H6) | existing H6 tests extended |

## 4. Targets

| ID | Target |
|---|---|
| CU1 | Reconnecting to a saved device: one click on the viewer, then Accept at the host. No code, no password |
| CU2 | Short code at home: the viewer finds the host within 2 s of typing the device code |
| CU3 | Nothing is announced on the network while the host is not ready (checked with `dns-sd -B _remora._udp` on the Mac) |

## 5. Dependencies

`mdns-sd` (version chosen by the 14-day check, expected 0.21.6),
pending S-C1's reading of its source and dependency tree. `serde_json`
is **not** in the lock (checked 2026-11-02: only `serde` 1.0.229 is), so
the two list files use a small hand-written line format (one device per
line, fixed fields, size-checked) with a fuzz target, rather than a new
dependency.

## 6. Build order (test first)

1. Criteria approved; spike S-C1 (mDNS on the home Wi-Fi, Mac ↔ laptop;
   macOS Local Network prompt; firewall); roadmap row.
2. Device and known-viewer stores (`remora-app`): C6, C8.
3. Host side: "remember / forget viewer" (CLI on Linux, GUI on Mac): C2, C3, C7.
4. Viewer side: saved devices and trusted reconnect: C1, CU1.
5. mDNS announce and lookup: C4, C5, CU2, CU3.
6. One app on the Mac (share + connect).
7. Live test Mac ↔ laptop; report; roadmap.

## 6b. Scope change (owner, 2026-11-02): "Close 4.7 lean, then sound"

Item 4 of §1 (one app on the Mac) and build step 6 move out of this
phase to roadmap D-55, after sound (Phase 4.8). Phase 4.7 closes with the
terminal apps, which already do everything else: `remora-viewer connect
--device <code> [--save]`, `saved`, `forget`; `remora-host serve`
(announcing), `remember`, `forget`, `known`. CU1 is met in the terminal
(one command, no password, host approves); its "one click" wording
belongs to D-55.

## 6a. Clarification while building (2026-11-02)

C5 says the host announces `{device code, nonce, port}`. Built, the
announcement is: instance name = the device code, TXT `id` = the full
80-bit device ID that code is computed from, `nonce`, `v`, and the port.
The full ID is the same identifier in its long form (every host already
sends it in its hello), not the computer's name. It is what lets the
viewer connect *expecting that exact ID*, so the handshake's A16 check
refuses a host whose key does not match. A short code alone is "an
address, not a credential" (`remora_crypto::identity::ShortCode`).

## 7. Known limitations (stated plainly)

- Short codes work on the home network only until Phase 8.
- Someone else on the same Wi-Fi can see that a Remora host is ready,
  and its device code, while it waits. Not its name, and they still need
  a password (or a remembered key) and the host's Accept.
- With nobody at the host, approving still needs the developer script
  (Q1) until a real remote-approval design exists.

## 8. Report (2026-11-02)

**Result:** on the owner's home Wi-Fi the Mac connects to the Fedora
laptop by its short device code alone, saves it, and reconnects with no
password while the laptop still asks for approval. All in the terminal
apps; the one-app GUI moved to D-55 (§6b). Commits b2f615f … fce32c5.
Plants: `results/phase4.7/plants.md`; numbers:
`results/phase4.7/measurements.md`; spike:
`spikes/connect-mdns/results/sc1-20261102.txt`.

### Security requirements

| ID | Status | Evidence |
|---|---|---|
| C1 | **Met** | `crates/remora-viewer/src/main.rs::c1_tests::c1_saved_computers_are_pinned_and_a_changed_identity_is_refused` (another key, or another ID with the same short code, is a hard stop; plant "always same" caught). The handshake also pins the saved key (trusted mode) |
| C2 | **Met** | `crates/remora-host/src/serve.rs::c2_tests::c2_accepting_never_remembers_only_the_remember_command_does` (plant auto-remember caught) |
| C3 | **Met** | `crates/remora-host/src/serve.rs::c3_tests::c3_a_remembered_viewer_waits_for_accept_in_the_host_app` (real viewer, real host app; plant auto-approve caught); `crates/remora-net/tests/c3_c7_known_viewers.rs`; live: prompt 3 on the laptop for the saved Mac viewer |
| C4 | **Met** | `crates/remora-net/src/discovery.rs` tests (limits at both sides of each boundary, signed hex, name ≠ ID's code); fuzz target `mdns_record`; real-network test that an oversized announcement is ignored; plant (name check removed) caught |
| C5 | **Met** | `crates/remora-net/tests/cu2_discovery.rs` (withdraw and drop make the host unfindable; plant no-op withdraw caught); `dns-sd`: seen while ready, not during a session, seen after |
| C6 | **Met** | `crates/remora-app/src/devices.rs` tests (0600 file, 0700 folder, refused when others can read, limits, exact boundaries); fuzz target `device_list`; three plants caught |
| C7 | **Met** | `crates/remora-net/tests/c3_c7_known_viewers.rs::c7_a_forgotten_viewer_is_refused_in_trusted_mode_at_once`; `crates/remora-session/tests/flow.rs::c7_set_trusted_remembers_and_forgets_for_the_next_connection` (plants caught) |
| C8 | **Met** | `crates/remora-viewer/src/main.rs::c8_tests::c8_saved_names_are_shown_escaped`, `crates/remora-host/src/serve.rs::c8_tests::c8_known_viewer_names_are_shown_escaped` (raw-name plants showed a forged second line; caught) |

### Targets

| ID | Result |
|---|---|
| CU1 | **Met in the terminal**: `connect --device <code>` reconnects a saved computer with no password; the host approves (live). "One click" is D-55's GUI |
| CU2 | **Met**: laptop found from the Mac in 0.07–1.1 s (spike), 1.09 s (test). A host that has just started is silent for a few seconds; the viewer looks for 8 s |
| CU3 | **Met**: `dns-sd` sees nothing from a host while its session is Active |

### Mutation testing (focused runs)

`devices.rs`: first 47 caught / **12 missed** (real gaps; tests added),
then **56 caught / 0 missed**. `discovery.rs`: first 40 caught / **13
missed** (boundaries, a masked sign test, the network side; tests added;
`is_announcing` removed as unused), rerun **51 caught / 0 missed** (5 unviable; real-network tests included, one at a time).
`set_trusted`: session 1/1, net 1/1 caught.

### Found while building

- Re-registering the announcement after every connection attempt made the
  host silent for seconds while mDNS checked its name again: it is now
  updated in place (mdns-sd's own docs).
- Closing the viewer with Ctrl-C left the host "busy" for 30 s, so it did
  not announce itself: Ctrl-C now says goodbye.
- An integer parser accepting `+` signs (Rust's `from_str_radix`) meant our
  hex pre-checks were the only defence: now tested everywhere we parse hex.
- The first C3 plant (in remora-net) deadlocked instead of failing and did
  not count; the host-app plant replaced it.

### Manual steps (as the owner ran them)

1. Laptop: `remora-host serve --bind <ip>:0` (prints `announce: …`).
2. Mac: `remora-viewer connect --device "7266 055 4675-2" --save`, type
   the password, compare safety codes; at the host `accept <n>`, then
   `remember <n>`.
3. Ctrl-C the viewer. Then `remora-viewer connect --device "7266 055
   4675-2"`: no password asked; compare codes; `accept <n>` at the host.
4. `remora-viewer saved` / `forget <code>`; host `known` / `forget <code>`.

### Known limitations

- Home network only; across the internet the short code needs Phase 8.
- Someone on the same Wi-Fi can see that a Remora host is ready and its
  device code (never its name).
- Approving with nobody at the host still uses the developer script (Q1).
- The one Mac app, with buttons for all of this, is D-55.

### Deferred items, row by row

- **D-52** (Connect simply): delivered as above in the terminal apps;
  closes when the owner accepts this phase.
- **D-55** (one Mac app): new, after sound.
- **D-51** sound: next (Phase 4.8). D-53, D-54 unchanged.
