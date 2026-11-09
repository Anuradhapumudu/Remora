//! Remora's GUI screens (phase4.5-criteria §4-§6), as Slint markup only.
//!
//! Architecture D45 (owner, 2026-11-01): the Rust that Slint generates from
//! this markup contains `unsafe` blocks (`const-field-offset`'s
//! `FieldOffsets`, with `#[allow(unsafe_code)]`), so this crate cannot use
//! `#![forbid(unsafe_code)]`; the workspace's `unsafe_code = "deny"` still
//! applies to anything written here. Nothing but markup and `pub use` may
//! live in this crate: the policy scanner (`remora-testkit`) enforces it.
//! `remora-host` and `remora-viewer` keep `forbid(unsafe_code)` and only use
//! the components' generated safe API.
//!
//! The screens decide nothing: every rule (who may be accepted, when Accept
//! is armed, what is shown when) is in `remora_app::decide`. Accept reports
//! the pointer's raw press and release so H4 is that module's rule.
//!
//! macOS only until Phase 6.5; on other systems the crate is empty.

#![cfg(target_os = "macos")]
// The components and their accessors are generated from the markup and cannot
// carry doc comments; each one is described in the markup and in the
// glue that drives it (remora-host / remora-viewer `gui.rs`).
#![allow(missing_docs)]

slint::slint! {
    import { Button, LineEdit, VerticalBox, HorizontalBox, GroupBox, Palette } from "std-widgets.slint";

    // UI/UX pass (owner, 2026-11-01; phase4.5-criteria §16): one clear task
    // per window, the most important thing largest, status always visible,
    // plain sentences, details on request.

    export component MainWindow inherits Window {
        title: "Remora \u{2014} share this screen";
        preferred-width: 520px;
        min-width: 420px;
        in property <string> device;
        in property <string> warning;
        in property <string> code;
        in property <string> password;
        in property <string> note;
        in property <string> status: "Waiting for someone to connect.";
        in property <bool> secrets-visible: true;
        in property <bool> session-active;
        in property <string> notice;
        in property <string> refused;
        in property <string> display;
        in-out property <bool> warning-details: false;
        callback show-secrets();
        callback hide-secrets();
        VerticalBox {
            spacing: 12px;
            status-text := Text { text: root.status; font-size: 15px; font-weight: 600; wrap: word-wrap; }
            if root.notice != "": Text { text: root.notice; wrap: word-wrap; color: #c0392b; }
            if root.display != "": Text { text: root.display; wrap: word-wrap; }
            if root.secrets-visible: GroupBox {
                title: "Give these to the person who will see your screen";
                VerticalLayout {
                    spacing: 6px;
                    Text { text: "Connection code"; color: Palette.foreground.with-alpha(0.7); font-size: 12px; }
                    HorizontalLayout {
                        spacing: 8px;
                        code-field := TextInput {
                            text: root.code; read-only: true; single-line: false; wrap: char-wrap;
                            font-size: 12px; font-family: "Menlo";
                        }
                        copy-button := Button {
                            text: "Copy";
                            clicked => { code-field.select-all(); code-field.copy(); code-field.clear-selection(); }
                        }
                    }
                    Text { text: "Password"; color: Palette.foreground.with-alpha(0.7); font-size: 12px; }
                    password-text := Text { text: root.password; font-size: 34px; font-weight: 700; font-family: "Menlo"; }
                    if root.note != "": Text { text: root.note; wrap: word-wrap; font-size: 12px; }
                }
            }
            if !root.secrets-visible: hidden-text := Text {
                text: "The code and password are hidden while your screen is being shared, so the viewer cannot see them.";
                wrap: word-wrap;
            }
            if root.session-active: show-button := Button {
                text: root.secrets-visible ? "Hide code and password" : "Show code and password";
                clicked => { if (root.secrets-visible) { root.hide-secrets(); } else { root.show-secrets(); } }
            }
            if root.refused != "": Text { text: root.refused; wrap: word-wrap; font-size: 12px; }
            HorizontalLayout {
                spacing: 8px;
                Text { text: "This computer: " + root.device; font-size: 12px; color: Palette.foreground.with-alpha(0.7); vertical-alignment: center; }
                Rectangle { }
            }
            HorizontalLayout {
                spacing: 6px;
                Text {
                    text: "Development build: this computer\u{2019}s keys are stored unencrypted.";
                    font-size: 11px; color: #b9770e; wrap: word-wrap; vertical-alignment: center;
                }
                Button { text: root.warning-details ? "Hide details" : "Details"; clicked => { root.warning-details = !root.warning-details; } }
            }
            if root.warning-details: warning-text := Text { text: root.warning; wrap: word-wrap; font-size: 11px; color: #b9770e; }
        }
    }

    export component DialogWindow inherits Window {
        title: "Remora \u{2014} someone wants to see your screen";
        always-on-top: true;
        preferred-width: 420px;
        in property <string> sas;
        in property <string> name;
        in property <string> device;
        in property <string> trust;
        in property <int> seconds-left;
        in property <bool> accept-enabled;
        callback accept-pressed();
        callback accept-released();
        callback accept-cancelled();
        callback accept-accessible();
        callback deny();
        callback key-deny();
        forward-focus: keys;
        keys := FocusScope {
            key-pressed(event) => {
                if (event.text == Key.Return || event.text == " " || event.text == Key.Escape) {
                    root.key-deny();
                    return accept;
                }
                return reject;
            }
            VerticalBox {
                spacing: 10px;
                Text { text: "Someone wants to see your screen"; font-size: 18px; font-weight: 700; }
                Text { text: "Ask them to read you the code on their screen. Accept only if it is exactly this one:"; wrap: word-wrap; }
                sas-text := Text { text: root.sas; font-size: 44px; font-weight: 700; font-family: "Menlo"; horizontal-alignment: center; }
                GroupBox {
                    title: "Who is asking";
                    VerticalLayout {
                        spacing: 4px;
                        device-text := Text { text: "Device ID: " + root.device + " (" + root.trust + ")"; }
                        name-text := Text { text: "Name: " + root.name; wrap: word-wrap; }
                        Text { text: "The name is chosen by the other computer and not checked."; font-size: 11px; color: Palette.foreground.with-alpha(0.6); wrap: word-wrap; }
                    }
                }
                left-text := Text { text: "Denied automatically in " + root.seconds-left + " s."; font-size: 12px; color: Palette.foreground.with-alpha(0.7); }
                HorizontalLayout {
                    spacing: 10px;
                    deny-button := Button { text: "Deny"; clicked => { root.deny(); } }
                    accept-button := Rectangle {
                        min-width: 120px;
                        min-height: 30px;
                        border-radius: 6px;
                        background: root.accept-enabled ? #2a7d2e : #8a8a8a;
                        opacity: root.accept-enabled ? 1 : 0.6;
                        accessible-role: button;
                        accessible-label: "Accept";
                        accessible-enabled: root.accept-enabled;
                        accessible-action-default => { root.accept-accessible(); }
                        Text { text: "Accept"; color: white; font-weight: 700; }
                        accept-area := TouchArea {
                            mouse-cursor: root.accept-enabled ? pointer : not-allowed;
                            pointer-event(event) => {
                                if (event.button == PointerEventButton.left) {
                                    if (event.kind == PointerEventKind.down) {
                                        root.accept-pressed();
                                    } else if (event.kind == PointerEventKind.up) {
                                        if (self.has-hover) { root.accept-released(); } else { root.accept-cancelled(); }
                                    } else if (event.kind == PointerEventKind.cancel) {
                                        root.accept-cancelled();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    export component SessionWindow inherits Window {
        title: "Remora \u{2014} sharing your screen";
        always-on-top: true;
        preferred-width: 340px;
        min-width: 300px;
        min-height: 150px;
        in property <string> text;
        in property <string> elapsed;
        in property <string> display;
        callback end-session();
        VerticalBox {
            spacing: 8px;
            HorizontalLayout {
                spacing: 8px;
                Rectangle { width: 12px; height: 12px; border-radius: 6px; background: #e74c3c; y: (parent.height - self.height) / 2; }
                indicator-text := Text { text: root.text; font-size: 15px; font-weight: 700; wrap: word-wrap; vertical-alignment: center; }
            }
            Text { text: "Shared for " + root.elapsed; font-size: 12px; color: Palette.foreground.with-alpha(0.7); }
            if root.display != "": Text { text: root.display; wrap: word-wrap; font-size: 12px; }
            end-button := Button { text: "End session"; primary: true; clicked => { root.end-session(); } }
        }
    }

    export component ViewerWindow inherits Window {
        title: "Remora \u{2014} connect to a computer";
        preferred-width: 460px;
        min-width: 380px;
        in property <string> stage: "form";
        in-out property <string> code-text;
        in-out property <string> password-text;
        in property <string> host-device;
        in property <string> form-error;
        in property <bool> can-connect;
        in property <string> sas;
        in property <string> verification;
        in property <bool> verified;
        in property <string> waiting;
        in property <string> display;
        in property <string> ended-text;
        callback code-edited(string);
        callback password-edited(string);
        callback connect();
        callback codes-match();
        callback codes-differ();
        callback disconnect();
        callback new-connection();
        VerticalBox {
            spacing: 10px;
            if root.stage == "form": VerticalLayout {
                spacing: 8px;
                Text { text: "Connect to a computer"; font-size: 18px; font-weight: 700; }
                Text { text: "Ask the person at the other computer for their connection code and password."; wrap: word-wrap; color: Palette.foreground.with-alpha(0.7); }
                Text { text: "Connection code"; font-size: 12px; }
                code-field := LineEdit {
                    placeholder-text: "remora1:\u{2026} (paste it here)";
                    text <=> root.code-text;
                    edited(t) => { root.code-edited(t); }
                }
                if root.host-device != "": host-text := Text { text: root.host-device; wrap: word-wrap; color: #27ae60; font-size: 12px; }
                Text { text: "Password"; font-size: 12px; }
                password-field := LineEdit {
                    input-type: password;
                    placeholder-text: "6 digits";
                    text <=> root.password-text;
                    edited(t) => { root.password-edited(t); }
                    accepted => { if (root.can-connect) { root.connect(); } }
                }
                if root.form-error != "": error-text := Text { text: root.form-error; wrap: word-wrap; color: #c0392b; }
                connect-button := Button { text: "Connect"; primary: true; enabled: root.can-connect; clicked => { root.connect(); } }
            }
            if root.stage == "connecting": VerticalLayout {
                spacing: 8px;
                Text { text: "Connecting\u{2026}"; font-size: 16px; }
                Button { text: "Cancel"; clicked => { root.disconnect(); } }
            }
            if root.stage == "comparing" || root.stage == "active": VerticalLayout {
                spacing: 8px;
                Text {
                    text: root.stage == "active" ? "Connected. The other screen is in the video window." : "Read this code to the person at the other computer:";
                    wrap: word-wrap;
                }
                sas-text := Text { text: root.sas; font-size: 44px; font-weight: 700; font-family: "Menlo"; horizontal-alignment: center; }
                verification-text := Text { text: root.verification; wrap: word-wrap; color: root.verified ? #27ae60 : #b9770e; }
                if root.waiting != "": waiting-text := Text { text: root.waiting; wrap: word-wrap; font-size: 12px; }
                if !root.verified: HorizontalLayout {
                    spacing: 8px;
                    match-button := Button { text: "The codes match"; clicked => { root.codes-match(); } }
                    differ-button := Button { text: "They don't match"; clicked => { root.codes-differ(); } }
                }
                if root.display != "": display-text := Text { text: root.display; wrap: word-wrap; font-size: 16px; }
                disconnect-button := Button { text: "Disconnect"; clicked => { root.disconnect(); } }
            }
            if root.stage == "ended": VerticalLayout {
                spacing: 8px;
                ended-message := Text { text: root.ended-text; wrap: word-wrap; font-size: 15px; }
                Button { text: "New connection"; primary: true; clicked => { root.new-connection(); } }
            }
        }
    }
}
