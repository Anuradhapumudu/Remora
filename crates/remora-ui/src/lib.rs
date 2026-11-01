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
    import { Button, LineEdit, VerticalBox, HorizontalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: "Remora host";
        preferred-width: 560px;
        in property <string> device;
        in property <string> warning;
        in property <string> code;
        in property <string> password;
        in property <string> note;
        in property <bool> secrets-visible: true;
        in property <bool> session-active;
        in property <string> notice;
        in property <string> refused;
        in property <string> display;
        callback show-secrets();
        callback hide-secrets();
        VerticalBox {
            Text { text: "This computer: " + root.device; font-weight: 700; }
            Text { text: root.warning; wrap: word-wrap; color: #9a4d00; font-size: 11px; }
            if root.secrets-visible: VerticalLayout {
                spacing: 6px;
                Text { text: "To let someone see this screen, give them this code and password:"; wrap: word-wrap; }
                code-field := TextInput { text: root.code; read-only: true; single-line: false; wrap: char-wrap; font-size: 11px; }
                password-text := Text { text: "Password: " + root.password; font-size: 28px; }
                Text { text: root.note; wrap: word-wrap; }
            }
            if !root.secrets-visible: hidden-text := Text {
                text: "The code and password are hidden while someone is connected: your screen is being shown to them.";
                wrap: word-wrap;
            }
            if root.session-active: show-button := Button {
                text: root.secrets-visible ? "Hide code and password" : "Show code and password";
                clicked => { if (root.secrets-visible) { root.hide-secrets(); } else { root.show-secrets(); } }
            }
            Text { text: root.notice; wrap: word-wrap; color: #9a4d00; }
            Text { text: root.display; wrap: word-wrap; }
            Text { text: root.refused; wrap: word-wrap; font-size: 11px; }
        }
    }

    export component DialogWindow inherits Window {
        title: "Remora \u{2014} someone wants to see your screen";
        always-on-top: true;
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
                Text { text: "Someone wants to see your screen"; font-size: 18px; font-weight: 700; }
                Text { text: "Safety code"; }
                sas-text := Text { text: root.sas; font-size: 40px; font-weight: 700; }
                Text { text: "Accept only if the other person reads you the same code."; wrap: word-wrap; }
                device-text := Text { text: "Device ID: " + root.device + " (" + root.trust + ")"; }
                name-text := Text { text: "Name: " + root.name; wrap: word-wrap; }
                Text { text: "name chosen by the other computer, not checked"; font-size: 11px; color: #666666; }
                left-text := Text { text: "No answer in " + root.seconds-left + " s means deny."; }
                HorizontalBox {
                    deny-button := Button { text: "Deny"; clicked => { root.deny(); } }
                    accept-button := Rectangle {
                        min-width: 110px;
                        min-height: 32px;
                        border-radius: 6px;
                        background: root.accept-enabled ? #2a7d2e : #c8c8c8;
                        accessible-role: button;
                        accessible-label: "Accept";
                        accessible-enabled: root.accept-enabled;
                        accessible-action-default => { root.accept-accessible(); }
                        Text { text: "Accept"; color: white; font-weight: 700; }
                        accept-area := TouchArea {
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
        title: "Remora \u{2014} your screen is being shown";
        always-on-top: true;
        in property <string> text;
        in property <string> elapsed;
        in property <string> display;
        callback end-session();
        VerticalBox {
            indicator-text := Text { text: root.text; font-size: 16px; font-weight: 700; wrap: word-wrap; }
            Text { text: "for " + root.elapsed; }
            Text { text: root.display; wrap: word-wrap; }
            end-button := Button { text: "End session"; clicked => { root.end-session(); } }
        }
    }

    export component ViewerWindow inherits Window {
        title: "Remora viewer";
        preferred-width: 520px;
        in property <string> stage: "form";
        in-out property <string> code-text;
        in-out property <string> password-text;
        in property <string> host-device;
        in property <string> form-error;
        in property <string> sas;
        in property <string> verification;
        in property <bool> verified;
        in property <string> waiting;
        in property <string> display;
        in property <string> ended-text;
        callback code-edited(string);
        callback connect();
        callback codes-match();
        callback codes-differ();
        callback disconnect();
        callback new-connection();
        VerticalBox {
            if root.stage == "form": VerticalLayout {
                spacing: 8px;
                Text { text: "Connection code (from the host's window)"; }
                code-field := LineEdit {
                    placeholder-text: "paste the code";
                    text <=> root.code-text;
                    edited(t) => { root.code-edited(t); }
                }
                host-text := Text { text: root.host-device; wrap: word-wrap; }
                Text { text: "Password (6 digits shown at the host)"; }
                password-field := LineEdit { input-type: password; text <=> root.password-text; }
                error-text := Text { text: root.form-error; wrap: word-wrap; color: #b00020; }
                connect-button := Button { text: "Connect"; clicked => { root.connect(); } }
            }
            if root.stage == "connecting": VerticalLayout {
                spacing: 8px;
                Text { text: "Connecting\u{2026}"; }
                Button { text: "Cancel"; clicked => { root.disconnect(); } }
            }
            if root.stage == "comparing" || root.stage == "active": VerticalLayout {
                spacing: 8px;
                Text { text: root.stage == "active" ? "Connected: the screen is in the video window." : "Safety code"; }
                sas-text := Text { text: root.sas; font-size: 40px; font-weight: 700; }
                verification-text := Text { text: root.verification; wrap: word-wrap; }
                waiting-text := Text { text: root.waiting; wrap: word-wrap; }
                if !root.verified: HorizontalBox {
                    match-button := Button { text: "The codes match"; clicked => { root.codes-match(); } }
                    differ-button := Button { text: "They don't match"; clicked => { root.codes-differ(); } }
                }
                display-text := Text { text: root.display; wrap: word-wrap; font-size: 18px; }
                disconnect-button := Button { text: "Disconnect"; clicked => { root.disconnect(); } }
            }
            if root.stage == "ended": VerticalLayout {
                spacing: 8px;
                ended-message := Text { text: root.ended-text; wrap: word-wrap; }
                Button { text: "New connection"; clicked => { root.new-connection(); } }
            }
        }
    }
}
