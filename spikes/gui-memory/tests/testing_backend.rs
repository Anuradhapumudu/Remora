//! S1 question for D-4: can a plain Rust test drive a Slint UI — find a
//! button, see whether it is enabled/visible, press it, and move time on
//! (mock time) — without a display? Also: what does Slint's own Button do
//! with a press that starts while it is disabled and is released after it
//! becomes enabled (H4)?

use i_slint_backend_testing as testing;
use slint::platform::{PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition};
use std::time::Duration;

slint::slint! {
    import { Button } from "std-widgets.slint";
    export component Dialog inherits Window {
        width: 300px; height: 200px;
        in property <bool> session-active;
        in-out property <bool> armed: false;
        in-out property <int> accepted: 0;
        in-out property <int> ended: 0;
        Timer { interval: 1s; running: !root.armed; triggered => { root.armed = true; } }
        accept := Button { x: 20px; y: 20px; width: 120px; height: 40px;
            text: "Accept"; enabled: root.armed; clicked => { root.accepted += 1; } }
        if root.session-active: indicator := Rectangle { x: 0; y: 100px; width: 300px; height: 60px;
            end := Button { text: "End session"; clicked => { root.ended += 1; } } }
    }
}

fn center(d: &Dialog, id: &str) -> LogicalPosition {
    let h = testing::ElementHandle::find_by_element_id(d, id).next().expect(id);
    let (p, s) = (h.absolute_position(), h.size());
    LogicalPosition::new(p.x + s.width / 2.0, p.y + s.height / 2.0)
}

#[test]
fn testing_backend_drives_buttons_visibility_and_time() {
    testing::init_integration_test_with_mock_time();
    let d = Dialog::new().unwrap();
    d.show().unwrap();
    let accept = testing::ElementHandle::find_by_element_id(&d, "Dialog::accept").next().unwrap();

    // Before 1 s: disabled, a click does nothing.
    assert_eq!(accept.accessible_enabled(), Some(false));
    accept.mock_single_click(PointerEventButton::Left);
    assert_eq!(d.get_accepted(), 0, "click before arming accepted");

    // Press at 0.9 s, release at 1.2 s (H4): does Slint's Button click?
    testing::mock_elapsed_time(Duration::from_millis(900));
    let pos = center(&d, "Dialog::accept");
    d.window().dispatch_event(WindowEvent::PointerMoved { position: pos });
    d.window().dispatch_event(WindowEvent::PointerPressed { position: pos, button: PointerEventButton::Left });
    testing::mock_elapsed_time(Duration::from_millis(300));
    assert!(d.get_armed(), "timer did not arm at 1 s");
    d.window().dispatch_event(WindowEvent::PointerReleased { position: pos, button: PointerEventButton::Left });
    println!("H4 press-before/release-after: accepted = {}", d.get_accepted());

    // After arming: a full click accepts once.
    let before = d.get_accepted();
    accept.mock_single_click(PointerEventButton::Left);
    assert_eq!(d.get_accepted(), before + 1, "armed click did not accept");

    // Indicator visible exactly while the session is active (I1), End works (I2).
    assert_eq!(testing::ElementHandle::find_by_element_id(&d, "Dialog::indicator").count(), 0);
    d.set_session_active(true);
    assert_eq!(testing::ElementHandle::find_by_element_id(&d, "Dialog::indicator").count(), 1);
    let end = testing::ElementHandle::find_by_element_id(&d, "Dialog::end").next().unwrap();
    end.invoke_accessible_default_action();
    assert_eq!(d.get_ended(), 1, "End session not pressed");
}
