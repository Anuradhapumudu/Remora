//! I3 on real AppKit (architecture D46): opens a window, puts it on every
//! Space, prints the flags AppKit reports and exits. Whether it then stays
//! visible over a full-screen app is manual step M3.
//!
//!     cargo run -p remora-input --example all_spaces
#![allow(clippy::unwrap_used, clippy::expect_used)] // a dev check: a panic is how it fails

#[cfg(target_os = "macos")]
fn main() {
    use remora_input::window::{CAN_JOIN_ALL_SPACES, FULL_SCREEN_AUXILIARY, show_on_all_spaces};
    use winit::application::ApplicationHandler;
    use winit::event::WindowEvent;
    use winit::event_loop::{ActiveEventLoop, EventLoop};
    use winit::raw_window_handle::HasWindowHandle;
    use winit::window::{Window, WindowId};

    struct App(Option<Window>);
    impl ApplicationHandler for App {
        fn resumed(&mut self, el: &ActiveEventLoop) {
            let w = el
                .create_window(Window::default_attributes().with_title("I3 check"))
                .unwrap();
            let raw = w.window_handle().unwrap().as_raw();
            let flags = show_on_all_spaces(raw).expect("AppKit call");
            let want = CAN_JOIN_ALL_SPACES | FULL_SCREEN_AUXILIARY;
            println!(
                "collectionBehavior after: {flags:#x}; both flags set: {}",
                flags & want == want
            );
            assert_eq!(flags & want, want);
            self.0 = Some(w);
            el.exit();
        }
        fn window_event(&mut self, _: &ActiveEventLoop, _: WindowId, _: WindowEvent) {}
    }
    EventLoop::new().unwrap().run_app(&mut App(None)).unwrap();
}

#[cfg(not(target_os = "macos"))]
fn main() {}
