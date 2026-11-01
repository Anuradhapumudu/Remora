//! I3 (phase4.5-criteria §5; owner-approved 2026-11-01, architecture D46):
//! the host's session indicator stays visible over a full-screen app on
//! another Space. winit 0.30.13 has no setting for it (`platform/macos.rs`);
//! AppKit does: `NSWindow.collectionBehavior` with `CanJoinAllSpaces` and
//! `FullScreenAuxiliary`.
//!
//! The setter is a safe function in objc2-app-kit 0.3.2
//! (`generated/NSWindow.rs:1446`). The one `unsafe` is turning winit's raw
//! `NSView` pointer (raw-window-handle's `AppKitWindowHandle`) into a
//! retained reference.

use objc2::MainThreadMarker;
use objc2::rc::Retained;
use objc2_app_kit::{NSView, NSWindowCollectionBehavior};
use raw_window_handle::RawWindowHandle;

use crate::window::Unsupported;

/// Puts the window behind `handle` on every Space, also beside full-screen
/// apps. Returns the window's behaviour flags as AppKit reports them after
/// the change, so the caller can check it took effect.
pub(crate) fn show_on_all_spaces(handle: RawWindowHandle) -> Result<u64, Unsupported> {
    // AppKit windows may only be touched on the main thread.
    let _mtm = MainThreadMarker::new().ok_or(Unsupported::NotMainThread)?;
    let RawWindowHandle::AppKit(h) = handle else {
        return Err(Unsupported::NotAppKit);
    };
    // SAFETY: an AppKitWindowHandle holds a pointer to the NSView of a window
    // that exists for as long as the handle is borrowed from it (the caller
    // passes a handle it just obtained from the live window; raw-window-handle
    // 0.6.2 src/appkit.rs:75-78 documents exactly this conversion). `retain`
    // adds a reference, so the view stays valid while we use it, and it
    // returns None instead of a dangling reference for a null pointer.
    let view: Retained<NSView> =
        unsafe { Retained::retain(h.ns_view.as_ptr().cast()) }.ok_or(Unsupported::NoView)?;
    let window = view.window().ok_or(Unsupported::NoWindow)?;
    window.setCollectionBehavior(
        window.collectionBehavior()
            | NSWindowCollectionBehavior::CanJoinAllSpaces
            | NSWindowCollectionBehavior::FullScreenAuxiliary,
    );
    Ok(window.collectionBehavior().0 as u64)
}
