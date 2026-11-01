//! Window placement the toolkit cannot do (I3, architecture D46).

/// Why a window could not be put on every Space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unsupported {
    /// Not called on the main thread (AppKit requires it).
    #[error("not on the main thread")]
    NotMainThread,
    /// The handle is not an AppKit window.
    #[error("not an AppKit window")]
    NotAppKit,
    /// The handle had no view.
    #[error("the handle has no view")]
    NoView,
    /// The view is not in a window.
    #[error("the view is not in a window")]
    NoWindow,
    /// This system has no such setting (only macOS is implemented).
    #[error("not available on this system")]
    NotThisOs,
}

/// AppKit's `NSWindowCollectionBehaviorCanJoinAllSpaces` (1 << 0).
pub const CAN_JOIN_ALL_SPACES: u64 = 1 << 0;
/// AppKit's `NSWindowCollectionBehaviorFullScreenAuxiliary` (1 << 8).
pub const FULL_SCREEN_AUXILIARY: u64 = 1 << 8;

/// Shows the window behind `handle` on every Space, also next to full-screen
/// apps (the host's session indicator, I3). Returns the window's behaviour
/// flags after the change.
pub fn show_on_all_spaces(handle: raw_window_handle::RawWindowHandle) -> Result<u64, Unsupported> {
    #[cfg(target_os = "macos")]
    {
        crate::sys::macos_window::show_on_all_spaces(handle)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = handle;
        Err(Unsupported::NotThisOs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flags_are_appkits() {
        // objc2-app-kit 0.3.2 generated/NSWindow.rs:153 and :168.
        #[cfg(target_os = "macos")]
        {
            use objc2_app_kit::NSWindowCollectionBehavior as B;
            assert_eq!(B::CanJoinAllSpaces.0 as u64, CAN_JOIN_ALL_SPACES);
            assert_eq!(B::FullScreenAuxiliary.0 as u64, FULL_SCREEN_AUXILIARY);
        }
    }

    #[test]
    fn off_the_main_thread_nothing_is_touched() {
        // Rust tests run on worker threads: AppKit must not be called there.
        let h = raw_window_handle::RawWindowHandle::AppKit(
            raw_window_handle::AppKitWindowHandle::new(std::ptr::NonNull::dangling()),
        );
        let want = if cfg!(target_os = "macos") {
            Unsupported::NotMainThread
        } else {
            Unsupported::NotThisOs
        };
        assert_eq!(show_on_all_spaces(h), Err(want));
    }
}
