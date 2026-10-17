//! Phase 2.5 THROWAWAY spike (docs/roadmap.md): does Remora's capture/input
//! design fit Windows? It opens its own small magenta window, captures one frame
//! with DXGI Desktop Duplication and checks the window's pixel, then injects one
//! click into that same window with `SendInput` and checks it arrived. It never
//! clicks anything but its own window.
//!
//! Delete this crate once the full Windows backends exist (Phase 6.5).

#[cfg(windows)]
#[allow(unsafe_code)]
mod win;

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    {
        win::run()
    }
    #[cfg(not(windows))]
    {
        println!("windows-spike only does something on Windows.");
        std::process::ExitCode::SUCCESS
    }
}
