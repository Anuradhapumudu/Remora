//! All Win32 / DXGI / D3D11 calls of the spike. Every step records what happened
//! (including error codes) so a failure is as informative as a success.

use std::process::ExitCode;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_MOVE_RECT,
    IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
};
use windows::Win32::Graphics::Gdi::CreateSolidBrush;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_SWITCHDESKTOP, OpenInputDesktop,
};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MOVE, MOUSEEVENTF_VIRTUALDESK, MOUSEINPUT, SendInput,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetCursorPos,
    GetSystemMetrics, MSG, PM_REMOVE, PeekMessageW, RegisterClassW, SM_CXVIRTUALSCREEN,
    SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SW_SHOW, SetCursorPos,
    SetForegroundWindow, ShowWindow, TranslateMessage, WM_LBUTTONDOWN, WM_LBUTTONUP, WNDCLASSW,
    WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};
use windows::core::{Interface, w};

/// Our window's position and size (screen coordinates).
const WIN_X: i32 = 120;
const WIN_Y: i32 = 120;
const WIN_SIZE: i32 = 240;
/// Magenta in COLORREF (0x00BBGGRR) — easy to recognise in a captured frame.
const MAGENTA: COLORREF = COLORREF(0x00FF_00FF);

/// Bit 0: left button down arrived; bit 1: left button up arrived.
static CLICKS: AtomicU32 = AtomicU32::new(0);

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_LBUTTONDOWN => {
            CLICKS.fetch_or(1, Ordering::SeqCst);
            LRESULT(0)
        }
        WM_LBUTTONUP => {
            CLICKS.fetch_or(2, Ordering::SeqCst);
            LRESULT(0)
        }
        // SAFETY: forwarding the unmodified message to the default handler.
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

struct Report {
    lines: Vec<String>,
}

impl Report {
    fn step(&mut self, name: &str, result: impl std::fmt::Display) {
        let line = format!("{name:<34} {result}");
        println!("{line}");
        self.lines.push(line);
    }
}

/// Dispatches window messages for `d` (our window must paint and receive clicks).
fn pump(d: Duration) {
    let end = Instant::now() + d;
    let mut msg = MSG::default();
    while Instant::now() < end {
        // SAFETY: `msg` is a valid out-parameter; messages are dispatched on the
        // thread that created the window.
        unsafe {
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn qpc_now() -> i64 {
    let mut t = 0i64;
    // SAFETY: valid out pointer.
    let _ = unsafe { QueryPerformanceCounter(&mut t) };
    t
}

pub(crate) fn run() -> ExitCode {
    let mut r = Report { lines: Vec::new() };
    println!("== Remora Phase 2.5 Windows spike ==");

    // ── 0. Session: is there an interactive desktop at all? ─────────────────
    let mut session = u32::MAX;
    // SAFETY: valid out pointer.
    let _ = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) };
    r.step(
        "session id",
        format!("{session} (0 = services session, no desktop)"),
    );
    // SAFETY: plain call; the handle is closed right away.
    match unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_SWITCHDESKTOP) } {
        Ok(h) => {
            r.step("interactive input desktop", "available");
            // SAFETY: handle from OpenInputDesktop.
            let _ = unsafe { CloseDesktop(h) };
        }
        Err(e) => r.step("interactive input desktop", format!("NOT available: {e}")),
    }

    // ── 1. Our own magenta window ───────────────────────────────────────────
    let hwnd = match create_window() {
        Ok(h) => {
            r.step(
                "test window",
                format!("created at ({WIN_X},{WIN_Y}) {WIN_SIZE}×{WIN_SIZE}"),
            );
            Some(h)
        }
        Err(e) => {
            r.step("test window", format!("FAILED: {e}"));
            None
        }
    };
    pump(Duration::from_millis(500));

    // ── 2. One DXGI Desktop Duplication frame ───────────────────────────────
    let capture_ok = match capture(&mut r) {
        Ok(ok) => ok,
        Err(e) => {
            r.step("capture", format!("FAILED: {e}"));
            false
        }
    };

    // ── 3. One SendInput click into our window ──────────────────────────────
    let input_ok = hwnd.is_some() && inject_click(&mut r);

    if let Some(h) = hwnd {
        // SAFETY: our own window handle.
        let _ = unsafe { DestroyWindow(h) };
    }
    println!(
        "\nSPIKE RESULT: capture {} | input {}",
        ok(capture_ok),
        ok(input_ok)
    );
    // Always exit 0: the report itself is the result (CI must keep the log).
    ExitCode::SUCCESS
}

fn ok(b: bool) -> &'static str {
    if b { "WORKS" } else { "did NOT work" }
}

fn create_window() -> windows::core::Result<HWND> {
    // SAFETY: standard window-class registration and creation; the class name
    // and title are static wide strings; wndproc has the required signature.
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: w!("RemoraSpikeWindow"),
            hbrBackground: CreateSolidBrush(MAGENTA),
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err(windows::core::Error::from_thread());
        }
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST,
            w!("RemoraSpikeWindow"),
            w!("Remora spike"),
            WS_POPUP | WS_VISIBLE,
            WIN_X,
            WIN_Y,
            WIN_SIZE,
            WIN_SIZE,
            None,
            None,
            Some(instance.into()),
            None,
        )?;
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
        Ok(hwnd)
    }
}

fn capture(r: &mut Report) -> windows::core::Result<bool> {
    // SAFETY: COM/DXGI calls with valid arguments; every interface is a
    // reference-counted smart pointer released on drop.
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1()?;
        let adapter = factory.EnumAdapters1(0)?;
        let ad = adapter.GetDesc1()?;
        let name = String::from_utf16_lossy(&ad.Description)
            .trim_end_matches('\0')
            .to_owned();
        r.step(
            "GPU adapter 0",
            format!("{name} (vendor {:#06x})", ad.VendorId),
        );
        let output: IDXGIOutput1 = adapter.EnumOutputs(0)?.cast()?;
        let od = output.GetDesc()?;
        let dc = od.DesktopCoordinates;
        r.step(
            "output 0",
            format!(
                "attached={} desktop ({},{})-({},{})",
                od.AttachedToDesktop.as_bool(),
                dc.left,
                dc.top,
                dc.right,
                dc.bottom
            ),
        );

        let mut device: Option<ID3D11Device> = None;
        let mut ctx: Option<ID3D11DeviceContext> = None;
        D3D11CreateDevice(
            &adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            Default::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut ctx),
        )?;
        let (Some(device), Some(ctx)) = (device, ctx) else {
            r.step("D3D11 device", "FAILED: no device");
            return Ok(false);
        };
        r.step("D3D11 device", "created");

        let dupl: IDXGIOutputDuplication = match output.DuplicateOutput(&device) {
            Ok(d) => d,
            Err(e) => {
                r.step(
                    "DuplicateOutput",
                    format!("FAILED: {e} ({:#010x})", e.code().0),
                );
                return Ok(false);
            }
        };
        let dd = dupl.GetDesc();
        r.step(
            "DuplicateOutput",
            format!(
                "ok: {}×{} format {} in-system-memory={}",
                dd.ModeDesc.Width,
                dd.ModeDesc.Height,
                dd.ModeDesc.Format.0,
                dd.DesktopImageInSystemMemory.as_bool()
            ),
        );

        // Acquire until a frame with a new desktop image arrives (pointer-only
        // updates have LastPresentTime == 0). Pull model: we ask; nothing is pushed.
        let mut freq = 0i64;
        let _ = QueryPerformanceFrequency(&mut freq);
        let deadline = Instant::now() + Duration::from_secs(3);
        let (mut timeouts, mut pointer_only) = (0, 0);
        loop {
            if Instant::now() > deadline {
                r.step(
                    "AcquireNextFrame",
                    format!("no image in 3 s ({timeouts} timeouts, {pointer_only} pointer-only)"),
                );
                return Ok(false);
            }
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut res: Option<IDXGIResource> = None;
            match dupl.AcquireNextFrame(500, &mut info, &mut res) {
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {
                    timeouts += 1;
                    pump(Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    r.step(
                        "AcquireNextFrame",
                        format!("FAILED: {e} ({:#010x})", e.code().0),
                    );
                    return Ok(false);
                }
                Ok(()) => {}
            }
            if info.LastPresentTime == 0 {
                pointer_only += 1;
                let _ = dupl.ReleaseFrame();
                continue;
            }
            let now = qpc_now();
            let age_ms = (now - info.LastPresentTime) as f64 * 1000.0 / freq.max(1) as f64;
            r.step(
                "frame",
                format!(
                    "present→acquire {age_ms:.2} ms, accumulated {}, coalesced {}, protected-masked {}",
                    info.AccumulatedFrames,
                    info.RectsCoalesced.as_bool(),
                    info.ProtectedContentMaskedOut.as_bool()
                ),
            );
            r.step(
                "pointer (separate from image)",
                format!(
                    "visible={} at ({},{}), shape buffer {} B",
                    info.PointerPosition.Visible.as_bool(),
                    info.PointerPosition.Position.x,
                    info.PointerPosition.Position.y,
                    info.PointerShapeBufferSize
                ),
            );
            report_metadata(r, &dupl, info.TotalMetadataBufferSize);

            let ok = match res.map(|x| x.cast::<ID3D11Texture2D>()) {
                Some(Ok(tex)) => check_pixel(r, &device, &ctx, &tex, dc)?,
                _ => {
                    r.step("frame texture", "FAILED: no ID3D11Texture2D");
                    false
                }
            };
            let _ = dupl.ReleaseFrame();
            return Ok(ok);
        }
    }
}

/// Dirty and MOVE rectangles (macOS gives no move rects — a design input).
fn report_metadata(r: &mut Report, dupl: &IDXGIOutputDuplication, total: u32) {
    if total == 0 {
        r.step("dirty / move rects", "none in this frame");
        return;
    }
    let cap = total as usize / std::mem::size_of::<RECT>() + 1;
    let mut dirty = vec![RECT::default(); cap];
    let mut moves = vec![
        DXGI_OUTDUPL_MOVE_RECT::default();
        total as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>() + 1
    ];
    let (mut dirty_bytes, mut move_bytes) = (0u32, 0u32);
    // SAFETY: buffers are sized from TotalMetadataBufferSize; sizes are in bytes.
    unsafe {
        let _ = dupl.GetFrameMoveRects(
            (moves.len() * std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>()) as u32,
            moves.as_mut_ptr(),
            &mut move_bytes,
        );
        let _ = dupl.GetFrameDirtyRects(
            (dirty.len() * std::mem::size_of::<RECT>()) as u32,
            dirty.as_mut_ptr(),
            &mut dirty_bytes,
        );
    }
    r.step(
        "dirty / move rects",
        format!(
            "{} dirty, {} move",
            dirty_bytes as usize / std::mem::size_of::<RECT>(),
            move_bytes as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>()
        ),
    );
}

/// Copies the frame to a CPU-readable texture and checks our window's centre pixel.
fn check_pixel(
    r: &mut Report,
    device: &ID3D11Device,
    ctx: &ID3D11DeviceContext,
    tex: &ID3D11Texture2D,
    desktop: RECT,
) -> windows::core::Result<bool> {
    // SAFETY: standard staging-texture readback; the mapped pointer is only read
    // within the mapped size (row pitch × height) before Unmap.
    unsafe {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        tex.GetDesc(&mut desc);
        r.step(
            "frame texture",
            format!(
                "{}×{} DXGI format {} (GPU, full resolution)",
                desc.Width, desc.Height, desc.Format.0
            ),
        );
        desc.Usage = D3D11_USAGE_STAGING;
        desc.BindFlags = 0;
        desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
        desc.MiscFlags = 0;
        let mut staging: Option<ID3D11Texture2D> = None;
        device.CreateTexture2D(&desc, None, Some(&mut staging))?;
        let Some(staging) = staging else {
            return Ok(false);
        };
        ctx.CopyResource(&staging, tex);
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        ctx.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
        let x = (WIN_X + WIN_SIZE / 2 - desktop.left).clamp(0, desc.Width as i32 - 1) as usize;
        let y = (WIN_Y + WIN_SIZE / 2 - desktop.top).clamp(0, desc.Height as i32 - 1) as usize;
        let row = mapped.pData.cast::<u8>().add(y * mapped.RowPitch as usize);
        let px = std::slice::from_raw_parts(row.add(x * 4), 4); // BGRA
        let (b, g, rr) = (px[0], px[1], px[2]);
        ctx.Unmap(&staging, 0);
        let magenta = rr > 200 && g < 60 && b > 200;
        r.step(
            "pixel at our window's centre",
            format!(
                "R{rr} G{g} B{b} → {}",
                if magenta {
                    "MAGENTA: capture saw our window"
                } else {
                    "not magenta"
                }
            ),
        );
        Ok(magenta)
    }
}

fn inject_click(r: &mut Report) -> bool {
    CLICKS.store(0, Ordering::SeqCst);
    let mut orig = POINT::default();
    // SAFETY: plain Win32 calls with valid arguments.
    let (vx, vy, vw, vh) = unsafe {
        let _ = GetCursorPos(&mut orig);
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };
    // SendInput absolute coordinates are 0..=65535 across the virtual desktop —
    // the same idea as Remora's normalised 0..1 coordinates.
    let (px, py) = (WIN_X + WIN_SIZE / 2, WIN_Y + WIN_SIZE / 2);
    let nx = ((px - vx) as i64 * 65535 / (vw - 1).max(1) as i64) as i32;
    let ny = ((py - vy) as i64 * 65535 / (vh - 1).max(1) as i64) as i32;
    let mouse = |flags| INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: nx,
                dy: ny,
                dwFlags: flags | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                ..Default::default()
            },
        },
    };
    let inputs = [
        mouse(MOUSEEVENTF_MOVE),
        mouse(MOUSEEVENTF_LEFTDOWN),
        mouse(MOUSEEVENTF_LEFTUP),
    ];
    // SAFETY: valid INPUT array and its element size.
    let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
    let err = windows::core::Error::from_thread();
    r.step(
        "SendInput",
        format!(
            "{sent}/{} events accepted{}",
            inputs.len(),
            if sent < 3 {
                format!(" — {err}")
            } else {
                String::new()
            }
        ),
    );
    pump(Duration::from_millis(800));
    let got = CLICKS.load(Ordering::SeqCst);
    r.step(
        "click received by our window",
        match got {
            3 => "yes (button down + up)".to_owned(),
            0 => "NO".to_owned(),
            n => format!("partial ({n:#b})"),
        },
    );
    // SAFETY: restore the user's cursor position.
    let _ = unsafe { SetCursorPos(orig.x, orig.y) };
    got == 3
}
