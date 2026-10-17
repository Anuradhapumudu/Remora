# Phase 2.5 — Windows spike report

Status: **done (option A, 2026-10-17)** — run on GitHub's `windows-2025` runner;
real-hardware confirmation still open (see §4).

Goal (roadmap): before the macOS design hardens, prove that Remora's capture and
input traits fit a second OS, using a **throwaway** binary
(`spikes/windows-spike`) that captures one DXGI Desktop Duplication frame and
injects one `SendInput` click. To be safe on anyone's PC it only touches its own
window: it opens a 240×240 magenta window, checks the captured pixel at its
centre, and clicks inside it.

## 1. Result

Run on GitHub Actions `windows-2025` (Windows Server 2025, Hyper-V VM). The
runner turned out to have a **real interactive console session** (`runneradmin`,
session 2, Active) — my earlier prediction that it would have no desktop was
wrong. Report: `windows-spike-report` artifact of the "Windows spike" workflow.

```
session id                         2 (0 = services session, no desktop)
interactive input desktop          available
GPU adapter 0                      Microsoft Basic Render Driver (vendor 0x1414)
output 0                           attached=true desktop (0,0)-(1024,768)
DuplicateOutput                    ok: 1024×768 format 87 in-system-memory=true
frame                              present→acquire 0.79 ms, accumulated 1, coalesced false, protected-masked false
pointer (separate from image)      visible=false at (0,0), shape buffer 0 B
dirty / move rects                 1 dirty, 0 move
frame texture                      1024×768 DXGI format 87 (GPU, full resolution)
pixel at our window's centre       R255 G0 B255 → MAGENTA: capture saw our window
SendInput                          3/3 events accepted
click received by our window       yes (button down + up)
SPIKE RESULT: capture WORKS | input WORKS
```

(Format 87 = `DXGI_FORMAT_B8G8R8A8_UNORM`.) Both halves work end to end on a
real Windows desktop: the captured frame contained our window, and the injected
click reached it.

## 2. How Windows differs from macOS — and what it means for the traits

| # | Windows (DXGI / SendInput) | macOS (ScreenCaptureKit / CGEvent) | Trait impact |
|---|---|---|---|
| 1 | **Pull**: we call `AcquireNextFrame(timeout)` in a loop | **Push**: frames arrive on a dispatch queue | **None.** The Windows backend owns a capture thread and calls the same `EventSink`; `ScreenCapture::start(sink)` fits as is. |
| 2 | Image is a **full-resolution BGRA GPU texture**; no scaling, no NV12 | We ask the OS for scaled NV12 | **None in the trait**, but the Windows backend needs a GPU scale + BGRA→NV12 step (D3D11 Video Processor) before encoding. `CapturedFrame.image` becomes a per-OS type (`PixelBufferRef` / D3D11 texture). |
| 3 | `LastPresentTime` (QPC clock) per frame; measured present→acquire **0.79–1.29 ms** | `displayTime` (mach clock) | **None.** Maps onto the existing signed `delivery_ns`. |
| 4 | No "idle" callbacks: nothing changed = `WAIT_TIMEOUT`; **pointer-only updates** arrive as frames with `LastPresentTime = 0` | ~5–6 `idle` callbacks/s | **Small change:** don't require `Idle` events; add a cursor-only event (see 6). |
| 5 | **Dirty rects AND move rects** (scrolled/dragged regions) | Dirty rects only | **Small addition:** optional `move_rects` on `CapturedFrame` (empty on macOS). Useful later as encoder hints. |
| 6 | **Pointer position and shape come with the frames**, separate from the image | We disabled the cursor in capture; macOS needs a separate cursor source | **Change:** add `CaptureEvent::Cursor { position, shape }` to the trait (architecture.md already planned `cursor` data). macOS backend must synthesize it from another API. |
| 7 | Interruptions = `DXGI_ERROR_ACCESS_LOST` (mode change, UAC/secure desktop, lock, full-screen apps) — **recoverable by re-creating the duplication** | Interruptions = `didStopWithError` −3815 (display gone/asleep) — stream is dead, must be recreated after the display returns | **Change:** `CaptureEvent::Stopped(CaptureError)` → `Interrupted { reason, recoverable }` with reasons like `DisplayGone`, `AccessLost`, `SecureDesktop`, `PermissionRevoked`, and a matching `Resumed`. Both OSes then report the same story to the session layer (needed for the Phase 4 restart logic). |
| 8 | Needs an interactive session (session 0 services can't capture); **no permission prompt**; UAC/lock screen not capturable without a SYSTEM service | TCC permission per app | **None in the trait**; a capability/limitation note. |
| 9 | `SendInput` absolute coordinates **0..65535 across the virtual desktop**; accepted 3/3; click delivered | `CGEvent` points | **None.** Remora's normalised 0..1 per-monitor coordinates map onto it with the monitor rectangle. |
| 10 | Physical-vs-injected input distinguishable in low-level hooks (`LLMHF_INJECTED`) | CGEventTap source state | **None**: `InputInjector::local_activity()` fits (not exercised in the spike). |

**Proposed trait changes** (to be applied when the Windows backends are built in
Phase 6.5, except #7 which Phase 4 needs for capture restarts):

1. `CaptureEvent::Cursor { position, shape }` (cursor separate from video, both OSes).
2. `CaptureEvent::Interrupted { reason, recoverable }` + `CaptureEvent::Resumed`
   replacing `Stopped(CaptureError)`.
3. `CapturedFrame.move_rects` (optional; empty on macOS).
4. `FrameStatus::Idle` becomes optional (Windows never sends it).

Nothing in the spike contradicts the overall design (push sink, signed delivery
time, normalised input coordinates, per-OS `sys` modules).

## 3. What the runner can't tell us

The runner uses **Microsoft's Basic Render Driver** (software, no real GPU):

* no hardware video encoder → **NVENC / QuickSync / AMF untested**;
* `in-system-memory=true` — on real GPUs the desktop image normally stays in GPU
  memory (`false`), a different code path;
* single 1024×768 output: multi-monitor, DPI scaling, HDR, rotated displays untested;
* `ACCESS_LOST` recovery (mode change, UAC prompt, lock screen) not provoked;
* UIPI: injecting into elevated (admin) windows not tested — expected to fail;
* latency/CPU numbers on real hardware.

## 4. Still to do on a real Windows PC (Phase 6.5 at the latest)

Run the same spike (`windows-spike.exe` from the portable build, or
`cargo run -p windows-spike`) on a real PC, then the full Windows backend work.
Tracked in docs/roadmap.md "Known gaps".
