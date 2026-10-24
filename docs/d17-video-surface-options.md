# D-17: can the Slint UI and our own video surface share a window?

Status: **desk research, 2026-10-19** (owner request: ~30 min timebox, no
code). Question: R1 (architecture D34) puts the video on our own winit + wgpu
surface because Slint always presents with vsync. Phase 7 needs Slint UI
(connect dialog, toolbar, session indicator) **with** that video. Is that
solvable, or do we need two windows or another toolkit?

**Answer: solvable — at least one option needs no integration at all (C), and
one needs only stock winit behaviour (B). The best-looking option (A) is
plausible but unverified.** R1 does not paint us into a corner.
Recommendation: a ≤ 2 h code spike of option A on macOS before Phase 7 design;
fall back to B, then C.

Everything below cites the source read at the locked versions (slint 1.18.1,
winit 0.30.13, wgpu 30.0.1) or is marked **unverified**.

## What the libraries give us

* Slint exposes the underlying winit window: `WinitWindowAccessor::with_winit_window`
  (i-slint-backend-winit 1.18.1 `lib.rs:1110`), plus a hook to change window
  attributes before creation (`lib.rs:324`). From the winit window we get the
  raw `NSView` / `HWND` handle.
* wgpu can render into a Core Animation layer we create ourselves:
  `SurfaceTargetUnsafe::CoreAnimationLayer` (wgpu 30.0.1
  `src/api/surface.rs:436`), and into a DirectComposition visual on Windows
  (`IDCompositionVisual`, same file, line 438). Both are `unsafe`.
* winit "child windows" (`WindowAttributes::with_parent_window`, winit 0.30.13
  `src/window.rs:475`, `unsafe`): on **Windows and X11** a true child confined to
  the parent's client area (doc comment, lines 466–470); **Wayland unsupported**.
  On **macOS** it is *not* an embedded view: a separate `NSWindow` added with
  `addChildWindow:ordered:NSWindowAbove` (`platform_impl/macos/window_delegate.rs:685-699`) —
  it moves with the parent but sits **above** it and is not clipped to it.
* Slint on macOS makes the window transparent only when its background is not
  opaque or it has no frame, because a transparent AppKit window also loses its
  painted title bar (`winitwindowadapter.rs:560-567`).

## Options

| | Option | How | Works on | Main risks | Risk |
|---|---|---|---|---|---|
| **A** | **One window, two layers** | Take Slint's `NSView`; add our own `CAMetalLayer` as a sublayer **below** Slint's; wgpu surface on it (`CoreAnimationLayer`), presented `Immediate`, independent of Slint's vsync'd UI. Slint draws the toolbar with a transparent hole over the video. Windows: a DirectComposition visual; X11: a child window | macOS first; per-OS work for Windows / X11; **Wayland: no winit API for subsurfaces** | (1) whether Slint's renderer layer can sit above ours with transparency — **unverified**; (2) transparency may cost the native title bar (above); (3) compositing a full-window alpha layer on every UI redraw — cost **unmeasured**; (4) live-resize sync of two independently presented layers (stretch/flicker); (5) needs `unsafe` (raw view, layer, unsafe surface) — must live in an allowed `src/sys/` module or get its own owner decision (CLAUDE.md, not D19) | **medium** — best UX, most unknowns |
| **B** | **Child window for video** | Video window created with `with_parent_window(slint_window)`; Slint UI laid out *around* the video area (toolbar strip), kept in position on move/resize | macOS, Windows, X11. **Not Wayland** | No UI can be drawn *over* the video (it is a separate window above, "airspace"); macOS child windows with full-screen / Spaces — **unverified**; keyboard focus must go to the video window for remote input | **low–medium** |
| **C** | **Two top-level windows** | Our video window; Slint for the connect dialog and settings; in-session controls in a small floating Slint toolbar window, menu bar items or shortcuts | everywhere, incl. Wayland | UX: two windows; floating-toolbar placement and focus | **low** — no integration at all |
| **D** | **Another UI toolkit drawn in our own wgpu pass** (e.g. egui via egui-wgpu, or iced) | UI rendered into the same frame as the video; we keep the surface and the present mode | everywhere wgpu runs | Re-opens the UI-toolkit decision (dependencies.md lists Slint); versions compatible with wgpu 30 **unverified**; accessibility support **unverified** (Slint has AccessKit integration, `i-slint-backend-winit accesskit.rs`) | **medium** (a rewrite of the Phase 7 plan, not a technical unknown) |
| E | Upstream a present-mode setting to Slint (the hard-coded line is `i-slint-renderer-femtovg wgpu.rs:339`) | — | — | Would still make Slint **own** the video surface — excluded by the R1 constraint (D34) | excluded |

## What would change the answer

* If option A's spike shows Slint's layer cannot be transparent over ours
  without losing the title bar, A becomes "frameless window + Slint-drawn
  title bar" (more UI work) or falls back to B.
* Wayland (Linux Phase 8+) has no in-window path through winit at all (A and B
  both need it); C or D would be the Wayland answer regardless.
* Any option that needs `unsafe` in the viewer requires an owner decision
  under the unsafe policy; moving the code into `remora-capture`/`-codec`/`-input`
  `src/sys/` only to satisfy the rule would be the wrong layering.

## Tracked as

roadmap **D-17** (Phase 7 BLOCKER) — now with the A-spike as its first step
and B/C as known fallbacks.
