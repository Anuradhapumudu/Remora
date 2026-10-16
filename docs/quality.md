# Quality, latency and rate control

Status: design v1 (Phase 1). Implemented in Phases 2, 4 and 7. Numbers marked
*estimate* are to be replaced by measurements; each phase report updates them.

## 1. Targets

| Metric | Target | Measured |
|---|---|---|
| Remora-added latency (capture → encode → net stack → decode → render submit), 1080p60 | < 20 ms (**never raised**; if exceeded, stop and report) | — (Phase 4) |
| Encode, Apple M4 hardware H.264 low-latency | ≤ 7 ms p95 (revised from an unmeasured 6 ms estimate — phase2-criteria.md §6) | 6.38 p50 / 6.76 p95 (encoder-only) |
| Total glass-to-glass latency | ≈ one-way network delay + 20 ms + display refresh wait | — |
| Host CPU, static screen | < 2 % | — (Phase 2) |
| Viewer memory | < 150 MB | — (Phase 4) |

Measured stage numbers are **per chip** (here: Apple M4). Other Macs and other
OSes are measured in their own phases; never reuse an M4 number for them.

## 2. Latency budget (Apple Silicon, 1080p60, *estimates*)

| Stage | Budget | How we keep it small |
|---|---|---|
| Capture delivery (ScreenCaptureKit) | 2–4 ms | Frame-change-driven; `minimumFrameInterval` = 1/fps cap; queue depth 3 |
| Encode (VideoToolbox) | ~~3–6 ms~~ **measured on M4: 6.4 p50 / 6.8 p95** |  Low-latency rate control, no B-frames, no lookahead, real-time priority, IOSurface passed zero-copy |
| Packetise + FEC + encrypt + send | < 1 ms | ChaCha20 is a few GB/s per core |
| Network | (not ours) | — |
| Reassemble + decode (VideoToolbox) | 2–4 ms | Decode as soon as the last fragment (or enough FEC) arrives |
| Upload + render (wgpu) | 1–2 ms | NV12 planes → textures; YUV→RGB in shader; zero-copy IOSurface import later |
| **Total** | **~9–17 ms** | |
| Viewer display refresh wait | 0–16.7 ms at 60 Hz | Reported separately. `Mailbox`/`Immediate` present mode when available; never `Fifo` with a deep queue |

**Cursor** is sent separately from video (position as a datagram, shape on
change) and drawn by the viewer, so the pointer feels instant even when video
is a frame behind.

### How latency is measured

* **`--test-pattern` host mode** renders a moving pattern with the capture
  timestamp and frame number encoded as a barcode strip. The viewer decodes the
  strip after rendering and computes `render_time − capture_time`.
* On one machine (loopback) both clocks are the same.
* Across machines, `ClockSync` messages estimate the clock offset NTP-style
  (`offset = ((t2 − t1) + (t3 − t4)) / 2`); the overlay shows the error bound
  (± RTT/2 of the best sample).
* Each pipeline stage is timestamped (`capture`, `encode_done`, `sent`,
  `received_last_fragment`, `decode_done`, `presented`) so we can see *where*
  time goes, not just the total.

## 3. Rate controller

Goal: the highest quality the path can carry **without building a queue**.
Loss-based congestion control (TCP Cubic, QUIC default) fills router buffers
until packets drop — that adds hundreds of milliseconds of latency. We use a
**delay-based** controller modelled on Google Congestion Control (the algorithm
behind WebRTC):

**Inputs** (viewer → host `Feedback` every 50 ms):
* per-frame arrival times vs send times → **one-way delay gradient**, smoothed
  with a trendline filter. Rising gradient = a queue is forming.
* loss fraction (before and after FEC), jitter, RTT (from QUIC), measured
  receive throughput.

**Two speeds**:
* **Fast path (every feedback, 50 ms):** if the delay gradient signals overuse
  or loss after FEC > 2 %, cut the target bitrate immediately to 0.85 × the
  measured receive rate. Waiting for the next 500 ms tick during congestion is
  how visible freezes happen.
* **Slow path (every 500 ms):** if no overuse for the last interval, increase
  multiplicatively (+8 %/s) far from the last known congestion point and
  additively (half a packet per RTT) near it.

**quinn's own congestion controller** is replaced via `ControllerFactory` with a
permissive controller (large window, pacing only) so it doesn't fight ours.
Reliable control traffic is tiny and still gets QUIC's loss recovery.

**Output:** a target bitrate `B`, then the *mode policy* (§4) maps `B` to
(resolution, fps, quantiser). The controller is a **pure function**
`(state, feedback, now) → (state, decision)` — no I/O, no clocks — so it is unit
tested with recorded and synthetic traces.

## 4. Quality modes (switchable live)

| Mode | Degrades first | Degrades last | Extras |
|---|---|---|---|
| **Auto** (default) | Mix: fps 60→45 first, then quantiser, then resolution | — | Detects content: mostly static text → behaves like Sharp text; large motion → like Smooth |
| **Sharp text** | fps (60→30→15→5) | resolution | 4:4:4 when both ends support it, otherwise 4:2:0 at lower QP; aggressive refinement frames |
| **Smooth** | resolution (1080→900→720→540) and QP | fps | — |
| **Low bandwidth** | — | — | Caps: 2 Mbps, 30 fps, 720p; longer refinement delay |

**Advanced panel (limits, not fixed values):** resolution, fps cap
(30/60/120/144), bitrate cap, codec, hardware/software encoder. Auto adapts
*within* these limits; it never exceeds them.

### 4:4:4 reality check — design constraint (measured on M4, Phase 2)

Chroma subsampling (4:2:0) blurs coloured text. Measured on the M4
(`docs/evidence/phase2-probe-encoder-m4.txt`, verified by parsing the stream's
own `chroma_format_idc`):

* **True 4:4:4 hardware encode works — but ONLY in normal rate-control mode**
  (H.264 High 4:4:4 Predictive and HEVC Range Extensions, `chroma_format_idc = 3`).
* **In low-latency mode the encoder silently falls back to 4:2:0** (H.264 High,
  `chroma_format_idc = 1`) even when fed 4:4:4 frames, and offers no 4:4:4
  profile at all.

Consequences:

1. **Sharp text is a latency-vs-chroma trade-off.** 4:4:4 means leaving
   low-latency rate control; Phase 7 measures what that costs (encode latency,
   bitrate, rate-control behaviour) before the mode ships.
2. **The stats overlay must show the chroma format actually in the stream**
   (read from the SPS we send), never the format we *asked* for, because the
   encoder can downgrade silently.
3. Decode side: hardware H.264 4:4:4 *decode* is rare on consumer GPUs; HEVC
   4:4:4 decode exists on newer Intel/NVIDIA/Apple hardware. 4:4:4 is used only
   when both peers report support in `Capabilities`.

## 5. Static content refinement

ScreenCaptureKit reports when a frame is unchanged. After ~300 ms without
changes (Low bandwidth: 1 s) the host encodes **one refinement frame** at a low
quantiser (near-lossless) and then sends nothing until the screen changes —
so a static screen costs ~0 bandwidth and < 2 % CPU while being pixel-sharp.

## 6. Loss recovery

1. **FEC** repairs small, random losses with no round trip.
2. If a frame still can't be reassembled, the viewer sends `RecoveryRequest`.
   The host recovers with, in order of preference:
   * **long-term reference (LTR)** frames — the encoder predicts from the last
     frame the viewer confirmed, so recovery costs about as much as a normal
     frame (VideoToolbox supports LTR; verify in Phase 2),
   * **intra refresh** (a column of intra blocks sweeping across a few frames;
     NVENC/openh264 support it, VideoToolbox likely does not — Phase 2),
   * a **capped-size keyframe** as last resort.
3. The viewer keeps showing the last good frame meanwhile — **no grey/green
   smear** — and the overlay counts recoveries.

## 7. Network-simulation test matrix (Phase 7)

| Delay (one-way) | Loss | Bandwidth cap |
|---|---|---|
| 50, 150, 300 ms | 0, 1, 3, 5 % | 1, 5, 20 Mbps |

Report per cell: delivered fps, mean bitrate, p50/p95 latency, freezes > 200 ms,
recoveries, and a quality score (PSNR/SSIM of decoded test-pattern frames).

**Linux (`tc netem`):**
```sh
sudo tc qdisc add dev lo root netem delay 75ms 10ms loss 1% rate 5mbit
sudo tc qdisc del dev lo root      # undo
```
**macOS (`dnctl` + `pfctl`):**
```sh
sudo dnctl pipe 1 config delay 75 plr 0.01 bw 5Mbit/s
echo "dummynet in quick proto udp from any to any port 47800 pipe 1" | sudo pfctl -f - -e
sudo pfctl -f /etc/pf.conf; sudo dnctl -q flush   # undo
```
(Loopback delay applies in each direction, so 75 ms each way ≈ 150 ms RTT.)
