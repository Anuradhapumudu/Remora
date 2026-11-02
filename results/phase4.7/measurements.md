# Phase 4.7 measurements (owner's Mac viewer, Fedora laptop host, home Wi-Fi)

## CU2: finding the host by device code
- Spike S-C1, laptop announcing, Mac looking: 0.072 s, 1.10 s, 1.09 s.
- `remora-net/tests/cu2_discovery.rs` (real mDNS on the Mac): 1.09 s.
- A host that has only just started is silent for its first seconds
  while mDNS checks its name (spike: 7 s), so the viewer looks for 8 s.

## CU1: reconnecting a saved computer (live, 2026-11-02)
- `remora-viewer connect --device "7266 055 4675-2" --save` with the
  password; the laptop accepted (codes 529 083) and `remember 2`.
- Then `remora-viewer connect --device "7266 055 4675-2"`: "saved
  computer: connecting without a password"; no password asked; the
  laptop still prompted (code 577 922) and was accepted. One command,
  no password, host approves: met in the terminal. The "one click" GUI
  is D-55.

## CU3 / C5: nothing announced while the host is not ready
`dns-sd -B _remora._udp local.` on the Mac for 4 s around a Mac host
(test host, its own device code):
- ready: seen (1); session Active: not seen (0); session ended: seen (1).
Also seen during the run: the laptop host announcing while free.

## Wi-Fi (from Phase 4.6's finding)
Laptop power saving off (owner): ping p50 4.4 ms, max 26 ms (was 54 /
277 ms).
