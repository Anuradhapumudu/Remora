# NAT traversal

Status: design v1 (Phase 1). Implemented in Phase 5 (`remora-net`).

## 1. The problem in one paragraph

Most computers sit behind a NAT (your home router, or your ISP's carrier-grade
NAT). A NAT lets *outgoing* traffic through and only lets *replies* back in. Two
NATed computers therefore can't simply connect to each other: each NAT drops the
other side's first packet as unsolicited. **Hole punching** fixes this: both
sides learn their public address (via STUN), swap addresses, and send to each
other *at the same time*. Each side's outgoing packet opens a mapping in its own
NAT, so the other side's packets look like replies and get through.

## 2. When it works and when it doesn't — plainly

What matters is the NAT's **mapping behaviour** (RFC 4787):

| NAT mapping | Meaning | Hole punching |
|---|---|---|
| Endpoint-independent (EIM) | Same public port for every destination | ✅ Works (most home routers; RFC 6888 requires it of CGNAT) |
| Address/port-dependent ("symmetric") | New public port per destination | ❌ STUN tells us a port the peer can't use |

| Viewer ↓ / Host → | No NAT / IPv6 | EIM NAT | Symmetric NAT |
|---|---|---|---|
| **No NAT / IPv6** | ✅ | ✅ | ✅ (the symmetric side connects outward) |
| **EIM NAT** | ✅ | ✅ | ⚠️ Sometimes (only if the EIM side's filtering is permissive) |
| **Symmetric NAT** | ✅ | ⚠️ Sometimes | ❌ **Fails** without a relay |

**CGNAT is not automatically fatal.** Many carrier NATs are EIM and punch fine.
What reliably fails is *symmetric NAT on one side combined with restrictive
filtering on the other*, or symmetric on both — common on mobile networks and
some corporate firewalls. **v0.1 has no relay, so those users cannot connect.**
We will not pretend otherwise: the app detects the case and says so (§7).

**IPv6 helps a lot.** With IPv6 there is usually no NAT, only a stateful
firewall, which simultaneous sending opens just like a NAT mapping. If both
peers have IPv6, a direct connection almost always works. We gather IPv6 host
candidates from day one.

## 3. Decision: use `is` (str0m's ICE agent), don't write ICE from scratch

ICE (RFC 8445) is the standard algorithm for trying many address pairs and
picking a working one. Its edge cases (role conflicts, retransmit timers,
nomination, triggered checks, peer-reflexive candidates) are where home-grown
implementations lose weeks.

str0m (a production Rust WebRTC library) extracted its ICE agent into the
standalone crate **[`is`](https://crates.io/crates/is)** (MIT/Apache-2.0,
v0.11.1, ~9 k lines). We depend on it instead of writing our own. Evaluation
(source read 2026-10-17):

| Requirement | `is` 0.11.1 | Notes |
|---|---|---|
| Sans-IO (no sockets, no runtime) | ✅ `handle_packet` / `handle_timeout` / `poll_transmit` / `poll_event` | Fits our one-socket demux and makes deterministic tests possible |
| Candidate pairing + priorities | ✅ RFC 8445 priorities, `LocalPreference` hook | We supply IPv6-first local preference |
| Connectivity checks w/ STUN short-term credentials | ✅ HMAC-SHA1 MESSAGE-INTEGRITY, `IceCreds` | ufrag/pwd come from our connection code |
| Role conflict (487) | ✅ tie-breaker, regression test `ignores_stale_487_after_role_swap` | We fix roles (viewer = controlling) so conflicts should never happen; the handling is a safety net |
| Nomination | ✅ re-nomination without ICE restart (`NominatedSend` can repeat) | Lets us switch to a better path (e.g. Wi-Fi → Ethernet) live |
| ICE restart | ✅ `ice_restart(creds, keep_local)` | Used on network change (§6) |
| Peer-reflexive candidates | ✅ `DiscoveredRecv` | Learned from incoming checks |
| Pair limit (DoS bound) | ✅ `set_max_candidate_pairs` (default 100) | We set 64 |
| STUN parser | ✅ `is::stun::StunMessage` | We fuzz it ourselves (cargo-fuzz target) |
| Address discovery | ❌ by design | We do STUN gathering ourselves (§4) |
| TURN / relay | ❌ by design | Post-v0.1; slots into `RemoraSocket` (§5) |

Behaviours we rely on from str0m's design (documented in its design notes and
code): single component (no RTP/RTCP split), trickle-only (candidates may arrive
late — good for IPv6 and for network changes), no "frozen" check state, and
non-final nomination.

Risks and how we contain them:
* **API churn:** 5 breaking releases in 7 months. All use goes through
  `remora_net::ice::IceDriver`, a thin wrapper; upgrades touch one file.
* **Crypto/hash deps:** `is` uses `hmac 0.12` / `sha1 0.10` — the same RustCrypto
  generation as the rest of our crypto, no duplicates.
* **ICE is not security for us:** the STUN credentials only stop accidental
  cross-talk. A broken ICE implementation can cause failed connections, never a
  security breach, because everything above it is end-to-end authenticated.

## 4. Gathering candidates

1. **Host candidates:** every non-loopback, non-link-local IPv4 and global IPv6
   address of up interfaces. VPN interfaces are included but given lower
   preference.
2. **Server-reflexive candidates:** STUN Binding requests (RFC 8489), sent from
   the *same* socket that QUIC will use, to:
   1. our own STUN responder in remora-signal (if configured),
   2. `stun.l.google.com:19302`, `stun.cloudflare.com:3478` (configurable,
      each can be disabled for privacy).
   Requests go in parallel, 3 retransmits (250 ms, 500 ms, 1 s), 2.5 s budget.
3. **NAT-behaviour detection:** compare the mapped address reported by two
   different STUN servers (different IPs). Same port → EIM (good). Different
   ports → symmetric (warn early). One server can't detect this without
   RFC 5780 CHANGE-REQUEST, which needs two public IPs — a free Oracle VM has
   one, so we use two servers instead.
4. Our STUN client verifies the transaction ID (96-bit random) and the source
   address of the response, accepts only XOR-MAPPED-ADDRESS, and rejects
   oversize messages (> 1280 bytes) before parsing.

## 5. One socket, demultiplexed (`RemoraSocket`)

STUN, ICE checks and QUIC must share **one** UDP socket, because the NAT mapping
we punched belongs to that socket's port. `RemoraSocket` implements quinn's
`AsyncUdpSocket` trait and sorts each incoming datagram:

| First byte / content | Goes to |
|---|---|
| `0x00–0x03` and bytes 4–8 == STUN magic cookie `0x2112A442` | ICE agent (`is`) or our STUN client (matched by transaction ID) |
| `0x40` fixed bit set (QUIC) | quinn |
| anything else | dropped and counted |

This is the same idea as Tailscale's "magicsock". It is also the seam where a
**relay** plugs in later: `RemoraSocket` would send some paths through a relay
server without quinn or the session layer noticing.

## 6. Keepalives and network changes

* **QUIC keep-alive every 15 s** (well under the 30 s UDP mapping timeout many
  NATs use). ICE consent-style checks continue on the nominated pair at a low
  rate.
* **Network change** (Wi-Fi switch, laptop wakes up, IP change):
  1. The OS reports an interface change (or we see the path's packets stop).
  2. Re-gather candidates, `ice_restart` with fresh credentials.
  3. Send the new candidates over the **existing** Noise control channel if it
     still works, otherwise through signaling (Phase 8) — in copy-paste mode
     without signaling, a full reconnect needs a new code.
  4. When ICE nominates a new pair, call quinn's `rebind_abstract` / migrate
     the QUIC connection to the new path.
  5. The Noise session and media keys stay the same: **no re-authentication**,
     no new accept prompt. The session state machine shows `Reconnecting` for
     at most 30 s, then gives up and releases all held keys (threat model INV10).

## 7. When hole punching fails — what the user sees

After 10 s without a nominated pair, the UI shows one of:

| Detected | Message (short form) |
|---|---|
| Our side is symmetric NAT | "Your network changes your public port for every connection (symmetric NAT). Direct connections can fail. Try: another network (phone hotspot), enable IPv6 on your router, or ask your ISP about a public IP." |
| Peer side symmetric (learned from its candidates) | Same text about the other side. |
| No server-reflexive candidates at all | "Couldn't reach any STUN server — UDP may be blocked by a firewall." |
| Candidates fine, checks time out | "Both networks look normal, but no packets got through. A firewall may be blocking UDP." |

And always: "Remora doesn't support relayed connections yet." The diagnosis
(our NAT type, candidate types, which pairs were tried) can be copied to the
clipboard for bug reports; it contains IP addresses, so the UI says so.

## 8. Testing

* **Unit:** candidate parsing/encoding, priority calculation, NAT-type detection
  from canned STUN answers, demux classification.
* **Deterministic ICE tests:** two `IceDriver`s connected by an in-memory
  "network" that can simulate EIM and symmetric NATs, loss and delay — possible
  because `is` is sans-IO.
* **Fuzz:** STUN parser, connection code decoder, demux classifier.
* **Real world (Phase 5):** test guide for two different home networks, plus a
  phone hotspot (often symmetric NAT) to exercise the failure message.
  Includes commands to check NAT type and capture packets (`tcpdump -n udp`).
