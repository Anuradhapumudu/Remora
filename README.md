# Remora

Open-source, end-to-end encrypted, peer-to-peer remote desktop for macOS,
Windows and Linux, written in Rust.

> **Status: pre-alpha.** Nothing usable yet. See [docs/roadmap.md](docs/roadmap.md)
> for what works today and how far we are from v0.1.

## Design goals (in priority order)

1. **Security** — Noise + SPAKE2 end-to-end encryption; servers and network are untrusted.
2. **Correctness**
3. **Low latency** — < 20 ms added by Remora itself at 1080p60.
4. **Image clarity**
5. **Resource efficiency**
6. **Features**

## Documentation

| Doc | What it covers |
|---|---|
| [architecture.md](docs/architecture.md) | Crates, data flow, key decisions, licensing |
| [threat-model.md](docs/threat-model.md) | STRIDE threat model and security invariants |
| [protocol.md](docs/protocol.md) | Wire protocol and handshake |
| [nat-traversal.md](docs/nat-traversal.md) | STUN, ICE, hole punching, known failure cases |
| [quality.md](docs/quality.md) | Latency budget, rate control, quality modes |
| [roadmap.md](docs/roadmap.md) | Phases and the v0.1 milestone |
| [distribution.md](docs/distribution.md) | Release builds, signing, antivirus, macOS permissions |
| [dependencies.md](docs/dependencies.md) | Every dependency, why, and how versions are chosen |

## License

- Applications (`remora-host`, `remora-viewer`, `remora-signal`):
  **GPL-3.0-or-later** ([LICENSE-GPL](LICENSE-GPL)).
- Library crates: **MIT OR Apache-2.0** ([LICENSE-MIT](LICENSE-MIT),
  [LICENSE-APACHE](LICENSE-APACHE)), at your option.

See [docs/architecture.md § Licensing](docs/architecture.md#licensing) for why.
