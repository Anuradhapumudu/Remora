# Next session: run-sheet (Phase 4.5)

Items that are due because **time passes**, not because other work finishes,
go first. A scheduled reminder exists in the Claude session of 2026-10-27,
but it lives only as long as that session, so this file is the record.

## First, by time

| When (local, +0530) | What | Row |
|---|---|---|
| ~~After 2026-10-28 15:24~~ **Done 2026-10-30** | Remove the `tokio 1.53.3` line from `.cargo/crate-age-exceptions.txt` (own commit, `scripts/ci/pre-push.sh` first) | D-37 |
| ~~After 2026-10-28 15:24~~ **Done 2026-10-30** | Remove the `rustls 0.23.46` line (own commit, pre-push first) | D-42 |
| After 2026-11-03 14:28 | Remove the `rustls-webpki 0.103.16` line (own commit, pre-push first) | D-43 |

Not before those times: until then the release is under 14 days old and the
check fails (`python3 -I scripts/ci/check-crate-age.py --exceptions-only`
prints each exact expiry and warns under 48 h). Each removal also marks the
row "Removed" in docs/dependencies.md's exception log and moves the roadmap
row to "Closed" with the evidence.

## Then

1. The P5 correction (draft shown to the owner 2026-10-27; committed only
   after the owner has read it).
2. The S1 report to the owner (memory per configuration, C′, testing
   backend, occlusion, always-on-top over full screen).
