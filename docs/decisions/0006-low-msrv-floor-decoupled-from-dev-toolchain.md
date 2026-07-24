# 6. Low MSRV floor (1.75), decoupled from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`ronin-issen/CLAUDE.md` and the global "Rust MSRV &
Toolchain Policy") separates two things that must not be conflated:

- the **dev toolchain** — pinned to the current stable in `rust-toolchain.toml`
  for every fleet repo (here `channel = "1.96.0"`), a purely internal choice;
- the **declared MSRV** (`rust-version`) — a downstream-facing promise, which for
  a **published library** must be kept **low and CI-verified**, because a low
  MSRV is a real compatibility feature and raising it narrows the crates.io
  audience.

Both `ufs-core` and `ufs-forensic` are published libraries, not apps.

## Decision

Declare **`rust-version = "1.75"`** in `[workspace.package]` (`Cargo.toml`) for
both crates, decoupled from the 1.96.0 dev toolchain (`rust-toolchain.toml`).
The floor is declared for both crates, and **`ufs-core`'s is CI-verified**: the
dedicated `msrv` job pins `1.75.0` and runs `cargo build -p ufs-core`
(`.github/workflows/ci.yml`), whose production tree is only `thiserror` (no
`zstd`/`crc` dependency to raise it). `ufs-forensic`'s floor is **asserted, not
exercised** — its deps (`forensicnomicon` + `sha2`) are expected to build at 1.75,
but the `msrv` job does not compile `ufs-forensic`, so its 1.75 promise rests on
the dependency survey rather than a CI check.

## Consequences

- Third-party consumers pinning against these libraries get a wide compatibility
  window; the low floor is a README trust signal (`Rust 1.75+` badge).
- For `ufs-core` the floor is a CI-verified guarantee — the `msrv` job fails if a
  change to `ufs-core` reaches for a newer-Rust feature, at which point raising it
  is a deliberate, near-breaking decision with an explicit reason. `ufs-forensic`'s
  1.75 is a declared promise backed by its dependency survey; extending the `msrv`
  job to also build `ufs-forensic` would make its floor equally verified.
- Development still happens on current stable (1.96.0), so fmt/clippy behavior is
  consistent fleet-wide without leaking into the promise.
