# 5. `forbid(unsafe)` + panic-free bounds-checked readers + per-structure fuzzing

Date: 2026-07-24
Status: Accepted

## Context

These crates parse untrusted, attacker-controllable disk images. The fleet's
Paranoid Gatekeeper standard (`ronin-issen/CLAUDE.md`) and the global Rust Lint
Posture require: never panic, never read out of bounds, never trust a length
field; `forbid(unsafe_code)` as the default and goal (downgraded to `deny` +
bounded `#[allow]` only for a genuine need such as an `mmap` reader); and a
`cargo-fuzz` target per parsed structure.

`ufs-core` is a pure **slice reader** — it takes the whole partition as `&[u8]`
and never memory-maps — so it has no `mmap` justification to downgrade `forbid`.

## Decision

- **`#![forbid(unsafe_code)]`** in both crates (`core/src/lib.rs`,
  `forensic/src/lib.rs`), backed by `[workspace.lints.rust] unsafe_code =
  "forbid"` — no `unsafe`, no C bindings. The `unsafe forbidden` README badge is
  therefore earned, not aspirational.
- **Panic-free bounds-checked reads.** Every integer/length/offset/block-pointer
  field is read through helpers that yield `0` (or `None`) when the range lies
  outside the buffer (`core/src/bytes.rs`: `le_u16`/`be_u16`/…/`u8_at`, each
  guarding with `data.get(off..off.saturating_add(N))`). A malformed or
  truncated image degrades to an empty or typed result, never a panic.
- **Runtime endian dispatch** is layered on top as the `Endian` enum
  (`core/src/bytes.rs`), because UFS byte order is resolved at runtime from the
  magic (ADR 0004) — a fixed-endian reader cannot express this.
- **`unwrap`/`expect` denied in production** (`[workspace.lints.clippy]
  unwrap_used = "deny"`, `expect_used = "deny"`), with tests exempted via
  `clippy.toml` (`allow-unwrap-in-tests`) and the per-crate `#![cfg_attr(test,
  allow(...))]`.
- **Fuzzing** — one `cargo-fuzz` target per parsed structure (`superblock`,
  `cg`, `inode`, `dir`, `file`) plus a `fuzz_forensic` target driving the full
  `audit_image` / `recover_deleted` pipeline (`fuzz/fuzz_targets/`,
  `fuzz/Cargo.toml`); `fuzz.yml` builds every target on push and deep-fuzzes
  weekly.

The fuzzed **evidence** ("fuzzed") is the headline robustness claim; "panic-free"
appears only as its qualified static half ("panic-free by lint / bounds-checked
readers"), per the fleet Evidence-Based Rigor wording rule (README
"Trust but verify").

## Consequences

- No place in either crate where a crafted input can corrupt memory — the
  memory-corruption/RCE class that C UFS readers carry is deleted by
  construction.
- Robustness is both proved-by-construction (lints) and tested empirically
  (fuzzing), the paired posture the fleet README standard requires.
- **Deviation from the fleet `safe-read` crate.** The constitution's Paranoid
  Gatekeeper standard says to route fixed-width integer reads through the
  published `safe-read` crate and *never* hand-roll a per-crate `bytes.rs`.
  `ufs-core` instead hand-rolls `core/src/bytes.rs` (its own `le/be_u16/u32/u64`
  plus the `Endian` runtime selector). The genuine need is the runtime
  little-/big-endian *dispatch* (`safe-read` exposes fixed-`le`/`be` functions,
  and a thin `Endian` wrapper could delegate to them), so the low-level readers
  are duplication of the audited crate. **Rationale reconstructed from
  structure; original intent not recovered in available history** — the git log
  (`c008371` "P0 UFS superblock", where `bytes.rs` was introduced) records no
  reason for hand-rolling rather than depending on `safe-read`, and no code
  comment explains it. A follow-on should evaluate re-basing `Endian` onto
  `safe-read` to remove the duplicated, separately-fuzzed reader surface.
