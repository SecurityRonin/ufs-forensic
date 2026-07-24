# 3. Publish the reader as `ufs-core`, import it as `ufs`

Date: 2026-07-24
Status: Accepted

## Context

The fleet naming grammar (`ronin-issen/CLAUDE.md`, "Crate naming grammar" and
"Naming / imports") says: if the bare `<x>` crate name is taken on crates.io by
an unrelated third party we can safely co-exist with, publish `<x>-core` with
`[lib] name = "<x>"` so consumers still write `use <x>::…`; only when the bare
name is a *popular* crate do we avoid taking the import path.

The Research-First survey (`docs/RESEARCH.md` §2) found the bare `ufs` name
already published: *"ufs embed files and read from disk"* (v0.1.2, 53 downloads)
— an obscure, unrelated file-embedding utility, not a filesystem reader.

## Decision

Publish the reader crate as **`ufs-core`** (`core/Cargo.toml`
`name = "ufs-core"`) and claim the import path with **`[lib] name = "ufs"`**, so
consumers write `use ufs::{Superblock, read_path_content, …}` (`core/src/lib.rs`
re-exports). The analyzer crate stays **`ufs-forensic`** and re-exports the
reader surface under the `ufs` path (`forensic/src/lib.rs`:
`use ufs::{…}` and `pub use ufs::{Superblock as ReaderSuperblock, …}`).

The bare `ufs` package on crates.io (53 downloads, an embedding utility) is
judged obscure enough to co-exist with under a distinct package name while we
take the natural import path — exactly the co-existence case the grammar permits.

## Consequences

- Downstream code reads naturally (`use ufs::…`) despite the package being
  `ufs-core`; the package name is self-describing on crates.io as "the core of
  the `ufs-forensic` suite".
- The workspace inter-crate dependency is a single hoisted line
  (`[workspace.dependencies] ufs-core = { path = "core", version = "0.1.0" }`),
  switched to the registry version once published per the prefer-published-crate
  policy.
- No hijack of a popular import path — the taken `ufs` package is obscure, so the
  collision is cosmetic, not a namespace grab.
