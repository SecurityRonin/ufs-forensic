# 9. Optional forensic-vfs adapter behind the `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet's VFS/Universal-Container abstraction (`ronin-issen/CLAUDE.md`, "VFS &
Universal Container Abstraction") says a consumer that reads an evidence image
must not know one filesystem format from another: readers implement the
`forensic-vfs` traits and `forensic-vfs-engine` composes a whole stack
(`E01 → GPT → BitLocker → NTFS`) as one `Arc<dyn FileSystem>`, auto-detected
through a shared probe registry. UFS should compose there alongside
NTFS/ext4/APFS/XFS.

Two facts complicate the adapter (`core/src/vfs.rs` module doc):

- `ufs-core` is a **slice reader** — `read_inode`/`list_dir`/`read_file` take the
  whole partition as `&[u8]` (filesystem byte 0), not a `Read + Seek` cursor —
  while a `forensic-vfs` source is a positioned-read byte source.
- A bare parser consumer wants no `forensic-vfs` dependency cost.

## Decision

- Provide `impl forensic_vfs::FileSystem for UfsFs` plus a `ufs_probe` sniffer
  (`core/src/vfs.rs`), gated behind an **opt-in `vfs` Cargo feature**
  (`core/Cargo.toml`: `vfs = ["dep:forensic-vfs"]`, `forensic-vfs` declared
  `optional = true`). A bare reader stays dependency-light; only a consumer
  wanting VFS composition pays the `forensic-vfs` cost.
- Bridge the `&[u8]`-vs-`positioned-read` gap by reading the **entire source into
  an owned `Vec<u8>` once at `UfsFs::open`** and serving every later call from
  that buffer — the same choice the XFS/HFS+ adapters make for their slice-based
  readers. The consequence (a UFS volume held wholly in RAM; no windowed
  `read_at`) is documented in the module doc rather than hidden.
- Map UFS identity onto `FileId::Opaque` carrying the inode number (UFS has no
  dedicated `FileId` variant), refuse any non-`Default` `StreamId` **loud** (UFS
  files are a single unnamed fork), and surface reader errors through a `map_err`
  seam rather than swallowing them.
- Pin `forensic-vfs` via the hoisted workspace dependency, bumped as the contract
  evolves (git log: `0.4 → 0.5 → 0.7`, dependency-freshness maintenance).

## Consequences

- A UFS/FFS volume auto-detects and composes as `Arc<dyn FileSystem>` in the
  forensic-vfs engine, so image-reading consumers need no UFS-specific branch.
- The whole-into-RAM bridge is a known, documented limit for multi-GB volumes —
  a `read_at`-windowing reader API would be the seam to add if streaming is later
  required; it is stated, not papered over.
- The default reader build has no `forensic-vfs` in its tree, preserving the
  low-MSRV, dependency-light posture (ADR 0006) for third-party parser-only use.
