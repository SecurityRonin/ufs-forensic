# ufs-forensic — Design (Purpose & Scope)

This is a **library** workspace, not a product an examiner runs. It ships two
crates to be linked, not a `*4n6` CLI, GUI, or MCP server. This document records
the purpose, scope, and boundaries; the load-bearing decisions live as ADRs in
[`docs/decisions/`](decisions/), the correctness evidence in
[`validation.md`](validation.md), and the pre-build survey in
[`RESEARCH.md`](RESEARCH.md).

## Purpose

Read and forensically audit **UFS/FFS** filesystems — the Unix File System, a.k.a.
the Berkeley Fast File System, native to FreeBSD, the historic BSDs, and Solaris —
in both on-disk generations (UFS1 and UFS2), over any byte source, with no C
bindings and no `unsafe`. UFS was an uncovered artifact family in a fleet that
already reads NTFS, ext4, APFS, and XFS; no forensic-grade Rust UFS crate existed
(ADR 0001).

## Who links this

- **The forensic-vfs engine / Issen / disk4n6** — to mount a UFS volume as one
  `Arc<dyn FileSystem>` in a composed image stack, and to aggregate its anomalies
  into the shared `forensicnomicon::report` model alongside the partition and
  container layers (ADR 0002, 0008, 0009).
- **Any Rust consumer** that needs to read a UFS1/UFS2 volume from a `&[u8]` —
  `ufs-core` alone, dependency-light, is a standalone reader (ADR 0003).

## What it does

Two crates, one workspace (ADR 0002):

- **`ufs-core`** (import path `ufs`) — the reader: UFS1/UFS2 superblock + geometry
  with magic-driven version and byte-order auto-detect (ADR 0004); cylinder-group
  headers and allocation bitmaps; UFS1 (128-byte) / UFS2 (256-byte) dinode decode;
  `struct direct` directory walking and path resolution; block-map → file content
  (12 direct + single/double/triple indirect chains); fast + slow symlink targets.
  Optionally adapts onto the `forensic-vfs` `FileSystem` contract behind the `vfs`
  feature (ADR 0009).
- **`ufs-forensic`** — the auditor: F-INTEGRITY structural findings
  (`UFS-SUPERBLOCK-MAGIC-INVALID`, `UFS-BACKUP-SUPERBLOCK-DIVERGENCE`,
  `UFS-CG-MAGIC-INVALID`, `UFS-ORPHANED-INODE`, `UFS-IMPOSSIBLE-GEOMETRY`) and
  F-CARVE deleted-item recovery from freed-but-intact residue, each carved file
  SHA-256-stamped and validated against an independent pre-delete hash (ADR 0008).
  Each finding is a graded
  `forensicnomicon::report::Finding` and an **observation** — the examiner draws
  the conclusion.

## Scope

- UFS1 and UFS2 on-disk formats, little- and big-endian images.
- Read-only structural parsing, path/content extraction, and anomaly/carve
  auditing over an in-memory partition slice.
- Composition into the fleet VFS + reporting layers.

## Non-goals

- **No writing / repair.** The crates are read-only; carving emits derived
  recovered content, never mutating the source.
- **No C / `libtsk` linkage.** The Sleuth Kit is an independent validation
  oracle, not a dependency (ADR 0001, 0007).
- **No end-user binary.** No CLI/GUI/MCP front-end lives here; the fuzz crate is
  dev-only (`publish = false`). User-facing UX belongs to Issen / disk4n6.
- **No soft-updates journal / snapshot semantics** beyond what the on-disk
  structures expose (flagged as a validation caveat in `RESEARCH.md` §4).
- **No streaming windowed reads yet.** The reader takes the whole partition as
  `&[u8]`; the forensic-vfs adapter reads the source wholly into RAM (ADR 0009).

## Robustness & validation posture

`#![forbid(unsafe_code)]` in both crates, panic-free bounds-checked readers, and a
`cargo-fuzz` target per parsed structure plus a full-pipeline target (ADR 0005).
The UFS2 read path is Tier-1 validated against a real third-party dfvfs image with
The Sleuth Kit as the independent oracle, down to per-file `icat | sha256`; the
indirect-block walk is cross-checked by an independent walker; the UFS1 path is
spec-derived and **labelled untested** until a real UFS1 image lands (ADR 0007,
`validation.md`).
