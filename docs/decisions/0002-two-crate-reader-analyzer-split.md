# 2. Two-crate reader/analyzer split (`ufs-core` + `ufs-forensic`)

Date: 2026-07-24
Status: Accepted

## Context

The fleet's Crate-structure standard (`ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") mandates that every single-format repo be one
workspace named `<x>-forensic` with two members: `core/` → `<x>-core` (the raw
reader, no findings) and `forensic/` → `<x>-forensic` (the anomaly auditor
emitting `forensicnomicon::report::Finding`).

That standard also carries a binding refinement: `-forensic` is **not required**
to route everything through `-core`. A `-core` reader is built to read *valid*
data robustly, so it normalizes away exactly the detail an auditor must see —
slack between records, freed-but-intact structure, fields a robust reader skips.
UFS delete semantics are a textbook case: an `rm` clears a directory entry's
`d_ino` (absorbing its bytes into the previous record's `d_reclen`) and clears
the cylinder-group inode-used bit, but leaves the dinode's `di_size`/`di_db` and
the data blocks intact (`forensic/src/lib.rs` module doc; `docs/RESEARCH.md` §4).

## Decision

Ship the workspace (`Cargo.toml` `members = ["core", "forensic"]`) as:

- **`ufs-core`** — superblock/geometry, cylinder-group headers + allocation
  bitmaps, UFS1/UFS2 dinode decode, `struct direct` walking, path resolution,
  and block-map → file content, over any `&[u8]`. Emits no findings.
- **`ufs-forensic`** — depends on `ufs-core` (`forensic/Cargo.toml`:
  `ufs-core = { workspace = true }`) for the valid-path reading, but **drops to
  parsing the raw partition bytes directly** where the audit must see what the
  reader normalizes: a `d_ino == 0` dirent slot, a bitmap-free-but-intact
  dinode, and the raw backup-superblock bytes. It reads `fs_magic` and `cg_magic`
  at fixed offsets itself (`FS_MAGIC_OFF = 1372`, `CG_MAGIC_OFF = 4` in
  `forensic/src/lib.rs`) rather than through a reader accessor.

This mirrors the established fleet models (`ewf-forensic`, `ntfs-forensic`) cited
in the constitution.

## Consequences

- The auditor is never contorted through a happy-path reader API that hides the
  anomaly it hunts — it sees the raw, possibly-broken structure.
- `ufs-core` stays reusable by any third party that only wants to read UFS
  volumes, with no forensic or reporting-model dependency.
- The two crates version independently (`Cargo.toml` comment: `version` is not
  hoisted into `[workspace.package]`), so a reader fix ships without forcing an
  auditor bump.
