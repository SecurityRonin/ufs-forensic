# 8. Deleted-item recovery from freed residue, SHA-256-stamped and validated against an independent pre-delete hash, reported as observations

Date: 2026-07-24
Status: Accepted

## Context

The forensic differentiator over a general-purpose UFS reader is recovering what
a delete leaves behind. UFS `rm` semantics leave rich residue (`forensic/src/lib.rs`
module doc; `docs/RESEARCH.md` §4): it clears the directory entry's `d_ino` and
absorbs the entry into the previous record's `d_reclen` (leaving the original
`d_name` bytes visible), and clears the cylinder-group inode-used bit — but leaves
the dinode's `di_mode`/`di_size`/`di_db` and the data blocks intact until they
are re-allocated.

Two fleet constraints shape how this is reported: findings are **observations,
never conclusions** ("consistent with …"; the examiner concludes), and a
value-producing recovery path needs an answer key **independent of the reader**
so a wrong carve cannot self-certify (Evidence-Based Rigor).

## Decision

`ufs-forensic` splits its capability into two entry points
(`forensic/src/lib.rs`):

- **F-INTEGRITY** (`audit_image` → `Vec<Anomaly>`, `audit_findings` →
  `Vec<Finding>`) emits severity-graded structural findings under stable,
  published SCREAMING-KEBAB codes: `UFS-SUPERBLOCK-MAGIC-INVALID`,
  `UFS-BACKUP-SUPERBLOCK-DIVERGENCE` (a spliced/edited-image tell),
  `UFS-CG-MAGIC-INVALID`, `UFS-ORPHANED-INODE`, `UFS-IMPOSSIBLE-GEOMETRY`
  (an allocation-bomb guard). Each is an `impl Observation` converting to a
  `forensicnomicon::report::Finding` (the fleet producer pattern).
- **F-CARVE** (`recover_deleted`) sweeps every cylinder group for inodes that are
  **free** in the cg bitmap yet still carry an intact `di_mode`/`di_size`/`di_db`,
  re-assembles their content, and walks the directory tree for `d_ino == 0` slots
  whose residual `d_name` survives — returning each as a `DeletedFile`
  (conceptually `UFS-DELETED-FILE-CARVED`) or `DeletedDirent`
  (`UFS-DELETED-DIRENT`).

Two guarantees are load-bearing:

1. **State-dependent, never fabricated.** Recovery succeeds only while the freed
   dinode and its data blocks are un-reallocated, and returns **nothing** rather
   than fabricate once the residue is gone (fail-loud / never-swallow applied to
   carving).
2. **SHA-256 provenance stamp, validated out-of-band — not a runtime gate.** Carved
   file content carries a `sha2`-computed SHA-256 as an output field
   (`RecoveredItem::DeletedFile::content_sha256`; `forensic/Cargo.toml`: `sha2` —
   "never hand-rolled", the audited RustCrypto crate). At runtime `recover_deleted`
   attaches this hash and emits the carved content whenever the residue survives; it
   does **not** reject a carve on a hash. The hash earns its keep in *validation*:
   the F-CARVE test (`forensic/tests/carve.rs`) compares it against a pre-delete
   hash derived independently of the reader (ADR 0007), so a wrong carve cannot
   self-certify.

## Consequences

- A UFS volume's deleted files and directory residue aggregate uniformly with
  the partition and container layers through the shared `report::Finding` model,
  so Issen/disk4n6 render them without a bespoke `UfsAnalysis` type.
- Codes are a published contract — never changed once shipped; new variants get
  new codes.
- Recovery output is defensible: it is an observation carrying a SHA-256 provenance
  stamp — checked against an independently-derived pre-delete hash in validation
  (ADR 0007) — that degrades to empty rather than inventing bytes.
