# 4. Detect UFS1/UFS2 and byte order from the superblock magic

Date: 2026-07-24
Status: Accepted

## Context

UFS exists in two on-disk generations that differ in inode size, block-pointer
width, geometry-field layout, and superblock location:

- **UFS1** — 128-byte dinodes, 32-bit block pointers, primary superblock at byte
  **8192**, magic `FS_UFS1_MAGIC = 0x00011954`, geometry in the `fs_old_*`
  32-bit fields.
- **UFS2** — 256-byte dinodes, 64-bit block pointers, primary superblock at byte
  **65536**, magic `FS_UFS2_MAGIC = 0x19540119`, 64-bit `fs_size`/`fs_dsize`.

Both offsets are relative to the *filesystem* start; a partition/disklabel may
offset the whole thing (the dfvfs `ufs2.raw` image places the filesystem at
sector 16 / byte 8192, so the primary superblock lands at image byte 73728 —
`docs/RESEARCH.md` §3, `docs/validation.md`).

Critically, **UFS is endianness-agnostic on disk**: the filesystem is written in
the byte order of the host that created it (little-endian x86, big-endian
SPARC/historic hosts), and the superblock magic is what disambiguates the order
— the same design as ZFS (`core/src/bytes.rs` and `core/src/lib.rs` module
docs). `docs/RESEARCH.md` §4 flags "superblock location + version/endian detect"
as the single highest-risk fact in the whole reader: a wrong offset or byte order
silently yields zero-geometry.

## Decision

Detect version and byte order together, driven by the magic:

1. `Superblock::parse` reads `fs_magic` (offset 1372, the last field of the
   1376-byte `struct fs`) and tries both interpretations, selecting the
   `(version, endian)` pair — UFS1/UFS2 × LE/BE — under which the magic matches
   a known constant (`core/src/superblock.rs`, `UfsVersion`, `Endian`).
2. Every field read thereafter goes through the resolved `Endian` selector
   (`Endian::{u16,u32,u64,i32,i64}` in `core/src/bytes.rs`), so the whole decode
   is byte-order-correct by construction.
3. The reader branches on the detected version: UFS2 reads the 64-bit
   `fs_size`/`fs_dsize` and 256-byte dinodes; UFS1 reads the `fs_old_*` fields
   and 128-byte dinodes (`UFS1_DINODE_SIZE`/`UFS2_DINODE_SIZE`,
   `docs/RESEARCH.md` §1).
4. A magic matching neither version in either order fails **loud** with the four
   offending bytes and both interpretations (`UfsError::BadMagic { offset, bytes,
   le, be }` in `core/src/error.rs`) — never a silent zero-geometry.

The field offsets in the table (`docs/RESEARCH.md` §1) were pinned empirically
against the real `ufs2.raw` superblock and cross-checked field-by-field against
`fsstat`, not taken from memory.

## Consequences

- Both little- and big-endian images, of either generation, read correctly with
  no caller hint — the auto-detect is a headline capability (README "Endianness
  auto-detect").
- Bad magic surfaces the evidence (raw bytes + both interpretations) so an
  examiner can identify what the image actually is, satisfying the fleet
  "show the unrecognized value" robustness rule.
- The UFS1 offset table is spec-derived and validated only by unit tests until a
  real UFS1 image lands (ADR 0007 records this tiering gap honestly).
