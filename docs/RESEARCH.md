# UFS Forensic Reader — Research-First Report (`ufs-core` + `ufs-forensic`)

UFS = the Unix File System, a.k.a. the Berkeley Fast File System (FFS). The
name **UFS** matches TSK and dfvfs; the two on-disk versions are **UFS1**
(4.4BSD/FreeBSD legacy) and **UFS2** (FreeBSD 5+, 64-bit). This document is the
Research-First front door required before the first line of the reader: the
authoritative spec, the existing implementations (build-vs-reuse), the real
sample data + independent oracle, and the phased build plan with tiering and
the highest-risk structures. Everything below marked "verified" was checked
against the real dfvfs `ufs2.raw` image and TSK on this host.

## Executive Summary

- **Build our own** pure-Rust reader (`ufs-core`) + analyzer (`ufs-forensic`),
  fleet policy (no forensic-grade Rust UFS crate exists — see §2). TSK is the
  independent oracle; the dfvfs `ufs2.raw` image is a genuine **Tier-1** corpus.
- **Spec:** the FreeBSD kernel headers `sys/ufs/ffs/fs.h` (`struct fs`,
  `struct cg`), `sys/ufs/ufs/dinode.h` (`struct ufs1_dinode` / `ufs2_dinode`),
  `sys/ufs/ufs/dir.h` (`struct direct`) — §1.
- **The single highest-risk fact** is the superblock location + version/endian
  detection: UFS1 SB at byte **8192** (magic `0x00011954`), UFS2 SB at **65536**
  (magic `0x19540119`), both relative to the *filesystem* start (a partition may
  offset the whole thing). Endianness is host-defined; the magic disambiguates
  byte order (like ZFS) — support **both LE and BE**, selected by which byte
  order makes the magic match.
- **P0 (this phase):** `Superblock::parse` (version + endian detect, full
  geometry) and a cylinder-group header parse (`struct cg`, magic `0x00090255`),
  validated field-by-field against `fsstat`. Panic-free, bounds-checked.

## 1. Authoritative spec

**Primary — the FreeBSD kernel on-disk headers** (BSD-licensed, the canonical
source; Linux's UFS driver and TSK both track these):

- **Superblock + cylinder group:**
  <https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/ufs/ffs/fs.h>
  — `struct fs` (the superblock, `CTASSERT(sizeof(struct fs) == 1376)`),
  `struct cg` (the cylinder-group header), and every geometry macro
  (`ino_to_fsba`, `cgimin`, `fsbtodb`, `blkstofrags`, …).
- **Inodes:**
  <https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/ufs/ufs/dinode.h>
  — `struct ufs1_dinode` (128 bytes) and `struct ufs2_dinode` (256 bytes);
  `UFS_NDADDR = 12` direct + `UFS_NIADDR = 3` indirect block pointers;
  `UFS_ROOTINO = 2`.
- **Directories:**
  <https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/ufs/ufs/dir.h>
  — `struct direct { u32 d_ino; u16 d_reclen; u8 d_type; u8 d_namlen; char
  d_name[UFS_MAXNAMLEN+1]; }`, `UFS_MAXNAMLEN = 255`, `DIRBLKSIZ = 512`.
- **Secondary / oracle:** `fsstat(1)`, `fls(1)`, `istat(1)`, `icat(1)` from
  **The Sleuth Kit** — TSK's `tsk/fs/ffs.c` is a mature independent UFS reader
  and doubles as the answer key (fstype `ufs1`/`ufs2`/`ffs`/`freebsd`/`solaris`).

### Superblock (`struct fs`) — verified field offsets

One superblock per cylinder group; the **primary** is at a version-fixed byte
offset from the filesystem start:

```
#define SBLOCK_UFS1  8192     // magic FS_UFS1_MAGIC = 0x00011954
#define SBLOCK_UFS2 65536     // magic FS_UFS2_MAGIC = 0x19540119
#define SBLOCK_PIGGY 262144   // fallback search location
#define SBLOCKSIZE   8192
```

`fs_magic` is the **last** field of the 1376-byte struct, at offset **1372**.
Every offset below was computed from `struct fs` and then confirmed by decoding
the real dfvfs `ufs2.raw` primary superblock (image byte 73728 = partition base
8192 + SBLOCK_UFS2 65536) and cross-checking each value against `fsstat`:

| field | offset | type | ufs2.raw value | fsstat |
|---|---|---|---|---|
| `fs_sblkno` | 8 | i32 | 24 | Super Block 24-31 (frags) |
| `fs_cblkno` | 12 | i32 | 32 | Group Desc / cg block base |
| `fs_iblkno` | 16 | i32 | 40 | Inode Table 40-47 |
| `fs_dblkno` | 20 | i32 | 48 | Data Fragments start 48 |
| `fs_ncg` | 44 | u32 | 4 | Number of Cylinder Groups: 4 |
| `fs_bsize` | 48 | i32 | 32768 | Block Size: 32768 |
| `fs_fsize` | 52 | i32 | 4096 | Fragment Size: 4096 |
| `fs_frag` | 56 | i32 | 8 | (bsize/fsize) |
| `fs_bmask` | 72 | i32 | -32768 | `~(bsize-1)` |
| `fs_fmask` | 76 | i32 | -4096 | `~(fsize-1)` |
| `fs_bshift` | 80 | i32 | 15 | log2(bsize) |
| `fs_fshift` | 84 | i32 | 12 | log2(fsize) |
| `fs_fragshift` | 96 | i32 | 3 | log2(frag) |
| `fs_fsbtodb` | 100 | i32 | 3 | fsblock→disk-block shift |
| `fs_sbsize` | 104 | i32 | 4096 | actual superblock size |
| `fs_nindir` | 116 | i32 | 4096 | pointers per indirect block |
| `fs_inopb` | 120 | u32 | 128 | inodes per block |
| `fs_ipg` | 184 | i32 | 128 | Inodes per group: 128 |
| `fs_fpg` | 188 | i32 | 256 | Fragments per group: 256 |
| `fs_size` | 1080 | i64 | 1022 | Fragment Range 0-1021 |
| `fs_dsize` | 1088 | i64 | 901 | data fragments |
| `fs_csaddr` | 1096 | i64 | 48 | cg-summary frag address |
| `fs_sblockloc` | 1000 | i64 | 65536 | = SBLOCK_UFS2 (self-locating) |
| `fs_maxsymlinklen` | 1320 | i32 | 120 | fast-symlink threshold |
| `fs_magic` | 1372 | u32 | 0x19540119 | UFS2 magic |

> The struct has a 128-byte region (`fs_snapinum[]` + spare) between `fs_fpg`
> (188) and `fs_size`; the ≤188 geometry offsets and every high offset in the
> table were each pinned against the image, so the table is empirical, not a
> guess. **UFS1** uses the same offsets for the shared low fields but stores the
> geometry in the `fs_old_*` 32-bit fields (`fs_old_size`@36, `fs_old_dsize`@40,
> `fs_old_time`@32) instead of the 64-bit `fs_size`/`fs_dsize`; the reader
> branches on the detected magic. UFS1 offsets are spec-derived and validated
> against a real UFS1 image in a follow-on (see §3).

### Cylinder group (`struct cg`) — verified field offsets

Magic `CG_MAGIC = 0x00090255`. The cg header lives at `cgtod(fs, c) =
cgstart + fs_cblkno` frags (for UFS2 `cgstart = fs_fpg * c`). Verified against
the four cg headers in `ufs2.raw` (first at image byte 139264 = 8192 + 32×4096):

| field | offset | type | cg0 value |
|---|---|---|---|
| `cg_magic` | 4 | i32 | 0x00090255 |
| `cg_cgx` | 12 | u32 | 0 (this cg index) |
| `cg_ndblk` | 20 | u32 | 256 (data blocks this cg) |
| `cg_iusedoff` | 92 | u32 | 168 (used-inode bitmap offset) |
| `cg_freeoff` | 96 | u32 | 184 (free-block bitmap offset) |
| `cg_niblk` | 116 | i32 | inode blocks this cg |
| `cg_initediblk` | 120 | u32 | initialized inodes |

The bitmaps (`cg_inosused` at `cg + cg_iusedoff`, `cg_blksfree` at `cg +
cg_freeoff`) are the per-group allocation maps P1 uses to tell allocated from
free/deleted inodes.

### Inode / directory (P1/P2 preview)

- `ufs1_dinode` (128 B): `di_mode`@0, `di_nlink`@2, `di_size`@8 (u64),
  `di_atime`@16, `di_mtime`@24, `di_ctime`@32, `di_db[12]`@40 (u32 direct),
  `di_ib[3]`@88 (u32 indirect), `di_blocks`@104. No birth time.
- `ufs2_dinode` (256 B): adds `di_birthtime`, 64-bit `di_db[12]`/`di_ib[3]`
  block pointers, `di_extb`/extended attrs. Fast symlinks (`di_size <=
  fs_maxsymlinklen`) store the target inline in the block-pointer area.
- `struct direct`: variable-length; `d_reclen > DIRSIZ` marks slack; a deleted
  entry's space is absorbed into the previous record's `d_reclen`, leaving the
  original `d_ino`/`d_name` bytes visible (the recovery signal). First free
  entry of a block sets `d_ino = 0`.

## 2. Existing implementations (build-vs-reuse)

- **crates.io search "ufs":** the bare `ufs` crate is *"ufs embed files and read
  from disk"* (v0.1.2, 53 downloads) — an unrelated file-embedding utility, NOT
  a filesystem reader. No forensic-grade or even read-oriented UFS/FFS
  filesystem crate exists. **→ build our own** per fleet policy.
- **TSK (The Sleuth Kit)** — `tsk/fs/ffs.c` is the mature reference reader
  (UFS1/UFS2/Solaris-UFS). We use it as the **independent oracle**, not a
  dependency: `fsstat`/`fls`/`istat`/`icat` give the answer key on real bytes.
- **dfvfs** (log2timeline) — has a `pyfsext`-style path but relies on `pytsk3`
  for UFS; it ships the `ufs2.raw` Tier-1 test image we use (Apache-2.0).
- **FreeBSD/Linux kernel drivers** — the authoritative on-disk definition; read,
  not reused (C, GPL/BSD, in-kernel).

## 3. Real sample data + oracle

**Tier-1 (REAL-ext) — dfvfs `ufs2.raw`.** A genuine third-party UFS2 image whose
answer key comes from an oracle we did not author.

- **Download:**
  <https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/ufs2.raw>
- **Size / md5:** 4194304 bytes (4 MiB) / `19216a75a7933dfdac9ded5ff591fe82`.
- **Redistribution:** Apache-2.0 (committed; 4 MiB is well under the ~10 MiB
  crates.io tarball limit, but excluded from the published `.crate` anyway).
- **Layout:** a BSD-disklabel image — the UFS2 filesystem partition starts at
  **sector 16 (byte 8192)**; TSK reads it with `-o 16 -f ufs2`. Primary
  superblock at image byte **73728**.
- **Ground truth (TSK, this host):** UFS2, block 32768 / fragment 4096, 4
  cylinder groups, 128 inodes/group, 256 frags/group, volume `ufs2_test`, root
  inode 2. `fls -r`: `.snap`(3), `a_directory`(128) → `a_file`(129),
  `another_file`(130), `passwords.txt`(4), `a_link`(5), `$OrphanFiles`(512).
  `istat 4`: size 116, mode 0644, direct block 57; `icat 4 | sha256 =
  02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252` (content
  oracle for the P3 file-read gate).

**UFS1 branch (deferred to a real image).** The dfvfs corpus does not ship a
UFS1 image, and the host's `newfs`/BSD tooling is not available on the Ubuntu VM
(Linux `mkfs` does not write UFS). UFS1 offsets in §1 are spec-derived; the UFS1
code path is validated in a follow-on against a real FreeBSD UFS1 image (or a
self-minted one on a FreeBSD VM) with TSK `-f ufs1` as the oracle. **This is
noted, not silently skipped.**

**Oracle tiering.** The UFS2 path is **Tier-1** (third-party image + independent
TSK oracle on their bytes). The UFS1 path is currently **untested** and is
labelled as such until a real UFS1 image lands — never presented as Tier-1.

## 4. Scope / phased build order

**MVP reader:** superblock (version + endian + geometry) → cylinder-group
headers + allocation bitmaps → inode-by-number (UFS1 128 B / UFS2 256 B) →
directory `direct` walk + path resolve → file content via direct + single/
double/triple indirect blocks → forensic analyzer.

- **P0 — THIS PHASE.** `Superblock::parse(&[u8])`: detect UFS1@8192 /
  UFS2@65536 + LE/BE by the magic, decode full geometry (all §1 fields), fail
  loud with the offending bytes on bad magic, reject absurd geometry. Plus a
  cylinder-group header parse (`struct cg`, magic `0x00090255`) exposing
  `cg_cgx`/`cg_ndblk`/`cg_niblk` and the inode/block bitmap offsets. Verified
  field-by-field vs `fsstat`. Panic-free, bounds-checked, `forbid(unsafe)`.
- **P1 — inodes.** `Inode::parse` for UFS1 & UFS2 cores; inode-number →
  (cg, block, offset) decode via `ino_to_fsba`/`cgimin`; allocated-vs-free from
  the cg `cg_inosused` bitmap. Oracle: `istat`.
- **P2 — directories / path.** `struct direct` walk over a directory's blocks,
  slack-aware; `read_by_path`. Oracle: `fls -r`.
- **P3 — file content.** Direct blocks + single/double/triple indirect
  (`fs_nindir` pointers per block); assemble file bytes. Oracle: `icat | sha256`
  (the passwords.txt hash above), a Tier-1 content check.
- **F (forensic analyzer, `ufs-forensic`).** Deleted-inode recovery (a
  cg-bitmap-free inode whose core still holds block pointers), directory-slack
  residue (freed `direct` keeping its `d_ino`/`d_name`), `$OrphanFiles`-style
  unlinked-but-referenced inodes, and geometry-sanity findings — each a graded
  `forensicnomicon::report::Finding`.

**Highest-risk structures (get these from the spec, never memory):**
1. **Superblock location + version/endian detect** — the P0 crux. Wrong offset
   or byte order silently yields zero-geometry (verified: `fs_magic` is at 1372,
   not the naive "start"; a partition base shifts everything). Mitigated by
   magic-driven detection validated against the real image.
2. **UFS1 vs UFS2 divergence** — different inode size (128 vs 256), 32-bit vs
   64-bit block pointers and `fs_size`, birthtime presence. Branch cleanly on
   the detected magic at the top.
3. **Fragment-vs-block addressing** — UFS's block/fragment duality (`fs_frag`
   frags per block, `fs_fsbtodb` to disk blocks). Every address math uses the
   spec macros, not ad-hoc shifts.
4. **Indirect-block chains (P3)** — single/double/triple; the classic place an
   off-by-one in `fs_nindir` corrupts large-file reads. Validate every block
   against `icat`.

**Gaps to close before later phases:** (1) source a real UFS1 image to lift the
UFS1 path from spec-derived to Tier-1; (2) confirm the exact `di_*` offsets of
`ufs2_dinode` against `istat` before trusting P1; (3) verify TSK's UFS feature
coverage (soft-updates journaling, snapshots) before relying on it as tiebreaker
on those cases.
