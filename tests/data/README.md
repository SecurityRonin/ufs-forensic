# UFS Forensic Test Data — Provenance

<!-- TODO(corpus-catalog): add a REAL-ext row for tests/data/ufs2.raw (dfvfs UFS2
     Tier-1, Apache-2.0, md5 19216a75a7933dfdac9ded5ff591fe82) to
     issen/docs/corpus-catalog.md. NOT done here — the issen repo is held by
     another session; add it there when that session is free. This repo touches
     only ufs-forensic per the task scope. -->

See the fleet catalog at `issen/docs/corpus-catalog.md` for the machine index;
this README is the co-located human detail. See `../../docs/RESEARCH.md` for the
full spec + oracle write-up.

## REAL-ext Tier-1 — dfvfs `ufs2.raw` (committed, always-on)

A genuine third-party UFS2 image whose answer key comes from oracles we did not
author (The Sleuth Kit on the real bytes). This is the load-bearing correctness
proof for the UFS2 path; it is committed (4 MiB, well under the ~10 MiB
crates.io tarball limit, and excluded from the published `.crate` regardless)
and its test is always-on.

- **Source:** log2timeline/dfvfs test corpus (`test_data/ufs2.raw`).
- **Download URL:**
  <https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/ufs2.raw>
- **Size / md5:** 4194304 bytes / `19216a75a7933dfdac9ded5ff591fe82`.
- **Redistribution:** Apache-2.0.
- **Identity / layout:** BSD-disklabel image; the UFS2 filesystem partition
  starts at **sector 16 (byte 8192)** — TSK reads it with `-o 16 -f ufs2`.
  Primary superblock at image byte **73728** (8192 + SBLOCK_UFS2 65536).
- **Ground truth (TSK on this host):** UFS2, block 32768 / fragment 4096, 4
  cylinder groups, 128 inodes/group, 256 frags/group, volume `ufs2_test`, root
  inode 2. Contents (`fls -o 16 -f ufs2 -r`): `.snap`(3), `a_directory`(128) →
  `a_file`(129), `another_file`(130), `passwords.txt`(4), `a_link`(5),
  `$OrphanFiles`(512). `istat 4`: size 116, mode 0644, direct block 57;
  `icat 4 | sha256 =
  02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252`.
- **Used by:** the env-gated full-image oracle test (`core/tests/
  superblock_oracle.rs`; env var `UFS2_DFVFS_ORACLE` points at this image; the
  test skips cleanly when absent, like an oracle binary). Later phases (P1 inode
  / P2 dir / P3 content) reuse the same image and the TSK ground truth above.

### Committed always-on fixtures (extracted from `ufs2.raw`)

Small slices of the image above, committed so `core/tests/fixture.rs` runs
in a plain `cargo test` (no env var). Re-extract with:
`python3 -c "d=open('ufs2.raw','rb').read();
open('ufs2_superblock.bin','wb').write(d[73728:73728+1376]);
open('ufs2_cg0.bin','wb').write(d[139264:139264+256]);
open('ufs2_inodes_0_15.bin','wb').write(d[172032:172032+4096])"`.

- **`ufs2_superblock.bin`** — the 1376-byte primary UFS2 superblock (image byte
  73728). md5 `6323c77a514e2e82c620dd4138259fbd`.
- **`ufs2_cg0.bin`** — the 256-byte first cylinder-group header (image byte
  139264). md5 `84f832db7344638fbd7319b1b66e15c4`.
- **`ufs2_inodes_0_15.bin`** — the first 16 UFS2 dinodes (256 B each = 4096
  bytes) of cg0's inode table (image byte 172032 = partition base 8192 +
  filesystem byte 163840, where the inode table starts at fragment
  `fs_iblkno`=40 × `fs_fsize`=4096). Covers the ground-truth inodes 2/4/5.
  md5 `106d1a90e7a80e9039ffcf4f0441abaf`. Used by the P1 inode-decode tests in
  `core/tests/fixture.rs`.
  - **Ground truth (`istat -o 16 -f ufs2 ufs2.raw <ino>`):**
    - inode **2** (root dir): mode `drwxr-xr-x` (040755), size 512, nlink 4,
      uid/gid 0, direct block 56.
    - inode **4** (`passwords.txt`): mode 0100644, size 116, nlink 1, uid/gid 0,
      direct block 57.
    - inode **5** (`a_link`): symlink (0120755), size 24, fast (inline) target
      `a_directory/another_file` (size ≤ `fs_maxsymlinklen`=120).
    - mtime seconds = 1682843463 (2023-04-30 08:31:03 UTC = 16:31:03 HKT).
- **Used by:** the env-gated full-image inode oracle test
  (`core/tests/inode_oracle.rs`; `read_inode` locate+decode on the partition
  slice, gated on `UFS2_DFVFS_ORACLE`) and the always-on `Inode::parse` decode
  tests over `ufs2_inodes_0_15.bin` in `core/tests/fixture.rs`.
- **`ufs2_rootdir.bin`** — the root directory's 512-byte (`DIRBLKSIZ`) data block
  (root inode 2's direct fragment 56 → image byte 237568 = partition base 8192 +
  fragment 56 × `fs_fsize` 4096). Re-extract with:
  `python3 -c "d=open('ufs2.raw','rb').read();
  open('ufs2_rootdir.bin','wb').write(d[237568:237568+512])"`.
  md5 `0d73dd459b9013e8e41a1b9e7e2cef30`. The `struct direct` entries here are the
  P2 directory-walk ground truth: `.`(2)/`..`(2)/`.snap`(3)/`a_directory`(128)/
  `passwords.txt`(4)/`a_link`(5), the last record's `d_reclen` (428) absorbing
  the block tail (12+12+16+20+24+428 = 512). Matches `fls -o 16 -f ufs2` (which
  omits `.`/`..`). Used by the always-on `list_dir_all` walk test in
  `core/tests/fixture.rs` and, on the full image, the env-gated
  `core/tests/dir_oracle.rs` (`list_dir` / `read_by_path` vs `fls` / `ffind`).

### P3 file-content ground truth (`icat`) + synthetic indirect fixture

**Real-image content oracle (Tier-1, `core/tests/file_oracle.rs`, env-gated on
`UFS2_DFVFS_ORACLE`).** `read_file` / `read_path_content` assemble a file's bytes
from its block map; the SHA-256 of the assembled bytes is checked against
`icat -o 16 -f ufs2 ufs2.raw <ino> | sha256sum`:

- inode **4** (`/passwords.txt`, 116 bytes): sha256
  `02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252`.
- inode **129** (`/a_directory/a_file`, 53 bytes): sha256
  `4a49638d0e1055fd9e4c17fef7fdf4d6ccf892b6d9c2f64164203c4bfb0ec92d`.
- inode **130** (`/a_directory/another_file`, 22 bytes): sha256
  `c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16`.
- inode **5** (`a_link`): a **fast (inline)** symlink; `read_symlink_target`
  returns `a_directory/another_file` straight from the dinode (no data block).

Every file in this image is a single direct block, so the image cannot exercise
the single / double / triple **indirect** chains.

**Synthetic indirect fixture (`core/tests/file_indirect.rs`, always-on, built at
runtime — NOT committed).** There is no `mkfs.ufs`/`makefs` on the build host to
mint a real large-file UFS2 image, so the test crafts a UFS2 partition in memory
whose one file's block map spans 12 direct blocks + a full single-indirect block
+ into the double-indirect tree + one block reached only through the
triple-indirect chain, plus a hole and a partial fragment tail. It is generated
by `build()` in `core/tests/file_indirect.rs` (geometry: `bsize`=`fsize`=512,
`frag`=1, `nindir`=64; deterministic content byte `(i*2654435761)&0xFF`). The
oracle is two independent decoders agreeing on the crafted artifact: the known
content pattern **and** a separately-written block-map walker (`independent_walk`)
that re-reads the on-disk pointer blocks. Robustness cases (allocation-bomb
`u64::MAX` di_size, truncation, lying pointer) are covered there and in the
`core/src/file.rs` unit tests (which also drive the UFS1 4-byte-pointer path).

## UFS1 — deferred to a real image (NOT yet committed)

The dfvfs corpus ships no UFS1 image, and Linux `mkfs` does not write UFS, so a
UFS1 fixture is not self-mintable on the Ubuntu oracle VM. The UFS1 code path's
offsets are spec-derived (FreeBSD `sys/ufs/ffs/fs.h`) and are lifted to Tier-1
in a follow-on against a real FreeBSD UFS1 image (or one minted on a FreeBSD VM
with `newfs`), with TSK `-f ufs1` as the independent oracle. This is documented,
not silently skipped.

## `ufs-forensic` analyzer layer — F-INTEGRITY + F-CARVE

**F-INTEGRITY (`forensic/tests/integrity.rs`).** Two tiers:

- **Tier-1 (real image, env-gated `UFS2_DFVFS_ORACLE`):** the committed
  `ufs2.raw` — a clean third-party UFS2 filesystem — must produce **no** false
  anomalies (`audit_image` empty). This is the load-bearing "clean-emits-nothing"
  proof.
- **Tier-3 (crafted corruption, built at runtime — NOT committed):** a synthetic
  UFS2 partition (`forensic/tests/common/mod.rs`, `clean_partition()`, geometry
  mirroring the real image: `bsize` 32768, `fsize` 4096, `fpg` 256, `ipg` 128,
  `sblkno` 24, `cblkno` 32, `iblkno` 40, 4 cylinder groups) into which exactly one
  corruption is injected per case, so each `UFS-*` code fires on precisely its
  trigger: a byte-flipped `fs_magic` (`UFS-SUPERBLOCK-MAGIC-INVALID`), a diverged
  backup-superblock `fs_ipg` (`UFS-BACKUP-SUPERBLOCK-DIVERGENCE`), a bad `cg_magic`
  (`UFS-CG-MAGIC-INVALID`), an allocated-but-unreferenced inode
  (`UFS-ORPHANED-INODE`), and an `fs_ncg` whose last cg base lies past the image
  (`UFS-IMPOSSIBLE-GEOMETRY`). These are detection-rule fixtures (correctness
  defined by the spec + the rule), not value-producing decoders.

**F-CARVE deletion oracle (`forensic/tests/carve.rs`, built at runtime — NOT
committed).** The fresh `ufs2.raw` has no user deletions, so recovery cannot be
exercised against it. Instead the test **crafts** a valid UFS2 partition with a
known file `secret.txt` (inode 6, size 250, deterministic content byte
`(i*2654435761)&0xFF`), records the content's SHA-256 **pre-delete**, then
**simulates a UFS `rm`**: it zeroes the dirent's `d_ino` in the parent directory
block (leaving the residual `d_name` in the reclen slack) AND clears inode 6's
used-bit in the cg0 inode bitmap, leaving `di_size`/`di_db` and the data block
INTACT — the classic residue a real UFS delete leaves. `recover_deleted`'s carved
content is checked against the recorded pre-delete SHA-256, a
construction-derived answer key independent of the reader, so a wrong carve cannot
pass by matching a fixture encoded to the bug. Real-world recovery is
state-dependent: it succeeds only while the freed dinode and data blocks are
un-reallocated; the analyzer returns nothing rather than fabricate once the
residue is gone.

**Edge / defensive-arm coverage (`forensic/tests/edge.rs`, built at runtime).**
Crafted adversarial partitions drive the panic-free guards a happy-path test never
reaches: truncation past the primary superblock (cg headers/backup SBs off the
end), an unparseable backup superblock, an allocated-in-bitmap inode with a zeroed
or unreadable dinode (the false-orphan guards), a directory cycle, a subdirectory
holding a deleted entry, an allocation-bomb `di_size` on a free inode, and a dir
entry naming an out-of-range inode.

<!-- TODO(corpus-catalog): the crafted UFS2 partitions above (F-INTEGRITY
     corruption cases, the F-CARVE deletion oracle, and the edge cases) are built
     at runtime and NOT committed; classify them SYNTHETIC in
     issen/docs/corpus-catalog.md with their builder fn + file:line
     (forensic/tests/common/mod.rs + forensic/tests/{integrity,carve,edge}.rs).
     NOT done here — the issen repo is held by another session. -->
