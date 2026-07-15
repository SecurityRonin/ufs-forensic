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
- **Used by:** the P0 superblock/cylinder-group tests (env var
  `UFS2_DFVFS_ORACLE` points at the image; the test skips cleanly when absent,
  like an oracle binary). Later phases (P1 inode / P2 dir / P3 content) reuse the
  same image and the TSK ground truth above.

## UFS1 — deferred to a real image (NOT yet committed)

The dfvfs corpus ships no UFS1 image, and Linux `mkfs` does not write UFS, so a
UFS1 fixture is not self-mintable on the Ubuntu oracle VM. The UFS1 code path's
offsets are spec-derived (FreeBSD `sys/ufs/ffs/fs.h`) and are lifted to Tier-1
in a follow-on against a real FreeBSD UFS1 image (or one minted on a FreeBSD VM
with `newfs`), with TSK `-f ufs1` as the independent oracle. This is documented,
not silently skipped.
