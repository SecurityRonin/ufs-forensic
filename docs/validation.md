# Validation

How `ufs-core` (and the `ufs-forensic` auditor over it) is proven correct, and at
what evidentiary tier. The axis is **who authored the artifact and its answer
key** — not whether the data is "synthetic" — following the fleet's
Evidence-Based Rigor discipline.

## Summary

- **Tier-1 (real image + independent decoder oracle):** the UFS2 reader is
  validated against a genuine third-party image, `tests/data/ufs2.raw` from
  [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) (Apache-2.0), whose
  ground truth comes from **The Sleuth Kit** (`fsstat` / `fls` / `istat` /
  `icat`) — a wholly separate implementation. Neither the image nor the answer
  key was authored by us. The image is committed (4 MiB, md5
  `19216a75a7933dfdac9ded5ff591fe82`); the always-on fixture tests run everywhere,
  and the full-image oracle tests are env-gated on `UFS2_DFVFS_ORACLE` (pointing
  at the same image) and skip cleanly when unset.
- **Tier-2 (synthetic, independent-walker cross-check):** the single / double /
  triple **indirect** block chains — which no publicly available real UFS image
  exercises — are validated over a **crafted** image by two decoders agreeing on
  it (a known content pattern **and** a separately-written block-map walker), not
  a self-encoded round-trip.
- **Tier-3 (self-authored detection-rule fixtures):** the `ufs-forensic` anomaly
  detectors and the deletion-carve residue are exercised by crafted partitions
  where correctness is defined by the spec + the rule, with the carve's answer key
  (a pre-delete SHA-256) derived independently of the reader.

## Tier-1 — dfvfs `ufs2.raw` (third-party, Apache-2.0)

**Source.** `test_data/ufs2.raw` from log2timeline/dfvfs (Joachim Metz),
Apache-2.0, downloaded from
<https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/ufs2.raw> and
committed here as `tests/data/ufs2.raw` (4 194 304 bytes, md5
`19216a75a7933dfdac9ded5ff591fe82`). It is a BSD-disklabel image whose UFS2
filesystem partition starts at **sector 16 (byte 8192)**; the primary superblock
is at image byte **73728** (8192 + `SBLOCK_UFS2` 65536).

**Oracle (independent of our reader) — The Sleuth Kit** run on the real bytes
(`-o 16 -f ufs2`):

| Oracle | What it establishes |
|---|---|
| `fsstat` | UFS2, block 32768 / fragment 4096, 4 cylinder groups, 128 inodes/group, 256 frags/group, volume `ufs2_test`, root inode 2 |
| `fls -r` | directory tree: `.snap`(3), `a_directory`(128) → `a_file`(129) / `another_file`(130), `passwords.txt`(4), `a_link`(5), `$OrphanFiles`(512) |
| `istat <ino>` | per-inode mode / size / nlink / uid-gid / direct-block placement (e.g. inode 4 = size 116, mode 0644, direct block 57) |
| `icat <ino> \| sha256` | per-file content hash — the load-bearing block-map proof |

**Ground truth captured** (verbatim in
[`tests/data/README.md`](https://github.com/SecurityRonin/ufs-forensic/blob/main/tests/data/README.md)),
including the `icat | sha256` content hashes the reader must reproduce:

- inode **4** (`/passwords.txt`, 116 B): sha256
  `02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252`.
- inode **129** (`/a_directory/a_file`, 53 B): sha256
  `4a49638d0e1055fd9e4c17fef7fdf4d6ccf892b6d9c2f64164203c4bfb0ec92d`.
- inode **130** (`/a_directory/another_file`, 22 B): sha256
  `c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16`.
- inode **5** (`a_link`): a fast (inline) symlink; `read_symlink_target` returns
  `a_directory/another_file` straight from the dinode.

**Tests.** The env-gated full-image oracle tests (`core/tests/superblock_oracle.rs`,
`inode_oracle.rs`, `dir_oracle.rs`, `file_oracle.rs`, gated on `UFS2_DFVFS_ORACLE`)
assert `Superblock::parse` / `read_inode` / `list_dir` / `read_by_path` /
`read_file` against the TSK values above; the always-on fixture tests
(`core/tests/fixture.rs`) run the same decode over small committed slices
(`ufs2_superblock.bin`, `ufs2_cg0.bin`, `ufs2_inodes_0_15.bin`, `ufs2_rootdir.bin`)
so a plain `cargo test` exercises the P0–P2 path with no env var. On the forensic
side, `forensic/tests/integrity.rs` asserts the clean third-party image produces
**no** false anomalies (`audit_image` empty) — the load-bearing
"clean-emits-nothing" proof.

**Result.** All assertions pass: `ufs-core` reads the real third-party UFS2 image
correctly, down to per-file content SHA-256, and the auditor raises nothing on the
clean image.

## Tier-2 — indirect block chains (synthetic, independent-walker cross-check)

Every file in `ufs2.raw` is a single direct block, so the image **cannot** exercise
the single / double / triple indirect chains — the highest-risk part of the
block-map walk. There is no `mkfs.ufs` / `makefs` on the Linux build host to mint a
real large-file UFS2 image (Linux `mkfs` does not write UFS), so
`core/tests/file_indirect.rs` crafts a UFS2 partition in memory whose one file's
block map spans 12 direct blocks + a full single-indirect block + into the
double-indirect tree + one block reached only through the triple-indirect chain,
plus a hole and a partial fragment tail (geometry `bsize`=`fsize`=512, `frag`=1,
`nindir`=64; deterministic content byte `(i*2654435761)&0xFF`).

This is **not a self-encoded round-trip** (the "LZNT1 trap"): the oracle is two
*independent* decoders agreeing on the crafted artifact — the known content
pattern **and** a separately-written block-map walker (`independent_walk`) that
re-reads the on-disk pointer blocks. Allocation-bomb (`u64::MAX` di_size),
truncation, and lying-pointer robustness cases live here and in the
`core/src/file.rs` unit tests, which also drive the UFS1 4-byte-pointer path.

## Tier-3 — self-authored detection-rule fixtures

The `ufs-forensic` anomaly detectors are exercised by crafted UFS2 partitions
(`forensic/tests/common/mod.rs` `clean_partition()`, geometry mirroring the real
image) into which exactly one corruption is injected per case, so each `UFS-*`
code fires on precisely its trigger (byte-flipped `fs_magic`, diverged backup
`fs_ipg`, bad `cg_magic`, an allocated-but-unreferenced inode, an `fs_ncg` whose
last cg lies past the image). These are detection-rule fixtures — correctness is
defined by the spec + the rule, not a value to oracle-check — and they stay as
fast, deterministic CI regression scaffolding beneath the Tier-1 image.

The **F-CARVE deletion oracle** (`forensic/tests/carve.rs`) is stronger than a
plain Tier-3: it crafts a valid UFS2 partition with a known file, records the
content's SHA-256 **pre-delete**, then simulates a UFS `rm` (zero the dirent's
`d_ino` into reclen slack, clear the inode's cg used-bit, leave `di_size`/`di_db`
and the data block intact), and checks `recover_deleted`'s carved content against
the recorded pre-delete hash — a construction-derived answer key **independent of
the reader**, so a wrong carve cannot pass by matching a fixture encoded to the
bug.

## UFS1 — spec-derived, deferred to a real image

The dfvfs corpus ships no UFS1 image and Linux `mkfs` does not write UFS, so a
UFS1 fixture is not self-mintable on the Ubuntu oracle VM. The UFS1 code path's
offsets are spec-derived (FreeBSD `sys/ufs/ffs/fs.h` — 128-byte dinode, 32-bit
block pointers, superblock at byte 8192, magic `0x00011954`) and are driven by
the unit tests in `core/src/inode.rs` / `file.rs`, but they are **not yet
Tier-1-validated against a real UFS1 image**. That is a documented gap, lifted to
Tier-1 in a follow-on against a real FreeBSD UFS1 image (or one minted on a
FreeBSD VM with `newfs`), with TSK `-f ufs1` as the independent oracle — not
silently skipped.
