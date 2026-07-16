//! P0 Tier-1 oracle test: parse the primary superblock and a cylinder-group
//! header of the real dfvfs `ufs2.raw` image and check every field against the
//! TSK `fsstat` ground truth (see `tests/data/README.md`).
//!
//! Env-gated on `UFS2_DFVFS_ORACLE` (a path to the image); skips cleanly when
//! absent, like an oracle binary. Ground truth (TSK `fsstat -o 16 -f ufs2`):
//! UFS2, block 32768 / fragment 4096, 4 cylinder groups, 128 inodes/group,
//! 256 frags/group. Primary superblock at image byte 73728 (partition base
//! 8192 + SBLOCK_UFS2 65536); first cg header at image byte 139264.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;

use ufs::{CylinderGroup, Endian, Superblock, UfsVersion, FS_UFS2_MAGIC, SBLOCK_UFS2, UFS_ROOTINO};

/// The dfvfs `ufs2.raw` filesystem partition starts at sector 16 = byte 8192.
const PART_BASE: usize = 8192;

fn oracle_image() -> Option<Vec<u8>> {
    let path = std::env::var("UFS2_DFVFS_ORACLE").ok()?;
    fs::read(path).ok()
}

#[test]
fn ufs2_superblock_matches_fsstat_ground_truth() {
    let Some(img) = oracle_image() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb_off = PART_BASE + SBLOCK_UFS2; // 73728
    let sb = Superblock::parse(&img[sb_off..]).expect("parse UFS2 superblock");

    assert_eq!(sb.version, UfsVersion::Ufs2, "detected version");
    assert_eq!(sb.endian, Endian::Little, "detected byte order");
    // Geometry vs fsstat.
    assert_eq!(sb.bsize, 32768, "Block Size");
    assert_eq!(sb.fsize, 4096, "Fragment Size");
    assert_eq!(sb.frag, 8, "frags per block");
    assert_eq!(sb.ncg, 4, "Number of Cylinder Groups");
    assert_eq!(sb.ipg, 128, "Inodes per group");
    assert_eq!(sb.fpg, 256, "Fragments per group");
    assert_eq!(sb.inopb, 128, "inodes per block");
    // Low-offset addressing fields.
    assert_eq!(sb.sblkno, 24, "fs_sblkno");
    assert_eq!(sb.cblkno, 32, "fs_cblkno");
    assert_eq!(sb.iblkno, 40, "fs_iblkno");
    assert_eq!(sb.dblkno, 48, "fs_dblkno (first data frag)");
    assert_eq!(sb.bshift, 15, "fs_bshift");
    assert_eq!(sb.fshift, 12, "fs_fshift");
    // High-offset fields.
    assert_eq!(sb.size, 1022, "fs_size (total frags, fsstat 0-1021)");
    assert_eq!(sb.maxsymlinklen, 120, "fs_maxsymlinklen");
    assert_eq!(
        sb.sblockloc, SBLOCK_UFS2 as i64,
        "fs_sblockloc self-locates"
    );
    assert_eq!(sb.inode_size(), 256, "UFS2 inode size");
    assert_eq!(UFS_ROOTINO, 2, "root inode");
    // Magic constant sanity.
    assert_eq!(FS_UFS2_MAGIC, 0x1954_0119);
}

#[test]
fn ufs2_first_cylinder_group_matches_fsstat() {
    let Some(img) = oracle_image() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    // cg0 header at cgtod = cgstart(0) + fs_cblkno frags = 0 + 32*4096, plus the
    // partition base: 8192 + 131072 = 139264.
    let cg_off = PART_BASE + 32 * 4096;
    let cg = CylinderGroup::parse(&img[cg_off..], Endian::Little).expect("parse cg0");
    assert_eq!(cg.cgx, 0, "cg index");
    assert_eq!(cg.ndblk, 256, "cg_ndblk == fpg");
    assert_eq!(cg.iusedoff, 168, "cg_iusedoff");
    assert_eq!(cg.freeoff, 184, "cg_freeoff");
    // The bitmap offsets are usable positions inside the header buffer.
    assert!(cg.inosused_off() < cg.blksfree_off());
}
