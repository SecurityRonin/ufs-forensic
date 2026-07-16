//! P1 Tier-1 oracle test: locate + decode inodes of the real dfvfs `ufs2.raw`
//! image with `read_inode` and check every field against the TSK `istat` ground
//! truth (see `tests/data/README.md`).
//!
//! Env-gated on `UFS2_DFVFS_ORACLE` (a path to the image); skips cleanly when
//! absent, like an oracle binary. `read_inode` takes the **filesystem-partition
//! bytes** (filesystem byte 0), so we slice the image at the BSD-disklabel
//! partition base (sector 16 = byte 8192).
//!
//! Ground truth (`istat -o 16 -f ufs2 ufs2.raw <ino>`):
//!   inode 2 (root): mode drwxr-xr-x (040755), size 512, nlink 4, uid/gid 0,
//!     direct block 56;
//!   inode 4 (passwords.txt): mode 0100644, size 116, nlink 1, uid/gid 0,
//!     direct block 57;
//!   inode 5 (a_link): symlink 0120755, size 24, fast target
//!     "a_directory/another_file".

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;

use ufs::{read_inode, FileType, Superblock, UfsVersion, SBLOCK_UFS2};

/// The dfvfs `ufs2.raw` filesystem partition starts at sector 16 = byte 8192.
const PART_BASE: usize = 8192;

fn oracle_partition() -> Option<Vec<u8>> {
    let path = std::env::var("UFS2_DFVFS_ORACLE").ok()?;
    let img = fs::read(path).ok()?;
    Some(img[PART_BASE..].to_vec())
}

fn superblock(part: &[u8]) -> Superblock {
    Superblock::parse(&part[SBLOCK_UFS2..]).expect("parse UFS2 superblock")
}

#[test]
fn read_inode_locates_and_decodes_root_inode2() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    assert_eq!(sb.version, UfsVersion::Ufs2);
    let ino = read_inode(&part, &sb, 2).expect("read inode 2");
    assert_eq!(ino.file_type, FileType::Directory);
    assert!(ino.is_dir());
    assert_eq!(ino.mode & 0o7777, 0o755);
    assert_eq!(ino.nlink, 4);
    assert_eq!(ino.uid, 0);
    assert_eq!(ino.gid, 0);
    assert_eq!(ino.size, 512);
    assert_eq!(ino.mtime.sec, 1_682_843_463);
    assert_eq!(ino.direct[0], 56, "istat direct block 56");
}

#[test]
fn read_inode_matches_istat_for_file_inode4() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    let ino = read_inode(&part, &sb, 4).expect("read inode 4");
    assert_eq!(ino.file_type, FileType::Regular);
    assert_eq!(ino.mode & 0o7777, 0o644);
    assert_eq!(ino.nlink, 1);
    assert_eq!(ino.size, 116, "istat size 116");
    assert_eq!(ino.mtime.sec, 1_682_843_463);
    assert_eq!(ino.direct[0], 57, "istat direct block 57");
    assert!(ino.direct[1..].iter().all(|&b| b == 0));
}

#[test]
fn read_inode_decodes_fast_symlink_inode5() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    let ino = read_inode(&part, &sb, 5).expect("read inode 5");
    assert_eq!(ino.file_type, FileType::Symlink);
    assert_eq!(ino.size, 24);
    assert_eq!(ino.symlink_target(), Some(&b"a_directory/another_file"[..]),);
}

#[test]
fn read_inode_rejects_out_of_range_ino() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    // fs_ipg (128) * fs_ncg (4) = 512 inodes; 512 is the first out-of-range one.
    let past_end = u64::from(sb.ipg as u32) * u64::from(sb.ncg);
    assert!(read_inode(&part, &sb, past_end).is_err());
}
