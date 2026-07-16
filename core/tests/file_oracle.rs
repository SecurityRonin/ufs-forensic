//! P3 Tier-1 oracle test: assemble file content on the real dfvfs `ufs2.raw`
//! image with `read_file` / `read_path_content` and check the SHA-256 of the
//! assembled bytes against the TSK `icat` ground truth (see `tests/data/README.md`).
//!
//! Env-gated on `UFS2_DFVFS_ORACLE` (a path to the image); skips cleanly when
//! absent, like an oracle binary. The content functions take the
//! **filesystem-partition bytes** (filesystem byte 0), so we slice the image at
//! the BSD-disklabel partition base (sector 16 = byte 8192).
//!
//! Ground truth (`icat -o 16 -f ufs2 ufs2.raw <ino> | sha256sum`):
//!   inode 4  (`/passwords.txt`,        116 bytes) sha256
//!     `02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252`;
//!   inode 129 (`/a_directory/a_file`,   53 bytes) sha256
//!     `4a49638d0e1055fd9e4c17fef7fdf4d6ccf892b6d9c2f64164203c4bfb0ec92d`;
//!   inode 130 (`/a_directory/another_file`, 22 bytes) sha256
//!     `c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16`.
//! `a_link` (inode 5) is a **fast (inline)** symlink; its target
//! `a_directory/another_file` comes straight from the dinode (P1), and
//! `read_symlink_target` returns those bytes without touching a data block.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;

use ufs::{
    read_by_path, read_file, read_path_content, read_symlink_target, Superblock, SBLOCK_UFS2,
};

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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn read_file_matches_icat_for_passwords_txt_inode4() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    let bytes = read_file(&part, &sb, 4).expect("read inode 4 content");
    assert_eq!(bytes.len(), 116, "istat: passwords.txt is 116 bytes");
    assert_eq!(
        sha256_hex(&bytes),
        "02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252",
        "read_file(4) sha256 == icat"
    );
}

#[test]
fn read_path_content_matches_icat_for_a_file_inode129() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    let bytes = read_path_content(&part, &sb, "/a_directory/a_file")
        .expect("read /a_directory/a_file")
        .expect("path exists");
    assert_eq!(bytes.len(), 53, "istat: a_file is 53 bytes");
    assert_eq!(
        sha256_hex(&bytes),
        "4a49638d0e1055fd9e4c17fef7fdf4d6ccf892b6d9c2f64164203c4bfb0ec92d",
        "read_path_content(/a_directory/a_file) sha256 == icat"
    );
}

#[test]
fn read_path_content_matches_icat_for_another_file_inode130() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    let bytes = read_path_content(&part, &sb, "/a_directory/another_file")
        .expect("read /a_directory/another_file")
        .expect("path exists");
    assert_eq!(bytes.len(), 22, "istat: another_file is 22 bytes");
    assert_eq!(
        sha256_hex(&bytes),
        "c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16",
        "read_path_content(/a_directory/another_file) sha256 == icat"
    );
}

#[test]
fn read_path_content_missing_path_is_none() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    assert!(read_path_content(&part, &sb, "/nope")
        .expect("resolve")
        .is_none());
}

#[test]
fn read_symlink_target_returns_fast_link_target_inode5() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    let (ino, inode) = read_by_path(&part, &sb, "/a_link")
        .expect("resolve /a_link")
        .expect("a_link exists");
    assert_eq!(ino, 5);
    // a_link is a fast (inline) symlink: di_size 24 <= fs_maxsymlinklen 120.
    let target = read_symlink_target(&part, &sb, &inode).expect("read symlink target");
    assert_eq!(target, b"a_directory/another_file", "readlink oracle");
}
