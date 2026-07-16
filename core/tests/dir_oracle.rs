//! P2 Tier-1 oracle test: list directories and resolve paths on the real dfvfs
//! `ufs2.raw` image with `list_dir` / `read_by_path`, checked against the TSK
//! `fls` / `ffind` ground truth (see `tests/data/README.md`).
//!
//! Env-gated on `UFS2_DFVFS_ORACLE` (a path to the image); skips cleanly when
//! absent, like an oracle binary. The listing functions take the
//! **filesystem-partition bytes** (filesystem byte 0), so we slice the image at
//! the BSD-disklabel partition base (sector 16 = byte 8192).
//!
//! Ground truth (`fls -o 16 -f ufs2 ufs2.raw`):
//!   root (/): `.snap`(3), `a_directory`(128), `passwords.txt`(4), `a_link`(5)
//!     (plus the `.`/`..` entries the raw block carries).
//!   `fls -r`: `a_directory` → `a_file`(129), `another_file`(130).
//! `ffind`: inode 4 = /passwords.txt, 129 = /a_directory/a_file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;

use ufs::{list_dir, read_by_path, DirEntryType, Superblock, SBLOCK_UFS2};

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

/// The names `fls` reports for the root (it omits `.`/`..`).
fn fls_root_names(entries: &[ufs::DirEntry]) -> Vec<Vec<u8>> {
    entries
        .iter()
        .map(|e| e.name.clone())
        .filter(|n| n != b"." && n != b"..")
        .collect()
}

#[test]
fn list_dir_root_matches_fls() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    let entries = list_dir(&part, &sb, 2).expect("list root");

    // Every entry must be live (fls lists allocated entries).
    assert!(entries.iter().all(|e| !e.deleted));

    // Name → inode must match the fls oracle for the four named entries.
    let by_name = |n: &[u8]| entries.iter().find(|e| e.name == n).map(|e| e.ino);
    assert_eq!(by_name(b".snap"), Some(3));
    assert_eq!(by_name(b"a_directory"), Some(128));
    assert_eq!(by_name(b"passwords.txt"), Some(4), "fls: passwords.txt = 4");
    assert_eq!(by_name(b"a_link"), Some(5));

    // Types match fls's d/r/l column.
    let ftype = |n: &[u8]| entries.iter().find(|e| e.name == n).map(|e| e.file_type);
    assert_eq!(ftype(b"a_directory"), Some(DirEntryType::Directory));
    assert_eq!(ftype(b"passwords.txt"), Some(DirEntryType::Regular));
    assert_eq!(ftype(b"a_link"), Some(DirEntryType::Symlink));

    // The full fls name set (order-independent).
    let mut got = fls_root_names(&entries);
    got.sort();
    let mut want: Vec<Vec<u8>> = [&b".snap"[..], b"a_directory", b"passwords.txt", b"a_link"]
        .iter()
        .map(|s| s.to_vec())
        .collect();
    want.sort();
    assert_eq!(got, want, "root listing == fls (minus ./..)");
}

#[test]
fn list_dir_nested_a_directory_matches_fls_r() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);
    let entries = list_dir(&part, &sb, 128).expect("list a_directory");
    let by_name = |n: &[u8]| entries.iter().find(|e| e.name == n).map(|e| e.ino);
    assert_eq!(by_name(b"a_file"), Some(129), "fls -r: a_file = 129");
    assert_eq!(
        by_name(b"another_file"),
        Some(130),
        "fls -r: another_file = 130"
    );
}

#[test]
fn read_by_path_matches_ffind() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let sb = superblock(&part);

    // ffind: /passwords.txt = inode 4 (the P1 known 116-byte file).
    let (ino, inode) = read_by_path(&part, &sb, "/passwords.txt")
        .expect("resolve path")
        .expect("path exists");
    assert_eq!(ino, 4, "ffind: /passwords.txt = 4");
    assert_eq!(inode.size, 116, "P1 metadata: 116 bytes");
    assert!(inode.is_regular());

    // ffind: /a_directory/a_file = inode 129.
    let (ino, inode) = read_by_path(&part, &sb, "/a_directory/a_file")
        .expect("resolve nested")
        .expect("path exists");
    assert_eq!(ino, 129, "ffind: /a_directory/a_file = 129");
    assert!(inode.is_regular());

    // Root resolves to inode 2.
    let (root_ino, root) = read_by_path(&part, &sb, "/")
        .expect("resolve root")
        .expect("root exists");
    assert_eq!(root_ino, 2);
    assert!(root.is_dir());

    // A path that does not exist is Ok(None), not an error.
    assert!(read_by_path(&part, &sb, "/does_not_exist")
        .expect("resolve missing")
        .is_none());
}
