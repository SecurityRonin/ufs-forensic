//! Always-on P0/P1 regression test over the small committed fixtures extracted
//! from the dfvfs `ufs2.raw` Tier-1 image (see `tests/data/README.md`):
//! `ufs2_superblock.bin` (the 1376-byte primary superblock at image byte 73728),
//! `ufs2_cg0.bin` (the 256-byte first cylinder-group header at 139264), and
//! `ufs2_inodes_0_15.bin` (the first 16 UFS2 dinodes = 4096 bytes of the cg0
//! inode table at image byte 172032 / filesystem byte 163840, covering the
//! ground-truth inodes 2/4/5).
//!
//! Unlike `superblock_oracle.rs` / `inode_oracle.rs` (env-gated on the full
//! image), these run in plain `cargo test` — the answer key is still the TSK
//! `fsstat` / `istat` ground truth.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ufs::{CylinderGroup, Endian, FileType, Inode, Superblock, UfsVersion};

// From <member>/tests/<file>.rs the repo root is two levels up.
const SUPERBLOCK: &[u8] = include_bytes!("../../tests/data/ufs2_superblock.bin");
const CG0: &[u8] = include_bytes!("../../tests/data/ufs2_cg0.bin");
/// First 16 UFS2 dinodes (256 B each) of cg0's inode table.
const INODES_0_15: &[u8] = include_bytes!("../../tests/data/ufs2_inodes_0_15.bin");

const UFS2_DINODE_SIZE: usize = 256;

/// Slice the committed inode-table fixture down to the `ino`-th dinode (the
/// fixture starts at inode 0, so the in-region offset is `ino * 256`).
fn dinode(ino: usize) -> &'static [u8] {
    let off = ino * UFS2_DINODE_SIZE;
    &INODES_0_15[off..off + UFS2_DINODE_SIZE]
}

#[test]
fn committed_ufs2_superblock_fixture_decodes() {
    let sb = Superblock::parse(SUPERBLOCK).expect("parse committed UFS2 superblock");
    assert_eq!(sb.version, UfsVersion::Ufs2);
    assert_eq!(sb.endian, Endian::Little);
    assert_eq!(sb.bsize, 32768);
    assert_eq!(sb.fsize, 4096);
    assert_eq!(sb.ncg, 4);
    assert_eq!(sb.ipg, 128);
    assert_eq!(sb.fpg, 256);
    assert_eq!(sb.size, 1022);
    assert_eq!(sb.maxsymlinklen, 120);
    assert_eq!(sb.inode_size(), 256);
}

#[test]
fn committed_ufs2_cg0_fixture_decodes() {
    let cg = CylinderGroup::parse(CG0, Endian::Little).expect("parse committed cg0");
    assert_eq!(cg.cgx, 0);
    assert_eq!(cg.ndblk, 256);
    assert_eq!(cg.iusedoff, 168);
    assert_eq!(cg.freeoff, 184);
}

// ── P1: inode decode vs the TSK `istat` ground truth ─────────────────────────
// istat -o 16 -f ufs2 ufs2.raw <ino> on the real image gives:
//   inode 2 (root): mode drwxr-xr-x, size 512, nlink 4, uid/gid 0, direct 56
//   inode 4 (passwords.txt): mode 0644, size 116, nlink 1, uid/gid 0, direct 57
//   inode 5 (a_link): symlink 0120755, size 24, fast target "a_directory/another_file"
// mtime seconds == 1682843463 (2023-04-30 08:31:03 UTC = 16:31:03 HKT).

#[test]
fn committed_root_inode2_decodes_as_dir() {
    let ino = Inode::parse(dinode(2), UfsVersion::Ufs2, Endian::Little).expect("parse inode 2");
    assert_eq!(ino.file_type, FileType::Directory);
    assert!(ino.is_dir());
    assert_eq!(ino.mode & 0o7777, 0o755, "permission bits");
    assert_eq!(ino.nlink, 4);
    assert_eq!(ino.uid, 0);
    assert_eq!(ino.gid, 0);
    assert_eq!(ino.size, 512);
    assert_eq!(ino.mtime.sec, 1_682_843_463);
    assert_eq!(ino.direct[0], 56, "istat direct block 56");
    assert!(
        ino.direct[1..].iter().all(|&b| b == 0),
        "single-fragment dir"
    );
    assert!(ino.indirect.iter().all(|&b| b == 0));
    assert!(ino.symlink_target().is_none());
}

#[test]
fn committed_file_inode4_matches_istat() {
    let ino = Inode::parse(dinode(4), UfsVersion::Ufs2, Endian::Little).expect("parse inode 4");
    assert_eq!(ino.file_type, FileType::Regular);
    assert!(!ino.is_dir());
    assert_eq!(ino.mode & 0o7777, 0o644);
    assert_eq!(ino.nlink, 1);
    assert_eq!(ino.uid, 0);
    assert_eq!(ino.gid, 0);
    assert_eq!(ino.size, 116, "istat size 116");
    assert_eq!(ino.mtime.sec, 1_682_843_463, "istat mtime");
    assert_eq!(ino.direct[0], 57, "istat direct block 57");
    assert!(ino.symlink_target().is_none());
}

#[test]
fn committed_symlink_inode5_is_fast_symlink() {
    let ino = Inode::parse(dinode(5), UfsVersion::Ufs2, Endian::Little).expect("parse inode 5");
    assert_eq!(ino.file_type, FileType::Symlink);
    assert_eq!(ino.size, 24);
    // size <= fs_maxsymlinklen (120) => inline fast symlink in the block array.
    assert_eq!(
        ino.symlink_target(),
        Some(&b"a_directory/another_file"[..]),
        "fast-symlink target inline in di_db",
    );
}
