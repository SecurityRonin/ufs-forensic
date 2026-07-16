//! F-CARVE tests for `ufs-forensic` — deleted-file / deleted-dirent recovery.
//!
//! ## The deletion oracle (crafted)
//!
//! The fresh dfvfs `ufs2.raw` has no user deletions, so it cannot exercise
//! recovery. Instead this test **crafts** a valid UFS2 partition with a known
//! file `secret.txt` (inode 6, a known deterministic content), records the file
//! content's sha256 pre-delete, then **simulates a UFS `rm`**: it zeroes the
//! dirent's `d_ino` in the parent directory block AND clears the inode's used-bit
//! in the cg inode bitmap, leaving `di_size`/`di_db` and the data blocks INTACT —
//! the classic UFS residue an `rm` leaves behind. Recovery is checked against the
//! builder's recorded pre-delete sha256 (an independent, construction-derived
//! answer key), so a wrong carve cannot pass by matching a fixture we encoded to
//! the bug.
//!
//! Real-world recovery is state-dependent: it succeeds only while the freed
//! dinode and data blocks are un-reallocated. This crafted case models exactly
//! that just-deleted state; the analyzer returns nothing rather than fabricate
//! when the residue is gone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]

mod common;

use common::{
    direct, ino_byte, set_inode_used, ufs2_dinode, write_cg_header, write_superblock, CBLKNO, FPG,
    FSIZE, IBLKNO, IPG, ISIZE, NCG, SBLKNO,
};
use sha2::{Digest, Sha256};
use ufs_forensic::{recover_deleted, RecoveredItem};

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    use std::fmt::Write as _;
    for b in d {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Deterministic content byte for file offset `i`.
fn content_byte(i: usize) -> u8 {
    ((i.wrapping_mul(2654435761)) & 0xFF) as u8
}

/// The recovery oracle: a crafted partition after a simulated UFS delete of
/// `secret.txt` (inode 6). Carries the pre-delete ground truth.
struct DeletionCase {
    part: Vec<u8>,
    /// The deleted file's inode number.
    inode: u64,
    /// The deleted file's name (residual in the dirent slot).
    name: String,
    /// The deleted file's exact size in bytes.
    size: u64,
    /// sha256 of the file content BEFORE deletion (the answer key).
    pre_delete_sha256: String,
    /// The file content BEFORE deletion.
    pre_delete_content: Vec<u8>,
}

fn build_deletion_case() -> DeletionCase {
    // Partition large enough for the SB, all cg headers/backup SBs, inode tables,
    // and the file + directory data fragments.
    let last_cg_end = ((NCG as usize - 1) * FPG as usize + CBLKNO as usize + 8) * FSIZE as usize;
    let last_itbl = ((NCG as usize - 1) * FPG as usize + IBLKNO as usize) * FSIZE as usize
        + IPG as usize * ISIZE;
    let file_frag = 210u64;
    let root_frag = 200u64;
    let data_end = (file_frag as usize + 2) * FSIZE as usize;
    let total = last_cg_end.max(last_itbl).max(data_end).max(65536 + 1376) + 4096;
    let mut part = vec![0u8; total];

    write_superblock(&mut part, 0);
    for cg in 0..NCG as usize {
        let sb_off = (cg * FPG as usize + SBLKNO as usize) * FSIZE as usize;
        write_superblock(&mut part, sb_off);
        let cg_off = (cg * FPG as usize + CBLKNO as usize) * FSIZE as usize;
        write_cg_header(&mut part, cg_off, cg as u32);
    }

    // The secret file: inode 6, size 250 (< one 32 KiB block so single direct),
    // deterministic content in fragment `file_frag`.
    let size = 250u64;
    let mut content = vec![0u8; size as usize];
    for (i, b) in content.iter_mut().enumerate() {
        *b = content_byte(i);
    }
    let pre_delete_sha256 = sha256_hex(&content);

    let fb = file_frag as usize * FSIZE as usize;
    part[fb..fb + content.len()].copy_from_slice(&content);
    // file inode 6 (regular, size 250, di_db[0] = file_frag), nlink=1.
    let fi = ufs2_dinode(0o100644, size, file_frag);
    part[ino_byte(6)..ino_byte(6) + ISIZE].copy_from_slice(&fi);

    // root dir inode 2 → root_frag with `.`/`..`/`secret.txt`(6).
    let rdi = ufs2_dinode(0o040755, 512, root_frag);
    part[ino_byte(2)..ino_byte(2) + ISIZE].copy_from_slice(&rdi);
    let rb = root_frag as usize * FSIZE as usize;
    // Lay `.`(12) `..`(12) then secret.txt in a 488-reclen record filling the block.
    let dot = direct(2, 12, 4, b".");
    let dotdot = direct(2, 12, 4, b"..");
    let secret = direct(6, 488, 8, b"secret.txt");
    part[rb..rb + 12].copy_from_slice(&dot);
    part[rb + 12..rb + 24].copy_from_slice(&dotdot);
    part[rb + 24..rb + 24 + secret.len()].copy_from_slice(&secret);

    // Mark inodes 2 and 6 used (allocated), as a live filesystem would.
    set_inode_used(&mut part, 0, 2, true);
    set_inode_used(&mut part, 0, 6, true);

    DeletionCase {
        part,
        inode: 6,
        name: "secret.txt".to_string(),
        size,
        pre_delete_sha256,
        pre_delete_content: content,
    }
}

/// Apply a UFS `rm secret.txt` to a built (live) partition: zero the dirent's
/// `d_ino` (leaving the residual name in the reclen slack) AND clear inode 6's
/// used-bit in the cg0 inode bitmap. `di_size`/`di_db` and the data block stay
/// intact — the residue a real UFS delete leaves.
fn simulate_delete(c: &mut DeletionCase) {
    let root_frag = 200usize;
    let rb = root_frag * FSIZE as usize;
    // The secret.txt dirent begins at rb+24 (after `.` and `..`, each 12 bytes).
    // Zero its d_ino (offset 0..4 of the entry).
    for b in &mut c.part[rb + 24..rb + 24 + 4] {
        *b = 0;
    }
    // Clear inode 6's used-bit → free in the cg inode bitmap.
    set_inode_used(&mut c.part, 0, 6, false);
}

#[test]
fn recovers_deleted_file_content_matching_pre_delete_hash() {
    let mut c = build_deletion_case();
    simulate_delete(&mut c);

    let recovered = recover_deleted(&c.part);

    // A deleted FILE must be recovered with content == the pre-delete bytes.
    let file = recovered
        .iter()
        .find_map(|r| match r {
            RecoveredItem::DeletedFile {
                inode,
                content,
                content_sha256,
                size,
                ..
            } if *inode == c.inode => Some((content.clone(), content_sha256.clone(), *size)),
            _ => None,
        })
        .expect("deleted file inode 6 must be recovered");

    let (content, sha, size) = file;
    assert_eq!(size, c.size, "recovered size == pre-delete size");
    assert_eq!(
        content, c.pre_delete_content,
        "carved content == pre-delete content"
    );
    assert_eq!(
        sha, c.pre_delete_sha256,
        "carved content sha256 == pre-delete sha256 (independent answer key)"
    );
}

#[test]
fn recovers_deleted_dirent_name() {
    let mut c = build_deletion_case();
    simulate_delete(&mut c);

    let recovered = recover_deleted(&c.part);
    // The deleted dirent's residual name must be recovered.
    assert!(
        recovered.iter().any(|r| matches!(
            r,
            RecoveredItem::DeletedDirent { name, .. } if name == &c.name
        )),
        "deleted dirent name '{}' must be recovered, got: {recovered:?}",
        c.name
    );
}

#[test]
fn clean_partition_recovers_nothing() {
    // A live partition with no deletions must recover nothing (no fabrication).
    let c = build_deletion_case(); // not deleted
    let recovered = recover_deleted(&c.part);
    assert!(
        recovered.is_empty(),
        "a partition with no deletions must recover nothing, got: {recovered:?}"
    );
}

#[test]
fn malformed_input_recovers_nothing_without_panic() {
    assert!(recover_deleted(&[]).is_empty());
    assert!(recover_deleted(&[0u8; 16]).is_empty());
    assert!(recover_deleted(&[0xffu8; 200_000]).is_empty());
    let mut c = build_deletion_case();
    c.part.truncate(70000);
    let _ = recover_deleted(&c.part); // must not panic
}
