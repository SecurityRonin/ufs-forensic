//! Edge-case / defensive-arm coverage for `ufs-forensic` over crafted UFS2
//! partitions. These exercise the panic-free guards a happy-path test never
//! reaches: truncation past the primary superblock (cg headers/backup SBs off
//! the end), an unparseable backup superblock, an allocated-in-bitmap inode with
//! a zeroed or unreadable dinode (the false-orphan guards), a directory cycle,
//! and a subdirectory in the deleted-dirent walk. Each is a genuinely-reachable
//! defensive branch, exercised by adversarial input rather than annotated away.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]

mod common;

use common::{
    direct, ino_byte, set_inode_used, ufs2_dinode, write_cg_header, write_superblock, CBLKNO, FPG,
    FSIZE, IBLKNO, IPG, ISIZE, NCG, SBLKNO, SBLOCK_UFS2,
};
use ufs_forensic::{audit_image, recover_deleted, AnomalyKind, RecoveredItem};

/// A fully-formed clean UFS2 partition: primary SB, all cg headers + backup SBs,
/// root dir (inode 2) with `.`/`..`. Callers inject a corruption or truncate.
fn clean_partition() -> Vec<u8> {
    let last_cg_end = ((NCG as usize - 1) * FPG as usize + CBLKNO as usize + 8) * FSIZE as usize;
    let last_itbl = ((NCG as usize - 1) * FPG as usize + IBLKNO as usize) * FSIZE as usize
        + IPG as usize * ISIZE;
    let root_data = 205usize * FSIZE as usize;
    let total = last_cg_end
        .max(last_itbl)
        .max(root_data)
        .max(SBLOCK_UFS2 + 1376)
        + 4096;
    let mut part = vec![0u8; total];

    write_superblock(&mut part, SBLOCK_UFS2);
    for cg in 0..NCG as usize {
        let sb_off = (cg * FPG as usize + SBLKNO as usize) * FSIZE as usize;
        write_superblock(&mut part, sb_off);
        let cg_off = (cg * FPG as usize + CBLKNO as usize) * FSIZE as usize;
        write_cg_header(&mut part, cg_off, cg as u32);
    }

    // root dir inode 2 → data fragment 200 holding `.`/`..`.
    let root_frag = 200u64;
    let rdi = ufs2_dinode(0o040755, 512, root_frag);
    part[ino_byte(2)..ino_byte(2) + ISIZE].copy_from_slice(&rdi);
    let rb = root_frag as usize * FSIZE as usize;
    part[rb..rb + 12].copy_from_slice(&direct(2, 12, 4, b"."));
    part[rb + 12..rb + 12 + 500].copy_from_slice(&direct(2, 500, 4, b".."));
    set_inode_used(&mut part, 0, 2, true);

    part
}

#[test]
fn truncated_after_primary_sb_skips_cg_regions_without_panic() {
    // Truncate the partition just past the primary SB so the primary parses but
    // every cylinder-group header + backup superblock lies off the end. audit
    // must not panic and must not fabricate cg-magic/backup findings for the
    // absent regions (the get(start..) None guards).
    let mut part = clean_partition();
    part.truncate(SBLOCK_UFS2 + 1376);
    let anomalies = audit_image(&part);
    // No cg-magic / backup-divergence findings for regions that are simply absent.
    assert!(
        !anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::CgMagicInvalid { .. })),
        "absent cg headers must not be flagged, got: {anomalies:?}"
    );
    assert!(!anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::BackupSuperblockDivergence { .. })));
    // recover_deleted over the same truncated image must also be safe.
    let _ = recover_deleted(&part);
}

#[test]
fn cg_region_off_end_without_geometry_error() {
    // A partition where the geometry check passes (last cg base is within the
    // image) yet an individual cg's header AND backup superblock fall off a
    // truncation — driving the get(start..) None guards in check_cg_magic /
    // check_backup_sb without the impossible-geometry early return. Reduce fs_ncg
    // to 2 so last_base = 1*fpg*fsize = 1048576, size the image just past that,
    // then truncate so cg1's backup SB (frag 280) and header (frag 288) are off.
    let mut part = clean_partition();
    // Set fs_ncg = 2 in the primary superblock (offset 44).
    let ncg_off = SBLOCK_UFS2 + 44;
    part[ncg_off..ncg_off + 4].copy_from_slice(&2i32.to_le_bytes());
    // last_base(ncg=2) = 1 * 256 * 4096 = 1_048_576. Keep the image just past it
    // (so geometry passes) but before cg1's backup SB at frag 280 = 1_146_880.
    part.truncate(1_100_000);
    let anomalies = audit_image(&part); // must not panic, no geometry error
    assert!(
        !anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::ImpossibleGeometry { .. })),
        "geometry passes; the absent cg1 regions are simply skipped: {anomalies:?}"
    );
    assert!(!anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::CgMagicInvalid { .. })));
}

#[test]
fn cg_header_slice_too_short_is_skipped() {
    // A partition truncated so a cg header's offset is present but the region is
    // shorter than the cg_magic field (4 bytes at offset 4) — the len < 8 guard
    // in check_cg_magic skips it. ncg=2, geometry passes; truncate so cg1's
    // header at frag 288 = 1_179_648 has only a couple bytes.
    let mut part = clean_partition();
    let ncg_off = SBLOCK_UFS2 + 44;
    part[ncg_off..ncg_off + 4].copy_from_slice(&2i32.to_le_bytes());
    // cg1 backup SB at 1_146_880; header at 1_179_648. Cut so the header offset
    // is in-bounds by only 2 bytes.
    part.truncate(1_179_648 + 2);
    let _ = audit_image(&part); // must not panic; the short cg header is skipped
}

#[test]
fn unparseable_backup_superblock_is_skipped() {
    // Corrupt cg1's backup superblock magic so it will not parse: the backup path
    // skips it (a bad-magic backup is not double-reported), exercising the
    // Superblock::parse-Err guard in check_backup_sb. The cg1 *header* magic stays
    // valid, so no cg-magic finding either.
    let mut part = clean_partition();
    let bsb = (FPG as usize + SBLKNO as usize) * FSIZE as usize; // cg1 backup SB
    part[bsb + 1372..bsb + 1372 + 4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    let anomalies = audit_image(&part);
    assert!(
        !anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::BackupSuperblockDivergence { .. })),
        "an unparseable backup SB is skipped, not reported as divergence: {anomalies:?}"
    );
}

#[test]
fn allocated_inode_with_zeroed_dinode_is_not_orphan() {
    // Mark inode 7 USED in the cg0 bitmap but leave its dinode all-zero (nlink 0):
    // a stale bitmap bit, not a live orphan. The nlink==0 guard must skip it, so
    // no orphan is reported (exercises the inode.nlink==0 continue).
    let mut part = clean_partition();
    set_inode_used(&mut part, 0, 7, true);
    // inode 7's dinode region stays zeroed (mode 0, nlink 0).
    let anomalies = audit_image(&part);
    assert!(
        !anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::OrphanedInode { inode: 7, .. })),
        "a zeroed dinode (nlink 0) must not be flagged orphan: {anomalies:?}"
    );
}

#[test]
fn allocated_inode_off_truncated_end_is_skipped_without_panic() {
    // Mark an inode in cg3 USED, then truncate the partition so its dinode lies
    // off the end: read_inode fails, and the orphan sweep skips it (the
    // read_inode Err guard) without panicking. Also drives carve's read_inode
    // Err guard for a FREE inode past the end.
    let mut part = clean_partition();
    // cg3 inode 3*128 + 5 = 389, mark used.
    set_inode_used(&mut part, 3, 389, true);
    // Truncate so cg3's inode table is partly off the end, but keep the primary
    // SB, cg0..cg2 intact.
    let cut = (3 * FPG as usize + IBLKNO as usize) * FSIZE as usize + 10; // mid cg3 itable
    part.truncate(cut.max(SBLOCK_UFS2 + 1376));
    let anomalies = audit_image(&part); // must not panic
                                        // Whatever it finds, it must not have paniced; the cg3 used inode past the
                                        // end is simply skipped.
    let _ = anomalies;
    let _ = recover_deleted(&part);
}

#[test]
fn directory_cycle_terminates() {
    // Craft a directory `d` (inode 8) whose entry `loop` points back at the root
    // (inode 2), forming a cycle. The visited-set guard must terminate the
    // deleted-dirent + reachable walks (exercises the visited `continue`).
    let mut part = clean_partition();
    // Rewrite root to reference subdir `d`(8) after `.`/`..`.
    let root_frag = 200usize;
    let rb = root_frag * FSIZE as usize;
    part[rb..rb + 12].copy_from_slice(&direct(2, 12, 4, b"."));
    part[rb + 12..rb + 24].copy_from_slice(&direct(2, 12, 4, b".."));
    part[rb + 24..rb + 24 + 488].copy_from_slice(&direct(8, 488, 4, b"d"));
    // subdir d (inode 8) → fragment 201: `.`(8) `..`(2) `loop`→2 (back to root).
    let d_frag = 201u64;
    let di = ufs2_dinode(0o040755, 512, d_frag);
    part[ino_byte(8)..ino_byte(8) + ISIZE].copy_from_slice(&di);
    let db = d_frag as usize * FSIZE as usize;
    part[db..db + 12].copy_from_slice(&direct(8, 12, 4, b"."));
    part[db + 12..db + 24].copy_from_slice(&direct(2, 12, 4, b".."));
    part[db + 24..db + 24 + 488].copy_from_slice(&direct(2, 488, 4, b"loop"));
    set_inode_used(&mut part, 0, 8, true);

    // Both a full audit and a recovery pass must terminate (no infinite loop /
    // panic) on the cycle.
    let _ = audit_image(&part);
    let _ = recover_deleted(&part);
}

#[test]
fn deleted_dirent_walk_descends_subdirectory() {
    // A subdirectory holding a deleted entry: the deleted-dirent walk must descend
    // into it (the queue.push branch) and recover the residual name there.
    let mut part = clean_partition();
    let root_frag = 200usize;
    let rb = root_frag * FSIZE as usize;
    part[rb..rb + 12].copy_from_slice(&direct(2, 12, 4, b"."));
    part[rb + 12..rb + 24].copy_from_slice(&direct(2, 12, 4, b".."));
    part[rb + 24..rb + 24 + 488].copy_from_slice(&direct(9, 488, 4, b"sub"));
    // subdir `sub` (inode 9) → fragment 202 with a DELETED entry `gone` (d_ino 0).
    let s_frag = 202u64;
    let si = ufs2_dinode(0o040755, 512, s_frag);
    part[ino_byte(9)..ino_byte(9) + ISIZE].copy_from_slice(&si);
    let sb = s_frag as usize * FSIZE as usize;
    part[sb..sb + 12].copy_from_slice(&direct(9, 12, 4, b"."));
    part[sb + 12..sb + 24].copy_from_slice(&direct(2, 12, 4, b".."));
    // deleted slot: d_ino 0, residual name "gone".
    part[sb + 24..sb + 24 + 488].copy_from_slice(&direct(0, 488, 8, b"gone"));
    set_inode_used(&mut part, 0, 9, true);

    let recovered = recover_deleted(&part);
    assert!(
        recovered.iter().any(|r| matches!(
            r,
            RecoveredItem::DeletedDirent { name, .. } if name == "gone"
        )),
        "the deleted dirent in the subdirectory must be recovered: {recovered:?}"
    );
}

#[test]
fn free_inode_with_absurd_di_size_is_not_carved() {
    // A FREE-in-bitmap inode that passes the regular/size/db gate but whose
    // di_size is an allocation bomb: read_file rejects it, so carve yields nothing
    // for that inode rather than fabricating (the read_file Err guard). No
    // DeletedFile is produced.
    let mut part = clean_partition();
    // inode 10: regular, di_size = u64::MAX (bomb), di_db[0] = 203 (nonzero). The
    // inode stays FREE in the bitmap (we do NOT set it used), a carve candidate.
    let fi = ufs2_dinode(0o100644, u64::MAX, 203);
    part[ino_byte(10)..ino_byte(10) + ISIZE].copy_from_slice(&fi);
    let recovered = recover_deleted(&part);
    assert!(
        !recovered
            .iter()
            .any(|r| matches!(r, RecoveredItem::DeletedFile { inode: 10, .. })),
        "an allocation-bomb di_size must not be carved: {recovered:?}"
    );
}

#[test]
fn dir_entry_to_out_of_range_inode_is_skipped_in_walk() {
    // A live directory entry pointing at an out-of-range inode number: list_dir_all
    // for that "directory" errors (InodeOutOfRange), and the reachable / dirent
    // walks skip it via the list_dir_all Err guard without panicking.
    let mut part = clean_partition();
    let root_frag = 200usize;
    let rb = root_frag * FSIZE as usize;
    part[rb..rb + 12].copy_from_slice(&direct(2, 12, 4, b"."));
    part[rb + 12..rb + 24].copy_from_slice(&direct(2, 12, 4, b".."));
    // `bad` names inode 99999 (past fs_ipg*fs_ncg = 512), typed as a directory so
    // the walk tries to descend and list_dir_all errors.
    part[rb + 24..rb + 24 + 488].copy_from_slice(&direct(99999, 488, 4, b"bad"));
    let _ = audit_image(&part); // reachable_inodes hits the list_dir_all Err guard
    let _ = recover_deleted(&part);
}

#[test]
fn zero_fpg_geometry_skips_cg_walk_without_panic() {
    // A superblock whose fs_fpg is 0 (degenerate but parseable): the geometry
    // check does not fire (fpg == 0), and the per-cg walk's guard returns without
    // attempting any cg addressing (fpg == 0). No panic, no cg findings.
    let mut part = clean_partition();
    let fpg_off = SBLOCK_UFS2 + 188;
    part[fpg_off..fpg_off + 4].copy_from_slice(&0i32.to_le_bytes());
    let anomalies = audit_image(&part); // must not panic
    assert!(!anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::CgMagicInvalid { .. })));
    let _ = recover_deleted(&part);
}
