//! F-INTEGRITY tests for `ufs-forensic`.
//!
//! Two tiers of evidence:
//!
//! - **Tier-1 (real image):** the committed dfvfs `ufs2.raw` — a clean UFS2
//!   filesystem authored by a third party — must produce **no** false anomalies
//!   (`audit_image` returns empty). Env-gated on `UFS2_DFVFS_ORACLE`; skips
//!   cleanly when absent, like an oracle binary.
//! - **Tier-3 (crafted corruption):** a synthetic UFS2 partition built in-test,
//!   into which one specific corruption is injected per case, so each anomaly
//!   code fires on exactly its trigger. These are detection-rule fixtures
//!   (correctness defined by the spec + the rule), not value-producing decoders.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]

mod common;

use common::{
    ufs2_dinode, write_cg_header, write_superblock, CBLKNO, FPG, FSIZE, IBLKNO, IPG, ISIZE, NCG,
    SBLKNO,
};
use ufs_forensic::{audit_findings, audit_image, AnomalyKind};

/// The dfvfs `ufs2.raw` filesystem partition starts at sector 16 = byte 8192.
const PART_BASE: usize = 8192;

fn oracle_partition() -> Option<Vec<u8>> {
    let path = std::env::var("UFS2_DFVFS_ORACLE").ok()?;
    let img = std::fs::read(path).ok()?;
    // audit_image reasons over the filesystem partition (filesystem byte 0), so
    // slice past the BSD-disklabel partition base, exactly like read_inode.
    Some(img[PART_BASE..].to_vec())
}

#[test]
fn clean_real_image_emits_no_anomalies() {
    let Some(part) = oracle_partition() else {
        eprintln!("skipping: set UFS2_DFVFS_ORACLE to the dfvfs ufs2.raw path");
        return;
    };
    let anomalies = audit_image(&part);
    assert!(
        anomalies.is_empty(),
        "a clean real UFS2 image must emit no anomalies, got: {anomalies:?}"
    );
    // And the Finding conversion is likewise empty.
    assert!(audit_findings(&part, "ufs2.raw").is_empty());
}

// ── crafted-partition builder ─────────────────────────────────────────────────

/// Build a minimal but structurally-valid UFS2 partition: a primary superblock
/// at `SBLOCK_UFS2`, `NCG` cylinder-group headers (each with its backup
/// superblock), a root directory (inode 2) with `.`/`..`, and the inode tables
/// zeroed (all inodes free). Callers then inject a single corruption. Returns
/// the partition bytes.
fn clean_partition() -> Vec<u8> {
    // Size to cover the SB, all cg headers + backup SBs, the inode tables, and a
    // couple of data fragments.
    let last_cg_end = ((NCG as usize - 1) * FPG as usize + CBLKNO as usize + 8) * FSIZE as usize;
    let last_itbl = ((NCG as usize - 1) * FPG as usize + IBLKNO as usize) * FSIZE as usize
        + IPG as usize * ISIZE;
    let root_data = 200usize * FSIZE as usize;
    let total = last_cg_end.max(last_itbl).max(root_data).max(65536 + 1376) + 4096;
    let mut part = vec![0u8; total];

    write_superblock(&mut part, common::SBLOCK_UFS2);
    for cg in 0..NCG as usize {
        // backup superblock for this cg at (cg*fpg + sblkno) frags.
        let sb_off = (cg * FPG as usize + SBLKNO as usize) * FSIZE as usize;
        write_superblock(&mut part, sb_off);
        // cg header at (cg*fpg + cblkno) frags.
        let cg_off = (cg * FPG as usize + CBLKNO as usize) * FSIZE as usize;
        write_cg_header(&mut part, cg_off, cg as u32);
    }

    // root dir inode 2 → a data fragment holding `.`/`..`.
    let root_frag = 200u64;
    let ino_byte = |ino: usize| -> usize {
        let c = ino / IPG as usize;
        let within = ino % IPG as usize;
        (c * FPG as usize + IBLKNO as usize) * FSIZE as usize + within * ISIZE
    };
    let rdi = ufs2_dinode(0o040755, 512, root_frag);
    part[ino_byte(2)..ino_byte(2) + ISIZE].copy_from_slice(&rdi);
    let rb = root_frag as usize * FSIZE as usize;
    let dot = common::direct(2, 12, 4, b".");
    let dotdot = common::direct(2, 500, 4, b"..");
    part[rb..rb + 12].copy_from_slice(&dot);
    part[rb + 12..rb + 12 + dotdot.len()].copy_from_slice(&dotdot);

    part
}

fn ino_byte(ino: usize) -> usize {
    let c = ino / IPG as usize;
    let within = ino % IPG as usize;
    (c * FPG as usize + IBLKNO as usize) * FSIZE as usize + within * ISIZE
}

#[test]
fn clean_crafted_partition_emits_nothing() {
    // The crafted builder must itself be clean, or every corruption test is
    // confounded by a baseline anomaly.
    let part = clean_partition();
    let anomalies = audit_image(&part);
    assert!(
        anomalies.is_empty(),
        "clean crafted partition must emit nothing, got: {anomalies:?}"
    );
}

#[test]
fn bad_superblock_magic_flags_magic_invalid() {
    let mut part = clean_partition();
    // Corrupt the primary superblock magic (offset 1372 within the SB at 65536).
    let mag = 65536 + 1372;
    part[mag..mag + 4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    let anomalies = audit_image(&part);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::SuperblockMagicInvalid { .. })),
        "bad SB magic must flag UFS-SUPERBLOCK-MAGIC-INVALID, got: {anomalies:?}"
    );
    let a = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::SuperblockMagicInvalid { .. }))
        .unwrap();
    assert_eq!(a.code, "UFS-SUPERBLOCK-MAGIC-INVALID");
    // Fail-loud: the offending bytes are carried.
    if let AnomalyKind::SuperblockMagicInvalid { bytes, .. } = a.kind {
        assert_eq!(bytes, 0xdead_beefu32.to_le_bytes());
    }
}

#[test]
fn backup_superblock_divergence_flags_divergence() {
    let mut part = clean_partition();
    // Corrupt cg1's backup superblock geometry (fs_ipg @184) so it diverges from
    // the primary — consistent with a spliced/edited image.
    let sb_off = (FPG as usize + SBLKNO as usize) * FSIZE as usize; // cg1 backup SB
    part[sb_off + 184..sb_off + 184 + 4].copy_from_slice(&999i32.to_le_bytes());
    let anomalies = audit_image(&part);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::BackupSuperblockDivergence { .. })),
        "diverging backup SB must flag UFS-BACKUP-SUPERBLOCK-DIVERGENCE, got: {anomalies:?}"
    );
    let a = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::BackupSuperblockDivergence { .. }))
        .unwrap();
    assert_eq!(a.code, "UFS-BACKUP-SUPERBLOCK-DIVERGENCE");
}

#[test]
fn bad_cg_magic_flags_cg_magic_invalid() {
    let mut part = clean_partition();
    // Corrupt cg2's header magic (offset 4 within the cg header).
    let cg_off = (2 * FPG as usize + CBLKNO as usize) * FSIZE as usize;
    part[cg_off + 4..cg_off + 4 + 4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let anomalies = audit_image(&part);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::CgMagicInvalid { .. })),
        "bad cg magic must flag UFS-CG-MAGIC-INVALID, got: {anomalies:?}"
    );
    let a = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::CgMagicInvalid { .. }))
        .unwrap();
    assert_eq!(a.code, "UFS-CG-MAGIC-INVALID");
    if let AnomalyKind::CgMagicInvalid { found, .. } = a.kind {
        assert_eq!(found, 0x1234_5678);
    }
}

#[test]
fn orphaned_inode_flags_orphan() {
    let mut part = clean_partition();
    // Craft inode 6: a regular file, di_nlink=1, marked ALLOCATED in the cg0
    // inode bitmap, but no directory entry anywhere points at it → orphan.
    let orphan = ufs2_dinode(0o100644, 116, 60);
    part[ino_byte(6)..ino_byte(6) + ISIZE].copy_from_slice(&orphan);
    common::set_inode_used(&mut part, 0, 6, true);
    let anomalies = audit_image(&part);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::OrphanedInode { inode: 6, .. })),
        "an allocated inode reachable by no dirent must flag UFS-ORPHANED-INODE, got: {anomalies:?}"
    );
    let a = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::OrphanedInode { .. }))
        .unwrap();
    assert_eq!(a.code, "UFS-ORPHANED-INODE");
    assert_eq!(a.severity, ufs_forensic::Severity::Medium);
}

#[test]
fn reachable_allocated_inode_is_not_orphan() {
    // A guard against a false-positive orphan: inode 2 (root) is allocated and
    // reachable (it IS the root), and the `.`-referenced entries must not be
    // flagged. With only the clean baseline (all inodes free), no orphan fires.
    let mut part = clean_partition();
    // Mark root (2) used and ensure it is not reported as orphan (root is the
    // walk origin).
    common::set_inode_used(&mut part, 0, 2, true);
    let anomalies = audit_image(&part);
    assert!(
        !anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::OrphanedInode { inode: 2, .. })),
        "root inode must never be flagged orphan, got: {anomalies:?}"
    );
}

#[test]
fn impossible_geometry_flags_bomb() {
    let mut part = clean_partition();
    // fs_ncg beyond what the partition can hold → impossible geometry. Use a
    // value that still parses (Superblock::parse caps ncg at 1<<24) but whose
    // last cg base lies past the image.
    let ncg_off = 65536 + 44;
    part[ncg_off..ncg_off + 4].copy_from_slice(&100_000i32.to_le_bytes());
    let anomalies = audit_image(&part);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::ImpossibleGeometry { .. })),
        "an ncg whose last cg lies past the image must flag UFS-IMPOSSIBLE-GEOMETRY, got: {anomalies:?}"
    );
}

#[test]
fn malformed_input_never_panics() {
    // A pile of hostile inputs: empty, tiny, all-0xff, a truncated SB, random.
    assert!(audit_image(&[]).is_empty());
    assert!(audit_image(&[0u8; 3]).is_empty());
    assert!(audit_image(&[0xffu8; 4096]).is_empty());
    let mut part = clean_partition();
    part.truncate(70000); // cut mid-superblock
    let _ = audit_image(&part); // must not panic
                                // A partition with a valid-looking SB magic but nonsense everywhere else.
    let mut junk = vec![0xabu8; 200_000];
    let mag = 65536 + 1372;
    junk[mag..mag + 4].copy_from_slice(&0x1954_0119u32.to_le_bytes());
    let _ = audit_image(&junk); // must not panic
}

#[test]
fn audit_findings_tags_analyzer_and_scope() {
    let mut part = clean_partition();
    let mag = 65536 + 1372;
    part[mag..mag + 4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    let findings = audit_findings(&part, "case-1/ufs2");
    assert!(!findings.is_empty());
    for f in &findings {
        assert_eq!(f.source.analyzer, "ufs-forensic");
        assert_eq!(f.source.scope, "case-1/ufs2");
    }
    assert!(findings
        .iter()
        .any(|f| f.code == "UFS-SUPERBLOCK-MAGIC-INVALID"));
}
