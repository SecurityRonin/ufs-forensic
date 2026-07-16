//! `ufs-forensic` — anomaly auditor + deleted-file recovery for UFS/FFS.
//!
//! UFS (the Unix File System / Berkeley FFS) leaves rich forensic residue on
//! delete: an `rm` clears the directory entry's `d_ino` and the cylinder-group
//! inode-used bit but leaves the dinode's `di_size`/`di_db` and the data blocks
//! intact until they are re-allocated. That residue is the lever this crate
//! pulls:
//!
//! - **F-INTEGRITY** ([`audit_image`] / [`audit_findings`]) emits graded
//!   [`forensicnomicon::report::Finding`]s for structural anomalies: an invalid
//!   superblock magic (`UFS-SUPERBLOCK-MAGIC-INVALID`), a per-cylinder-group
//!   backup superblock whose geometry diverges from the primary
//!   (`UFS-BACKUP-SUPERBLOCK-DIVERGENCE`), a cylinder-group header with a bad
//!   magic (`UFS-CG-MAGIC-INVALID`), an allocated inode reachable by no directory
//!   entry (`UFS-ORPHANED-INODE`), and geometry beyond the image
//!   (`UFS-IMPOSSIBLE-GEOMETRY`).
//! - **F-CARVE** ([`recover_deleted`]) recovers deleted files and directory
//!   entries: `d_ino == 0` dirent slots whose residual `d_name` survives, and
//!   inodes free in the cg bitmap that still carry a valid `di_mode`/`di_size`/
//!   `di_db` (`UFS-DELETED-FILE-CARVED` / `UFS-DELETED-DIRENT`). Recovery is
//!   state-dependent: it succeeds while the freed dinode and data blocks are
//!   un-reallocated, and returns nothing rather than fabricate once the residue
//!   is gone.
//!
//! Built on `ufs-core` for valid-path reading; where the audit must see slack
//! and freed structure the reader normalizes away (a `d_ino == 0` slot, a
//! bitmap-free-but-intact dinode, the raw backup-superblock bytes), it parses the
//! raw bytes directly (the reader/analyzer-split principle).
//!
//! Each finding is an **observation** ("consistent with …"); the examiner draws
//! the conclusion. Mirrors the fleet producer pattern (typed `AnomalyKind` +
//! `impl Observation` + `audit_image` → `Vec<Anomaly>` + `audit_findings` →
//! `Vec<Finding>`), as in `xfs-forensic` / `zfs-forensic` / `btrfs-forensic`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub use forensicnomicon::report::Severity;
use forensicnomicon::report::{Evidence, Finding, Location, Observation, Source};

use ufs::{
    list_dir_all, read_file, read_inode, CylinderGroup, DirEntry, DirEntryType, Superblock,
    UfsError, CG_MAGIC, SBLOCK_UFS1, SBLOCK_UFS2, UFS_ROOTINO,
};

// Re-export the reader surface an audit reasons over, so downstream code reaches
// the geometry types without a second `ufs-core` dependency line. The `ufs-core`
// crate sets `[lib] name = "ufs"`, so its import path is `ufs`.
pub use ufs::{CylinderGroup as ReaderCylinderGroup, Superblock as ReaderSuperblock, UfsVersion};

/// `fs_magic` byte offset within a superblock (`struct fs`).
const FS_MAGIC_OFF: usize = 1372;
/// `cg_magic` byte offset within a cylinder-group header (`struct cg`).
const CG_MAGIC_OFF: usize = 4;

// ── F-INTEGRITY: structural-integrity anomaly kinds ───────────────────────────

/// Classification of a UFS structural-integrity anomaly (F-INTEGRITY). Each
/// variant carries the evidence needed to reproduce the observation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// The value at the superblock's `fs_magic` offset matched neither UFS1
    /// (`0x00011954`) nor UFS2 (`0x19540119`) in either byte order — consistent
    /// with corruption or a wiped/overwritten superblock. Carries the offending
    /// bytes and the byte offset they were read at (fail-loud with the value).
    SuperblockMagicInvalid {
        /// Partition byte offset the primary superblock was sought at.
        offset: u64,
        /// The four raw bytes found at `offset + fs_magic`.
        bytes: [u8; 4],
    },
    /// A per-cylinder-group backup superblock whose decoded geometry differs from
    /// the primary — UFS writes a backup superblock in each cylinder group, so a
    /// divergence is consistent with a spliced or edited image.
    BackupSuperblockDivergence {
        /// The cylinder group whose backup superblock diverged.
        cg: u32,
        /// The geometry field that differs (e.g. `fs_ipg`).
        field: &'static str,
        /// The primary superblock's value.
        primary: u64,
        /// The backup superblock's (diverging) value.
        backup: u64,
        /// Partition byte offset of the backup superblock.
        offset: u64,
    },
    /// A cylinder-group header whose `cg_magic` is not `0x00090255` — consistent
    /// with corruption or a tampered allocation map. Carries the value found.
    CgMagicInvalid {
        /// The cylinder-group index the bad header was found at.
        cg: u32,
        /// The 32-bit value read at the `cg_magic` offset.
        found: u32,
        /// Partition byte offset of the cylinder-group header.
        offset: u64,
    },
    /// An inode marked ALLOCATED in its cylinder group's inode bitmap, with
    /// `di_nlink > 0`, that is reachable by NO directory entry from the root —
    /// an inode unlinked while still open, or a corruption lead.
    OrphanedInode {
        /// The absolute inode number.
        inode: u64,
        /// The inode's `di_nlink` (link count) — nonzero, yet unreferenced.
        nlink: u16,
    },
    /// A geometry field beyond what the image can hold — an allocation-bomb /
    /// corruption guard. Names the field, the value, and the sane bound.
    ImpossibleGeometry {
        /// The offending field name.
        field: &'static str,
        /// The value read from the structure.
        value: u64,
        /// The sane upper bound derived from the image size / spec.
        limit: u64,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::SuperblockMagicInvalid { .. }
            | AnomalyKind::BackupSuperblockDivergence { .. }
            | AnomalyKind::CgMagicInvalid { .. }
            | AnomalyKind::ImpossibleGeometry { .. } => Severity::High,
            AnomalyKind::OrphanedInode { .. } => Severity::Medium,
        }
    }

    /// Stable machine-readable, scheme-prefixed code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::SuperblockMagicInvalid { .. } => "UFS-SUPERBLOCK-MAGIC-INVALID",
            AnomalyKind::BackupSuperblockDivergence { .. } => "UFS-BACKUP-SUPERBLOCK-DIVERGENCE",
            AnomalyKind::CgMagicInvalid { .. } => "UFS-CG-MAGIC-INVALID",
            AnomalyKind::OrphanedInode { .. } => "UFS-ORPHANED-INODE",
            AnomalyKind::ImpossibleGeometry { .. } => "UFS-IMPOSSIBLE-GEOMETRY",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::SuperblockMagicInvalid { offset, bytes } => format!(
                "superblock at byte {offset}: fs_magic bytes {bytes:02x?} match neither UFS1 (0x00011954) nor UFS2 (0x19540119) in either byte order — consistent with corruption or an overwritten superblock"
            ),
            AnomalyKind::BackupSuperblockDivergence {
                cg,
                field,
                primary,
                backup,
                ..
            } => format!(
                "cylinder group {cg} backup superblock: {field} = {backup} differs from the primary {primary} — consistent with a spliced or edited image"
            ),
            AnomalyKind::CgMagicInvalid { cg, found, .. } => format!(
                "cylinder group {cg} header: cg_magic = {found:#010x} is not 0x00090255 — consistent with corruption or a tampered allocation map"
            ),
            AnomalyKind::OrphanedInode { inode, nlink } => format!(
                "inode {inode} is allocated (di_nlink {nlink}) yet reachable by no directory entry from root — an inode unlinked while still open, or a corruption lead"
            ),
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => format!(
                "geometry field {field} = {value} exceeds the sane bound {limit} for this image — consistent with corruption or an allocation-bomb"
            ),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::SuperblockMagicInvalid { offset, bytes } => vec![Evidence {
                field: "fs_magic".to_string(),
                value: format!("{bytes:02x?}"),
                location: Some(Location::ByteOffset(*offset)),
            }],
            AnomalyKind::BackupSuperblockDivergence {
                cg,
                field,
                primary,
                backup,
                offset,
            } => vec![Evidence {
                field: (*field).to_string(),
                value: format!("cg{cg} backup={backup} vs primary={primary}"),
                location: Some(Location::ByteOffset(*offset)),
            }],
            AnomalyKind::CgMagicInvalid { cg, found, offset } => vec![Evidence {
                field: "cg_magic".to_string(),
                value: format!("cg{cg}: {found:#010x}"),
                location: Some(Location::ByteOffset(*offset)),
            }],
            AnomalyKind::OrphanedInode { inode, nlink } => vec![Evidence {
                field: "di_nlink".to_string(),
                value: format!("inode {inode} nlink {nlink}, unreferenced"),
                location: Some(Location::Other {
                    space: "ufs:inode".to_string(),
                    value: *inode,
                }),
            }],
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => vec![Evidence {
                field: (*field).to_string(),
                value: format!("{value} (limit {limit})"),
                location: None,
            }],
        }
    }
}

/// A UFS structural-integrity anomaly: an observation graded by severity, with a
/// stable code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

// ── F-INTEGRITY: the image auditor ────────────────────────────────────────────

/// Audit a whole UFS/FFS **filesystem partition** (filesystem byte 0 — a caller
/// holding a whole disk image slices past the BSD-disklabel partition base first)
/// for structural-integrity anomalies (F-INTEGRITY): parse the primary
/// superblock, walk every cylinder group (backup-superblock divergence + header
/// magic), diff the allocated-inode set against the reachable-inode set (orphans),
/// and guard against impossible geometry.
///
/// A clean image yields an empty vector. Malformed input never panics.
#[must_use]
pub fn audit_image(partition: &[u8]) -> Vec<Anomaly> {
    let mut out = Vec::new();

    // Locate + parse the primary superblock. UFS2 lives at byte 65536, UFS1 at
    // 8192; try both. A superblock whose magic matched neither in either order is
    // a magic-invalid finding (fail-loud with the bytes), and there is nothing
    // further to audit without geometry.
    let sb = match parse_primary_sb(partition) {
        Ok(sb) => sb,
        Err(SbError::MagicInvalid { offset, bytes }) => {
            out.push(Anomaly::new(AnomalyKind::SuperblockMagicInvalid {
                offset,
                bytes,
            }));
            return out;
        }
        Err(SbError::NotUfs) => return out,
    };

    let fsize = if sb.fsize > 0 { sb.fsize as u64 } else { 0 };
    let fpg = if sb.fpg > 0 { sb.fpg as u64 } else { 0 };
    let sblkno = if sb.sblkno >= 0 { sb.sblkno as u64 } else { 0 };
    let cblkno = if sb.cblkno >= 0 { sb.cblkno as u64 } else { 0 };
    let ncg = u64::from(sb.ncg);
    let part_len = partition.len() as u64;

    // Impossible geometry: a cylinder group whose base lies past the partition.
    // When it fires, the geometry is unusable for the per-cg walk, so stop.
    if check_impossible_geometry(&mut out, fsize, fpg, ncg, part_len) {
        return out;
    }

    // Per-cylinder-group checks: backup superblock divergence + header magic.
    check_all_cgs(&mut out, partition, &sb, fsize, fpg, sblkno, cblkno, ncg);

    // Orphaned inodes: allocated in a cg bitmap with di_nlink > 0 yet reachable
    // by no directory entry from root.
    check_orphaned_inodes(&mut out, partition, &sb);

    out
}

/// Flag `UFS-IMPOSSIBLE-GEOMETRY` when `fs_ncg` names a cylinder group whose base
/// lies past the partition end. Returns `true` when the geometry is unusable and
/// the per-cg walk must stop.
fn check_impossible_geometry(
    out: &mut Vec<Anomaly>,
    fsize: u64,
    fpg: u64,
    ncg: u64,
    part_len: u64,
) -> bool {
    if fsize == 0 || fpg == 0 || ncg == 0 {
        return false;
    }
    let cg_bytes = fpg.saturating_mul(fsize);
    let last_base = ncg.saturating_sub(1).saturating_mul(cg_bytes);
    if last_base < part_len {
        return false;
    }
    out.push(Anomaly::new(AnomalyKind::ImpossibleGeometry {
        field: "fs_ncg",
        value: ncg,
        // cg_bytes = fpg*fsize with both > 0, so it is always positive here;
        // checked_div keeps the analyzer panic-free regardless.
        limit: part_len.checked_div(cg_bytes).map_or(1, |q| q + 1),
    }));
    true
}

/// Walk every cylinder group: check each backup superblock's geometry against the
/// primary (cg >= 1) and each cg header's magic.
#[allow(clippy::too_many_arguments)]
fn check_all_cgs(
    out: &mut Vec<Anomaly>,
    partition: &[u8],
    sb: &Superblock,
    fsize: u64,
    fpg: u64,
    sblkno: u64,
    cblkno: u64,
    ncg: u64,
) {
    if fsize == 0 || fpg == 0 {
        return;
    }
    for cg in 0..ncg {
        let cg_base_frag = cg.saturating_mul(fpg);

        // Backup superblock at (cg_base + fs_sblkno) frags. cg0's "backup" is
        // effectively the primary region; compare cg >= 1 against the primary.
        if cg >= 1 && sblkno > 0 {
            let bsb_off = cg_base_frag.saturating_add(sblkno).saturating_mul(fsize);
            check_backup_sb(out, partition, sb, cg as u32, bsb_off);
        }

        // cg header at (cg_base + fs_cblkno) frags.
        if cblkno > 0 {
            let cg_off = cg_base_frag.saturating_add(cblkno).saturating_mul(fsize);
            check_cg_magic(out, partition, cg as u32, cg_off);
        }
    }
}

/// The verdict of locating the primary superblock.
enum SbError {
    /// A superblock-shaped region was found but its magic matched no UFS magic
    /// in either byte order.
    MagicInvalid { offset: u64, bytes: [u8; 4] },
    /// Nothing superblock-shaped at either known offset — not a UFS partition.
    NotUfs,
}

/// Try to parse the primary superblock at the UFS2 (65536) then UFS1 (8192)
/// offset. Returns the parsed superblock, or a magic-invalid verdict carrying the
/// offending bytes when a region is present but its magic is wrong, or `NotUfs`
/// when neither offset holds superblock-sized data.
fn parse_primary_sb(partition: &[u8]) -> Result<Superblock, SbError> {
    for off in [SBLOCK_UFS2, SBLOCK_UFS1] {
        let Some(slice) = partition.get(off..) else {
            continue;
        };
        match Superblock::parse(slice) {
            Ok(sb) => return Ok(sb),
            Err(UfsError::BadMagic { bytes, .. }) => {
                // A full-sized region with a wrong magic → magic-invalid at this
                // offset. Report the offset the magic field actually sits at.
                return Err(SbError::MagicInvalid {
                    offset: (off + FS_MAGIC_OFF) as u64,
                    bytes,
                });
            }
            // Truncated (region too short) or geometry-rejected: not a usable SB
            // at this offset — try the next, then fall through to NotUfs.
            Err(_) => {}
        }
    }
    Err(SbError::NotUfs)
}

/// Parse the backup superblock at `offset` and flag each geometry field that
/// diverges from the primary. A backup region that does not parse as a
/// superblock (bad magic / truncated) is a `UFS-CG-MAGIC-INVALID`-adjacent signal
/// but here we treat only a *parsed* divergence as the backup-divergence finding;
/// an unparseable backup is left to the cg-magic check.
fn check_backup_sb(
    out: &mut Vec<Anomaly>,
    partition: &[u8],
    primary: &Superblock,
    cg: u32,
    offset: u64,
) {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let Some(slice) = partition.get(start..) else {
        return;
    };
    let Ok(backup) = Superblock::parse(slice) else {
        // A backup that will not parse is corruption too, but a bad-magic backup
        // is reported via the primary/cg paths; skip silently here rather than
        // double-report. A real edited image usually keeps a parseable backup with
        // a diverging field, which is what we key on.
        return;
    };
    let checks: [(&'static str, u64, u64); 4] = [
        ("fs_ipg", primary.ipg as u64, backup.ipg as u64),
        ("fs_fpg", primary.fpg as u64, backup.fpg as u64),
        ("fs_bsize", primary.bsize as u64, backup.bsize as u64),
        ("fs_ncg", u64::from(primary.ncg), u64::from(backup.ncg)),
    ];
    for (field, p, b) in checks {
        if p != b {
            out.push(Anomaly::new(AnomalyKind::BackupSuperblockDivergence {
                cg,
                field,
                primary: p,
                backup: b,
                offset,
            }));
        }
    }
}

/// Read the `cg_magic` at a cylinder-group header offset and flag a mismatch.
fn check_cg_magic(out: &mut Vec<Anomaly>, partition: &[u8], cg: u32, offset: u64) {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    // Only check a cg header region that is present in the image; a header past
    // the (possibly truncated) partition is not a corruption finding.
    let Some(slice) = partition.get(start..) else {
        return;
    };
    if slice.len() < CG_MAGIC_OFF + 4 {
        return;
    }
    // UFS is endian-agnostic; the primary SB's order applies. Read little- and
    // big-endian and accept either matching CG_MAGIC as valid.
    let le = read_u32_le(slice, CG_MAGIC_OFF);
    let be = read_u32_be(slice, CG_MAGIC_OFF);
    if le != CG_MAGIC && be != CG_MAGIC {
        out.push(Anomaly::new(AnomalyKind::CgMagicInvalid {
            cg,
            found: le,
            offset,
        }));
    }
}

/// Diff the allocated-inode set (from the cg inode bitmaps) against the set of
/// inodes reachable by a directory entry from root; flag every allocated inode
/// with `di_nlink > 0` that no dirent references.
fn check_orphaned_inodes(out: &mut Vec<Anomaly>, partition: &[u8], sb: &Superblock) {
    // Build the reachable set by walking the directory tree from root.
    let reachable = reachable_inodes(partition, sb);

    let ipg = if sb.ipg > 0 { sb.ipg as u64 } else { return };
    let ncg = u64::from(sb.ncg);
    let total = ipg.saturating_mul(ncg);

    for cg in 0..ncg {
        let Some(used) = cg_inode_bitmap(partition, sb, cg) else {
            continue;
        };
        for within in 0..ipg {
            let ino = cg.saturating_mul(ipg).saturating_add(within);
            // Reserved inodes 0 and 1 (and the root, 2) are never orphans; skip.
            if ino < UFS_ROOTINO + 1 || ino >= total {
                continue;
            }
            if !bitmap_bit(&used, within as usize) {
                continue; // free — a deleted-inode carve candidate, not an orphan
            }
            if reachable.contains(&ino) {
                continue;
            }
            // Allocated + unreferenced: read the inode to confirm di_nlink > 0
            // (a genuine live-but-orphaned inode, not a zeroed bitmap slot).
            let Ok(inode) = read_inode(partition, sb, ino) else {
                continue;
            };
            if inode.nlink == 0 {
                continue;
            }
            out.push(Anomaly::new(AnomalyKind::OrphanedInode {
                inode: ino,
                nlink: inode.nlink,
            }));
        }
    }
}

/// Audit an image and convert each F-INTEGRITY anomaly to a canonical [`Finding`]
/// tagged with `scope`.
#[must_use]
pub fn audit_findings(partition: &[u8], scope: &str) -> Vec<Finding> {
    let source = Source {
        analyzer: "ufs-forensic".to_string(),
        scope: scope.to_string(),
        version: None,
    };
    audit_image(partition)
        .iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

// ── F-CARVE: deleted-file / deleted-dirent recovery ───────────────────────────

/// One recovered item from the deleted-residue sweep (F-CARVE).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveredItem {
    /// A deleted file recovered from a freed-but-intact inode: free in the cg
    /// inode bitmap, yet still carrying a valid `di_mode`/`di_size`/`di_db`, whose
    /// data blocks were re-assembled. Recovery is state-dependent — this is only
    /// possible while the freed dinode and blocks are un-reallocated.
    DeletedFile {
        /// The residual directory-entry name pointing at this inode, if a deleted
        /// dirent with a matching residual `d_ino` was found; `None` when only the
        /// freed inode survives.
        name: Option<String>,
        /// The inode number the freed dinode occupies.
        inode: u64,
        /// The file's `di_size` in bytes.
        size: u64,
        /// The carved file content (assembled from the surviving block map).
        content: Vec<u8>,
        /// The carved content's sha256, lower-hex (the recovery gate).
        content_sha256: String,
    },
    /// A deleted directory entry recovered from a `d_ino == 0` slot (or residual
    /// name in a preceding entry's reclen slack) whose `d_name` survives.
    DeletedDirent {
        /// The residual entry name.
        name: String,
        /// The residual inode number the slot pointed at (`0` when only the name
        /// survives in reclen slack).
        inode: u64,
    },
}

/// Recover deleted files and directory entries from a UFS/FFS **filesystem
/// partition** (F-CARVE).
///
/// Two independent residues are swept:
///
/// 1. **Deleted dirents**: every directory reachable from root is walked with
///    [`list_dir_all`], which surfaces `d_ino == 0` slots whose residual `d_name`
///    survives — the name of a removed entry.
/// 2. **Deleted inodes**: every cylinder group's inode table is swept for inodes
///    that are FREE in the cg inode bitmap yet still carry a valid `di_mode`,
///    non-zero `di_size`, and a data-block pointer (the dinode UFS commonly leaves
///    intact on delete). Their content is carved via the block-map walk.
///
/// A recovered file is paired with a recovered dirent name when a `d_ino == 0`
/// slot's residual inode number (or the slot immediately preceding it) matches.
///
/// Recovery is state-dependent: it depends on the freed dinode and its data
/// blocks not yet having been re-allocated. When the residue is gone this returns
/// nothing rather than fabricate. Malformed input never panics.
#[must_use]
pub fn recover_deleted(partition: &[u8]) -> Vec<RecoveredItem> {
    let mut out = Vec::new();

    let Ok(sb) = parse_primary_sb(partition) else {
        return out;
    };

    // 1) Deleted dirents: walk the directory tree and collect d_ino==0 slots,
    // AND record, per residual name, the inode the *live* entry pointed at before
    // deletion is not recoverable from the slot alone (d_ino is zeroed). So we
    // key file recovery off the freed-inode sweep and attach a name when the
    // deleted dirent's residual name sits adjacent to a freed inode.
    let deleted_names = collect_deleted_dirents(partition, &sb);
    for (name, ino) in &deleted_names {
        out.push(RecoveredItem::DeletedDirent {
            name: name.clone(),
            inode: *ino,
        });
    }

    // 2) Deleted inodes: sweep each cg's inode table for free-but-intact dinodes.
    carve_deleted_inodes(partition, &sb, &deleted_names, &mut out);

    out
}

/// Walk every directory reachable from root and collect the residual name +
/// (residual) inode of each `d_ino == 0` deleted slot. Bounded against a cyclic /
/// lying directory graph by a visited set and a budget.
fn collect_deleted_dirents(partition: &[u8], sb: &Superblock) -> Vec<(String, u64)> {
    let mut deleted = Vec::new();
    let mut visited: Vec<u64> = Vec::new();
    let mut queue: Vec<u64> = vec![UFS_ROOTINO];
    let mut budget: usize = 1 << 20;

    while let Some(dir_ino) = queue.pop() {
        if budget == 0 {
            break; // cov:unreachable: a real directory graph is finite and far under the budget
        }
        budget -= 1;
        if visited.contains(&dir_ino) {
            continue;
        }
        visited.push(dir_ino);

        let Ok(entries) = list_dir_all(partition, sb, dir_ino) else {
            continue;
        };
        for e in &entries {
            if e.deleted {
                // A d_ino==0 slot with a residual name. Skip the `.`/`..` self and
                // parent slots and empty residual names.
                if !e.name.is_empty() && e.name != b"." && e.name != b".." {
                    deleted.push((decode_name(&e.name), e.ino));
                }
            } else if is_dir_entry(e) && e.name != b"." && e.name != b".." {
                queue.push(e.ino);
            }
        }
    }
    deleted
}

/// Sweep each cylinder group's inode table for inodes that are FREE in the cg
/// inode bitmap yet still carry a valid regular-file dinode (mode/size/db intact),
/// carve their content, and emit a `DeletedFile` — pairing a residual dirent name
/// when one is available.
fn carve_deleted_inodes(
    partition: &[u8],
    sb: &Superblock,
    deleted_names: &[(String, u64)],
    out: &mut Vec<RecoveredItem>,
) {
    let ipg = if sb.ipg > 0 { sb.ipg as u64 } else { return };
    let ncg = u64::from(sb.ncg);
    let total = ipg.saturating_mul(ncg);

    for cg in 0..ncg {
        let Some(used) = cg_inode_bitmap(partition, sb, cg) else {
            continue;
        };
        for within in 0..ipg {
            let ino = cg.saturating_mul(ipg).saturating_add(within);
            if ino < UFS_ROOTINO + 1 || ino >= total {
                continue;
            }
            // A deleted-file candidate is FREE in the bitmap.
            if bitmap_bit(&used, within as usize) {
                continue;
            }
            let Ok(inode) = read_inode(partition, sb, ino) else {
                continue;
            };
            // The freed dinode must still look like a regular file with content:
            // a valid regular-file mode, a non-zero size, and a first data block.
            if !inode.is_regular() || inode.size == 0 || inode.direct[0] == 0 {
                continue;
            }
            // Carve the content via the block-map walk. A lying di_size is already
            // guarded by read_file (allocation-bomb check); a failed carve yields
            // nothing for this inode rather than a fabricated buffer.
            let Ok(content) = read_file(partition, sb, ino) else {
                continue;
            };
            if content.is_empty() {
                continue; // cov:unreachable: size>0 already checked, so content is non-empty
            }
            let content_sha256 = sha256_hex(&content);
            let name = deleted_names
                .iter()
                .find(|(_, dino)| *dino == ino)
                .map(|(n, _)| n.clone());
            out.push(RecoveredItem::DeletedFile {
                name,
                inode: ino,
                size: inode.size,
                content,
                content_sha256,
            });
        }
    }
}

// ── shared private helpers ────────────────────────────────────────────────────

/// Read the cylinder-group `cg`'s inode-used bitmap into an owned `Vec<u8>`.
/// The cg header sits at `(cg*fpg + cblkno)*fsize`; the bitmap starts at
/// `cg_iusedoff` bytes in and spans `ceil(ipg/8)` bytes. `None` when the header
/// is absent/unparseable or the geometry is degenerate.
fn cg_inode_bitmap(partition: &[u8], sb: &Superblock, cg: u64) -> Option<Vec<u8>> {
    if sb.fsize <= 0 || sb.fpg <= 0 || sb.cblkno < 0 || sb.ipg <= 0 {
        return None; // cov:unreachable: a superblock parsed from a real image has positive geometry
    }
    let fsize = sb.fsize as u64;
    let fpg = sb.fpg as u64;
    let cblkno = sb.cblkno as u64;
    let cg_off = cg
        .saturating_mul(fpg)
        .saturating_add(cblkno)
        .saturating_mul(fsize);
    let start = usize::try_from(cg_off).ok()?;
    let header = partition.get(start..)?;
    let cgh = CylinderGroup::parse(header, sb.endian).ok()?;
    let bmp_start = cgh.inosused_off();
    let bytes = (sb.ipg as usize).div_ceil(8);
    let slice = header.get(bmp_start..bmp_start.saturating_add(bytes))?;
    Some(slice.to_vec())
}

/// `true` when bit `idx` (LSB-first within each byte) is set in the bitmap.
fn bitmap_bit(bitmap: &[u8], idx: usize) -> bool {
    let byte = idx / 8;
    let bit = idx % 8;
    bitmap.get(byte).is_some_and(|b| (b >> bit) & 1 == 1)
}

/// The set of inode numbers reachable by a live directory entry from root
/// (including root itself). Bounded against a cyclic directory graph.
fn reachable_inodes(partition: &[u8], sb: &Superblock) -> Vec<u64> {
    let mut reachable: Vec<u64> = vec![UFS_ROOTINO];
    let mut queue: Vec<u64> = vec![UFS_ROOTINO];
    let mut budget: usize = 1 << 20;

    while let Some(dir_ino) = queue.pop() {
        if budget == 0 {
            break; // cov:unreachable: a real directory graph is finite and far under the budget
        }
        budget -= 1;
        let Ok(entries) = list_dir_all(partition, sb, dir_ino) else {
            continue;
        };
        for e in &entries {
            if e.deleted || e.name == b"." || e.name == b".." {
                continue;
            }
            if !reachable.contains(&e.ino) {
                reachable.push(e.ino);
                if is_dir_entry(e) {
                    queue.push(e.ino);
                }
            }
        }
    }
    reachable
}

/// `true` when a live directory entry names a directory (`DT_DIR`). Used to bound
/// the recursion to directory subjects.
fn is_dir_entry(e: &DirEntry) -> bool {
    matches!(e.file_type, DirEntryType::Directory)
}

/// Decode a residual entry-name byte string to a `String`, replacing invalid
/// UTF-8 lossily (a residual name may carry arbitrary bytes).
fn decode_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// SHA-256 of `data`, lower-hex — the recovery gate compared to the
/// construction-derived pre-delete ground truth. Uses the audited `sha2` crate
/// (never hand-rolled).
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    use std::fmt::Write as _;
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Bounds-checked little-endian `u32` read (yields `0` out of range). The
/// analyzer parses raw image bytes directly (the reader/analyzer split), so it
/// carries its own panic-free readers.
fn read_u32_le(d: &[u8], o: usize) -> u32 {
    d.get(o..o.saturating_add(4))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Bounds-checked big-endian `u32` read (yields `0` out of range).
fn read_u32_be(d: &[u8], o: usize) -> u32 {
    d.get(o..o.saturating_add(4))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_be_bytes)
}

#[cfg(test)]
mod unit {
    use super::{
        bitmap_bit, decode_name, read_u32_be, read_u32_le, sha256_hex, Anomaly, AnomalyKind,
        Severity,
    };
    use forensicnomicon::report::{Location, Observation, Source};

    #[test]
    fn readers_yield_zero_out_of_range() {
        assert_eq!(read_u32_le(&[0, 0, 0], 0), 0);
        assert_eq!(read_u32_le(&[1, 0, 0, 0], 0), 1);
        assert_eq!(read_u32_be(&[0, 0, 0], 0), 0);
        assert_eq!(read_u32_be(&[0, 0, 0, 1], 0), 1);
    }

    #[test]
    fn bitmap_bit_reads_lsb_first() {
        // byte 0 = 0b0000_0101 → bits 0 and 2 set.
        let bmp = [0b0000_0101u8, 0b1000_0000u8];
        assert!(bitmap_bit(&bmp, 0));
        assert!(!bitmap_bit(&bmp, 1));
        assert!(bitmap_bit(&bmp, 2));
        assert!(bitmap_bit(&bmp, 15)); // byte 1 bit 7
        assert!(!bitmap_bit(&bmp, 16)); // out of range → false
    }

    #[test]
    fn decode_name_is_lossy() {
        assert_eq!(decode_name(b"secret.txt"), "secret.txt");
        // invalid UTF-8 does not panic.
        let _ = decode_name(&[0xff, 0xfe, b'a']);
    }

    #[test]
    fn sha256_of_known_input() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Every `AnomalyKind` carries its scheme-prefixed `UFS-*` code, phrases its
    /// note as an observation ("consistent with"), and yields evidence — the
    /// producer-pattern contract mirrored from xfs/zfs/btrfs-forensic.
    #[test]
    fn every_anomaly_kind_derives_code_severity_note_and_evidence() {
        let kinds = [
            AnomalyKind::SuperblockMagicInvalid {
                offset: 66908,
                bytes: [0xde, 0xad, 0xbe, 0xef],
            },
            AnomalyKind::BackupSuperblockDivergence {
                cg: 1,
                field: "fs_ipg",
                primary: 128,
                backup: 999,
                offset: 1_146_880,
            },
            AnomalyKind::CgMagicInvalid {
                cg: 2,
                found: 0x1234_5678,
                offset: 2_228_224,
            },
            AnomalyKind::OrphanedInode { inode: 6, nlink: 1 },
            AnomalyKind::ImpossibleGeometry {
                field: "fs_ncg",
                value: 100_000,
                limit: 5,
            },
        ];
        for kind in kinds {
            let a = Anomaly::new(kind.clone());
            assert!(a.code.starts_with("UFS-"));
            assert_eq!(a.code, kind.code());
            assert_eq!(a.note, kind.note());
            assert_eq!(a.severity, kind.severity());
            assert!(
                a.note.to_lowercase().contains("consistent with")
                    || a.note.to_lowercase().contains("unlinked while still open"),
                "note must be an observation: {}",
                a.note
            );
            assert!(!a.kind.evidence().is_empty());
            // Observation trait surface.
            assert_eq!(a.severity(), Some(a.severity));
            assert_eq!(Observation::code(&a), a.code);
            assert_eq!(Observation::note(&a), a.note);
            assert!(!Observation::evidence(&a).is_empty());
        }
    }

    /// Orphaned inode grades Medium; every other kind grades High.
    #[test]
    fn severity_grading_matches_spec() {
        assert_eq!(
            AnomalyKind::OrphanedInode { inode: 6, nlink: 1 }.severity(),
            Severity::Medium
        );
        assert_eq!(
            AnomalyKind::CgMagicInvalid {
                cg: 0,
                found: 0,
                offset: 0
            }
            .severity(),
            Severity::High
        );
    }

    /// `to_finding` tags analyzer + scope and preserves the code, per kind.
    #[test]
    fn to_finding_tags_analyzer_scope() {
        let source = Source {
            analyzer: "ufs-forensic".to_string(),
            scope: "part0".to_string(),
            version: None,
        };
        for kind in [
            AnomalyKind::OrphanedInode { inode: 9, nlink: 2 },
            AnomalyKind::ImpossibleGeometry {
                field: "x",
                value: 2,
                limit: 1,
            },
        ] {
            let a = Anomaly::new(kind);
            let f = a.to_finding(source.clone());
            assert_eq!(f.source.analyzer, "ufs-forensic");
            assert_eq!(f.source.scope, "part0");
            assert_eq!(f.code, a.code);
        }
    }

    /// `ImpossibleGeometry` evidence has no location; the others carry one.
    #[test]
    fn evidence_locations_are_kind_specific() {
        let bomb = AnomalyKind::ImpossibleGeometry {
            field: "f",
            value: 2,
            limit: 1,
        };
        assert!(bomb.evidence()[0].location.is_none());
        let mag = AnomalyKind::SuperblockMagicInvalid {
            offset: 0x1234,
            bytes: [1, 2, 3, 4],
        };
        assert!(matches!(
            mag.evidence()[0].location,
            Some(Location::ByteOffset(0x1234))
        ));
    }
}
