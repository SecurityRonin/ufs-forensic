//! `ufs-forensic` — anomaly auditor for UFS/FFS filesystems.
//!
//! Emits graded [`forensicnomicon::report::Finding`]s for UFS-specific forensic
//! signals: deleted-inode recovery (a cylinder-group-bitmap-free inode whose
//! core still holds block pointers), directory-slack residue (freed `direct`
//! entries keeping their `d_ino`/`d_name`), orphaned/unlinked-but-referenced
//! inodes, and geometry-integrity anomalies.
//!
//! Built on `ufs-core` for valid-path reading; where the audit must see slack
//! and malformed structure the reader normalizes away, it parses the raw bytes
//! directly (the reader/analyzer-split principle).
//!
//! Each finding is an **observation** ("consistent with …"); the examiner draws
//! the conclusion.
//!
//! # Status
//!
//! Phase 0 (superblock + cylinder-group reader) is complete in `ufs-core`. The
//! analyzer surface here is scaffolded; the `AnomalyKind`/`audit_*` pipeline
//! lands in the forensic phase that follows the reader phases (P1 inodes → P2
//! directories → P3 file content), as in `ntfs-forensic` / `xfs-forensic`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub use forensicnomicon::report::Severity;

/// Re-exported reader entry point, so downstream code can reach the geometry an
/// audit reasons over without a second dependency line. The `ufs-core` crate
/// sets `[lib] name = "ufs"`, so its import path is `ufs`.
pub use ufs::{CylinderGroup, Superblock, UfsError, UfsVersion};
