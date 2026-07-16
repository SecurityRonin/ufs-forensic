//! Always-on P0 regression test over the small committed fixtures extracted
//! from the dfvfs `ufs2.raw` Tier-1 image (see `tests/data/README.md`):
//! `ufs2_superblock.bin` (the 1376-byte primary superblock at image byte 73728)
//! and `ufs2_cg0.bin` (the 256-byte first cylinder-group header at 139264).
//!
//! Unlike `superblock_oracle.rs` (env-gated on the full image), these run in
//! plain `cargo test` — the answer key is still the TSK `fsstat` ground truth.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ufs::{CylinderGroup, Endian, Superblock, UfsVersion};

// From <member>/tests/<file>.rs the repo root is two levels up.
const SUPERBLOCK: &[u8] = include_bytes!("../../tests/data/ufs2_superblock.bin");
const CG0: &[u8] = include_bytes!("../../tests/data/ufs2_cg0.bin");

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
