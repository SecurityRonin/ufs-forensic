//! UFS/FFS cylinder-group header (`struct cg`).
//!
//! Every cylinder group carries a header (`struct cg`, magic `0x00090255`)
//! holding the per-group allocation state: how many data blocks/inodes it owns
//! and the byte offsets (from the header start) of the used-inode and free-block
//! bitmaps that P1 uses to tell allocated from free/deleted inodes. Field
//! offsets follow `struct cg` in `sys/ufs/ffs/fs.h`, verified against the four
//! cg headers in the dfvfs `ufs2.raw` image (see `docs/RESEARCH.md` §1).

use crate::bytes::Endian;
use crate::error::UfsError;

/// The cylinder-group header magic (`CG_MAGIC`), at offset 4 of the header.
pub const CG_MAGIC: u32 = 0x0009_0255;

/// `cg_magic` is at offset 4 (`cg_firstfield` occupies bytes 0..4).
const OFF_MAGIC: usize = 4;
const OFF_CGX: usize = 12;
const OFF_NDBLK: usize = 20;
const OFF_IUSEDOFF: usize = 92;
const OFF_FREEOFF: usize = 96;
const OFF_CLUSTEROFF: usize = 108;
const OFF_NIBLK: usize = 116;
const OFF_INITEDIBLK: usize = 120;

/// Minimum bytes required to read the header fields (through `cg_initediblk` at
/// offset 120, +4).
const CG_MIN_LEN: usize = 124;

/// Parsed cylinder-group header — the per-group allocation map.
///
/// Carries the subset of `struct cg` P1 needs; `#[non_exhaustive]` so later
/// phases add fields without a breaking change. The bitmaps themselves are not
/// copied here — [`Self::inosused_off`] / [`Self::blksfree_off`] give the byte
/// offsets into the header buffer where they live.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CylinderGroup {
    /// `cg_cgx` — this cylinder group's index.
    pub cgx: u32,
    /// `cg_ndblk` — number of data blocks in this cylinder group.
    pub ndblk: u32,
    /// `cg_niblk` — number of inode blocks in this cylinder group.
    pub niblk: i32,
    /// `cg_initediblk` — number of initialized inodes in this cg (UFS2).
    pub initediblk: u32,
    /// `cg_iusedoff` — byte offset (from the header start) of the used-inode
    /// bitmap (`cg_inosused`).
    pub iusedoff: u32,
    /// `cg_freeoff` — byte offset (from the header start) of the free-block
    /// bitmap (`cg_blksfree`).
    pub freeoff: u32,
    /// `cg_clusteroff` — byte offset of the free-cluster bitmap.
    pub clusteroff: u32,
}

impl CylinderGroup {
    /// Parse a cylinder-group header from the start of `data` (i.e. `data`
    /// begins at the `struct cg` header), using the byte order resolved from the
    /// superblock.
    ///
    /// # Errors
    ///
    /// - [`UfsError::Truncated`] if `data` is shorter than the header fields.
    /// - [`UfsError::BadCgMagic`] if `cg_magic` (offset 4) is not `0x00090255`
    ///   in the given byte order — the offending value is carried.
    pub fn parse(data: &[u8], endian: Endian) -> Result<Self, UfsError> {
        if data.len() < CG_MIN_LEN {
            return Err(UfsError::Truncated {
                structure: "cylinder group",
                need: CG_MIN_LEN,
                have: data.len(),
            });
        }
        let magic = endian.u32(data, OFF_MAGIC);
        if magic != CG_MAGIC {
            return Err(UfsError::BadCgMagic {
                found: magic,
                endian,
            });
        }
        Ok(Self {
            cgx: endian.u32(data, OFF_CGX),
            ndblk: endian.u32(data, OFF_NDBLK),
            niblk: endian.i32(data, OFF_NIBLK),
            initediblk: endian.u32(data, OFF_INITEDIBLK),
            iusedoff: endian.u32(data, OFF_IUSEDOFF),
            freeoff: endian.u32(data, OFF_FREEOFF),
            clusteroff: endian.u32(data, OFF_CLUSTEROFF),
        })
    }

    /// Byte offset (from the header start) of the used-inode bitmap.
    #[must_use]
    pub fn inosused_off(&self) -> usize {
        self.iusedoff as usize
    }

    /// Byte offset (from the header start) of the free-block bitmap.
    #[must_use]
    pub fn blksfree_off(&self) -> usize {
        self.freeoff as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic(endian: Endian) -> Vec<u8> {
        let mut d = vec![0u8; CG_MIN_LEN];
        let wr32 = |d: &mut [u8], off: usize, v: u32| {
            let b = match endian {
                Endian::Little => v.to_le_bytes(),
                Endian::Big => v.to_be_bytes(),
            };
            d[off..off + 4].copy_from_slice(&b);
        };
        wr32(&mut d, OFF_MAGIC, CG_MAGIC);
        wr32(&mut d, OFF_CGX, 0);
        wr32(&mut d, OFF_NDBLK, 256);
        wr32(&mut d, OFF_NIBLK, 8);
        wr32(&mut d, OFF_INITEDIBLK, 128);
        wr32(&mut d, OFF_IUSEDOFF, 168);
        wr32(&mut d, OFF_FREEOFF, 184);
        wr32(&mut d, OFF_CLUSTEROFF, 200);
        d
    }

    #[test]
    fn parses_valid_cg_little_endian() {
        let d = synthetic(Endian::Little);
        let cg = CylinderGroup::parse(&d, Endian::Little).unwrap();
        assert_eq!(cg.cgx, 0);
        assert_eq!(cg.ndblk, 256);
        assert_eq!(cg.niblk, 8);
        assert_eq!(cg.iusedoff, 168);
        assert_eq!(cg.freeoff, 184);
        assert_eq!(cg.inosused_off(), 168);
        assert_eq!(cg.blksfree_off(), 184);
    }

    #[test]
    fn parses_valid_cg_big_endian() {
        let d = synthetic(Endian::Big);
        let cg = CylinderGroup::parse(&d, Endian::Big).unwrap();
        assert_eq!(cg.ndblk, 256);
        assert_eq!(cg.iusedoff, 168);
    }

    #[test]
    fn bad_cg_magic_fails_loud() {
        let mut d = synthetic(Endian::Little);
        d[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        let err = CylinderGroup::parse(&d, Endian::Little).unwrap_err();
        assert!(
            matches!(&err, UfsError::BadCgMagic { found, .. } if *found == 0x1234_5678),
            "expected BadCgMagic with the offending value, got {err:?}"
        );
    }

    #[test]
    fn wrong_endian_is_detected_as_bad_magic() {
        // A little-endian cg read as big-endian yields a byte-swapped magic.
        let d = synthetic(Endian::Little);
        assert!(matches!(
            CylinderGroup::parse(&d, Endian::Big),
            Err(UfsError::BadCgMagic { .. })
        ));
    }

    #[test]
    fn truncated_cg_does_not_panic() {
        let d = vec![0u8; CG_MIN_LEN - 1];
        assert!(matches!(
            CylinderGroup::parse(&d, Endian::Little),
            Err(UfsError::Truncated {
                structure: "cylinder group",
                ..
            })
        ));
    }
}
