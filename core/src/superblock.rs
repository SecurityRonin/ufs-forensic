//! UFS/FFS superblock (`struct fs`) parse, geometry, and version/endian detect.
//!
//! The primary superblock sits at a version-fixed byte offset from the
//! filesystem start: **UFS1 at 8192** (magic `0x00011954`), **UFS2 at 65536**
//! (magic `0x19540119`). Field offsets follow `struct fs` in the FreeBSD kernel
//! header `sys/ufs/ffs/fs.h` (`CTASSERT(sizeof(struct fs) == 1376)`); `fs_magic`
//! is the last field, at offset 1372.

use crate::bytes::{u8_at, Endian};
use crate::error::UfsError;

/// UFS1 superblock magic (`FS_UFS1_MAGIC`), read at `fs_magic` (offset 1372).
pub const FS_UFS1_MAGIC: u32 = 0x0001_1954;

/// UFS2 superblock magic (`FS_UFS2_MAGIC`), read at `fs_magic` (offset 1372).
pub const FS_UFS2_MAGIC: u32 = 0x1954_0119;

/// Byte offset of the primary UFS1 superblock from the filesystem start
/// (`SBLOCK_UFS1`).
pub const SBLOCK_UFS1: usize = 8192;

/// Byte offset of the primary UFS2 superblock from the filesystem start
/// (`SBLOCK_UFS2`).
pub const SBLOCK_UFS2: usize = 65536;

/// The UFS root inode number (`UFS_ROOTINO`).
pub const UFS_ROOTINO: u64 = 2;

/// `fs_magic` is the final field of the 1376-byte `struct fs`.
const FS_MAGIC_OFF: usize = 1372;

/// Minimum bytes required to parse every field this reader extracts (through
/// `fs_magic` at offset 1372, +4).
const SB_MIN_LEN: usize = 1376;

// ── verified `struct fs` field offsets (see docs/RESEARCH.md §1) ─────────────
const OFF_SBLKNO: usize = 8;
const OFF_CBLKNO: usize = 12;
const OFF_IBLKNO: usize = 16;
const OFF_DBLKNO: usize = 20;
const OFF_OLD_TIME: usize = 32;
const OFF_OLD_SIZE: usize = 36;
const OFF_OLD_DSIZE: usize = 40;
const OFF_NCG: usize = 44;
const OFF_BSIZE: usize = 48;
const OFF_FSIZE: usize = 52;
const OFF_FRAG: usize = 56;
const OFF_BSHIFT: usize = 80;
const OFF_FSHIFT: usize = 84;
const OFF_FRAGSHIFT: usize = 96;
const OFF_FSBTODB: usize = 100;
const OFF_SBSIZE: usize = 104;
const OFF_NINDIR: usize = 116;
const OFF_INOPB: usize = 120;
const OFF_IPG: usize = 184;
const OFF_FPG: usize = 188;
const OFF_SIZE: usize = 1080;
const OFF_DSIZE: usize = 1088;
const OFF_CSADDR: usize = 1096;
const OFF_SBLOCKLOC: usize = 1000;
const OFF_MAXSYMLINKLEN: usize = 1320;

/// The on-disk UFS version, resolved from the superblock magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UfsVersion {
    /// UFS1 — 4.4BSD/FreeBSD legacy: 128-byte inodes, 32-bit block pointers,
    /// primary superblock at byte 8192, magic `0x00011954`.
    Ufs1,
    /// UFS2 — FreeBSD 5+: 256-byte inodes, 64-bit block pointers, birthtime,
    /// primary superblock at byte 65536, magic `0x19540119`.
    Ufs2,
}

/// Parsed UFS superblock — geometry and addressing fields the cylinder-group
/// and inode decode (P1) need.
///
/// This carries the subset of `struct fs` the reader currently uses; it is
/// `#[non_exhaustive]` so later phases add fields without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Superblock {
    /// On-disk version (UFS1 vs UFS2), from the magic.
    pub version: UfsVersion,
    /// On-disk byte order, from the magic.
    pub endian: Endian,
    /// `fs_sblkno` — superblock offset within a cylinder group (frags).
    pub sblkno: i32,
    /// `fs_cblkno` — cylinder-group-block offset within a cg (frags).
    pub cblkno: i32,
    /// `fs_iblkno` — inode-blocks offset within a cg (frags).
    pub iblkno: i32,
    /// `fs_dblkno` — first data-block offset within a cg (frags).
    pub dblkno: i32,
    /// `fs_ncg` — number of cylinder groups.
    pub ncg: u32,
    /// `fs_bsize` — basic block size in bytes.
    pub bsize: i32,
    /// `fs_fsize` — fragment size in bytes.
    pub fsize: i32,
    /// `fs_frag` — number of fragments in a block (`bsize / fsize`).
    pub frag: i32,
    /// `fs_bshift` — `log2(bsize)`.
    pub bshift: i32,
    /// `fs_fshift` — `log2(fsize)`.
    pub fshift: i32,
    /// `fs_fragshift` — `log2(frag)`.
    pub fragshift: i32,
    /// `fs_fsbtodb` — fsblock→disk-block shift constant.
    pub fsbtodb: i32,
    /// `fs_sbsize` — actual on-disk superblock size in bytes.
    pub sbsize: i32,
    /// `fs_nindir` — pointers per indirect block.
    pub nindir: i32,
    /// `fs_inopb` — inodes per block.
    pub inopb: u32,
    /// `fs_ipg` — inodes per cylinder group.
    pub ipg: i32,
    /// `fs_fpg` — fragments per cylinder group.
    pub fpg: i32,
    /// Total size of the filesystem in fragments (`fs_size` on UFS2, the 32-bit
    /// `fs_old_size` on UFS1).
    pub size: i64,
    /// Data-region size in fragments (`fs_dsize` / `fs_old_dsize`).
    pub dsize: i64,
    /// `fs_csaddr` — fragment address of the cylinder-summary area (UFS2).
    pub csaddr: i64,
    /// `fs_sblockloc` — the byte offset at which this superblock records itself
    /// (self-locating; `SBLOCK_UFS2` on UFS2). `0` on UFS1 (field absent).
    pub sblockloc: i64,
    /// `fs_maxsymlinklen` — inline (fast) symlink length threshold.
    pub maxsymlinklen: i32,
}

impl Superblock {
    /// Parse a superblock from the start of `data` (i.e. `data` begins at the
    /// superblock, not at the filesystem start — callers slice from
    /// `SBLOCK_UFS1`/`SBLOCK_UFS2`).
    ///
    /// Detects the UFS version and byte order from `fs_magic` (offset 1372) by
    /// trying both interpretations against both known magics, then decodes the
    /// geometry in the resolved byte order.
    ///
    /// # Errors
    ///
    /// - [`UfsError::BadMagic`] if the value at offset 1372 is neither UFS
    ///   magic in either byte order — the offending bytes are carried.
    /// - [`UfsError::Truncated`] if `data` is shorter than the fields read.
    /// - [`UfsError::ImpossibleGeometry`] if a geometry field is out of range.
    pub fn parse(data: &[u8]) -> Result<Self, UfsError> {
        // RED STUB (TDD): not yet implemented — every P0 test fails here.
        return Err(UfsError::Truncated {
            structure: "UNIMPLEMENTED superblock",
            need: 0,
            have: data.len(),
        });
        #[allow(unreachable_code)]
        // Validate magic before length so a wrong-image identity error names the
        // offending bytes even on a short buffer (fail loud with the value).
        let bytes = [
            u8_at(data, FS_MAGIC_OFF),
            u8_at(data, FS_MAGIC_OFF + 1),
            u8_at(data, FS_MAGIC_OFF + 2),
            u8_at(data, FS_MAGIC_OFF + 3),
        ];
        let le = u32::from_le_bytes(bytes);
        let be = u32::from_be_bytes(bytes);
        let (version, endian) = match (le, be) {
            (FS_UFS1_MAGIC, _) => (UfsVersion::Ufs1, Endian::Little),
            (FS_UFS2_MAGIC, _) => (UfsVersion::Ufs2, Endian::Little),
            (_, FS_UFS1_MAGIC) => (UfsVersion::Ufs1, Endian::Big),
            (_, FS_UFS2_MAGIC) => (UfsVersion::Ufs2, Endian::Big),
            _ => {
                return Err(UfsError::BadMagic {
                    offset: FS_MAGIC_OFF,
                    bytes,
                    le,
                    be,
                })
            }
        };

        // All parsed fields lie within the first SB_MIN_LEN bytes; range-check
        // once so the bounds-checked readers below never mask a short image.
        if data.len() < SB_MIN_LEN {
            return Err(UfsError::Truncated {
                structure: "superblock",
                need: SB_MIN_LEN,
                have: data.len(),
            });
        }

        // UFS1 stores size/time in the 32-bit `fs_old_*` fields; UFS2 in the
        // 64-bit fields. Branch on the detected version.
        let (size, dsize) = match version {
            UfsVersion::Ufs1 => (
                i64::from(endian.i32(data, OFF_OLD_SIZE)),
                i64::from(endian.i32(data, OFF_OLD_DSIZE)),
            ),
            UfsVersion::Ufs2 => (endian.i64(data, OFF_SIZE), endian.i64(data, OFF_DSIZE)),
        };
        let sblockloc = match version {
            UfsVersion::Ufs1 => 0,
            UfsVersion::Ufs2 => endian.i64(data, OFF_SBLOCKLOC),
        };
        // Silence the unused-constant lints for fields reserved for later phases
        // by touching them here; they document the verified offsets in-place.
        let _ = (OFF_OLD_TIME, OFF_CSADDR);

        let sb = Self {
            version,
            endian,
            sblkno: endian.i32(data, OFF_SBLKNO),
            cblkno: endian.i32(data, OFF_CBLKNO),
            iblkno: endian.i32(data, OFF_IBLKNO),
            dblkno: endian.i32(data, OFF_DBLKNO),
            ncg: endian.u32(data, OFF_NCG),
            bsize: endian.i32(data, OFF_BSIZE),
            fsize: endian.i32(data, OFF_FSIZE),
            frag: endian.i32(data, OFF_FRAG),
            bshift: endian.i32(data, OFF_BSHIFT),
            fshift: endian.i32(data, OFF_FSHIFT),
            fragshift: endian.i32(data, OFF_FRAGSHIFT),
            fsbtodb: endian.i32(data, OFF_FSBTODB),
            sbsize: endian.i32(data, OFF_SBSIZE),
            nindir: endian.i32(data, OFF_NINDIR),
            inopb: endian.u32(data, OFF_INOPB),
            ipg: endian.i32(data, OFF_IPG),
            fpg: endian.i32(data, OFF_FPG),
            size,
            dsize,
            csaddr: endian.i64(data, OFF_CSADDR),
            sblockloc,
            maxsymlinklen: endian.i32(data, OFF_MAXSYMLINKLEN),
        };

        sb.validate_geometry()?;
        Ok(sb)
    }

    /// Reject absurd geometry (corruption / allocation-bomb) with the offending
    /// value, so downstream address math never overflows or over-allocates.
    fn validate_geometry(&self) -> Result<(), UfsError> {
        // Block size must be a sane power-of-two frame; UFS allows 4 KiB..64 KiB.
        if self.bsize <= 0 || self.bsize > 65536 {
            return Err(UfsError::ImpossibleGeometry {
                field: "fs_bsize",
                value: self.bsize as u64,
                limit: 65536,
            });
        }
        if self.fsize <= 0 || self.fsize > self.bsize {
            return Err(UfsError::ImpossibleGeometry {
                field: "fs_fsize",
                value: self.fsize as u64,
                limit: self.bsize as u64,
            });
        }
        // A single UFS volume never has this many cylinder groups; cap to guard
        // any per-cg iteration against an allocation-bomb count.
        const MAX_NCG: u64 = 1 << 24;
        if u64::from(self.ncg) > MAX_NCG {
            return Err(UfsError::ImpossibleGeometry {
                field: "fs_ncg",
                value: u64::from(self.ncg),
                limit: MAX_NCG,
            });
        }
        Ok(())
    }

    /// The inode size in bytes for this version: 128 (UFS1) or 256 (UFS2).
    #[must_use]
    pub fn inode_size(&self) -> u32 {
        match self.version {
            UfsVersion::Ufs1 => 128,
            UfsVersion::Ufs2 => 256,
        }
    }

    /// The primary-superblock byte offset for this version from the filesystem
    /// start (`SBLOCK_UFS1` / `SBLOCK_UFS2`).
    #[must_use]
    pub fn primary_offset(&self) -> usize {
        match self.version {
            UfsVersion::Ufs1 => SBLOCK_UFS1,
            UfsVersion::Ufs2 => SBLOCK_UFS2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic 1376-byte superblock with the given magic bytes (in the
    /// given byte order) and a minimal valid geometry, so version/endian detect
    /// and geometry decode can be exercised without a real image.
    fn synthetic(magic: u32, endian: Endian, ufs2: bool) -> Vec<u8> {
        let mut d = vec![0u8; SB_MIN_LEN];
        let wr32 = |d: &mut [u8], off: usize, v: i32| {
            let b = match endian {
                Endian::Little => v.to_le_bytes(),
                Endian::Big => v.to_be_bytes(),
            };
            d[off..off + 4].copy_from_slice(&b);
        };
        let wr64 = |d: &mut [u8], off: usize, v: i64| {
            let b = match endian {
                Endian::Little => v.to_le_bytes(),
                Endian::Big => v.to_be_bytes(),
            };
            d[off..off + 8].copy_from_slice(&b);
        };
        // magic (already in the caller's chosen order value; write raw so the
        // parser's dual-order detect sees it correctly).
        let mb = match endian {
            Endian::Little => magic.to_le_bytes(),
            Endian::Big => magic.to_be_bytes(),
        };
        d[FS_MAGIC_OFF..FS_MAGIC_OFF + 4].copy_from_slice(&mb);
        wr32(&mut d, OFF_SBLKNO, 24);
        wr32(&mut d, OFF_CBLKNO, 32);
        wr32(&mut d, OFF_IBLKNO, 40);
        wr32(&mut d, OFF_DBLKNO, 48);
        wr32(&mut d, OFF_NCG, 4);
        wr32(&mut d, OFF_BSIZE, 32768);
        wr32(&mut d, OFF_FSIZE, 4096);
        wr32(&mut d, OFF_FRAG, 8);
        wr32(&mut d, OFF_BSHIFT, 15);
        wr32(&mut d, OFF_FSHIFT, 12);
        wr32(&mut d, OFF_INOPB, 128);
        wr32(&mut d, OFF_IPG, 128);
        wr32(&mut d, OFF_FPG, 256);
        wr32(&mut d, OFF_MAXSYMLINKLEN, 120);
        if ufs2 {
            wr64(&mut d, OFF_SIZE, 1022);
            wr64(&mut d, OFF_DSIZE, 901);
            wr64(&mut d, OFF_SBLOCKLOC, SBLOCK_UFS2 as i64);
        } else {
            wr32(&mut d, OFF_OLD_SIZE, 1000);
            wr32(&mut d, OFF_OLD_DSIZE, 900);
        }
        d
    }

    #[test]
    fn detects_ufs2_little_endian() {
        let d = synthetic(FS_UFS2_MAGIC, Endian::Little, true);
        let sb = Superblock::parse(&d).unwrap();
        assert_eq!(sb.version, UfsVersion::Ufs2);
        assert_eq!(sb.endian, Endian::Little);
        assert_eq!(sb.bsize, 32768);
        assert_eq!(sb.ncg, 4);
        assert_eq!(sb.size, 1022);
        assert_eq!(sb.sblockloc, SBLOCK_UFS2 as i64);
        assert_eq!(sb.inode_size(), 256);
        assert_eq!(sb.primary_offset(), SBLOCK_UFS2);
    }

    #[test]
    fn detects_ufs2_big_endian() {
        let d = synthetic(FS_UFS2_MAGIC, Endian::Big, true);
        let sb = Superblock::parse(&d).unwrap();
        assert_eq!(sb.version, UfsVersion::Ufs2);
        assert_eq!(sb.endian, Endian::Big);
        assert_eq!(sb.bsize, 32768);
        assert_eq!(sb.fpg, 256);
    }

    #[test]
    fn detects_ufs1_and_uses_old_size_fields() {
        let d = synthetic(FS_UFS1_MAGIC, Endian::Little, false);
        let sb = Superblock::parse(&d).unwrap();
        assert_eq!(sb.version, UfsVersion::Ufs1);
        assert_eq!(sb.size, 1000, "UFS1 uses fs_old_size@36");
        assert_eq!(sb.dsize, 900, "UFS1 uses fs_old_dsize@40");
        assert_eq!(sb.sblockloc, 0, "UFS1 has no fs_sblockloc");
        assert_eq!(sb.inode_size(), 128);
        assert_eq!(sb.primary_offset(), SBLOCK_UFS1);
    }

    #[test]
    fn bad_magic_fails_loud_with_bytes() {
        let mut d = vec![0u8; SB_MIN_LEN];
        d[FS_MAGIC_OFF..FS_MAGIC_OFF + 4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
        match Superblock::parse(&d) {
            Err(UfsError::BadMagic {
                offset, bytes, le, ..
            }) => {
                assert_eq!(offset, FS_MAGIC_OFF);
                assert_eq!(le, 0xdead_beef);
                assert_eq!(bytes, 0xdead_beef_u32.to_le_bytes());
            }
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn truncated_after_valid_magic_does_not_panic() {
        // A buffer carrying the magic but shorter than the struct: magic is read
        // via bounds-checked u8_at, then the length check fails loud.
        let mut d = vec![0u8; SB_MIN_LEN - 1];
        d[FS_MAGIC_OFF..FS_MAGIC_OFF + 4].copy_from_slice(&FS_UFS2_MAGIC.to_le_bytes());
        match Superblock::parse(&d) {
            Err(UfsError::Truncated {
                structure, need, ..
            }) => {
                assert_eq!(structure, "superblock");
                assert_eq!(need, SB_MIN_LEN);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn empty_buffer_reports_bad_magic_not_panic() {
        // Magic reads as 0 (bounds-checked), so it is a BadMagic, not a panic.
        assert!(matches!(
            Superblock::parse(&[]),
            Err(UfsError::BadMagic { .. })
        ));
    }

    #[test]
    fn impossible_block_size_rejected() {
        let mut d = synthetic(FS_UFS2_MAGIC, Endian::Little, true);
        // bsize = 1 << 20 (over the 64 KiB cap).
        d[OFF_BSIZE..OFF_BSIZE + 4].copy_from_slice(&(1_048_576_i32).to_le_bytes());
        assert!(matches!(
            Superblock::parse(&d),
            Err(UfsError::ImpossibleGeometry {
                field: "fs_bsize",
                ..
            })
        ));
    }

    #[test]
    fn impossible_fragment_size_rejected() {
        let mut d = synthetic(FS_UFS2_MAGIC, Endian::Little, true);
        // fsize > bsize.
        d[OFF_FSIZE..OFF_FSIZE + 4].copy_from_slice(&(65536_i32).to_le_bytes());
        assert!(matches!(
            Superblock::parse(&d),
            Err(UfsError::ImpossibleGeometry {
                field: "fs_fsize",
                ..
            })
        ));
    }

    #[test]
    fn absurd_cg_count_rejected() {
        let mut d = synthetic(FS_UFS2_MAGIC, Endian::Little, true);
        d[OFF_NCG..OFF_NCG + 4].copy_from_slice(&0x7fff_ffff_u32.to_le_bytes());
        assert!(matches!(
            Superblock::parse(&d),
            Err(UfsError::ImpossibleGeometry {
                field: "fs_ncg",
                ..
            })
        ));
    }
}
