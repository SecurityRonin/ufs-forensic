//! UFS inode (`struct ufs2_dinode` / `ufs1_dinode`) locate and decode.
//!
//! An inode carries a file's metadata (mode, ownership, size, timestamps) and
//! the block-pointer arrays that map file offsets to disk fragments. UFS2 uses
//! a 256-byte dinode with 64-bit block pointers and a birthtime; UFS1 a
//! 128-byte dinode with 32-bit pointers and no birthtime. Field offsets follow
//! `struct ufs2_dinode` / `struct ufs1_dinode` in the FreeBSD kernel header
//! `sys/ufs/ufs/dinode.h`, verified field-by-field against the dfvfs `ufs2.raw`
//! image with the TSK `istat` oracle (see `docs/RESEARCH.md` and
//! `tests/data/README.md`).
//!
//! ## Inode location math
//!
//! An inode number maps to a byte offset within the filesystem partition:
//! `cg = ino / fs_ipg`; the cg's inode table begins at fragment
//! `cgimin = cg * fs_fpg + fs_iblkno`; so the dinode is at byte
//! `cgimin * fs_fsize + (ino % fs_ipg) * inode_size`. [`read_inode`] operates on
//! the **filesystem-partition** bytes (filesystem byte 0) — callers holding a
//! whole disk image slice past the partition base first.

use crate::bytes::Endian;
use crate::error::UfsError;
use crate::superblock::{Superblock, UfsVersion};

/// Number of direct block pointers in a dinode (`UFS_NDADDR`).
pub const UFS_NDADDR: usize = 12;

/// Number of indirect block pointers in a dinode (`UFS_NIADDR`): single,
/// double, and triple indirect.
pub const UFS_NIADDR: usize = 3;

/// Size in bytes of a UFS2 dinode (`sizeof(struct ufs2_dinode)`).
pub const UFS2_DINODE_SIZE: usize = 256;

/// Size in bytes of a UFS1 dinode (`sizeof(struct ufs1_dinode)`).
pub const UFS1_DINODE_SIZE: usize = 128;

// ── struct ufs2_dinode field offsets (dinode.h) ──────────────────────────────
const U2_MODE: usize = 0;
const U2_NLINK: usize = 2;
const U2_UID: usize = 4;
const U2_GID: usize = 8;
const U2_SIZE: usize = 16;
const U2_BLOCKS: usize = 24;
const U2_ATIME: usize = 32;
const U2_MTIME: usize = 40;
const U2_CTIME: usize = 48;
const U2_BIRTHTIME: usize = 56;
const U2_MTIMENSEC: usize = 64;
const U2_ATIMENSEC: usize = 68;
const U2_CTIMENSEC: usize = 72;
const U2_BIRTHNSEC: usize = 76;
const U2_DB: usize = 112;
const U2_IB: usize = 208;

// ── struct ufs1_dinode field offsets (dinode.h) ──────────────────────────────
const U1_MODE: usize = 0;
const U1_NLINK: usize = 2;
const U1_SIZE: usize = 8;
const U1_ATIME: usize = 16;
const U1_ATIMENSEC: usize = 20;
const U1_MTIME: usize = 24;
const U1_MTIMENSEC: usize = 28;
const U1_CTIME: usize = 32;
const U1_CTIMENSEC: usize = 36;
const U1_DB: usize = 40;
const U1_IB: usize = 88;
const U1_BLOCKS: usize = 104;
const U1_UID: usize = 112;
const U1_GID: usize = 116;

/// `IFMT` mask over `di_mode` selecting the file-type bits.
const IFMT: u16 = 0o170_000;

/// A UFS timestamp: whole seconds since the Unix epoch plus a nanosecond
/// fraction. UFS2 stores seconds as a signed 64-bit value; UFS1 as 32-bit
/// (widened here). The nanosecond field is a signed 32-bit count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Whole seconds since the Unix epoch (may be negative before 1970).
    pub sec: i64,
    /// Nanoseconds within the second.
    pub nsec: i32,
}

/// The file type decoded from `di_mode & IFMT`.
///
/// `#[non_exhaustive]` so a later phase can add a variant (or the `Other`
/// classification changes) without a breaking change; consumers matching this
/// enum use a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileType {
    /// Named pipe / FIFO (`IFIFO`, 0o010000).
    Fifo,
    /// Character device (`IFCHR`, 0o020000).
    CharDevice,
    /// Directory (`IFDIR`, 0o040000).
    Directory,
    /// Block device (`IFBLK`, 0o060000).
    BlockDevice,
    /// Regular file (`IFREG`, 0o100000).
    Regular,
    /// Symbolic link (`IFLNK`, 0o120000).
    Symlink,
    /// UNIX-domain socket (`IFSOCK`, 0o140000).
    Socket,
    /// Whiteout (`IFWHT`, 0o160000).
    Whiteout,
    /// An `IFMT` value not defined by the format — carries the raw type nibble
    /// so an unknown type is reported with its evidence, never hidden.
    Other(u16),
}

impl FileType {
    /// Classify the file type from a raw `di_mode`.
    #[must_use]
    pub fn from_mode(mode: u16) -> Self {
        match mode & IFMT {
            0o010_000 => FileType::Fifo,
            0o020_000 => FileType::CharDevice,
            0o040_000 => FileType::Directory,
            0o060_000 => FileType::BlockDevice,
            0o100_000 => FileType::Regular,
            0o120_000 => FileType::Symlink,
            0o140_000 => FileType::Socket,
            0o160_000 => FileType::Whiteout,
            other => FileType::Other(other),
        }
    }
}

/// A decoded UFS inode — the metadata and block-pointer arrays a forensic tool
/// needs. Carries the union (superset) of the UFS1 and UFS2 dinode fields;
/// UFS1-absent fields (birthtime) are `None`. `#[non_exhaustive]` so later
/// phases add fields without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Inode {
    /// The on-disk version this inode was decoded as.
    pub version: UfsVersion,
    /// `di_mode` — file type (`IFMT`) plus permission bits.
    pub mode: u16,
    /// The file type decoded from `di_mode & IFMT`.
    pub file_type: FileType,
    /// `di_nlink` — hard-link count.
    pub nlink: u16,
    /// `di_uid` — owning user id.
    pub uid: u32,
    /// `di_gid` — owning group id.
    pub gid: u32,
    /// `di_size` — file length in bytes.
    pub size: u64,
    /// `di_blocks` — count of 512-byte sectors actually held.
    pub blocks: u64,
    /// `di_atime` — last access time.
    pub atime: Timespec,
    /// `di_mtime` — last data-modification time.
    pub mtime: Timespec,
    /// `di_ctime` — last inode-change time.
    pub ctime: Timespec,
    /// `di_birthtime` — inode creation time (UFS2 only; `None` on UFS1).
    pub birthtime: Option<Timespec>,
    /// `di_db[UFS_NDADDR]` — direct block pointers (fragment addresses). For a
    /// fast (inline) symlink these bytes hold the target instead — see
    /// [`Self::symlink_target`].
    pub direct: [u64; UFS_NDADDR],
    /// `di_ib[UFS_NIADDR]` — single/double/triple indirect block pointers
    /// (fragment addresses).
    pub indirect: [u64; UFS_NIADDR],
    /// The inline fast-symlink target bytes, when this inode is a symlink whose
    /// `di_size` fits within the block-pointer array (`di_size <=
    /// fs_maxsymlinklen`). `None` for non-symlinks and for slow symlinks whose
    /// target lives in a data block. The bytes are the raw path (not
    /// NUL-terminated); length is `size`.
    fast_symlink: Option<Vec<u8>>,
}

impl Inode {
    /// Decode a single dinode from `data`, which must begin at the dinode (a
    /// 256-byte UFS2 or 128-byte UFS1 record). `version` and `endian` come from
    /// the superblock. `maxsymlinklen` is `fs_maxsymlinklen`, the inline-symlink
    /// threshold; pass it so a symlink whose target fits inline is decoded from
    /// the block-pointer bytes. Use [`read_inode`] to locate and decode by inode
    /// number; this is the lower-level decode over already-located bytes.
    ///
    /// Reads through bounds-checked helpers, so a short `data` never panics —
    /// missing tail bytes read as `0`. It still fails loud when `data` is too
    /// short to hold the whole dinode, so a truncated buffer is reported rather
    /// than silently zero-filled.
    ///
    /// # Errors
    ///
    /// [`UfsError::Truncated`] if `data` is shorter than the dinode for this
    /// version.
    pub fn parse(data: &[u8], version: UfsVersion, endian: Endian) -> Result<Self, UfsError> {
        Self::parse_with_maxsymlink(data, version, endian, DEFAULT_MAXSYMLINKLEN)
    }

    /// Decode a dinode using an explicit `fs_maxsymlinklen` (the inline-symlink
    /// threshold from the superblock). [`Self::parse`] calls this with the
    /// format default (120); [`read_inode`] passes the superblock's value.
    ///
    /// # Errors
    ///
    /// [`UfsError::Truncated`] if `data` is shorter than the dinode.
    pub fn parse_with_maxsymlink(
        data: &[u8],
        version: UfsVersion,
        endian: Endian,
        maxsymlinklen: i32,
    ) -> Result<Self, UfsError> {
        let need = match version {
            UfsVersion::Ufs1 => UFS1_DINODE_SIZE,
            UfsVersion::Ufs2 => UFS2_DINODE_SIZE,
        };
        if data.len() < need {
            return Err(UfsError::Truncated {
                structure: "dinode",
                need,
                have: data.len(),
            });
        }

        let (mode, nlink, uid, gid, size, blocks, atime, mtime, ctime, birthtime, db_off, ib_off) =
            match version {
                UfsVersion::Ufs2 => (
                    endian.u16(data, U2_MODE),
                    endian.u16(data, U2_NLINK),
                    endian.u32(data, U2_UID),
                    endian.u32(data, U2_GID),
                    endian.u64(data, U2_SIZE),
                    endian.u64(data, U2_BLOCKS),
                    Timespec {
                        sec: endian.i64(data, U2_ATIME),
                        nsec: endian.i32(data, U2_ATIMENSEC),
                    },
                    Timespec {
                        sec: endian.i64(data, U2_MTIME),
                        nsec: endian.i32(data, U2_MTIMENSEC),
                    },
                    Timespec {
                        sec: endian.i64(data, U2_CTIME),
                        nsec: endian.i32(data, U2_CTIMENSEC),
                    },
                    Some(Timespec {
                        sec: endian.i64(data, U2_BIRTHTIME),
                        nsec: endian.i32(data, U2_BIRTHNSEC),
                    }),
                    U2_DB,
                    U2_IB,
                ),
                UfsVersion::Ufs1 => (
                    endian.u16(data, U1_MODE),
                    endian.u16(data, U1_NLINK),
                    endian.u32(data, U1_UID),
                    endian.u32(data, U1_GID),
                    endian.u64(data, U1_SIZE),
                    u64::from(endian.u32(data, U1_BLOCKS)),
                    Timespec {
                        sec: i64::from(endian.i32(data, U1_ATIME)),
                        nsec: endian.i32(data, U1_ATIMENSEC),
                    },
                    Timespec {
                        sec: i64::from(endian.i32(data, U1_MTIME)),
                        nsec: endian.i32(data, U1_MTIMENSEC),
                    },
                    Timespec {
                        sec: i64::from(endian.i32(data, U1_CTIME)),
                        nsec: endian.i32(data, U1_CTIMENSEC),
                    },
                    None,
                    U1_DB,
                    U1_IB,
                ),
            };

        let ptr_size = match version {
            UfsVersion::Ufs1 => 4usize,
            UfsVersion::Ufs2 => 8usize,
        };
        let read_ptr = |off: usize| -> u64 {
            match version {
                UfsVersion::Ufs1 => u64::from(endian.u32(data, off)),
                UfsVersion::Ufs2 => endian.u64(data, off),
            }
        };

        let mut direct = [0u64; UFS_NDADDR];
        for (i, slot) in direct.iter_mut().enumerate() {
            *slot = read_ptr(db_off + i * ptr_size);
        }
        let mut indirect = [0u64; UFS_NIADDR];
        for (i, slot) in indirect.iter_mut().enumerate() {
            *slot = read_ptr(ib_off + i * ptr_size);
        }

        let file_type = FileType::from_mode(mode);

        // Fast (inline) symlink: a symlink whose target fits within the
        // block-pointer array region (`di_size <= fs_maxsymlinklen`) stores the
        // path inline where di_db/di_ib would be, not in a data block. The
        // region spans (UFS_NDADDR + UFS_NIADDR) pointers = 120 bytes (UFS2) /
        // 60 bytes (UFS1), which is exactly what fs_maxsymlinklen bounds.
        let fast_symlink = if file_type == FileType::Symlink
            && maxsymlinklen > 0
            && size <= maxsymlinklen as u64
        {
            let region_len = (UFS_NDADDR + UFS_NIADDR) * ptr_size;
            let take = (size as usize).min(region_len);
            data.get(db_off..db_off + take).map(<[u8]>::to_vec)
        } else {
            None
        };

        Ok(Self {
            version,
            mode,
            file_type,
            nlink,
            uid,
            gid,
            size,
            blocks,
            atime,
            mtime,
            ctime,
            birthtime,
            direct,
            indirect,
            fast_symlink,
        })
    }

    /// `true` when this inode is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }

    /// `true` when this inode is a regular file.
    #[must_use]
    pub fn is_regular(&self) -> bool {
        self.file_type == FileType::Regular
    }

    /// `true` when this inode is a symbolic link.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.file_type == FileType::Symlink
    }

    /// The inline fast-symlink target bytes, when this inode is a symlink whose
    /// target is stored inline (`di_size <= fs_maxsymlinklen`). `None` for
    /// non-symlinks and for slow symlinks whose target lives in a data block
    /// (those are resolved by reading the block in a later phase). The bytes are
    /// the raw path, not NUL-terminated.
    #[must_use]
    pub fn symlink_target(&self) -> Option<&[u8]> {
        self.fast_symlink.as_deref()
    }
}

/// The format default for `fs_maxsymlinklen` (used by [`Inode::parse`] when the
/// caller does not supply the superblock's value): 120, the size of the UFS2
/// block-pointer region `(UFS_NDADDR + UFS_NIADDR) * 8`.
const DEFAULT_MAXSYMLINKLEN: i32 = ((UFS_NDADDR + UFS_NIADDR) * 8) as i32;

/// Locate and decode the inode numbered `ino` from `partition`, the filesystem
/// partition bytes (filesystem byte 0 — a caller holding a whole disk image
/// slices past the BSD-disklabel partition base first).
///
/// The byte offset is derived from the superblock geometry (see the module doc):
/// `cg = ino / fs_ipg`; `cgimin = cg * fs_fpg + fs_iblkno` (fragments); byte =
/// `cgimin * fs_fsize + (ino % fs_ipg) * inode_size`.
///
/// # Errors
///
/// - [`UfsError::InodeOutOfRange`] if `ino >= fs_ipg * fs_ncg` (past the last
///   addressable inode) — carries the requested number and the bound.
/// - [`UfsError::ImpossibleGeometry`] if a geometry field needed for the address
///   math is non-positive (e.g. `fs_ipg <= 0`), so the address cannot be
///   computed — never a panic or a wild read.
/// - [`UfsError::Truncated`] if the computed offset plus the dinode size lies
///   outside `partition`.
pub fn read_inode(partition: &[u8], sb: &Superblock, ino: u64) -> Result<Inode, UfsError> {
    // Guard the geometry the address math divides/multiplies by; a corrupt
    // superblock with fs_ipg <= 0 must fail loud, not divide-by-zero or wrap.
    if sb.ipg <= 0 {
        return Err(UfsError::ImpossibleGeometry {
            field: "fs_ipg",
            value: sb.ipg as u64,
            limit: i64::MAX as u64,
        });
    }
    if sb.fpg <= 0 {
        return Err(UfsError::ImpossibleGeometry {
            field: "fs_fpg",
            value: sb.fpg as u64,
            limit: i64::MAX as u64,
        });
    }
    if sb.fsize <= 0 {
        return Err(UfsError::ImpossibleGeometry {
            field: "fs_fsize",
            value: sb.fsize as u64,
            limit: i64::MAX as u64,
        });
    }
    if sb.iblkno < 0 {
        return Err(UfsError::ImpossibleGeometry {
            field: "fs_iblkno",
            value: sb.iblkno as u64,
            limit: i64::MAX as u64,
        });
    }

    let ipg = sb.ipg as u64;
    let fpg = sb.fpg as u64;
    let fsize = sb.fsize as u64;
    let iblkno = sb.iblkno as u64;
    let inode_size = u64::from(sb.inode_size());

    // Reject an inode past the filesystem's total inode count.
    let count = ipg.saturating_mul(u64::from(sb.ncg));
    if ino >= count {
        return Err(UfsError::InodeOutOfRange { ino, count });
    }

    // cg = ino / fs_ipg; cgimin (frags) = cg * fs_fpg + fs_iblkno; byte offset
    // = cgimin * fs_fsize + (ino % fs_ipg) * inode_size. Saturating throughout
    // so a hostile/huge value yields a Truncated error at the bounds check,
    // never an arithmetic overflow.
    let cg = ino / ipg;
    let within = ino % ipg;
    let cgimin = cg.saturating_mul(fpg).saturating_add(iblkno);
    let byte = cgimin
        .saturating_mul(fsize)
        .saturating_add(within.saturating_mul(inode_size));

    let start = usize::try_from(byte).unwrap_or(usize::MAX);
    let end = start.saturating_add(inode_size as usize);
    let Some(slice) = partition.get(start..end) else {
        return Err(UfsError::Truncated {
            structure: "dinode (located)",
            need: end,
            have: partition.len(),
        });
    };

    Inode::parse_with_maxsymlink(slice, sb.version, sb.endian, sb.maxsymlinklen)
}

#[cfg(test)]
// Octal file-mode literals (0o040755, 0o100644, …) read most clearly ungrouped —
// the POSIX/Unix convention for modes — so the tests opt out of the
// digit-grouping lint rather than write non-idiomatic 0o04_0755 forms.
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;

    /// Build a minimal UFS2 dinode (256 B) in little-endian with the given
    /// mode/size and a first direct block, so decode can be exercised without a
    /// real image.
    fn ufs2_dinode(mode: u16, size: u64, db0: u64) -> Vec<u8> {
        let mut d = vec![0u8; UFS2_DINODE_SIZE];
        d[U2_MODE..U2_MODE + 2].copy_from_slice(&mode.to_le_bytes());
        d[U2_NLINK..U2_NLINK + 2].copy_from_slice(&1u16.to_le_bytes());
        d[U2_UID..U2_UID + 4].copy_from_slice(&1000u32.to_le_bytes());
        d[U2_GID..U2_GID + 4].copy_from_slice(&1000u32.to_le_bytes());
        d[U2_SIZE..U2_SIZE + 8].copy_from_slice(&size.to_le_bytes());
        d[U2_BLOCKS..U2_BLOCKS + 8].copy_from_slice(&8u64.to_le_bytes());
        d[U2_MTIME..U2_MTIME + 8].copy_from_slice(&0x1122_3344i64.to_le_bytes());
        d[U2_MTIMENSEC..U2_MTIMENSEC + 4].copy_from_slice(&500i32.to_le_bytes());
        d[U2_BIRTHTIME..U2_BIRTHTIME + 8].copy_from_slice(&0x2233i64.to_le_bytes());
        d[U2_DB..U2_DB + 8].copy_from_slice(&db0.to_le_bytes());
        d
    }

    /// Build a minimal UFS1 dinode (128 B) in little-endian.
    fn ufs1_dinode(mode: u16, size: u64, db0: u32) -> Vec<u8> {
        let mut d = vec![0u8; UFS1_DINODE_SIZE];
        d[U1_MODE..U1_MODE + 2].copy_from_slice(&mode.to_le_bytes());
        d[U1_NLINK..U1_NLINK + 2].copy_from_slice(&2u16.to_le_bytes());
        d[U1_SIZE..U1_SIZE + 8].copy_from_slice(&size.to_le_bytes());
        d[U1_MTIME..U1_MTIME + 4].copy_from_slice(&0x0055_6677u32.to_le_bytes());
        d[U1_MTIMENSEC..U1_MTIMENSEC + 4].copy_from_slice(&7i32.to_le_bytes());
        d[U1_BLOCKS..U1_BLOCKS + 4].copy_from_slice(&4u32.to_le_bytes());
        d[U1_UID..U1_UID + 4].copy_from_slice(&501u32.to_le_bytes());
        d[U1_GID..U1_GID + 4].copy_from_slice(&20u32.to_le_bytes());
        d[U1_DB..U1_DB + 4].copy_from_slice(&db0.to_le_bytes());
        d
    }

    #[test]
    fn file_type_from_mode_classifies_all_ifmt() {
        assert_eq!(FileType::from_mode(0o040755), FileType::Directory);
        assert_eq!(FileType::from_mode(0o100644), FileType::Regular);
        assert_eq!(FileType::from_mode(0o120777), FileType::Symlink);
        assert_eq!(FileType::from_mode(0o010000), FileType::Fifo);
        assert_eq!(FileType::from_mode(0o020000), FileType::CharDevice);
        assert_eq!(FileType::from_mode(0o060000), FileType::BlockDevice);
        assert_eq!(FileType::from_mode(0o140000), FileType::Socket);
        assert_eq!(FileType::from_mode(0o160000), FileType::Whiteout);
        // An undefined IFMT nibble carries the raw value.
        assert_eq!(FileType::from_mode(0o050000), FileType::Other(0o050000));
    }

    #[test]
    fn decodes_ufs2_regular_file() {
        let d = ufs2_dinode(0o100644, 116, 57);
        let ino = Inode::parse(&d, UfsVersion::Ufs2, Endian::Little).unwrap();
        assert_eq!(ino.version, UfsVersion::Ufs2);
        assert_eq!(ino.file_type, FileType::Regular);
        assert!(ino.is_regular());
        assert!(!ino.is_dir());
        assert_eq!(ino.mode & 0o7777, 0o644);
        assert_eq!(ino.nlink, 1);
        assert_eq!(ino.uid, 1000);
        assert_eq!(ino.gid, 1000);
        assert_eq!(ino.size, 116);
        assert_eq!(ino.blocks, 8);
        assert_eq!(ino.mtime.sec, 0x1122_3344);
        assert_eq!(ino.mtime.nsec, 500);
        assert_eq!(
            ino.birthtime,
            Some(Timespec {
                sec: 0x2233,
                nsec: 0
            })
        );
        assert_eq!(ino.direct[0], 57);
        assert!(ino.direct[1..].iter().all(|&b| b == 0));
        assert!(ino.symlink_target().is_none());
    }

    #[test]
    fn decodes_ufs2_directory() {
        let d = ufs2_dinode(0o040755, 512, 56);
        let ino = Inode::parse(&d, UfsVersion::Ufs2, Endian::Little).unwrap();
        assert!(ino.is_dir());
        assert_eq!(ino.direct[0], 56);
    }

    #[test]
    fn decodes_ufs2_fast_symlink_inline_target() {
        let target = b"a_directory/another_file";
        let mut d = ufs2_dinode(0o120755, target.len() as u64, 0);
        d[U2_DB..U2_DB + target.len()].copy_from_slice(target);
        let ino = Inode::parse(&d, UfsVersion::Ufs2, Endian::Little).unwrap();
        assert_eq!(ino.file_type, FileType::Symlink);
        assert!(ino.is_symlink());
        assert_eq!(ino.symlink_target(), Some(&target[..]));
    }

    #[test]
    fn slow_symlink_over_threshold_has_no_inline_target() {
        // A symlink whose size exceeds maxsymlinklen stores its target in a data
        // block, not inline — symlink_target() is None (resolved in a later
        // phase by reading the block).
        let d = ufs2_dinode(0o120755, 200, 57);
        let ino = Inode::parse_with_maxsymlink(&d, UfsVersion::Ufs2, Endian::Little, 120).unwrap();
        assert_eq!(ino.file_type, FileType::Symlink);
        assert!(ino.symlink_target().is_none());
        // The block pointer is still readable as a normal direct block.
        assert_eq!(ino.direct[0], 57);
    }

    #[test]
    fn decodes_ufs2_big_endian() {
        let mut d = vec![0u8; UFS2_DINODE_SIZE];
        d[U2_MODE..U2_MODE + 2].copy_from_slice(&0o100644u16.to_be_bytes());
        d[U2_SIZE..U2_SIZE + 8].copy_from_slice(&999u64.to_be_bytes());
        d[U2_DB..U2_DB + 8].copy_from_slice(&123u64.to_be_bytes());
        let ino = Inode::parse(&d, UfsVersion::Ufs2, Endian::Big).unwrap();
        assert_eq!(ino.file_type, FileType::Regular);
        assert_eq!(ino.size, 999);
        assert_eq!(ino.direct[0], 123);
    }

    #[test]
    fn decodes_ufs1_dinode_32bit_layout() {
        let d = ufs1_dinode(0o100600, 4096, 0xdead);
        let ino = Inode::parse(&d, UfsVersion::Ufs1, Endian::Little).unwrap();
        assert_eq!(ino.version, UfsVersion::Ufs1);
        assert_eq!(ino.file_type, FileType::Regular);
        assert_eq!(ino.mode & 0o7777, 0o600);
        assert_eq!(ino.nlink, 2);
        assert_eq!(ino.uid, 501);
        assert_eq!(ino.gid, 20);
        assert_eq!(ino.size, 4096);
        assert_eq!(ino.blocks, 4);
        assert_eq!(ino.mtime.sec, 0x0055_6677);
        assert_eq!(ino.mtime.nsec, 7);
        assert_eq!(ino.birthtime, None, "UFS1 has no birthtime");
        assert_eq!(ino.direct[0], 0xdead);
    }

    #[test]
    fn decodes_ufs1_fast_symlink() {
        let target = b"../elsewhere";
        let mut d = ufs1_dinode(0o120777, target.len() as u64, 0);
        d[U1_DB..U1_DB + target.len()].copy_from_slice(target);
        // UFS1 inline region = (12 + 3) * 4 = 60 bytes.
        let ino = Inode::parse_with_maxsymlink(&d, UfsVersion::Ufs1, Endian::Little, 60).unwrap();
        assert_eq!(ino.symlink_target(), Some(&target[..]));
    }

    #[test]
    fn truncated_dinode_fails_loud_not_panic() {
        let d = vec![0u8; UFS2_DINODE_SIZE - 1];
        let err = Inode::parse(&d, UfsVersion::Ufs2, Endian::Little).unwrap_err();
        assert!(matches!(
            err,
            UfsError::Truncated {
                structure: "dinode",
                need: UFS2_DINODE_SIZE,
                ..
            }
        ));
    }

    #[test]
    fn empty_dinode_buffer_does_not_panic() {
        assert!(matches!(
            Inode::parse(&[], UfsVersion::Ufs2, Endian::Little),
            Err(UfsError::Truncated { .. })
        ));
    }

    // ── read_inode locate math over a synthetic partition ────────────────────

    /// Build a tiny synthetic partition: a UFS2 superblock at `SBLOCK_UFS2` with a
    /// known geometry, and one dinode placed where `read_inode` should find it.
    fn synthetic_partition(ino_to_place: u64, dinode: &[u8]) -> (Vec<u8>, Superblock) {
        use crate::superblock::{FS_UFS2_MAGIC, SBLOCK_UFS2};
        // Geometry: fs_iblkno=40 frags, fs_fsize=4096, fs_ipg=128, fs_fpg=256,
        // fs_ncg=4 — matching the real dfvfs image so the math is identical.
        let iblkno = 40u64;
        let fsize = 4096u64;
        let ipg = 128u64;
        let fpg = 256u64;
        let ncg = 4u32;
        let inode_size = 256u64;

        let cg = ino_to_place / ipg;
        let within = ino_to_place % ipg;
        let cgimin = cg * fpg + iblkno;
        let byte = (cgimin * fsize + within * inode_size) as usize;

        // Size the partition to hold both the placed dinode and the superblock
        // at SBLOCK_UFS2 (whichever ends later), with a little slack.
        let sboff = SBLOCK_UFS2;
        let total = (byte + dinode.len()).max(sboff + 1376) + 16;
        let mut part = vec![0u8; total];
        part[byte..byte + dinode.len()].copy_from_slice(dinode);
        let wr32 = |p: &mut [u8], off: usize, v: i32| {
            p[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        let wr64 = |p: &mut [u8], off: usize, v: i64| {
            p[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };
        wr32(&mut part, sboff + 8, 24); // sblkno
        wr32(&mut part, sboff + 12, 32); // cblkno
        wr32(&mut part, sboff + 16, iblkno as i32); // iblkno
        wr32(&mut part, sboff + 20, 48); // dblkno
        wr32(&mut part, sboff + 44, ncg as i32); // ncg
        wr32(&mut part, sboff + 48, 32768); // bsize
        wr32(&mut part, sboff + 52, fsize as i32); // fsize
        wr32(&mut part, sboff + 56, 8); // frag
        wr32(&mut part, sboff + 80, 15); // bshift
        wr32(&mut part, sboff + 84, 12); // fshift
        wr32(&mut part, sboff + 120, 128); // inopb
        wr32(&mut part, sboff + 184, ipg as i32); // ipg
        wr32(&mut part, sboff + 188, fpg as i32); // fpg
        wr32(&mut part, sboff + 1320, 120); // maxsymlinklen
        wr64(&mut part, sboff + 1080, 1022); // size
        wr64(&mut part, sboff + 1088, 901); // dsize
        wr64(&mut part, sboff + 1000, SBLOCK_UFS2 as i64); // sblockloc
        part[sboff + 1372..sboff + 1376].copy_from_slice(&FS_UFS2_MAGIC.to_le_bytes());

        let sb = Superblock::parse(&part[sboff..]).unwrap();
        (part, sb)
    }

    #[test]
    fn read_inode_locates_and_decodes() {
        let dinode = ufs2_dinode(0o100644, 116, 57);
        let (part, sb) = synthetic_partition(4, &dinode);
        let ino = read_inode(&part, &sb, 4).unwrap();
        assert_eq!(ino.file_type, FileType::Regular);
        assert_eq!(ino.size, 116);
        assert_eq!(ino.direct[0], 57);
    }

    #[test]
    fn read_inode_rejects_out_of_range() {
        let (part, sb) = synthetic_partition(4, &ufs2_dinode(0o100644, 1, 1));
        // fs_ipg (128) * fs_ncg (4) = 512 inodes; 512 is out of range.
        let err = read_inode(&part, &sb, 512).unwrap_err();
        assert!(matches!(
            err,
            UfsError::InodeOutOfRange {
                ino: 512,
                count: 512
            }
        ));
    }

    #[test]
    fn read_inode_truncated_partition_fails_loud() {
        let dinode = ufs2_dinode(0o100644, 1, 1);
        let (mut part, sb) = synthetic_partition(4, &dinode);
        // Truncate the partition so the located dinode falls off the end, but
        // keep the superblock (it sits at 65536, past our small inode table).
        part.truncate(180_000);
        // Inode in cg1 (>= 128) is located near byte ~1.16 MiB, past the cut.
        let err = read_inode(&part, &sb, 200).unwrap_err();
        assert!(matches!(err, UfsError::Truncated { .. }));
    }

    #[test]
    fn read_inode_rejects_zero_ipg_geometry() {
        let dinode = ufs2_dinode(0o100644, 1, 1);
        let (part, mut sb) = synthetic_partition(4, &dinode);
        // Force a corrupt fs_ipg on the parsed superblock; read_inode must fail
        // loud rather than divide by zero.
        sb.ipg = 0;
        let err = read_inode(&part, &sb, 4).unwrap_err();
        assert!(matches!(
            err,
            UfsError::ImpossibleGeometry {
                field: "fs_ipg",
                ..
            }
        ));
    }

    #[test]
    fn read_inode_rejects_zero_fpg_geometry() {
        let (part, mut sb) = synthetic_partition(4, &ufs2_dinode(0o100644, 1, 1));
        sb.fpg = 0;
        let err = read_inode(&part, &sb, 4).unwrap_err();
        assert!(matches!(
            err,
            UfsError::ImpossibleGeometry {
                field: "fs_fpg",
                ..
            }
        ));
    }

    #[test]
    fn read_inode_rejects_zero_fsize_geometry() {
        let (part, mut sb) = synthetic_partition(4, &ufs2_dinode(0o100644, 1, 1));
        sb.fsize = 0;
        let err = read_inode(&part, &sb, 4).unwrap_err();
        assert!(matches!(
            err,
            UfsError::ImpossibleGeometry {
                field: "fs_fsize",
                ..
            }
        ));
    }

    #[test]
    fn read_inode_rejects_negative_iblkno_geometry() {
        let (part, mut sb) = synthetic_partition(4, &ufs2_dinode(0o100644, 1, 1));
        sb.iblkno = -1;
        let err = read_inode(&part, &sb, 4).unwrap_err();
        assert!(matches!(
            err,
            UfsError::ImpossibleGeometry {
                field: "fs_iblkno",
                ..
            }
        ));
    }
}
