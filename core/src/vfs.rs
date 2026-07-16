//! `impl forensic_vfs::FileSystem for UfsFs` — the forensic-vfs adapter
//! (behind the `vfs` feature).
//!
//! [`UfsFs`] mounts a UFS/FFS volume onto the [`forensic_vfs::FileSystem`]
//! contract so a UFS filesystem composes as `Arc<dyn FileSystem>` in the
//! forensic-vfs engine, auto-detected through the same probe registry as
//! NTFS/ext4/APFS/XFS/…
//!
//! ## The `&[u8]`-vs-`Read + Seek` bridge (the load-bearing design choice)
//!
//! `ufs-core` is a **slice reader**: [`read_inode`], [`list_dir`], [`read_file`]
//! all take the *whole filesystem partition* as `&[u8]` (filesystem byte 0), not
//! a `Read + Seek` cursor. A forensic-vfs [`DynSource`] is a positioned-read byte
//! source. The adapter bridges the two by reading the **entire source into an
//! owned `Vec<u8>` once at [`UfsFs::open`]** and serving every subsequent call
//! from that buffer (the same choice the XFS/HFS+ adapters make for their
//! slice-based readers). Consequence: a UFS volume is held wholly in RAM — a
//! memory consideration for multi-GB volumes, and the reason a streaming
//! `read_at` cannot window the source directly (there is no windowed reader API
//! to defer to).
//!
//! ## Mapping notes / known limits
//! - **Identity.** UFS has no dedicated [`forensic_vfs::FileId`] variant, so nodes
//!   are addressed by [`FileId::Opaque`] carrying the inode number — the natural
//!   UFS identity. Any other identity domain is a caller error, surfaced loud.
//! - **Single stream.** UFS files are a single unnamed data fork; every
//!   non-`Default` [`StreamId`] is refused loud rather than silently read as the
//!   default.
//! - **`read_at`** reconstructs the whole file via [`read_file`] and windows the
//!   result — the reader exposes no partial-read API, so a huge file is
//!   reconstructed in full per call. Correctness over cleverness for now.
//! - **`extents`** surfaces the inode's *direct* data-block runs (the common
//!   small-file case); indirect-block enumeration is a follow-up, matching the
//!   fleet adapters that leave richer forensic surfaces default-empty. `read_at`
//!   still walks the full (direct + indirect) map, so file content is complete.
//! - **Deleted / unallocated** are empty streams here; UFS deleted-inode /
//!   free-slot carving is the `ufs-forensic` layer's job, not the reader adapter's.
//! - **Symlinks.** `read_link` reconstructs the (fast inline or slow data-block)
//!   target bytes for a symlink node and reads as an empty target for a
//!   non-symlink, matching the ext4/NTFS/XFS adapters.

use forensic_vfs::{
    Allocation, ByteRun, Confidence, DirEntry as VfsDirEntry, DirStream, DynSource, ExtentStream,
    FileId, FileSystem, FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc,
    RunFlags, RunInfo, SectorSizes, SmallHex, SniffWindow, StreamId, TimeResolution, TimeSource,
    TimeStamp, TimeZonePolicy, VfsError, VfsResult,
};

use crate::dir::list_dir;
use crate::error::UfsError;
use crate::file::{read_file, read_symlink_target};
use crate::inode::{read_inode, FileType, Inode, Timespec, UFS_NDADDR};
use crate::superblock::{Superblock, SBLOCK_UFS1, SBLOCK_UFS2, UFS_ROOTINO};

/// The UFS1 superblock magic `0x0001_1954`, little-endian bytes `54 19 01 00`, at
/// absolute offset 9564 (`SBLOCK_UFS1` 8192 + `fs_magic` 1372).
const UFS1_MAGIC_LE: &[u8] = &[0x54, 0x19, 0x01, 0x00];
/// The UFS1 magic in big-endian byte order (`00 01 19 54`) — UFS is
/// endianness-agnostic on disk, so a probe must accept either order.
const UFS1_MAGIC_BE: &[u8] = &[0x00, 0x01, 0x19, 0x54];
/// Absolute byte offset of `fs_magic` for a UFS1 primary superblock.
const UFS1_MAGIC_OFF: usize = SBLOCK_UFS1 + 1372;

/// The UFS2 superblock magic `0x1954_0119`, little-endian bytes `19 01 54 19`, at
/// absolute offset 66908 (`SBLOCK_UFS2` 65536 + `fs_magic` 1372).
const UFS2_MAGIC_LE: &[u8] = &[0x19, 0x01, 0x54, 0x19];
/// The UFS2 magic in big-endian byte order (`19 54 01 19`).
const UFS2_MAGIC_BE: &[u8] = &[0x19, 0x54, 0x01, 0x19];
/// Absolute byte offset of `fs_magic` for a UFS2 primary superblock.
const UFS2_MAGIC_OFF: usize = SBLOCK_UFS2 + 1372;

/// Probe a sniff window for a UFS/FFS superblock magic.
///
/// Matches the UFS2 `fs_magic` (`0x1954_0119`) at offset 66908 or the UFS1
/// `fs_magic` (`0x0001_1954`) at offset 9564, in either byte order (UFS is
/// endianness-agnostic on disk). A definite [`Confidence::Yes`] on a match,
/// [`Confidence::No`] otherwise — panic-free (a short window declines). Exposed
/// so the engine registers it without re-deriving the magic, and so tests drive
/// the probe directly.
#[must_use]
pub fn ufs_probe(w: &SniffWindow) -> Confidence {
    if w.has_magic(UFS2_MAGIC_OFF, UFS2_MAGIC_LE) || w.has_magic(UFS2_MAGIC_OFF, UFS2_MAGIC_BE) {
        return Confidence::Yes {
            how: "UFS2 fs_magic 0x19540119 at offset 66908",
        };
    }
    if w.has_magic(UFS1_MAGIC_OFF, UFS1_MAGIC_LE) || w.has_magic(UFS1_MAGIC_OFF, UFS1_MAGIC_BE) {
        return Confidence::Yes {
            how: "UFS1 fs_magic 0x00011954 at offset 9564",
        };
    }
    Confidence::No
}

/// A mounted, read-only UFS/FFS filesystem over an in-memory image.
///
/// Holds the whole partition bytes (see the module docs on the `&[u8]` bridge)
/// plus the parsed [`Superblock`]; every navigation call reads from the buffer.
pub struct UfsFs {
    image: Vec<u8>,
    sb: Superblock,
}

impl UfsFs {
    /// Read the entire `source` into memory and parse the UFS superblock, trying
    /// the UFS2 primary offset (65536) first, then UFS1 (8192).
    ///
    /// # Errors
    ///
    /// [`VfsError::Decode`] if the bytes are not a valid UFS superblock at either
    /// primary offset, keeping the underlying [`UfsError`] message.
    pub fn open(source: &DynSource) -> VfsResult<Self> {
        let len = source.len();
        // Read the whole source into an owned buffer. usize::try_from can only
        // fail on a <64-bit target (usize == u64 on the supported ones); clamp
        // rather than panic.
        let cap = usize::try_from(len).unwrap_or(usize::MAX);
        let mut image = vec![0u8; cap];
        let n = source.read_at(0, &mut image)?;
        image.truncate(n);

        // The reader's Superblock::parse expects a slice that BEGINS at the
        // superblock; the primary superblock lives at SBLOCK_UFS2 (65536) on
        // UFS2 or SBLOCK_UFS1 (8192) on UFS1. Try UFS2 first (the modern default),
        // then UFS1; keep the last error to report if neither parses.
        let sb = Self::parse_primary(&image, SBLOCK_UFS2)
            .or_else(|_| Self::parse_primary(&image, SBLOCK_UFS1))
            .map_err(map_err)?;
        Ok(Self { image, sb })
    }

    /// Parse the superblock at absolute byte offset `off` within `image`.
    fn parse_primary(image: &[u8], off: usize) -> Result<Superblock, UfsError> {
        let slice = image.get(off..).ok_or(UfsError::Truncated {
            structure: "superblock (primary offset)",
            need: off,
            have: image.len(),
        })?;
        Superblock::parse(slice)
    }

    /// Read and parse the inode carried by a VFS [`FileId`].
    fn inode(&self, id: FileId) -> VfsResult<Inode> {
        let ino = ino_of(id)?;
        read_inode(&self.image, &self.sb, ino).map_err(map_err)
    }
}

/// The inode number carried by a [`FileId`]. UFS addresses nodes by inode number
/// in a [`FileId::Opaque`]; any other identity domain is a caller error.
fn ino_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::Opaque(ino) => Ok(ino),
        other => Err(VfsError::Unsupported {
            layer: "ufs file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// UFS exposes a single unnamed data fork; a named-stream id is refused loud
/// rather than silently read as the default stream.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "ufs stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Translate a ufs-core error into the VFS error type.
fn map_err(e: UfsError) -> VfsError {
    match e {
        UfsError::Truncated { need, have, .. } => VfsError::OutOfRange {
            what: "ufs image slice",
            offset: need as u64,
            len: 1,
            bound: have as u64,
        },
        other => VfsError::Decode {
            layer: "ufs",
            offset: 0,
            detail: other.to_string(),
            bytes: SmallHex::new(&[]),
        },
    }
}

/// Map a UFS `IFMT` file type to the unified node kind.
fn node_kind(ft: FileType) -> NodeKind {
    match ft {
        FileType::Regular => NodeKind::File,
        FileType::Directory => NodeKind::Dir,
        FileType::Symlink => NodeKind::Symlink,
        FileType::CharDevice | FileType::BlockDevice => NodeKind::Device,
        FileType::Fifo | FileType::Socket | FileType::Whiteout | FileType::Other(_) => {
            NodeKind::Other
        }
    }
}

/// Convert a decoded UFS timestamp to a VFS [`TimeStamp`] with inode-table
/// provenance and nanosecond resolution (UFS records ns since the epoch).
fn to_ts(ts: Timespec) -> TimeStamp {
    TimeStamp {
        unix_nanos: i128::from(ts.sec) * 1_000_000_000 + i128::from(ts.nsec),
        source: TimeSource::InodeTable,
        resolution: TimeResolution::Nanos,
    }
}

impl FileSystem for UfsFs {
    fn kind(&self) -> FsKind {
        FsKind::UFS
    }

    fn root(&self) -> FileId {
        FileId::Opaque(UFS_ROOTINO)
    }

    fn sector_sizes(&self) -> SectorSizes {
        SectorSizes {
            logical: 512,
            physical: 512,
            cluster_or_block: if self.sb.bsize > 0 {
                self.sb.bsize as u32
            } else {
                0 // cov:unreachable: Superblock::parse rejects fs_bsize<=0
            },
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        // UFS timestamps are seconds/nanoseconds from the Unix epoch, in UTC.
        TimeZonePolicy::Utc
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let dir_ino = ino_of(ino)?;
        let entries = list_dir(&self.image, &self.sb, dir_ino).map_err(map_err)?;
        // `.`/`..` are real UFS entries; surface them like the reader does, each
        // classified via a cheap inode read rather than trusting the on-disk
        // d_type byte (absent on old-format directories).
        let out: Vec<VfsResult<VfsDirEntry>> = entries
            .into_iter()
            .map(|e| {
                Ok(VfsDirEntry {
                    name: e.name,
                    id: FileId::Opaque(e.ino),
                    kind: self.entry_kind(e.ino),
                })
            })
            .collect();
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        require_default_stream(stream)?;
        let inode = self.inode(ino)?;
        let fsize = self.sb.fsize.max(0) as u64;
        let bsize = self.sb.bsize.max(0) as u64;
        // Surface the direct-block runs (the common small-file case). Each
        // non-zero direct pointer is a fragment address (`addr * fs_fsize`); the
        // run length is one block, clamped by the file's remaining size so the
        // last (tail) block is not over-reported. Indirect-block runs are a
        // follow-up (read_at still walks them for content).
        let mut remaining = inode.size;
        let mut runs: Vec<VfsResult<RunInfo>> = Vec::new();
        for &addr in inode.direct.iter().take(UFS_NDADDR) {
            if remaining == 0 {
                break;
            }
            let this = remaining.min(bsize.max(1));
            if addr != 0 {
                runs.push(Ok(RunInfo {
                    run: ByteRun {
                        image_offset: addr.saturating_mul(fsize),
                        len: this,
                        flags: RunFlags::default(),
                    },
                    alloc: RunAlloc::Allocated,
                }));
            }
            remaining = remaining.saturating_sub(bsize.max(1));
        }
        Ok(ExtentStream::new(runs.into_iter()))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let dir_ino = ino_of(parent)?;
        let entries = list_dir(&self.image, &self.sb, dir_ino).map_err(map_err)?;
        Ok(entries
            .into_iter()
            .find(|e| e.name == name)
            .map(|e| FileId::Opaque(e.ino)))
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let inode_no = ino_of(ino)?;
        let inode = read_inode(&self.image, &self.sb, inode_no).map_err(map_err)?;
        // A fast (inline) symlink stores its target in the block-pointer bytes of
        // the dinode → resident; every other node's data lives out in blocks.
        let residency = match inode.symlink_target() {
            Some(t) => ResidencyKind::Resident {
                inline_len: u32::try_from(t.len()).unwrap_or(u32::MAX),
            },
            None => ResidencyKind::NonResident,
        };
        Ok(FsMeta {
            ino: inode_no,
            kind: node_kind(inode.file_type),
            allocated: Allocation::Allocated,
            size: inode.size,
            nlink: u32::from(inode.nlink),
            uid: Some(inode.uid),
            gid: Some(inode.gid),
            mode: Some(u32::from(inode.mode)),
            times: MacbTimes {
                modified: Some(to_ts(inode.mtime)),
                accessed: Some(to_ts(inode.atime)),
                changed: Some(to_ts(inode.ctime)),
                born: inode.birthtime.map(to_ts),
            },
            streams: Vec::new(),
            residency,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        require_default_stream(stream)?;
        let inode_no = ino_of(ino)?;
        // ufs-core exposes only whole-file reconstruction; window its result to
        // [off, off+buf.len()). A start past EOF reads zero bytes (never panics).
        let file = read_file(&self.image, &self.sb, inode_no).map_err(map_err)?;
        let start = usize::try_from(off).unwrap_or(usize::MAX);
        let Some(slice) = file.get(start..) else {
            return Ok(0);
        };
        let n = slice.len().min(buf.len());
        buf[..n].copy_from_slice(&slice[..n]);
        Ok(n)
    }

    fn read_link(&self, ino: FileId, cap: usize) -> VfsResult<Vec<u8>> {
        let inode = self.inode(ino)?;
        if inode.file_type != FileType::Symlink {
            // A non-symlink reads as an empty target (matches ext4/NTFS/XFS).
            return Ok(Vec::new());
        }
        // read_symlink_target handles both fast (inline) and slow (data-block)
        // symlinks; cap the returned target so a hostile symlink cannot allocate
        // without bound beyond the cap.
        let mut target = read_symlink_target(&self.image, &self.sb, &inode).map_err(map_err)?;
        target.truncate(cap);
        Ok(target)
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // Deleted-inode / free-slot carving is the ufs-forensic layer's job; the
        // reader adapter's default surface is an empty stream, not a bootstrap
        // failure.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

impl UfsFs {
    /// Classify a child by reading its inode; degrade to `Other` (never panic) if
    /// the inode read fails on a volume this handle was already opened from.
    fn entry_kind(&self, ino: u64) -> NodeKind {
        read_inode(&self.image, &self.sb, ino).map_or(NodeKind::Other, |i| node_kind(i.file_type))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::inode::UFS2_DINODE_SIZE;
    use crate::superblock::FS_UFS2_MAGIC;
    use std::sync::Arc as StdArc;

    struct Bytes(Vec<u8>);
    impl forensic_vfs::ImageSource for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
            let off = usize::try_from(offset).unwrap_or(usize::MAX);
            let Some(s) = self.0.get(off..) else {
                return Ok(0); // cov:unreachable: UfsFs::open only reads within bounds
            };
            let n = s.len().min(buf.len());
            buf[..n].copy_from_slice(&s[..n]);
            Ok(n)
        }
    }

    // ── unit tests over the pure mapping helpers ─────────────────────────────

    #[test]
    fn node_kind_maps_every_ifmt_type() {
        assert_eq!(node_kind(FileType::Regular), NodeKind::File);
        assert_eq!(node_kind(FileType::Directory), NodeKind::Dir);
        assert_eq!(node_kind(FileType::Symlink), NodeKind::Symlink);
        assert_eq!(node_kind(FileType::CharDevice), NodeKind::Device);
        assert_eq!(node_kind(FileType::BlockDevice), NodeKind::Device);
        assert_eq!(node_kind(FileType::Fifo), NodeKind::Other);
        assert_eq!(node_kind(FileType::Socket), NodeKind::Other);
        assert_eq!(node_kind(FileType::Whiteout), NodeKind::Other);
        assert_eq!(node_kind(FileType::Other(0o050_000)), NodeKind::Other);
    }

    #[test]
    fn to_ts_carries_ns_and_inode_table_provenance() {
        let ts = to_ts(Timespec { sec: 5, nsec: 123 });
        assert_eq!(ts.unix_nanos, 5 * 1_000_000_000 + 123);
        assert_eq!(ts.source, TimeSource::InodeTable);
        assert_eq!(ts.resolution, TimeResolution::Nanos);
        // A pre-1970 (negative seconds) stamp keeps the sign.
        assert_eq!(
            to_ts(Timespec { sec: -1, nsec: 0 }).unix_nanos,
            -1_000_000_000
        );
    }

    #[test]
    fn map_err_splits_truncated_from_decode() {
        let oor = map_err(UfsError::Truncated {
            structure: "x",
            need: 9,
            have: 4,
        });
        assert!(matches!(
            oor,
            VfsError::OutOfRange {
                offset: 9,
                bound: 4,
                ..
            }
        ));
        let dec = map_err(UfsError::InodeOutOfRange { ino: 1, count: 1 });
        assert!(matches!(dec, VfsError::Decode { layer: "ufs", .. }));
    }

    #[test]
    fn require_default_stream_refuses_named_streams() {
        assert!(require_default_stream(StreamId::Default).is_ok());
        assert!(matches!(
            require_default_stream(StreamId::Slack),
            Err(VfsError::Unsupported {
                layer: "ufs stream",
                ..
            })
        ));
    }

    #[test]
    fn ino_of_refuses_foreign_identity() {
        assert_eq!(ino_of(FileId::Opaque(42)).unwrap(), 42);
        assert!(matches!(
            ino_of(FileId::NtfsRef { entry: 1, seq: 1 }),
            Err(VfsError::Unsupported {
                layer: "ufs file-id",
                ..
            })
        ));
    }

    #[test]
    fn ufs_probe_matches_ufs2_magic_either_order() {
        // UFS2 magic at offset 66908, little-endian on-disk bytes.
        let mut le = vec![0u8; UFS2_MAGIC_OFF + 4];
        le[UFS2_MAGIC_OFF..UFS2_MAGIC_OFF + 4].copy_from_slice(UFS2_MAGIC_LE);
        assert!(matches!(
            ufs_probe(&SniffWindow::new(0, &le)),
            Confidence::Yes { .. }
        ));
        // Big-endian image (byte-swapped magic) still probes Yes.
        let mut be = vec![0u8; UFS2_MAGIC_OFF + 4];
        be[UFS2_MAGIC_OFF..UFS2_MAGIC_OFF + 4].copy_from_slice(UFS2_MAGIC_BE);
        assert!(matches!(
            ufs_probe(&SniffWindow::new(0, &be)),
            Confidence::Yes { .. }
        ));
    }

    #[test]
    fn ufs_probe_matches_ufs1_magic_either_order() {
        let mut le = vec![0u8; UFS1_MAGIC_OFF + 4];
        le[UFS1_MAGIC_OFF..UFS1_MAGIC_OFF + 4].copy_from_slice(UFS1_MAGIC_LE);
        assert!(matches!(
            ufs_probe(&SniffWindow::new(0, &le)),
            Confidence::Yes { .. }
        ));
        let mut be = vec![0u8; UFS1_MAGIC_OFF + 4];
        be[UFS1_MAGIC_OFF..UFS1_MAGIC_OFF + 4].copy_from_slice(UFS1_MAGIC_BE);
        assert!(matches!(
            ufs_probe(&SniffWindow::new(0, &be)),
            Confidence::Yes { .. }
        ));
    }

    #[test]
    fn ufs_probe_declines_non_ufs() {
        assert_eq!(ufs_probe(&SniffWindow::new(0, b"not ufs")), Confidence::No);
        assert_eq!(ufs_probe(&SniffWindow::new(0, &[])), Confidence::No);
    }

    // ── A complete synthetic UFS2 image driving the whole adapter surface ────
    //
    // No env-gated oracle is present on CI, so the adapter surface would go
    // uncovered there. This builds a small but *complete* UFS2 image entirely in
    // memory — a superblock at SBLOCK_UFS2, a root directory (inode 2) listing a
    // regular file, a fast symlink, and a subdirectory — so every navigation
    // method is driven without any external fixture. Ground truth is derivable
    // from the construction (the geometry places each inode/data block at a
    // computed byte offset), the same self-describing-fixture discipline the
    // reader's own module tests use.

    /// Geometry shared by the builder and the located-byte assertions.
    const FSIZE: usize = 4096;
    const IBLKNO: usize = 40;
    const FPG: usize = 256;
    const IPG: usize = 128;
    const ISZ: usize = UFS2_DINODE_SIZE;
    const BSIZE: usize = 32768;

    /// The byte offset of inode `ino` in the synthetic partition.
    fn ino_byte(ino: usize) -> usize {
        let c = ino / IPG;
        let within = ino % IPG;
        (c * FPG + IBLKNO) * FSIZE + within * ISZ
    }

    /// Encode a UFS2 dinode with the given mode/size and up to 12 direct
    /// fragment pointers.
    fn dinode(mode: u16, size: u64, direct: &[u64]) -> Vec<u8> {
        let mut d = vec![0u8; ISZ];
        d[0..2].copy_from_slice(&mode.to_le_bytes()); // di_mode
        d[2..4].copy_from_slice(&1u16.to_le_bytes()); // di_nlink
        d[4..8].copy_from_slice(&1000u32.to_le_bytes()); // di_uid
        d[8..12].copy_from_slice(&1000u32.to_le_bytes()); // di_gid
        d[16..24].copy_from_slice(&size.to_le_bytes()); // di_size
        d[40..48].copy_from_slice(&0x1122_3344i64.to_le_bytes()); // di_mtime
        d[64..68].copy_from_slice(&500i32.to_le_bytes()); // di_mtimensec
        d[56..64].copy_from_slice(&0x2233i64.to_le_bytes()); // di_birthtime
        for (i, &a) in direct.iter().enumerate().take(UFS_NDADDR) {
            d[112 + i * 8..112 + i * 8 + 8].copy_from_slice(&a.to_le_bytes());
        }
        d
    }

    /// Encode a fast-symlink UFS2 dinode: mode IFLNK, target inline in `di_db`.
    fn symlink_dinode(target: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; ISZ];
        d[0..2].copy_from_slice(&0o120_777u16.to_le_bytes()); // di_mode IFLNK
        d[2..4].copy_from_slice(&1u16.to_le_bytes());
        d[16..24].copy_from_slice(&(target.len() as u64).to_le_bytes()); // di_size
        d[112..112 + target.len()].copy_from_slice(target); // inline in di_db
        d
    }

    /// Encode one `struct direct` entry padded to `reclen`.
    fn direct(ino: u32, reclen: u16, d_type: u8, name: &[u8]) -> Vec<u8> {
        let mut e = vec![0u8; reclen as usize];
        e[0..4].copy_from_slice(&ino.to_le_bytes());
        e[4..6].copy_from_slice(&reclen.to_le_bytes());
        e[6] = d_type;
        e[7] = name.len() as u8;
        e[8..8 + name.len()].copy_from_slice(name);
        e
    }

    /// Write a valid UFS2 superblock (1376 bytes) at `SBLOCK_UFS2`.
    fn write_superblock(part: &mut [u8]) {
        let mut d = vec![0u8; 1376];
        let wr32 = |d: &mut [u8], off: usize, v: i32| {
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        let wr64 = |d: &mut [u8], off: usize, v: i64| {
            d[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };
        wr32(&mut d, 8, 24); // sblkno
        wr32(&mut d, 12, 32); // cblkno
        wr32(&mut d, 16, IBLKNO as i32); // iblkno
        wr32(&mut d, 20, 48); // dblkno
        wr32(&mut d, 44, 4); // ncg
        wr32(&mut d, 48, BSIZE as i32); // bsize
        wr32(&mut d, 52, FSIZE as i32); // fsize
        wr32(&mut d, 56, 8); // frag
        wr32(&mut d, 80, 15); // bshift
        wr32(&mut d, 84, 12); // fshift
        wr32(&mut d, 116, 2048); // nindir
        wr32(&mut d, 120, 128); // inopb
        wr32(&mut d, 184, IPG as i32); // ipg
        wr32(&mut d, 188, FPG as i32); // fpg
        wr32(&mut d, 1320, 120); // maxsymlinklen
        wr64(&mut d, 1080, 1022); // size
        wr64(&mut d, 1088, 901); // dsize
        wr64(&mut d, 1000, SBLOCK_UFS2 as i64); // sblockloc
        d[1372..1376].copy_from_slice(&FS_UFS2_MAGIC.to_le_bytes());
        part[SBLOCK_UFS2..SBLOCK_UFS2 + 1376].copy_from_slice(&d);
    }

    /// Build a complete in-memory UFS2 image:
    ///  - inode 2 (root dir) → data frag 60, listing `.`(2) `..`(2)
    ///    `file.txt`(4) `sym`(5) `sub`(6)
    ///  - inode 4 regular file → data frag 61, content "content-1\n"
    ///  - inode 5 fast symlink → inline target "target/path"
    ///  - inode 6 subdirectory → data frag 62, listing `.`(6) `..`(2)
    fn image_with_tree() -> Vec<u8> {
        let root_frag = 60u64;
        let file_frag = 61u64;
        let sub_frag = 62u64;
        let content = b"content-1\n";

        let max = [
            SBLOCK_UFS2 + 1376,
            ino_byte(7) + ISZ,
            (sub_frag as usize + 1) * FSIZE,
        ]
        .into_iter()
        .max()
        .unwrap();
        let mut part = vec![0u8; max + 16];

        write_superblock(&mut part);

        // inodes
        let root = dinode(0o040_755, 512, &[root_frag]);
        part[ino_byte(2)..ino_byte(2) + ISZ].copy_from_slice(&root);
        let file = dinode(0o100_644, content.len() as u64, &[file_frag]);
        part[ino_byte(4)..ino_byte(4) + ISZ].copy_from_slice(&file);
        let sym = symlink_dinode(b"target/path");
        part[ino_byte(5)..ino_byte(5) + ISZ].copy_from_slice(&sym);
        let sub = dinode(0o040_755, 512, &[sub_frag]);
        part[ino_byte(6)..ino_byte(6) + ISZ].copy_from_slice(&sub);

        // root directory block
        let mut rb = Vec::new();
        rb.extend(direct(2, 12, 4, b"."));
        rb.extend(direct(2, 12, 4, b".."));
        rb.extend(direct(4, 24, 8, b"file.txt"));
        rb.extend(direct(5, 16, 10, b"sym"));
        rb.extend(direct(6, DIRBLKSIZ as u16 - 64, 4, b"sub"));
        assert_eq!(rb.len(), DIRBLKSIZ, "root block is one DIRBLKSIZ");
        let rbo = root_frag as usize * FSIZE;
        part[rbo..rbo + rb.len()].copy_from_slice(&rb);

        // file content
        let fbo = file_frag as usize * FSIZE;
        part[fbo..fbo + content.len()].copy_from_slice(content);

        // subdirectory block
        let mut sbk = Vec::new();
        sbk.extend(direct(6, 12, 4, b"."));
        sbk.extend(direct(2, DIRBLKSIZ as u16 - 12, 4, b".."));
        let sbo = sub_frag as usize * FSIZE;
        part[sbo..sbo + sbk.len()].copy_from_slice(&sbk);

        part
    }

    use crate::dir::DIRBLKSIZ;

    fn mount(image: Vec<u8>) -> UfsFs {
        UfsFs::open(&(StdArc::new(Bytes(image)) as DynSource)).unwrap()
    }

    #[test]
    fn open_rejects_non_ufs_source_loud() {
        // UfsFs holds the whole image and intentionally derives no Debug (so an
        // image never leaks into a panic message), so assert via `matches!`
        // rather than `.unwrap_err()` (which would need Debug).
        let bad = vec![0u8; SBLOCK_UFS2 + 2000];
        let opened = UfsFs::open(&(StdArc::new(Bytes(bad)) as DynSource));
        assert!(
            matches!(opened, Err(VfsError::Decode { layer: "ufs", .. })),
            "a non-UFS source must fail loud with a UFS Decode error"
        );
    }

    #[test]
    fn adapter_geometry_surface() {
        let fs = mount(image_with_tree());
        let vfs: &dyn FileSystem = &fs;
        assert_eq!(vfs.kind(), FsKind::UFS);
        assert_eq!(vfs.timestamp_zone(), TimeZonePolicy::Utc);
        let sizes = vfs.sector_sizes();
        assert_eq!(sizes.logical, 512);
        assert_eq!(sizes.physical, 512);
        assert_eq!(sizes.cluster_or_block, BSIZE as u32);
        assert_eq!(vfs.root(), FileId::Opaque(UFS_ROOTINO));
    }

    #[test]
    fn adapter_navigates_the_synthetic_tree() {
        let fs = mount(image_with_tree());
        let vfs: &dyn FileSystem = &fs;
        let root = vfs.root();
        assert_eq!(vfs.meta(root).unwrap().kind, NodeKind::Dir);

        // read_dir lists every entry (incl. `.`/`..`), each classified.
        let listing: Vec<(String, FileId, NodeKind)> = vfs
            .read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| (String::from_utf8_lossy(&e.name).into_owned(), e.id, e.kind))
            .collect();
        assert!(listing.contains(&("file.txt".to_string(), FileId::Opaque(4), NodeKind::File)));
        assert!(listing.contains(&("sym".to_string(), FileId::Opaque(5), NodeKind::Symlink)));
        assert!(listing.contains(&("sub".to_string(), FileId::Opaque(6), NodeKind::Dir)));

        // lookup resolves present names and reports None for an absent one.
        let file = vfs.lookup(root, b"file.txt").unwrap().expect("file.txt");
        assert_eq!(file, FileId::Opaque(4));
        assert!(vfs.lookup(root, b"nope").unwrap().is_none());

        // meta on the regular file.
        let meta = vfs.meta(file).unwrap();
        assert_eq!(meta.kind, NodeKind::File);
        assert_eq!(meta.size, 10);
        assert_eq!(meta.residency, ResidencyKind::NonResident);
        assert_eq!(meta.uid, Some(1000));
        assert_eq!(meta.gid, Some(1000));
        assert_eq!(meta.nlink, 1);
        assert!(meta.times.modified.is_some());
        assert!(meta.times.born.is_some());

        // read_at reconstructs the file's bytes; a start past EOF reads zero.
        let mut buf = vec![0u8; meta.size as usize];
        let n = vfs.read_at(file, StreamId::Default, 0, &mut buf).unwrap();
        buf.truncate(n);
        assert_eq!(buf, b"content-1\n");
        assert_eq!(
            vfs.read_at(file, StreamId::Default, meta.size + 100, &mut [0u8; 4])
                .unwrap(),
            0
        );

        // extents yields the file's one direct-block run.
        let runs: Vec<_> = vfs
            .extents(file, StreamId::Default)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run.image_offset, 61 * FSIZE as u64);
        assert_eq!(runs[0].run.len, 10);
        assert_eq!(runs[0].alloc, RunAlloc::Allocated);

        // A named stream is refused loud on both extents and read_at.
        assert!(vfs.extents(file, StreamId::Named(1)).is_err());
        assert!(vfs
            .read_at(file, StreamId::Slack, 0, &mut [0u8; 4])
            .is_err());

        // descend into the subdirectory.
        let sub = vfs.lookup(root, b"sub").unwrap().expect("sub");
        assert_eq!(vfs.meta(sub).unwrap().kind, NodeKind::Dir);
        let sub_children: Vec<String> = vfs
            .read_dir(sub)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect();
        assert!(sub_children.contains(&".".to_string()));
        assert!(sub_children.contains(&"..".to_string()));

        // read_link on the child symlink returns the inline target;
        // read_link on a non-symlink (the root dir) reads as an empty target.
        let sym = vfs.lookup(root, b"sym").unwrap().expect("sym");
        assert_eq!(vfs.meta(sym).unwrap().kind, NodeKind::Symlink);
        assert!(matches!(
            vfs.meta(sym).unwrap().residency,
            ResidencyKind::Resident { .. }
        ));
        assert_eq!(vfs.read_link(sym, 4096).unwrap(), b"target/path");
        assert_eq!(vfs.read_link(sym, 6).unwrap(), b"target");
        assert_eq!(vfs.read_link(root, 4096).unwrap(), Vec::<u8>::new());

        // The reader adapter's deleted/unallocated surfaces are empty streams.
        assert_eq!(vfs.deleted().unwrap().count(), 0);
        assert_eq!(vfs.unallocated().unwrap().count(), 0);
    }

    #[test]
    fn extents_on_empty_file_is_empty() {
        // A zero-size inode has no direct-block runs.
        let mut part = image_with_tree();
        // Overwrite inode 4 with a zero-size regular file.
        let empty = dinode(0o100_644, 0, &[]);
        part[ino_byte(4)..ino_byte(4) + ISZ].copy_from_slice(&empty);
        let fs = mount(part);
        let vfs: &dyn FileSystem = &fs;
        assert_eq!(
            vfs.extents(FileId::Opaque(4), StreamId::Default)
                .unwrap()
                .count(),
            0
        );
    }
}
