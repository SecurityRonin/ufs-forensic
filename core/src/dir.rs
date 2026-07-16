//! UFS/FFS directory (`struct direct`) walk and path resolution.
//!
//! A UFS directory is a sequence of `DIRBLKSIZ`-byte (512) blocks, each holding
//! variable-length `struct direct` entries. Each entry begins with a fixed
//! 8-byte head — `d_ino`(u32)@0, `d_reclen`(u16)@4, `d_type`(u8)@6,
//! `d_namlen`(u8)@7 — followed by `d_name` (NUL-terminated, padded to a 4-byte
//! boundary); the whole entry spans `d_reclen` bytes. Field offsets follow
//! `struct direct` in the FreeBSD kernel header `sys/ufs/ufs/dir.h`, verified
//! against the real dfvfs `ufs2.raw` root directory block with the TSK
//! `fls`/`ffind` oracle (see `docs/RESEARCH.md` and `tests/data/README.md`).
//!
//! ## Deleted / empty slots
//!
//! A `d_ino == 0` entry is a free/deleted slot: UFS reclaims a removed entry's
//! space by extending the *previous* record's `d_reclen`, but the removed
//! entry's `d_name` bytes often remain readable within that slack. [`list_dir`]
//! returns live entries by default; [`list_dir_all`] additionally surfaces the
//! `d_ino == 0` slots (flagged `deleted`) so a forensic analyzer can recover the
//! residual names. Recovering names hidden *inside* a preceding entry's slack is
//! a `ufs-forensic` concern (a later phase); this phase exposes the block-level
//! `d_ino == 0` slots the `direct` walk lands on.
//!
//! ## UFS1 big-endian `d_namlen`/`d_type` quirk
//!
//! In the historic "old" directory format (`OLDDIRFMT`) the type byte did not
//! exist: the field was a 16-bit `d_namlen`. On a little-endian host the low
//! byte reads as the name length (offset 7 held 0), so old- and new-format
//! entries decode identically; on a **big-endian** old-format image the two
//! bytes are swapped — offset 6 is the name length and offset 7 is 0. The dfvfs
//! oracle is UFS2 little-endian (new format), so this reader decodes the common
//! new-format case (`d_type`@6, `d_namlen`@7); the big-endian old-format swap is
//! documented here and handled when a real such image lands (a follow-on, like
//! the UFS1 path in `docs/RESEARCH.md`).

use crate::bytes::Endian;
use crate::error::UfsError;
use crate::inode::{read_inode, Inode};
use crate::superblock::{Superblock, UFS_ROOTINO};

/// The directory block size (`DIRBLKSIZ`) — a directory's data is a sequence of
/// these atomically-written blocks.
pub const DIRBLKSIZ: usize = 512;

/// The directory-entry name roundup (`DIR_ROUNDUP`): names are padded to a
/// 4-byte boundary.
pub const DIR_ROUNDUP: usize = 4;

/// Fixed size of a `struct direct` head (before `d_name`): `d_ino`(4) +
/// `d_reclen`(2) + `d_type`(1) + `d_namlen`(1).
const DIRECT_HEAD: usize = 8;

// ── struct direct field offsets (dir.h) ──────────────────────────────────────
const OFF_INO: usize = 0;
const OFF_RECLEN: usize = 4;
const OFF_TYPE: usize = 6;
const OFF_NAMLEN: usize = 7;
const OFF_NAME: usize = 8;

/// A directory-entry file type (`d_type`, `DT_*` in `dir.h`).
///
/// `#[non_exhaustive]` so a later phase can add a variant without a breaking
/// change; consumers matching this enum use a `_` arm. An undefined type byte is
/// carried as [`DirEntryType::Other`] so an unknown value is reported with its
/// evidence rather than hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirEntryType {
    /// `DT_UNKNOWN` (0) — the entry does not record a type (old-format dirs).
    Unknown,
    /// `DT_FIFO` (1) — named pipe / FIFO.
    Fifo,
    /// `DT_CHR` (2) — character device.
    CharDevice,
    /// `DT_DIR` (4) — directory.
    Directory,
    /// `DT_BLK` (6) — block device.
    BlockDevice,
    /// `DT_REG` (8) — regular file.
    Regular,
    /// `DT_LNK` (10) — symbolic link.
    Symlink,
    /// `DT_SOCK` (12) — UNIX-domain socket.
    Socket,
    /// `DT_WHT` (14) — whiteout.
    Whiteout,
    /// A `d_type` value not defined by the format — carries the raw byte so an
    /// unknown type is reported with its evidence.
    Other(u8),
}

impl DirEntryType {
    /// Classify a directory-entry type from the raw `d_type` byte.
    #[must_use]
    pub fn from_d_type(d_type: u8) -> Self {
        match d_type {
            0 => DirEntryType::Unknown,
            1 => DirEntryType::Fifo,
            2 => DirEntryType::CharDevice,
            4 => DirEntryType::Directory,
            6 => DirEntryType::BlockDevice,
            8 => DirEntryType::Regular,
            10 => DirEntryType::Symlink,
            12 => DirEntryType::Socket,
            14 => DirEntryType::Whiteout,
            other => DirEntryType::Other(other),
        }
    }
}

/// One decoded directory entry (`struct direct`).
///
/// `#[non_exhaustive]` so later phases add fields without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DirEntry {
    /// The entry name (`d_name`), decoded from the `d_namlen` bytes after the
    /// head. Not NUL-terminated; invalid UTF-8 is preserved as raw bytes.
    pub name: Vec<u8>,
    /// `d_ino` — the inode number this entry points at. `0` for a free/deleted
    /// slot (only surfaced by [`list_dir_all`]).
    pub ino: u64,
    /// The file type from `d_type`.
    pub file_type: DirEntryType,
    /// `true` when this is a free/deleted slot (`d_ino == 0`) whose residual
    /// name bytes are still readable. Live entries are `false`.
    pub deleted: bool,
}

/// Read `len` bytes of a file's block `addr` from `partition` (the filesystem
/// partition bytes, filesystem byte 0). `addr` is a **fragment address** as
/// stored in an inode's `di_db[]`/`di_ib[]`; the byte offset is
/// `addr * fs_fsize`.
///
/// A directory's data lives in whole blocks; the tail block may be a partial
/// fragment run, so `len` bounds how much is read (typically `fs_bsize`, or the
/// remaining `di_size` for the last block). Reading past the partition end is
/// **not** an error here — the returned slice is clamped to what is present, so
/// a truncated image yields a short (possibly empty) block rather than a
/// failure, and the caller's `d_reclen`/`di_size` bounds still hold.
///
/// # Errors
///
/// [`UfsError::ImpossibleGeometry`] if `fs_fsize <= 0` (the multiplier for the
/// byte offset), so the address cannot be computed — never a panic.
pub fn read_block<'a>(
    partition: &'a [u8],
    sb: &Superblock,
    addr: u64,
    len: usize,
) -> Result<&'a [u8], UfsError> {
    if sb.fsize <= 0 {
        return Err(UfsError::ImpossibleGeometry {
            field: "fs_fsize",
            value: sb.fsize as u64,
            limit: i64::MAX as u64,
        });
    }
    // RED STUB — implemented in GREEN.
    let _ = (partition, addr, len);
    Ok(&[])
}

/// Decode the directory entries of the directory inode `dir_ino`, returning the
/// **live** entries (skipping `d_ino == 0` free/deleted slots). See
/// [`list_dir_all`] to also surface the deleted slots.
///
/// Reads the directory inode's direct data blocks (`di_db[..]`), bounded by
/// `di_size`, and walks consecutive `struct direct` entries by `d_reclen`. A
/// lying `d_reclen` (`0` or past the block) or an over-long `d_namlen` can
/// neither panic nor loop forever: a zero/short `d_reclen` ends the block walk,
/// and a name that would run past the entry is clamped.
///
/// # Errors
///
/// - [`UfsError::InodeOutOfRange`] / [`UfsError::ImpossibleGeometry`] /
///   [`UfsError::Truncated`] propagated from locating/decoding `dir_ino`.
pub fn list_dir(
    partition: &[u8],
    sb: &Superblock,
    dir_ino: u64,
) -> Result<Vec<DirEntry>, UfsError> {
    Ok(list_dir_all(partition, sb, dir_ino)?
        .into_iter()
        .filter(|e| !e.deleted)
        .collect())
}

/// Decode the directory entries of `dir_ino`, including `d_ino == 0`
/// free/deleted slots (flagged `deleted`). The forensic-relevant superset of
/// [`list_dir`] — a deleted slot's residual `d_name` bytes are preserved so an
/// analyzer can recover them.
///
/// # Errors
///
/// As [`list_dir`].
pub fn list_dir_all(
    partition: &[u8],
    sb: &Superblock,
    dir_ino: u64,
) -> Result<Vec<DirEntry>, UfsError> {
    let inode = read_inode(partition, sb, dir_ino)?;
    Ok(list_dir_entries(partition, sb, &inode))
}

/// Walk the `struct direct` entries of an already-decoded directory `inode`,
/// over its direct data blocks bounded by `di_size`. Returns every slot
/// (including `d_ino == 0`); callers filter on `deleted` as needed.
///
/// The walk is bounded three ways so a hostile image is safe: (1) only the bytes
/// within `di_size` are consumed; (2) each block is walked while a full
/// `struct direct` head fits and `d_reclen` advances the cursor; (3) a
/// `d_reclen` of `0` (or one that would not advance past the head) ends the
/// current block rather than spinning.
fn list_dir_entries(partition: &[u8], sb: &Superblock, inode: &Inode) -> Vec<DirEntry> {
    // RED STUB — implemented in GREEN.
    let _ = (partition, sb, inode);
    Vec::new()
}

/// Walk one directory data `block`, appending every `struct direct` slot to
/// `out`. Bounds every read; a lying `d_reclen`/`d_namlen` never over-reads or
/// loops forever.
fn walk_block(block: &[u8], endian: Endian, out: &mut Vec<DirEntry>) {
    // RED STUB — implemented in GREEN.
    let _ = (block, endian, out);
}

/// Resolve an absolute path (e.g. `"/a/b/c"`) to its `(inode number, inode)`,
/// descending from the root inode (`UFS_ROOTINO` = 2) and matching each
/// component against the live directory entries at each level.
///
/// The root (`"/"`) resolves to inode 2. An empty component (`//`, or a trailing
/// `/`) is skipped. A component that names a non-directory before the final
/// component (so the path cannot continue) yields `None`, as does a component no
/// entry matches.
///
/// # Errors
///
/// Propagates [`UfsError`] from locating/decoding an inode along the path. A
/// component that simply does not exist is `Ok(None)`, not an error.
pub fn read_by_path(
    partition: &[u8],
    sb: &Superblock,
    path: &str,
) -> Result<Option<(u64, Inode)>, UfsError> {
    let root = read_inode(partition, sb, UFS_ROOTINO)?;
    let mut cur_ino = UFS_ROOTINO;
    let mut cur = root;

    for comp in path.split('/') {
        if comp.is_empty() {
            continue; // leading/trailing/duplicate slash
        }
        if !cur.is_dir() {
            return Ok(None); // cannot descend through a non-directory
        }
        let entries = list_dir_entries(partition, sb, &cur);
        let Some(hit) = entries
            .iter()
            .find(|e| !e.deleted && e.name == comp.as_bytes())
        else {
            return Ok(None);
        };
        cur_ino = hit.ino;
        cur = read_inode(partition, sb, cur_ino)?;
    }
    Ok(Some((cur_ino, cur)))
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;
    use crate::superblock::{FS_UFS2_MAGIC, SBLOCK_UFS2};

    #[test]
    fn d_type_classifies_all_dt_values() {
        assert_eq!(DirEntryType::from_d_type(0), DirEntryType::Unknown);
        assert_eq!(DirEntryType::from_d_type(1), DirEntryType::Fifo);
        assert_eq!(DirEntryType::from_d_type(2), DirEntryType::CharDevice);
        assert_eq!(DirEntryType::from_d_type(4), DirEntryType::Directory);
        assert_eq!(DirEntryType::from_d_type(6), DirEntryType::BlockDevice);
        assert_eq!(DirEntryType::from_d_type(8), DirEntryType::Regular);
        assert_eq!(DirEntryType::from_d_type(10), DirEntryType::Symlink);
        assert_eq!(DirEntryType::from_d_type(12), DirEntryType::Socket);
        assert_eq!(DirEntryType::from_d_type(14), DirEntryType::Whiteout);
        assert_eq!(DirEntryType::from_d_type(9), DirEntryType::Other(9));
    }

    /// Encode one `struct direct` entry: head + name padded to `reclen`.
    fn direct(ino: u32, reclen: u16, d_type: u8, name: &[u8]) -> Vec<u8> {
        let mut e = vec![0u8; reclen as usize];
        e[OFF_INO..OFF_INO + 4].copy_from_slice(&ino.to_le_bytes());
        e[OFF_RECLEN..OFF_RECLEN + 2].copy_from_slice(&reclen.to_le_bytes());
        e[OFF_TYPE] = d_type;
        e[OFF_NAMLEN] = name.len() as u8;
        e[OFF_NAME..OFF_NAME + name.len()].copy_from_slice(name);
        e
    }

    /// Build the root directory block exactly as the real dfvfs image lays it
    /// out: `.`(2)/`..`(2)/`.snap`(3)/`a_directory`(128)/`passwords.txt`(4)/
    /// `a_link`(5), the last record's reclen absorbing the rest of the 512 block.
    fn real_root_block() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(direct(2, 12, 4, b"."));
        b.extend(direct(2, 12, 4, b".."));
        b.extend(direct(3, 16, 4, b".snap"));
        b.extend(direct(128, 20, 4, b"a_directory"));
        b.extend(direct(4, 24, 8, b"passwords.txt"));
        b.extend(direct(5, 428, 10, b"a_link"));
        assert_eq!(b.len(), DIRBLKSIZ, "root block is one DIRBLKSIZ");
        b
    }

    fn walk(block: &[u8]) -> Vec<DirEntry> {
        let mut out = Vec::new();
        walk_block(block, Endian::Little, &mut out);
        out
    }

    #[test]
    fn walk_block_decodes_real_root_layout() {
        let entries = walk(&real_root_block());
        let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(
            names,
            vec![
                &b"."[..],
                &b".."[..],
                &b".snap"[..],
                &b"a_directory"[..],
                &b"passwords.txt"[..],
                &b"a_link"[..],
            ]
        );
        let inos: Vec<u64> = entries.iter().map(|e| e.ino).collect();
        assert_eq!(inos, vec![2, 2, 3, 128, 4, 5]);
        assert_eq!(entries[3].file_type, DirEntryType::Directory);
        assert_eq!(entries[4].file_type, DirEntryType::Regular);
        assert_eq!(entries[5].file_type, DirEntryType::Symlink);
        assert!(entries.iter().all(|e| !e.deleted));
    }

    #[test]
    fn walk_block_surfaces_deleted_slot() {
        // First entry live, then a d_ino==0 slot whose name bytes remain.
        let mut b = Vec::new();
        b.extend(direct(7, 16, 8, b"live"));
        b.extend(direct(0, 16, 8, b"ghost")); // d_ino==0 => deleted slot
        let entries = walk(&b);
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].deleted);
        assert_eq!(entries[0].name, b"live");
        assert!(entries[1].deleted, "d_ino==0 is a deleted slot");
        assert_eq!(entries[1].ino, 0);
        assert_eq!(entries[1].name, b"ghost", "residual name preserved");
    }

    #[test]
    fn lying_zero_reclen_does_not_loop_forever() {
        // A d_reclen of 0 must end the block walk, not spin.
        let mut b = direct(9, 16, 8, b"ok");
        // Append a head with reclen==0.
        let mut bad = vec![0u8; DIRECT_HEAD];
        bad[OFF_INO..OFF_INO + 4].copy_from_slice(&5u32.to_le_bytes());
        // reclen stays 0
        b.extend(bad);
        let entries = walk(&b);
        assert_eq!(entries.len(), 1, "walk stops at the zero-reclen entry");
        assert_eq!(entries[0].name, b"ok");
    }

    #[test]
    fn over_long_namlen_is_clamped_not_overread() {
        // namlen claims 200 but the record is only 16 bytes: clamp to the record.
        let mut e = vec![0u8; 16];
        e[OFF_INO..OFF_INO + 4].copy_from_slice(&3u32.to_le_bytes());
        e[OFF_RECLEN..OFF_RECLEN + 2].copy_from_slice(&16u16.to_le_bytes());
        e[OFF_TYPE] = 8;
        e[OFF_NAMLEN] = 200; // lying length
        e[OFF_NAME..OFF_NAME + 4].copy_from_slice(b"abcd");
        let entries = walk(&e);
        assert_eq!(entries.len(), 1);
        // The name is clamped to what the record can hold (reclen-8 = 8 bytes),
        // never reading past the record/block.
        assert!(entries[0].name.len() <= 16 - OFF_NAME);
    }

    #[test]
    fn reclen_below_head_ends_block() {
        // A reclen smaller than the 8-byte head is corrupt: stop, don't advance
        // by a sub-head amount and mis-align forever.
        let mut e = vec![0u8; 8];
        e[OFF_INO..OFF_INO + 4].copy_from_slice(&1u32.to_le_bytes());
        e[OFF_RECLEN..OFF_RECLEN + 2].copy_from_slice(&4u16.to_le_bytes()); // < 8
        let entries = walk(&e);
        assert!(entries.is_empty());
    }

    #[test]
    fn walk_empty_or_short_block_is_safe() {
        assert!(walk(&[]).is_empty());
        assert!(walk(&[0u8; 3]).is_empty()); // shorter than a head
    }

    // ── read_block address math ──────────────────────────────────────────────

    fn tiny_sb() -> Superblock {
        // A minimal superblock via parse over a synthetic buffer.
        let mut d = vec![0u8; 1376];
        let wr32 = |d: &mut [u8], off: usize, v: i32| {
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        let wr64 = |d: &mut [u8], off: usize, v: i64| {
            d[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };
        wr32(&mut d, 8, 24); // sblkno
        wr32(&mut d, 12, 32); // cblkno
        wr32(&mut d, 16, 40); // iblkno
        wr32(&mut d, 20, 48); // dblkno
        wr32(&mut d, 44, 4); // ncg
        wr32(&mut d, 48, 32768); // bsize
        wr32(&mut d, 52, 4096); // fsize
        wr32(&mut d, 56, 8); // frag
        wr32(&mut d, 184, 128); // ipg
        wr32(&mut d, 188, 256); // fpg
        wr32(&mut d, 1320, 120); // maxsymlinklen
        wr64(&mut d, 1080, 1022); // size
        wr64(&mut d, 1000, SBLOCK_UFS2 as i64);
        d[1372..1376].copy_from_slice(&FS_UFS2_MAGIC.to_le_bytes());
        Superblock::parse(&d).unwrap()
    }

    #[test]
    fn read_block_offsets_by_fragment_size() {
        let sb = tiny_sb();
        // fragment 2, fsize 4096 => byte 8192.
        let mut part = vec![0u8; 8192 + 16];
        part[8192..8192 + 4].copy_from_slice(b"HERE");
        let block = read_block(&part, &sb, 2, 4).unwrap();
        assert_eq!(block, b"HERE");
    }

    #[test]
    fn read_block_clamps_past_end_without_error() {
        let sb = tiny_sb();
        let part = vec![0u8; 100];
        // fragment 1 => byte 4096, past the 100-byte partition: clamped to empty.
        let block = read_block(&part, &sb, 1, 512).unwrap();
        assert!(block.is_empty());
    }

    #[test]
    fn read_block_rejects_zero_fsize() {
        let mut sb = tiny_sb();
        sb.fsize = 0;
        assert!(matches!(
            read_block(&[0u8; 16], &sb, 0, 4),
            Err(UfsError::ImpossibleGeometry {
                field: "fs_fsize",
                ..
            })
        ));
    }

    // ── list_dir / read_by_path over a synthetic partition ───────────────────

    /// Build a synthetic partition holding: a UFS2 superblock at SBLOCK_UFS2;
    /// the root dir inode (2) pointing at a data block that lists the real root
    /// layout; and a nested `a_directory` (inode 128) + `a_file` (inode 129).
    /// Returns (partition, superblock).
    fn synthetic_fs() -> (Vec<u8>, Superblock) {
        let sb = tiny_sb();
        let fsize = 4096usize;
        let iblkno = 40usize;
        let fpg = 256usize;
        let ipg = 128usize;
        let inode_size = 256usize;

        // Choose fragment addresses (in cg0 data region) for the two dir blocks
        // and give the file inode a dummy block.
        let root_dir_frag = 60u64;
        let adir_frag = 61u64;

        // Layout inode-table location for cg c, inode within: byte =
        // (c*fpg + iblkno)*fsize + within*inode_size.
        let ino_byte = |ino: usize| -> usize {
            let c = ino / ipg;
            let within = ino % ipg;
            (c * fpg + iblkno) * fsize + within * inode_size
        };

        // Size the partition to cover the superblock, the inode table region,
        // and the two data fragments.
        let max_byte = [
            SBLOCK_UFS2 + 1376,
            ino_byte(130) + inode_size,
            (root_dir_frag as usize + 1) * fsize,
            (adir_frag as usize + 1) * fsize,
        ]
        .into_iter()
        .max()
        .unwrap();
        let mut part = vec![0u8; max_byte + 16];

        // Write the superblock at SBLOCK_UFS2.
        let sb_bytes = {
            let mut d = vec![0u8; 1376];
            let wr32 = |d: &mut [u8], off: usize, v: i32| {
                d[off..off + 4].copy_from_slice(&v.to_le_bytes());
            };
            let wr64 = |d: &mut [u8], off: usize, v: i64| {
                d[off..off + 8].copy_from_slice(&v.to_le_bytes());
            };
            wr32(&mut d, 8, 24);
            wr32(&mut d, 12, 32);
            wr32(&mut d, 16, iblkno as i32);
            wr32(&mut d, 20, 48);
            wr32(&mut d, 44, 4);
            wr32(&mut d, 48, 32768);
            wr32(&mut d, 52, fsize as i32);
            wr32(&mut d, 56, 8);
            wr32(&mut d, 184, ipg as i32);
            wr32(&mut d, 188, fpg as i32);
            wr32(&mut d, 1320, 120);
            wr64(&mut d, 1080, 1022);
            wr64(&mut d, 1000, SBLOCK_UFS2 as i64);
            d[1372..1376].copy_from_slice(&FS_UFS2_MAGIC.to_le_bytes());
            d
        };
        part[SBLOCK_UFS2..SBLOCK_UFS2 + 1376].copy_from_slice(&sb_bytes);

        // A UFS2 dinode: dir with size 512 pointing at `frag`, or a regular file.
        let dir_inode = |frag: u64, size: u64, mode: u16| -> Vec<u8> {
            let mut d = vec![0u8; inode_size];
            d[0..2].copy_from_slice(&mode.to_le_bytes()); // di_mode
            d[2..4].copy_from_slice(&1u16.to_le_bytes()); // di_nlink
            d[16..24].copy_from_slice(&size.to_le_bytes()); // di_size
            d[112..120].copy_from_slice(&frag.to_le_bytes()); // di_db[0]
            d
        };
        // root inode 2: directory
        part[ino_byte(2)..ino_byte(2) + inode_size].copy_from_slice(&dir_inode(
            root_dir_frag,
            512,
            0o040755,
        ));
        // a_directory inode 128: directory
        part[ino_byte(128)..ino_byte(128) + inode_size]
            .copy_from_slice(&dir_inode(adir_frag, 512, 0o040755));
        // a_file inode 129: regular file
        part[ino_byte(129)..ino_byte(129) + inode_size]
            .copy_from_slice(&dir_inode(0, 116, 0o100644));

        // root data block: real layout.
        let root_block = real_root_block();
        let rb = root_dir_frag as usize * fsize;
        part[rb..rb + root_block.len()].copy_from_slice(&root_block);

        // a_directory data block: ./ ../ a_file(129).
        let mut adir = Vec::new();
        adir.extend(direct(128, 12, 4, b"."));
        adir.extend(direct(2, 12, 4, b".."));
        adir.extend(direct(129, 488, 8, b"a_file"));
        let ab = adir_frag as usize * fsize;
        part[ab..ab + adir.len()].copy_from_slice(&adir);

        (part, sb)
    }

    #[test]
    fn list_dir_returns_live_root_entries() {
        let (part, sb) = synthetic_fs();
        let entries = list_dir(&part, &sb, 2).unwrap();
        let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(
            names,
            vec![
                &b"."[..],
                &b".."[..],
                &b".snap"[..],
                &b"a_directory"[..],
                &b"passwords.txt"[..],
                &b"a_link"[..],
            ]
        );
        // passwords.txt is inode 4 (the P1 known file).
        let pw = entries.iter().find(|e| e.name == b"passwords.txt").unwrap();
        assert_eq!(pw.ino, 4);
        assert_eq!(pw.file_type, DirEntryType::Regular);
    }

    #[test]
    fn read_by_path_root_resolves_to_inode2() {
        let (part, sb) = synthetic_fs();
        let (ino, inode) = read_by_path(&part, &sb, "/").unwrap().unwrap();
        assert_eq!(ino, 2);
        assert!(inode.is_dir());
    }

    #[test]
    fn read_by_path_resolves_known_file_inode4() {
        let (part, sb) = synthetic_fs();
        let (ino, inode) = read_by_path(&part, &sb, "/passwords.txt").unwrap().unwrap();
        assert_eq!(ino, 4);
        assert_eq!(inode.size, 116, "P1 metadata: passwords.txt is 116 bytes");
    }

    #[test]
    fn read_by_path_descends_nested_directory() {
        let (part, sb) = synthetic_fs();
        let (ino, inode) = read_by_path(&part, &sb, "/a_directory/a_file")
            .unwrap()
            .unwrap();
        assert_eq!(ino, 129);
        assert!(inode.is_regular());
    }

    #[test]
    fn read_by_path_missing_component_is_none() {
        let (part, sb) = synthetic_fs();
        assert!(read_by_path(&part, &sb, "/nope").unwrap().is_none());
        assert!(read_by_path(&part, &sb, "/a_directory/missing")
            .unwrap()
            .is_none());
    }

    #[test]
    fn read_by_path_through_non_directory_is_none() {
        let (part, sb) = synthetic_fs();
        // passwords.txt (inode 4) is a file; descending through it fails.
        assert!(read_by_path(&part, &sb, "/passwords.txt/x")
            .unwrap()
            .is_none());
    }
}
