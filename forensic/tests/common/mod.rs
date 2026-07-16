//! Shared crafted-UFS2-partition builders for the `ufs-forensic` integration
//! tests. Kept in one place so F-INTEGRITY and F-CARVE mint identical geometry.
//!
//! The geometry mirrors the real dfvfs image's addressing constants so the
//! address math the analyzer exercises is the same one the real oracle proves.

#![allow(dead_code, clippy::unwrap_used, clippy::unreadable_literal)]

/// UFS2 magic (`FS_UFS2_MAGIC`).
pub const UFS2_MAGIC: u32 = 0x1954_0119;
/// The cylinder-group header magic (`CG_MAGIC`).
pub const CG_MAGIC: u32 = 0x0009_0255;
/// UFS2 dinode size.
pub const ISIZE: usize = 256;

// ── crafted geometry (small, so the partition stays tiny) ─────────────────────
pub const BSIZE: i32 = 32768;
pub const FSIZE: i32 = 4096;
pub const FRAG: i32 = 8;
pub const NCG: u32 = 4;
pub const IPG: i32 = 128;
pub const FPG: i32 = 256;
pub const SBLKNO: i32 = 24;
pub const CBLKNO: i32 = 32;
pub const IBLKNO: i32 = 40;
pub const DBLKNO: i32 = 48;

/// `SBLOCK_UFS2` — primary superblock byte offset within the partition.
pub const SBLOCK_UFS2: usize = 65536;

// ── cg header field offsets (struct cg) ──────────────────────────────────────
const CG_MAGIC_OFF: usize = 4;
const CG_CGX: usize = 12;
const CG_NDBLK: usize = 20;
const CG_IUSEDOFF: usize = 92;
const CG_FREEOFF: usize = 96;
const CG_CLUSTEROFF: usize = 108;
const CG_NIBLK: usize = 116;
const CG_INITEDIBLK: usize = 120;
/// Byte offset (within the cg header) where we lay the used-inode bitmap.
pub const IUSEDOFF: usize = 168;
/// Byte offset (within the cg header) where we lay the free-block bitmap.
pub const FREEOFF: usize = 184;

/// Write a valid UFS2 superblock at `off` within `part` (little-endian).
pub fn write_superblock(part: &mut [u8], off: usize) {
    let wr32 = |p: &mut [u8], o: usize, v: i32| {
        p[off + o..off + o + 4].copy_from_slice(&v.to_le_bytes());
    };
    let wr64 = |p: &mut [u8], o: usize, v: i64| {
        p[off + o..off + o + 8].copy_from_slice(&v.to_le_bytes());
    };
    wr32(part, 8, SBLKNO);
    wr32(part, 12, CBLKNO);
    wr32(part, 16, IBLKNO);
    wr32(part, 20, DBLKNO);
    wr32(part, 44, NCG as i32);
    wr32(part, 48, BSIZE);
    wr32(part, 52, FSIZE);
    wr32(part, 56, FRAG);
    wr32(part, 80, 15); // bshift
    wr32(part, 84, 12); // fshift
    wr32(part, 116, BSIZE / 8); // nindir (UFS2 8-byte pointers)
    wr32(part, 120, 128); // inopb
    wr32(part, 184, IPG);
    wr32(part, 188, FPG);
    wr32(part, 1320, 120); // maxsymlinklen
    wr64(part, 1080, 1022); // fs_size (frags)
    wr64(part, 1088, 901); // fs_dsize
    wr64(part, 1000, SBLOCK_UFS2 as i64); // fs_sblockloc
    part[off + 1372..off + 1372 + 4].copy_from_slice(&UFS2_MAGIC.to_le_bytes());
}

/// Write a valid cylinder-group header (magic + bitmap offsets) at `off`, index
/// `cgx`. The inode-used bitmap (`IUSEDOFF`) and free-block bitmap (`FREEOFF`)
/// are left all-zero (all inodes free / all blocks in use), so a caller marks
/// inodes used via [`set_inode_used`].
pub fn write_cg_header(part: &mut [u8], off: usize, cgx: u32) {
    let wr32 = |p: &mut [u8], o: usize, v: u32| {
        p[off + o..off + o + 4].copy_from_slice(&v.to_le_bytes());
    };
    wr32(part, CG_MAGIC_OFF, CG_MAGIC);
    wr32(part, CG_CGX, cgx);
    wr32(part, CG_NDBLK, FPG as u32);
    wr32(part, CG_NIBLK, IPG as u32);
    wr32(part, CG_INITEDIBLK, IPG as u32);
    wr32(part, CG_IUSEDOFF, IUSEDOFF as u32);
    wr32(part, CG_FREEOFF, FREEOFF as u32);
    wr32(part, CG_CLUSTEROFF, 200);
}

/// Set (or clear) the used-bit for the given absolute inode number in its cg's
/// inode-used bitmap. The cg header lives at `(cg*fpg + cblkno)*fsize`; the
/// bitmap starts `IUSEDOFF` bytes in; the bit for the within-group inode index
/// is `byte = idx/8, bit = idx%8`.
pub fn set_inode_used(part: &mut [u8], cg: usize, ino: usize, used: bool) {
    let cg_off = (cg * FPG as usize + CBLKNO as usize) * FSIZE as usize;
    let idx = ino % IPG as usize;
    let byte = cg_off + IUSEDOFF + idx / 8;
    let mask = 1u8 << (idx % 8);
    if used {
        part[byte] |= mask;
    } else {
        part[byte] &= !mask;
    }
}

/// Build a minimal UFS2 dinode (256 B, little-endian) with the given mode, size,
/// and first direct block; nlink=1.
pub fn ufs2_dinode(mode: u16, size: u64, db0: u64) -> Vec<u8> {
    let mut d = vec![0u8; ISIZE];
    d[0..2].copy_from_slice(&mode.to_le_bytes()); // di_mode
    d[2..4].copy_from_slice(&1u16.to_le_bytes()); // di_nlink
    d[16..24].copy_from_slice(&size.to_le_bytes()); // di_size
    d[112..120].copy_from_slice(&db0.to_le_bytes()); // di_db[0]
    d
}

/// Encode one `struct direct` entry: head + name padded to `reclen`.
pub fn direct(ino: u32, reclen: u16, d_type: u8, name: &[u8]) -> Vec<u8> {
    let mut e = vec![0u8; reclen as usize];
    e[0..4].copy_from_slice(&ino.to_le_bytes());
    e[4..6].copy_from_slice(&reclen.to_le_bytes());
    e[6] = d_type;
    e[7] = name.len() as u8;
    e[8..8 + name.len()].copy_from_slice(name);
    e
}

/// Byte offset of inode `ino`'s dinode within a crafted partition.
pub fn ino_byte(ino: usize) -> usize {
    let c = ino / IPG as usize;
    let within = ino % IPG as usize;
    (c * FPG as usize + IBLKNO as usize) * FSIZE as usize + within * ISIZE
}
