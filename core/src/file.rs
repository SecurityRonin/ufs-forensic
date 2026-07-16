//! UFS/FFS file-content assembly — the block map walk from an inode to its bytes.
//!
//! A UFS file's data is addressed by a block map rooted in the inode: the first
//! `UFS_NDADDR` (12) logical blocks come from the direct pointers `di_db[0..12]`;
//! beyond that, `di_ib[0]` is a single-indirect block (a full data block holding
//! `fs_nindir` further block pointers), `di_ib[1]` a double-indirect block (its
//! pointers name single-indirect blocks), and `di_ib[2]` a triple-indirect block
//! (→ double → single → data). Every pointer is a **fragment address**
//! (`addr * fs_fsize` bytes); a pointer of `0` is a hole and reads as zeros. The
//! last block of a file is a partial fragment run sized to the remaining
//! `di_size`. Pointer width is 8 bytes on UFS2 and 4 bytes on UFS1.
//!
//! Layout and macros follow the FreeBSD kernel header `sys/ufs/ufs/dinode.h`
//! (`di_db`/`di_ib`, `UFS_NDADDR`/`UFS_NIADDR`) and `sys/ufs/ffs/fs.h`
//! (`fs_nindir`); validated by SHA-256 against TSK `icat` on the real dfvfs
//! `ufs2.raw` (direct-block + path cases) and by an independent block-map walker
//! over a crafted image (the single/double/triple indirect chains) — see
//! `core/tests/file_oracle.rs` and `core/tests/file_indirect.rs`.
//!
//! # Safety
//!
//! Every read is bounds-checked and every count derived from the image is capped
//! against the partition size, so a lying `di_size`, a hostile pointer, or a
//! truncated image can neither panic, over-read, nor allocate an absurd buffer
//! (the Paranoid Gatekeeper standard): `di_size` larger than the partition is
//! rejected as an allocation bomb, and indirect recursion is bounded to the three
//! architectural levels.

use crate::dir::{read_block, read_by_path};
use crate::error::UfsError;
use crate::inode::{read_inode, Inode, UFS_NDADDR};
use crate::superblock::{Superblock, UfsVersion};

/// Assemble the full byte content of the file inode `ino`, walking its block map
/// (direct `di_db[0..12]`, then single/double/triple indirect via `di_ib[0..3]`)
/// up to `di_size`. A hole (a `0` pointer, at any level of the tree) reads as
/// zeros; the last block is sized to the remaining `di_size` (fragment tail).
///
/// The assembled buffer is exactly `di_size` bytes.
///
/// # Errors
///
/// - [`UfsError::ImpossibleGeometry`] if `di_size` exceeds the partition length
///   (an allocation bomb — the file cannot possibly be that large), or if
///   `fs_bsize` / `fs_fsize` are non-positive so block addressing is undefined.
/// - Propagates [`UfsError`] from locating/decoding `ino`.
pub fn read_file(partition: &[u8], sb: &Superblock, ino: u64) -> Result<Vec<u8>, UfsError> {
    let inode = read_inode(partition, sb, ino)?;
    read_inode_file(partition, sb, &inode)
}

/// Assemble the byte content of an already-decoded `inode` (the block-map walk
/// [`read_file`] performs after locating the inode). Exposed so callers holding
/// an [`Inode`] (e.g. after [`read_by_path`]) need not re-locate it.
///
/// # Errors
///
/// As [`read_file`] (minus the inode-location errors).
pub fn read_inode_file(
    partition: &[u8],
    sb: &Superblock,
    inode: &Inode,
) -> Result<Vec<u8>, UfsError> {
    if sb.bsize <= 0 {
        return Err(UfsError::ImpossibleGeometry {
            field: "fs_bsize",
            value: sb.bsize as u64,
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
    let size = inode.size;
    // Allocation-bomb guard: a real file cannot be larger than the partition it
    // lives in. Reject a lying di_size before allocating anything.
    let part_len = partition.len() as u64;
    if size > part_len {
        return Err(UfsError::ImpossibleGeometry {
            field: "di_size",
            value: size,
            limit: part_len,
        });
    }
    let bsize = sb.bsize as u64;
    let size_usize = usize::try_from(size).unwrap_or(usize::MAX);
    let mut out = vec![0u8; size_usize];

    if size == 0 {
        return Ok(out);
    }

    // Number of logical blocks the file spans (ceil to a block).
    let n_blocks = size.div_ceil(bsize);
    let nindir = if sb.nindir > 0 { sb.nindir as u64 } else { 0 };

    let mut remaining = size;
    let mut written = 0usize;
    let mut bi: u64 = 0;
    while bi < n_blocks {
        let this_len = usize::try_from(remaining.min(bsize)).unwrap_or(usize::MAX);
        let addr = resolve_block(partition, sb, inode, bi, nindir);
        if addr != 0 {
            let block = read_block(partition, sb, addr, this_len)?;
            // block may be shorter than this_len on a truncated image; copy what
            // is present, leaving the rest zero (already-zeroed buffer).
            let take = block.len().min(this_len);
            if let Some(dst) = out.get_mut(written..written + take) {
                dst.copy_from_slice(&block[..take]);
            }
        }
        // addr == 0 is a hole: leave the block's range zero-filled.
        written = written.saturating_add(this_len);
        remaining = remaining.saturating_sub(bsize);
        bi += 1;
    }

    Ok(out)
}

/// Resolve logical file block index `bi` to its data-fragment address via the
/// inode's block map. Returns `0` for a hole (a `0` pointer at any level).
///
/// `bi < UFS_NDADDR` → `di_db[bi]`; else the single/double/triple indirect trees
/// rooted at `di_ib[0..3]`, each pointer block holding `nindir` further pointers.
/// A `nindir` of `0` (corrupt superblock) collapses the indirect ranges so only
/// the direct blocks resolve — never a divide-by-zero.
fn resolve_block(partition: &[u8], sb: &Superblock, inode: &Inode, bi: u64, nindir: u64) -> u64 {
    let ndaddr = UFS_NDADDR as u64;
    if bi < ndaddr {
        return inode.direct[bi as usize];
    }
    if nindir == 0 {
        return 0; // cov:unreachable: real UFS fs_nindir > 0; guards divide-by-zero
    }
    let mut i = bi - ndaddr;

    // single-indirect: di_ib[0] → data
    if i < nindir {
        return indirect_ptr(partition, sb, inode.indirect[0], i);
    }
    i -= nindir;

    // double-indirect: di_ib[1] → single → data
    let nindir2 = nindir.saturating_mul(nindir);
    if i < nindir2 {
        let sib = indirect_ptr(partition, sb, inode.indirect[1], i / nindir);
        return indirect_ptr(partition, sb, sib, i % nindir);
    }
    i -= nindir2;

    // triple-indirect: di_ib[2] → double → single → data. A block index past the
    // triple reach cannot exist for a di_size that passed the allocation-bomb
    // check (di_size <= partition length), so `i >= nindir3` is unreachable for a
    // valid file; if it ever occurs (a future invariant break) it degrades to a
    // hole rather than mis-address, via the saturating index into a 0-pointer.
    let nindir3 = nindir2.saturating_mul(nindir);
    if i >= nindir3 {
        return 0; // cov:unreachable: di_size <= partition length caps bi below the triple reach
    }
    let dib = indirect_ptr(partition, sb, inode.indirect[2], i / nindir2);
    let rem = i % nindir2;
    let sib = indirect_ptr(partition, sb, dib, rem / nindir);
    indirect_ptr(partition, sb, sib, rem % nindir)
}

/// Read the `idx`-th block pointer from the indirect block at fragment `ind_addr`.
/// `ind_addr == 0` is a hole → `0`. Pointer width is 8 bytes (UFS2) or 4 bytes
/// (UFS1); a read past the block end yields `0` (bounds-checked, never a panic).
fn indirect_ptr(partition: &[u8], sb: &Superblock, ind_addr: u64, idx: u64) -> u64 {
    if ind_addr == 0 {
        return 0;
    }
    let bsize = if sb.bsize > 0 { sb.bsize as usize } else { 0 };
    let Ok(block) = read_block(partition, sb, ind_addr, bsize) else {
        return 0; // cov:unreachable: caller checks fs_fsize>0; read_block only errors on fsize<=0
    };
    let ptr_size = match sb.version {
        UfsVersion::Ufs2 => 8usize,
        UfsVersion::Ufs1 => 4usize,
    };
    let off = usize::try_from(idx.saturating_mul(ptr_size as u64)).unwrap_or(usize::MAX);
    match sb.version {
        UfsVersion::Ufs2 => sb.endian.u64(block, off),
        UfsVersion::Ufs1 => u64::from(sb.endian.u32(block, off)),
    }
}

/// The target of a symbolic-link inode. For a **fast (inline)** symlink
/// (`di_size <= fs_maxsymlinklen`) the target lives in the block-pointer bytes of
/// the dinode and is returned directly (P1 already decoded it — see
/// [`Inode::symlink_target`]). For a **slow** symlink (`di_size >
/// fs_maxsymlinklen`) the target is stored in the file's data block(s), so it is
/// read via the block map like any file's content and truncated to `di_size`.
///
/// # Errors
///
/// As [`read_inode_file`] for a slow symlink (block-map walk); a fast symlink
/// reads no data block and cannot error.
pub fn read_symlink_target(
    partition: &[u8],
    sb: &Superblock,
    inode: &Inode,
) -> Result<Vec<u8>, UfsError> {
    if let Some(inline) = inode.symlink_target() {
        return Ok(inline.to_vec());
    }
    // Slow symlink: the target is the file's data content.
    read_inode_file(partition, sb, inode)
}

/// Resolve an absolute path to its file content: [`read_by_path`] then
/// [`read_file`]. Returns `Ok(None)` when the path does not resolve (like
/// [`read_by_path`]); `Ok(Some(bytes))` with the file's `di_size` bytes otherwise.
///
/// # Errors
///
/// Propagates [`UfsError`] from path resolution or content assembly.
pub fn read_path_content(
    partition: &[u8],
    sb: &Superblock,
    path: &str,
) -> Result<Option<Vec<u8>>, UfsError> {
    let Some((_ino, inode)) = read_by_path(partition, sb, path)? else {
        return Ok(None);
    };
    Ok(Some(read_inode_file(partition, sb, &inode)?))
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;
    use crate::superblock::FS_UFS2_MAGIC;

    // A tiny UFS2 superblock (frag == block for simple addressing) built by
    // parsing a synthetic buffer, so tests exercise resolve_block/read_file over
    // real geometry.
    fn tiny_sb(bsize: i32, fsize: i32, nindir: i32) -> Superblock {
        let mut d = vec![0u8; 1376];
        let wr32 = |d: &mut [u8], off: usize, v: i32| {
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        let wr64 = |d: &mut [u8], off: usize, v: i64| {
            d[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };
        wr32(&mut d, 8, 1); // sblkno
        wr32(&mut d, 12, 2); // cblkno
        wr32(&mut d, 16, 4); // iblkno
        wr32(&mut d, 20, 8); // dblkno
        wr32(&mut d, 44, 1); // ncg
        wr32(&mut d, 48, bsize); // bsize
        wr32(&mut d, 52, fsize); // fsize
        wr32(&mut d, 56, 1); // frag
        wr32(&mut d, 116, nindir); // nindir
        wr32(&mut d, 120, bsize / 256); // inopb
        wr32(&mut d, 184, 128); // ipg
        wr32(&mut d, 188, 4096); // fpg
        wr32(&mut d, 1320, 120); // maxsymlinklen
        wr64(&mut d, 1080, 65536); // size
        d[1372..1376].copy_from_slice(&FS_UFS2_MAGIC.to_le_bytes());
        Superblock::parse(&d).unwrap()
    }

    /// Build a UFS2 inode with the given size, direct and indirect pointers.
    fn inode_with(size: u64, direct: &[u64], ib: [u64; 3]) -> Inode {
        // Encode a UFS2 dinode and parse it, so we get a real Inode.
        let mut d = vec![0u8; 256];
        d[0..2].copy_from_slice(&0o100644u16.to_le_bytes()); // di_mode
        d[2..4].copy_from_slice(&1u16.to_le_bytes()); // di_nlink
        d[16..24].copy_from_slice(&size.to_le_bytes()); // di_size
        for (i, &a) in direct.iter().enumerate() {
            d[112 + i * 8..112 + i * 8 + 8].copy_from_slice(&a.to_le_bytes());
        }
        for (i, &a) in ib.iter().enumerate() {
            d[208 + i * 8..208 + i * 8 + 8].copy_from_slice(&a.to_le_bytes());
        }
        Inode::parse(&d, UfsVersion::Ufs2, crate::Endian::Little).unwrap()
    }

    #[test]
    fn read_file_direct_only_single_block() {
        let sb = tiny_sb(512, 512, 64);
        // partition: data fragment 10 holds the file.
        let mut part = vec![0u8; 512 * 32];
        let payload: Vec<u8> = (0..100u16).map(|i| (i & 0xff) as u8).collect();
        let frag = 10usize;
        part[frag * 512..frag * 512 + payload.len()].copy_from_slice(&payload);
        let inode = inode_with(payload.len() as u64, &[frag as u64], [0, 0, 0]);
        let got = read_inode_file(&part, &sb, &inode).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn read_file_zero_size_is_empty() {
        let sb = tiny_sb(512, 512, 64);
        let part = vec![0u8; 512 * 4];
        let inode = inode_with(0, &[0; 12], [0, 0, 0]);
        assert!(read_inode_file(&part, &sb, &inode).unwrap().is_empty());
    }

    #[test]
    fn read_file_single_indirect_block() {
        let sb = tiny_sb(512, 512, 64);
        // File spans 13 blocks: 12 direct + 1 via single-indirect.
        let mut part = vec![0u8; 512 * 64];
        let mut direct = [0u64; 12];
        // direct data at fragments 20..32
        for (i, slot) in direct.iter_mut().enumerate() {
            let f = 20 + i as u64;
            *slot = f;
            part[f as usize * 512] = (i + 1) as u8; // marker
        }
        // single-indirect block at fragment 40 pointing at data fragment 41
        let sib = 40usize;
        let data13 = 41u64;
        part[sib * 512..sib * 512 + 8].copy_from_slice(&data13.to_le_bytes());
        part[data13 as usize * 512] = 0xAB;
        let size = 13 * 512u64;
        let inode = inode_with(size, &direct, [sib as u64, 0, 0]);
        let got = read_inode_file(&part, &sb, &inode).unwrap();
        assert_eq!(got.len() as u64, size);
        assert_eq!(got[0], 1, "first direct block marker");
        assert_eq!(got[12 * 512], 0xAB, "block 12 came via single-indirect");
    }

    #[test]
    fn read_file_double_and_triple_indirect_with_nindir2() {
        // nindir = 2 makes the fan-out tiny, so a ~20-block file already reaches
        // the triple-indirect region: single=blocks[12,13], double=[14..18),
        // triple=[18..). Each pointer block holds 2 u64 pointers (16 bytes).
        let sb = tiny_sb(512, 512, 2);
        let bsize = 512usize;
        let mut part = vec![0u8; bsize * 128];
        let put_ptr = |p: &mut [u8], frag: usize, idx: usize, target: u64| {
            let off = frag * bsize + idx * 8;
            p[off..off + 8].copy_from_slice(&target.to_le_bytes());
        };
        // A distinctive marker byte per logical block so we can prove the map.
        let mark = |p: &mut [u8], frag: usize, m: u8| p[frag * bsize] = m;

        // 12 direct data blocks at frags 20..32.
        let mut direct = [0u64; 12];
        for (i, slot) in direct.iter_mut().enumerate() {
            let f = 20 + i;
            *slot = f as u64;
            mark(&mut part, f, i as u8 + 1);
        }
        // single-indirect at frag 40 → data frags 50,51 (blocks 12,13).
        put_ptr(&mut part, 40, 0, 50);
        put_ptr(&mut part, 40, 1, 51);
        mark(&mut part, 50, 100);
        mark(&mut part, 51, 101);
        // double-indirect at frag 41 → single-indirect frags 42,43; each → 2 data.
        put_ptr(&mut part, 41, 0, 42);
        put_ptr(&mut part, 41, 1, 43);
        put_ptr(&mut part, 42, 0, 52); // block 14
        put_ptr(&mut part, 42, 1, 53); // block 15
        put_ptr(&mut part, 43, 0, 54); // block 16
        put_ptr(&mut part, 43, 1, 55); // block 17
        for (blk, f) in [(14, 52), (15, 53), (16, 54), (17, 55)] {
            mark(&mut part, f, blk as u8);
        }
        // triple-indirect at frag 44 → double frag 45 → single frag 46 → data 56.
        put_ptr(&mut part, 44, 0, 45);
        put_ptr(&mut part, 45, 0, 46);
        put_ptr(&mut part, 46, 0, 56); // block 18
        mark(&mut part, 56, 200);

        let n_blocks = 19u64; // blocks 0..18 inclusive => reaches triple
        let size = n_blocks * bsize as u64;
        let inode = inode_with(size, &direct, [40, 41, 44]);
        let got = read_inode_file(&part, &sb, &inode).unwrap();
        assert_eq!(got.len() as u64, size);
        assert_eq!(got[0], 1, "direct block 0");
        assert_eq!(got[12 * bsize], 100, "block 12 via single-indirect");
        assert_eq!(got[14 * bsize], 14, "block 14 via double-indirect");
        assert_eq!(got[17 * bsize], 17, "block 17 via double-indirect");
        assert_eq!(got[18 * bsize], 200, "block 18 via triple-indirect");
    }

    #[test]
    fn read_file_ufs1_single_indirect_uses_4byte_pointers() {
        // UFS1: 32-bit block pointers in the indirect block, 128-byte dinode.
        let mut d = vec![0u8; 1376];
        let wr32 = |d: &mut [u8], off: usize, v: i32| {
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        wr32(&mut d, 8, 1);
        wr32(&mut d, 12, 2);
        wr32(&mut d, 16, 4);
        wr32(&mut d, 20, 8);
        wr32(&mut d, 44, 1);
        wr32(&mut d, 48, 512); // bsize
        wr32(&mut d, 52, 512); // fsize
        wr32(&mut d, 56, 1); // frag
        wr32(&mut d, 116, 128); // nindir (bsize/4 for UFS1)
        wr32(&mut d, 120, 4); // inopb (bsize/128)
        wr32(&mut d, 184, 128);
        wr32(&mut d, 188, 4096);
        wr32(&mut d, 1320, 60);
        wr32(&mut d, 36, 65536); // fs_old_size (UFS1 size field)
        d[1372..1376].copy_from_slice(&crate::superblock::FS_UFS1_MAGIC.to_le_bytes());
        let sb = Superblock::parse(&d).unwrap();
        assert_eq!(sb.version, UfsVersion::Ufs1);

        let bsize = 512usize;
        let mut part = vec![0u8; bsize * 64];
        // 12 direct + 1 single-indirect block. UFS1 dinode: di_db@40 (u32),
        // di_ib@88 (u32), di_size@8 (u64).
        let mut dn = vec![0u8; 128];
        dn[0..2].copy_from_slice(&0o100644u16.to_le_bytes());
        dn[8..16].copy_from_slice(&(13u64 * bsize as u64).to_le_bytes());
        for i in 0..12u32 {
            let f = 20 + i;
            dn[40 + i as usize * 4..40 + i as usize * 4 + 4].copy_from_slice(&f.to_le_bytes());
            part[f as usize * bsize] = i as u8 + 1;
        }
        let sib = 40u32;
        dn[88..92].copy_from_slice(&sib.to_le_bytes());
        // single-indirect block: 4-byte pointer to data frag 41 (block 12).
        part[sib as usize * bsize..sib as usize * bsize + 4].copy_from_slice(&41u32.to_le_bytes());
        part[41 * bsize] = 0xCD;
        let inode = Inode::parse(&dn, UfsVersion::Ufs1, crate::Endian::Little).unwrap();
        let got = read_inode_file(&part, &sb, &inode).unwrap();
        assert_eq!(got.len(), 13 * bsize);
        assert_eq!(
            got[12 * bsize],
            0xCD,
            "UFS1 4-byte indirect pointer resolved"
        );
    }

    #[test]
    fn read_file_by_inode_number_locates_then_reads() {
        // Exercise the public read_file(ino) locate+read wrapper. Build a minimal
        // partition with inode 4 as a one-block file and read it by number.
        let (part, sb) = minimal_fs();
        let got = read_file(&part, &sb, 4).unwrap();
        assert_eq!(got, b"twenty-byte-content!");
    }

    #[test]
    fn read_file_hole_zero_fills() {
        let sb = tiny_sb(512, 512, 64);
        let mut part = vec![0u8; 512 * 16];
        // 2-block file, block 0 is a hole (addr 0), block 1 has data.
        let f1 = 9u64;
        part[f1 as usize * 512] = 0x77;
        let inode = inode_with(2 * 512, &[0, f1], [0, 0, 0]);
        let got = read_inode_file(&part, &sb, &inode).unwrap();
        assert!(got[..512].iter().all(|&b| b == 0), "hole zero-filled");
        assert_eq!(got[512], 0x77);
    }

    #[test]
    fn read_file_rejects_allocation_bomb() {
        let sb = tiny_sb(512, 512, 64);
        let part = vec![0u8; 512 * 4];
        let inode = inode_with(u64::MAX, &[0; 12], [0, 0, 0]);
        let err = read_inode_file(&part, &sb, &inode).unwrap_err();
        assert!(matches!(
            err,
            UfsError::ImpossibleGeometry {
                field: "di_size",
                ..
            }
        ));
    }

    #[test]
    fn read_file_rejects_zero_bsize() {
        let mut sb = tiny_sb(512, 512, 64);
        sb.bsize = 0;
        let part = vec![0u8; 512 * 4];
        let inode = inode_with(100, &[1], [0, 0, 0]);
        let err = read_inode_file(&part, &sb, &inode).unwrap_err();
        assert!(matches!(
            err,
            UfsError::ImpossibleGeometry {
                field: "fs_bsize",
                ..
            }
        ));
    }

    #[test]
    fn read_file_rejects_zero_fsize() {
        let mut sb = tiny_sb(512, 512, 64);
        sb.fsize = 0;
        let part = vec![0u8; 512 * 4];
        let inode = inode_with(100, &[1], [0, 0, 0]);
        let err = read_inode_file(&part, &sb, &inode).unwrap_err();
        assert!(matches!(
            err,
            UfsError::ImpossibleGeometry {
                field: "fs_fsize",
                ..
            }
        ));
    }

    #[test]
    fn read_file_truncated_partition_no_panic() {
        let sb = tiny_sb(512, 512, 64);
        // File claims 2 blocks but its data fragment falls off the (short)
        // partition — must not panic, missing bytes read as zero.
        let part = vec![0u8; 512 * 3];
        let inode = inode_with(2 * 512, &[2, 100], [0, 0, 0]); // frag 100 is past end
        let got = read_inode_file(&part, &sb, &inode).unwrap();
        assert_eq!(got.len(), 2 * 512);
    }

    #[test]
    fn resolve_block_zero_nindir_collapses_to_direct_only() {
        let sb = tiny_sb(512, 512, 0); // nindir 0 (corrupt)
        let inode = inode_with(20 * 512, &[5; 12], [40, 0, 0]);
        // block 12 needs the indirect tree, but nindir==0 => hole (0).
        assert_eq!(resolve_block(&[], &sb, &inode, 12, 0), 0);
        // a direct block still resolves.
        assert_eq!(resolve_block(&[], &sb, &inode, 0, 0), 5);
    }

    #[test]
    fn indirect_ptr_hole_addr_is_zero() {
        let sb = tiny_sb(512, 512, 64);
        assert_eq!(indirect_ptr(&[0u8; 512], &sb, 0, 0), 0);
    }

    #[test]
    fn read_symlink_target_fast_inline() {
        let sb = tiny_sb(512, 512, 64);
        // A fast symlink: mode 0120xxx, size 5, target "a/b/c" inline in di_db.
        let mut d = vec![0u8; 256];
        d[0..2].copy_from_slice(&0o120755u16.to_le_bytes());
        d[16..24].copy_from_slice(&5u64.to_le_bytes());
        d[112..117].copy_from_slice(b"a/b/c");
        let inode = Inode::parse(&d, UfsVersion::Ufs2, crate::Endian::Little).unwrap();
        let target = read_symlink_target(&[], &sb, &inode).unwrap();
        assert_eq!(target, b"a/b/c");
    }

    #[test]
    fn read_symlink_target_slow_reads_data_block() {
        let sb = tiny_sb(512, 512, 64);
        // Slow symlink: size 130 > maxsymlinklen 120, target in data block.
        let target = b"x".repeat(130);
        let mut part = vec![0u8; 512 * 16];
        let frag = 7u64;
        part[frag as usize * 512..frag as usize * 512 + 130].copy_from_slice(&target);
        // dinode: mode symlink, size 130, di_db[0]=frag. size>maxsymlinklen so
        // Inode::parse leaves fast_symlink None.
        let mut d = vec![0u8; 256];
        d[0..2].copy_from_slice(&0o120755u16.to_le_bytes());
        d[16..24].copy_from_slice(&130u64.to_le_bytes());
        d[112..120].copy_from_slice(&frag.to_le_bytes());
        let inode = Inode::parse(&d, UfsVersion::Ufs2, crate::Endian::Little).unwrap();
        assert!(
            inode.symlink_target().is_none(),
            "slow symlink is not inline"
        );
        let got = read_symlink_target(&part, &sb, &inode).unwrap();
        assert_eq!(got, target);
    }

    /// A minimal UFS2 partition: root dir (ino 2) with one entry `f` → ino 4, a
    /// 20-byte file. Exercises the `read_path_content` wrapper end-to-end without
    /// reaching into another module's test helpers.
    fn minimal_fs() -> (Vec<u8>, Superblock) {
        let sb = tiny_sb(512, 512, 64);
        let fsize = 512usize;
        let iblkno = 4usize;
        let fpg = 4096usize;
        let ipg = 128usize;
        let isz = 256usize;
        let ino_byte = |ino: usize| (ino / ipg * fpg + iblkno) * fsize + (ino % ipg) * isz;

        let root_frag = 300u64;
        let file_frag = 301u64;
        let max = [ino_byte(5), (file_frag as usize + 1) * fsize]
            .into_iter()
            .max()
            .unwrap();
        let mut part = vec![0u8; max + 16];

        // root dir inode 2 → root_frag
        let mut rdi = vec![0u8; isz];
        rdi[0..2].copy_from_slice(&0o040755u16.to_le_bytes());
        rdi[16..24].copy_from_slice(&512u64.to_le_bytes());
        rdi[112..120].copy_from_slice(&root_frag.to_le_bytes());
        part[ino_byte(2)..ino_byte(2) + isz].copy_from_slice(&rdi);

        // file inode 4 → file_frag, size 20
        let payload = b"twenty-byte-content!";
        let mut fi = vec![0u8; isz];
        fi[0..2].copy_from_slice(&0o100644u16.to_le_bytes());
        fi[16..24].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        fi[112..120].copy_from_slice(&file_frag.to_le_bytes());
        part[ino_byte(4)..ino_byte(4) + isz].copy_from_slice(&fi);
        let fb = file_frag as usize * fsize;
        part[fb..fb + payload.len()].copy_from_slice(payload);

        // root directory block: . .. f(4)
        let mut rb = Vec::new();
        let direct = |ino: u32, reclen: u16, name: &[u8]| -> Vec<u8> {
            let mut e = vec![0u8; reclen as usize];
            e[0..4].copy_from_slice(&ino.to_le_bytes());
            e[4..6].copy_from_slice(&reclen.to_le_bytes());
            e[6] = 8; // d_type reg (dir for . .. but immaterial here)
            e[7] = name.len() as u8;
            e[8..8 + name.len()].copy_from_slice(name);
            e
        };
        rb.extend(direct(2, 12, b"."));
        rb.extend(direct(2, 12, b".."));
        rb.extend(direct(4, 512 - 24, b"f"));
        let rbo = root_frag as usize * fsize;
        part[rbo..rbo + rb.len()].copy_from_slice(&rb);

        (part, sb)
    }

    #[test]
    fn read_path_content_reads_a_file_and_missing_is_none() {
        let (part, sb) = minimal_fs();
        let got = read_path_content(&part, &sb, "/f").unwrap().expect("found");
        assert_eq!(got, b"twenty-byte-content!");
        assert!(read_path_content(&part, &sb, "/does-not-exist")
            .unwrap()
            .is_none());
    }
}
