//! P3 indirect-block addressing test over a **synthetic** UFS2 partition.
//!
//! The real dfvfs `ufs2.raw` oracle holds only tiny files (<= one direct block),
//! so it cannot exercise the single / double / triple indirect chains — the
//! classic place an off-by-one in `fs_nindir` corrupts large-file reads
//! (`docs/RESEARCH.md` §risks). There is no `mkfs.ufs`/`makefs` on the build
//! host to mint a real large-file image, so this test **crafts** a UFS2
//! partition whose one file's block map deliberately spans direct blocks, a full
//! single-indirect block, into the double-indirect tree, and one block reached
//! only through the triple-indirect chain — plus a hole and a partial fragment
//! tail.
//!
//! ## Oracle (independence)
//!
//! File content is a deterministic byte pattern the builder writes to each data
//! block. `read_file` is checked two independent ways: (1) against that known
//! pattern; and (2) against a **second, separately-written** reassembly walker
//! (`independent_walk`) that re-reads the on-disk pointer blocks from the raw
//! partition bytes — code with no shared logic with the reader. Two independent
//! decoders agreeing on the same crafted artifact, plus the known construction,
//! is the indirect-chain answer key the real image cannot supply. (The real-image
//! `icat` Tier-1 oracle in `file_oracle.rs` carries content correctness for the
//! direct-block + path cases.)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]

use ufs::{read_file, Superblock, UfsError, SBLOCK_UFS2};

// ── crafted geometry ─────────────────────────────────────────────────────────
// Small block/fragment so the indirect fan-out is cheap. UFS2 uses 8-byte block
// pointers, so nindir = bsize / 8.
const BSIZE: usize = 512;
const FSIZE: usize = 512; // frag == block (frag=1) keeps addressing simple
const FRAG: i32 = 1;
const NINDIR: usize = BSIZE / 8; // 64 pointers per indirect block
const ISIZE: usize = 256; // UFS2 dinode size
const IPG: i32 = 64;
const NCG: u32 = 4;
const IBLKNO: usize = 4; // inode table start (fragments) within cg0
const FPG: i32 = 8192; // fragments per group (roomy)

const UFS2_MAGIC: u32 = 0x1954_0119;

// dinode field offsets (UFS2)
const DI_MODE: usize = 0;
const DI_NLINK: usize = 2;
const DI_SIZE: usize = 16;
const DI_DB: usize = 112; // di_db[12], u64 each
const DI_IB: usize = 208; // di_ib[3], u64 each

// superblock field offsets (relative to superblock start; mirror core P0 parser)
const SB_SBLKNO: usize = 8;
const SB_CBLKNO: usize = 12;
const SB_IBLKNO: usize = 16;
const SB_DBLKNO: usize = 20;
const SB_NCG: usize = 44;
const SB_BSIZE: usize = 48;
const SB_FSIZE: usize = 52;
const SB_FRAG: usize = 56;
const SB_NINDIR: usize = 116;
const SB_INOPB: usize = 120;
const SB_IPG: usize = 184;
const SB_FPG: usize = 188;
const SB_SIZE: usize = 1080;
const SB_MAXSYMLINKLEN: usize = 1320;
const SB_MAGIC: usize = 1372;

/// Deterministic content byte for logical file offset `i`.
fn content_byte(i: usize) -> u8 {
    ((i.wrapping_mul(2654435761)) & 0xFF) as u8
}

/// A crafted UFS2 partition holding one file (inode 4) whose block map exercises
/// direct, single-, double-, and triple-indirect addressing, with a hole and a
/// partial fragment tail. Returns `(partition, superblock, file_size, hole_block)`.
struct Built {
    part: Vec<u8>,
    sb: Superblock,
    file_size: u64,
    /// Logical block index that is a hole (addr 0 => zero-filled).
    hole_block: usize,
}

fn build() -> Built {
    // Choose a file that just reaches the triple-indirect region.
    //   direct:            blocks 0..12
    //   single-indirect:   blocks 12..12+NINDIR                 (di_ib[0])
    //   double-indirect:   blocks 12+NINDIR .. 12+NINDIR+NINDIR*NINDIR (di_ib[1])
    //   triple-indirect:   next region                          (di_ib[2])
    const NDADDR: usize = 12;
    let single_start = NDADDR;
    let double_start = NDADDR + NINDIR;
    let triple_start = NDADDR + NINDIR + NINDIR * NINDIR;
    // Total blocks: go a couple blocks past triple_start so di_ib[2] is used, and
    // make the last block a partial fragment tail.
    let n_full_blocks = triple_start + 1; // fully-populated blocks before tail
    let tail = 123usize; // partial last block
    let file_size = (n_full_blocks * BSIZE + tail) as u64;
    let n_blocks = n_full_blocks + 1;
    // Pick a hole inside the single-indirect region.
    let hole_block = single_start + 3;

    // ── fragment allocator (frag == block here) ──────────────────────────────
    let data_start = 256usize; // first data fragment (well past inode table)
    let mut next = data_start;
    let mut alloc = || {
        let a = next;
        next += 1;
        a as u64
    };

    // Allocate a data-block fragment for every non-hole logical block.
    let mut data_addr = vec![0u64; n_blocks];
    for (b, slot) in data_addr.iter_mut().enumerate() {
        if b == hole_block {
            *slot = 0; // hole
        } else {
            *slot = alloc();
        }
    }

    // ── build the indirect trees ─────────────────────────────────────────────
    // Each indirect block is BSIZE bytes = NINDIR u64 pointers.
    // We collect (fragment_addr, Vec<u64> pointers) to write after allocation.
    let mut ind_blocks: Vec<(u64, Vec<u64>)> = Vec::new();

    // single-indirect (di_ib[0]): points at data blocks [single_start .. double_start)
    let single_ib = alloc();
    {
        let mut ptrs = vec![0u64; NINDIR];
        for k in 0..NINDIR {
            let b = single_start + k;
            if b < n_blocks {
                ptrs[k] = data_addr[b];
            }
        }
        ind_blocks.push((single_ib, ptrs));
    }

    // double-indirect (di_ib[1]): a block of pointers to single-indirect blocks,
    // each covering NINDIR data blocks of [double_start .. triple_start).
    let double_ib = alloc();
    {
        let mut lvl1 = vec![0u64; NINDIR];
        for s in 0..NINDIR {
            let seg_start = double_start + s * NINDIR;
            if seg_start >= n_blocks {
                break;
            }
            let sib = alloc();
            let mut ptrs = vec![0u64; NINDIR];
            for k in 0..NINDIR {
                let b = seg_start + k;
                if b < n_blocks && b < triple_start {
                    ptrs[k] = data_addr[b];
                }
            }
            ind_blocks.push((sib, ptrs));
            lvl1[s] = sib;
        }
        ind_blocks.push((double_ib, lvl1));
    }

    // triple-indirect (di_ib[2]): pointer → double-indirect → single-indirect →
    // data, for blocks [triple_start ..). We only need the first data block or two.
    let triple_ib = alloc();
    {
        let mut lvl1 = vec![0u64; NINDIR]; // pointers to double-indirect blocks
                                           // first double-indirect block under the triple
        let dib = alloc();
        let mut lvl2 = vec![0u64; NINDIR]; // pointers to single-indirect blocks
                                           // first single-indirect block under that double
        let sib = alloc();
        let mut lvl3 = vec![0u64; NINDIR]; // pointers to data blocks
        for k in 0..NINDIR {
            let b = triple_start + k;
            if b < n_blocks {
                lvl3[k] = data_addr[b];
            }
        }
        ind_blocks.push((sib, lvl3));
        lvl2[0] = sib;
        ind_blocks.push((dib, lvl2));
        lvl1[0] = dib;
        ind_blocks.push((triple_ib, lvl1));
    }

    let total_frags = next;

    // ── size + zero the partition ────────────────────────────────────────────
    let part_len = (total_frags + 8) * FSIZE;
    let part_len = part_len.max(SBLOCK_UFS2 + 1376 + 16);
    let mut part = vec![0u8; part_len];

    // ── write file data blocks (deterministic pattern) ───────────────────────
    for (b, &addr) in data_addr.iter().enumerate() {
        if addr == 0 {
            continue; // hole: leave zero
        }
        let logical = b * BSIZE;
        let this_len = if b == n_blocks - 1 { tail } else { BSIZE };
        let off = addr as usize * FSIZE;
        for j in 0..this_len {
            part[off + j] = content_byte(logical + j);
        }
    }

    // ── write indirect blocks (UFS2 8-byte LE pointers) ──────────────────────
    for (addr, ptrs) in &ind_blocks {
        let off = *addr as usize * FSIZE;
        for (i, p) in ptrs.iter().enumerate() {
            part[off + i * 8..off + i * 8 + 8].copy_from_slice(&p.to_le_bytes());
        }
    }

    // ── write the file inode (ino 4) ─────────────────────────────────────────
    let ino_byte = |ino: usize| -> usize {
        let c = ino / IPG as usize;
        let within = ino % IPG as usize;
        (c * FPG as usize + IBLKNO) * FSIZE + within * ISIZE
    };
    {
        let off = ino_byte(4);
        part[off + DI_MODE..off + DI_MODE + 2].copy_from_slice(&0o100644u16.to_le_bytes());
        part[off + DI_NLINK..off + DI_NLINK + 2].copy_from_slice(&1u16.to_le_bytes());
        part[off + DI_SIZE..off + DI_SIZE + 8].copy_from_slice(&file_size.to_le_bytes());
        for i in 0..NDADDR {
            let a = data_addr[i];
            part[off + DI_DB + i * 8..off + DI_DB + i * 8 + 8].copy_from_slice(&a.to_le_bytes());
        }
        for (i, a) in [single_ib, double_ib, triple_ib].into_iter().enumerate() {
            part[off + DI_IB + i * 8..off + DI_IB + i * 8 + 8].copy_from_slice(&a.to_le_bytes());
        }
    }

    // ── write the superblock at SBLOCK_UFS2 ──────────────────────────────────
    let sb_off = SBLOCK_UFS2;
    let put_i32 = |part: &mut [u8], off: usize, v: i32| {
        part[sb_off + off..sb_off + off + 4].copy_from_slice(&v.to_le_bytes());
    };
    let put_i64 = |part: &mut [u8], off: usize, v: i64| {
        part[sb_off + off..sb_off + off + 8].copy_from_slice(&v.to_le_bytes());
    };
    put_i32(&mut part, SB_SBLKNO, 1);
    put_i32(&mut part, SB_CBLKNO, 2);
    put_i32(&mut part, SB_IBLKNO, IBLKNO as i32);
    put_i32(&mut part, SB_DBLKNO, data_start as i32);
    put_i32(&mut part, SB_NCG, NCG as i32);
    put_i32(&mut part, SB_BSIZE, BSIZE as i32);
    put_i32(&mut part, SB_FSIZE, FSIZE as i32);
    put_i32(&mut part, SB_FRAG, FRAG);
    put_i32(&mut part, SB_NINDIR, NINDIR as i32);
    put_i32(&mut part, SB_INOPB, (BSIZE / ISIZE) as i32);
    put_i32(&mut part, SB_IPG, IPG);
    put_i32(&mut part, SB_FPG, FPG);
    put_i64(&mut part, SB_SIZE, (part_len / FSIZE) as i64);
    put_i32(&mut part, SB_MAXSYMLINKLEN, 120);
    part[sb_off + SB_MAGIC..sb_off + SB_MAGIC + 4].copy_from_slice(&UFS2_MAGIC.to_le_bytes());

    let sb = Superblock::parse(&part[SBLOCK_UFS2..]).expect("parse crafted UFS2 superblock");

    Built {
        part,
        sb,
        file_size,
        hole_block,
    }
}

/// A **second, independent** block-map walker. Reassembles the file bytes by
/// re-reading the raw on-disk pointer blocks itself — no shared logic with the
/// reader — so agreement is an independent oracle on the crafted artifact.
///
/// Reads UFS2 8-byte little-endian fragment pointers; `addr == 0` means a hole
/// (zero-fill). Recurses `level` (1=single, 2=double, 3=triple) indirect blocks.
fn independent_walk(part: &[u8], size: u64) -> Vec<u8> {
    let n_blocks = size.div_ceil(BSIZE as u64) as usize;

    // Re-read the file inode 4's di_db / di_ib the same way build() wrote it.
    let ino_byte = |ino: usize| -> usize {
        let c = ino / IPG as usize;
        let within = ino % IPG as usize;
        (c * FPG as usize + IBLKNO) * FSIZE + within * ISIZE
    };
    let ib = ino_byte(4);
    let rd_ptr = |p: &[u8], off: usize| -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&p[off..off + 8]);
        u64::from_le_bytes(b)
    };
    let mut db = [0u64; 12];
    for (i, slot) in db.iter_mut().enumerate() {
        *slot = rd_ptr(part, ib + DI_DB + i * 8);
    }
    let single_ib = rd_ptr(part, ib + DI_IB);
    let double_ib = rd_ptr(part, ib + DI_IB + 8);
    let triple_ib = rd_ptr(part, ib + DI_IB + 16);

    // Resolve the data-fragment address of logical block index `bi`.
    fn ptr_at(part: &[u8], ind_addr: u64, idx: usize) -> u64 {
        if ind_addr == 0 {
            return 0;
        }
        let off = ind_addr as usize * FSIZE + idx * 8;
        let mut b = [0u8; 8];
        b.copy_from_slice(&part[off..off + 8]);
        u64::from_le_bytes(b)
    }
    let resolve = |bi: usize| -> u64 {
        if bi < 12 {
            return db[bi];
        }
        let mut i = bi - 12;
        if i < NINDIR {
            return ptr_at(part, single_ib, i);
        }
        i -= NINDIR;
        if i < NINDIR * NINDIR {
            let sib = ptr_at(part, double_ib, i / NINDIR);
            return ptr_at(part, sib, i % NINDIR);
        }
        i -= NINDIR * NINDIR;
        // triple
        let dib = ptr_at(part, triple_ib, i / (NINDIR * NINDIR));
        let rem = i % (NINDIR * NINDIR);
        let sib = ptr_at(part, dib, rem / NINDIR);
        ptr_at(part, sib, rem % NINDIR)
    };

    let mut out = vec![0u8; size as usize];
    for bi in 0..n_blocks {
        let addr = resolve(bi);
        let logical = bi * BSIZE;
        let this_len = ((size as usize) - logical).min(BSIZE);
        if addr == 0 {
            continue; // hole => already zero
        }
        let src = addr as usize * FSIZE;
        out[logical..logical + this_len].copy_from_slice(&part[src..src + this_len]);
    }
    out
}

#[test]
fn read_file_assembles_indirect_chains_matching_pattern_and_independent_walk() {
    let b = build();
    let got = read_file(&b.part, &b.sb, 4).expect("read crafted file");

    // (1) length == di_size (fragment tail respected).
    assert_eq!(got.len() as u64, b.file_size, "assembled length == di_size");

    // (2) matches the deterministic content pattern, with the hole zero-filled.
    let mut expected = vec![0u8; b.file_size as usize];
    let n_blocks = b.file_size.div_ceil(BSIZE as u64) as usize;
    for bi in 0..n_blocks {
        if bi == b.hole_block {
            continue; // hole: expected stays zero
        }
        let logical = bi * BSIZE;
        let this_len = ((b.file_size as usize) - logical).min(BSIZE);
        for j in 0..this_len {
            expected[logical + j] = content_byte(logical + j);
        }
    }
    assert_eq!(
        got, expected,
        "read_file == known pattern (hole zero-filled)"
    );

    // (3) matches an independent second walker over the same raw partition.
    let indep = independent_walk(&b.part, b.file_size);
    assert_eq!(got, indep, "read_file == independent block-map walk");

    // sanity: the file genuinely reaches the triple-indirect region.
    assert!(
        n_blocks > 12 + NINDIR + NINDIR * NINDIR,
        "test must exercise triple-indirect"
    );
}

#[test]
fn read_file_zero_fills_a_hole() {
    let b = build();
    let got = read_file(&b.part, &b.sb, 4).expect("read crafted file");
    let logical = b.hole_block * BSIZE;
    assert!(
        got[logical..logical + BSIZE].iter().all(|&x| x == 0),
        "hole block must be zero-filled, never read from fragment 0"
    );
}

#[test]
fn read_file_rejects_absurd_di_size_as_allocation_bomb() {
    let mut b = build();
    // Overwrite di_size with u64::MAX; read_file must reject, never allocate.
    let ino_byte = |ino: usize| -> usize {
        let c = ino / IPG as usize;
        let within = ino % IPG as usize;
        (c * FPG as usize + IBLKNO) * FSIZE + within * ISIZE
    };
    let off = ino_byte(4) + DI_SIZE;
    b.part[off..off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    // The parsed inode now carries the absurd size; re-read via read_file.
    let err = read_file(&b.part, &b.sb, 4).unwrap_err();
    assert!(
        matches!(
            err,
            UfsError::ImpossibleGeometry {
                field: "di_size",
                ..
            }
        ),
        "u64::MAX di_size must be rejected as an allocation bomb, got {err:?}"
    );
}

#[test]
fn read_file_truncated_partition_does_not_panic() {
    let mut b = build();
    // Cut the partition mid-file: read_file must not panic; missing tail reads
    // as zero (clamped by read_block), the length still equals di_size.
    b.part.truncate(b.part.len() / 2);
    let got = read_file(&b.part, &b.sb, 4).expect("truncated read is not an error");
    assert_eq!(got.len() as u64, b.file_size, "length still == di_size");
}

#[test]
fn read_file_lying_indirect_pointer_does_not_over_read() {
    let mut b = build();
    // Point di_ib[0] (single-indirect) at a wildly out-of-range fragment; the
    // reader must clamp to empty (zero-filled), never panic or over-read.
    let ino_byte = |ino: usize| -> usize {
        let c = ino / IPG as usize;
        let within = ino % IPG as usize;
        (c * FPG as usize + IBLKNO) * FSIZE + within * ISIZE
    };
    let off = ino_byte(4) + DI_IB;
    b.part[off..off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let got = read_file(&b.part, &b.sb, 4).expect("lying pointer is not a panic");
    assert_eq!(got.len() as u64, b.file_size, "length still == di_size");
}
