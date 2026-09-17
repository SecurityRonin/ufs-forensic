//! Tier-1 validation against a vendor-authored `FreeBSD` 15.0 root filesystem.
//!
//! Every other UFS fixture in this repo is **self-minted**: real UFS2 bytes, but
//! written by a `newfs` command in this project and checked against ground truth
//! this project recorded. That is Tier-2 — it cannot catch a misunderstanding of
//! the format that the minting command and the reader happen to share.
//!
//! This one is Tier-1 on both axes:
//!
//! - **The artifact is third-party.** The `freebsd-ufs` partition of
//!   `FreeBSD-15.0-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz`, built by
//!   `FreeBSD` release engineering on 2025-11-28 and published with a SHA256 that
//!   was verified before extraction. Nothing in this project authored a byte of it.
//! - **The oracle is an independent implementation.** Ground truth below was read
//!   back through the `FreeBSD` kernel's own UFS driver from a read-only mount,
//!   with `dumpfs` for geometry and `sha256`/`stat` for contents and metadata.
//!
//! ## Why a real root filesystem is worth more than a bigger synthetic one
//!
//! 38,977 files, 2,331 directories and 1,361 symlinks laid out by a real
//! installer — not by a loop that writes what the test is about to assert. It
//! exercises paths a minted fixture never produces by accident:
//!
//! | property | where |
//! |---|---|
//! | indirect block traversal | `/boot/kernel/kernel`, 18,838,832 B (48× the 393,216 B direct-block limit) |
//! | a second large file | `/lib/libcrypto.so.35`, 5,070,200 B |
//! | direct blocks only | `/etc/fstab` 215 B, `/etc/rc.conf` 247 B |
//! | fragment-tail handling | `/COPYRIGHT` 6,070 B — not a block multiple |
//! | hard links | inode 1668 has **`nlink` = 146** (`/rescue/*`) |
//! | inline symlinks | `/etc/aliases` → `mail/aliases` (12 B, ≤ 120 so in-inode) |
//!
//! ## Env-gated
//!
//! The partition is 5 `GiB`, so it is not committed. Set `UFS2_FREEBSD15_ORACLE`
//! to the extracted `freebsd-ufs.part`; the tests skip loudly when it is absent.
//! `tests/data/README.md` records the download URL, the vendor checksum, the
//! exact extraction offsets and the md5 of the result.
//!
//! ## Evidence label
//!
//! These tests were written **after** the reader, against an artifact the reader
//! had never seen. They are `Tier-1 validation`, not `TDD-compliant`: no RED was
//! staged or fabricated, because no behaviour was being added. A failure here
//! would be a genuine defect in the reader, not a missing feature.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use ufs::{list_dir, read_file, read_inode, Superblock, SBLOCK_UFS2};

/// The extracted `freebsd-ufs` partition, or `None` to skip.
fn partition() -> Option<Vec<u8>> {
    let p = PathBuf::from(std::env::var("UFS2_FREEBSD15_ORACLE").ok()?);
    if !p.exists() {
        return None;
    }
    std::fs::read(&p).ok()
}

/// Skip loudly: a silent skip is indistinguishable from a pass, and that is how
/// an oracle-gated test quietly stops running for a year.
macro_rules! oracle {
    () => {
        match partition() {
            Some(p) => p,
            None => {
                eprintln!(
                    "SKIPPED: set UFS2_FREEBSD15_ORACLE to the extracted freebsd-ufs.part \
                     (see tests/data/README.md for the download URL, vendor SHA256 and \
                     extraction offsets)"
                );
                return;
            }
        }
    };
}

fn sb_of(part: &[u8]) -> Superblock {
    Superblock::parse(&part[SBLOCK_UFS2..]).expect("vendor partition must parse as UFS2")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    use std::fmt::Write as _;
    h.finalize().iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Geometry must match `dumpfs`, field for field.
///
/// This is the assertion that would have caught my own hand-decode of the
/// superblock, which read `bsize = 9` off this very partition before `dumpfs`
/// was consulted.
#[test]
fn geometry_matches_dumpfs() {
    let part = oracle!();
    let sb = sb_of(&part);

    // dumpfs /dev/vtbd1:
    //   magic 19540119 (UFS2)   ncg 9   size 1310720   blocks 1265407
    //   bsize 32768   fsize 4096   frag 8
    //   bpg 20042   fpg 160336   ipg 80256
    assert_eq!(sb.bsize, 32_768, "fs_bsize");
    assert_eq!(sb.fsize, 4_096, "fs_fsize");
    assert_eq!(sb.ipg, 80_256, "fs_ipg");
    assert_eq!(sb.fpg, 160_336, "fs_fpg");
    assert_eq!(sb.iblkno, 40, "fs_iblkno");
}

/// File contents must be byte-identical to what the `FreeBSD` kernel returns.
///
/// Sizes are chosen to walk the block-layout cases rather than to be convenient:
/// a sub-block file, a non-block-multiple file, and two files far past the
/// 393,216-byte direct-block limit that can only be read through indirect blocks.
#[test]
fn file_contents_match_the_freebsd_kernel() {
    let part = oracle!();
    let sb = sb_of(&part);

    // (inode, size, sha256) — `stat -f %i/%z` and `sha256 -q` on a read-only
    // mount of this partition.
    let cases: &[(u64, usize, &str)] = &[
        // /etc/fstab — 215 B, one fragment.
        (
            962,
            215,
            "141ada2bdfef989f148aec93ae1b35a35d5620e175c4554a166d59c4a0c61d27",
        ),
        // /etc/rc.conf — 247 B.
        (
            1013,
            247,
            "353956ef18b1ba5a220bda9158c11d277584fe5c31d5cf8eddaf77b3fd801aca",
        ),
        // /etc/motd.template — 849 B.
        (
            983,
            849,
            "6c11d29869d8698306ce69a22f4507b32b4a1124f003e7bdbbd1d45189aee490",
        ),
        // /COPYRIGHT — 6,070 B, deliberately not a block multiple.
        (
            3,
            6_070,
            "4bb0fdcd07d8a7774ba71faecf86d7db64d7a8574ee395f51a86d629c39f77cc",
        ),
        // /lib/libcrypto.so.35 — 5,070,200 B, needs indirect blocks.
        (
            1586,
            5_070_200,
            "34b7711e151ad01289693bfb952312927ef5ea542579550befb78078e58b35cf",
        ),
        // /boot/kernel/kernel — 18,838,832 B, 48x the direct-block limit.
        (
            562,
            18_838_832,
            "3a94f6521563ec70936c10dcb48d4fe890382111b38c949ac05b5462e1443a7b",
        ),
    ];

    for &(ino, size, sha) in cases {
        let inode =
            read_inode(&part, &sb, ino).unwrap_or_else(|e| panic!("inode {ino} must parse: {e:?}"));
        assert_eq!(inode.size as usize, size, "inode {ino} di_size");

        let data =
            read_file(&part, &sb, ino).unwrap_or_else(|e| panic!("inode {ino} must read: {e:?}"));
        assert_eq!(data.len(), size, "inode {ino} reconstructed length");
        // Hash rather than length: a wrong indirect-block walk yields the right
        // LENGTH with the wrong bytes, which a size check cannot see.
        assert_eq!(sha256_hex(&data), sha, "inode {ino} content sha256");
    }
}

/// The root directory must list what the kernel lists.
#[test]
fn root_directory_matches_the_kernel_listing() {
    let part = oracle!();
    let sb = sb_of(&part);

    let entries = list_dir(&part, &sb, 2).expect("root directory (inode 2) must list");
    let mut names: Vec<String> = entries
        .iter()
        .map(|e| String::from_utf8_lossy(&e.name).into_owned())
        .filter(|n| n != "." && n != "..")
        .collect();
    names.sort();

    // `ls -1 /mnt/t` on the read-only mount.
    let expected = [
        "COPYRIGHT",
        "bin",
        "boot",
        "dev",
        "etc",
        "firstboot",
        "lib",
        "libexec",
        "media",
        "mnt",
        "net",
        "proc",
        "rescue",
        "root",
        "sbin",
        "tmp",
        "usr",
        "var",
    ];
    assert_eq!(
        names, expected,
        "root listing must match the kernel's, exactly and in full"
    );
}

/// A directory with many entries must enumerate completely.
///
/// `/etc` holds 103 entries, enough to span more than one directory block at a
/// 32 `KiB` block size — a truncated walk shows up here and not in a small
/// fixture's root.
#[test]
fn a_large_directory_enumerates_completely() {
    let part = oracle!();
    let sb = sb_of(&part);

    let root = list_dir(&part, &sb, 2).expect("root");
    let etc = root
        .iter()
        .find(|e| e.name == b"etc")
        .expect("/etc must exist");
    let entries = list_dir(&part, &sb, etc.ino).expect("/etc must list");
    let n = entries
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .count();
    assert_eq!(n, 103, "`ls -1 /mnt/t/etc | wc -l` reported 103");
}

/// Hard links: 146 names share inode 1668, and the inode says so.
///
/// A reader that conflated the name layer with the metadata layer would report
/// `nlink` as 1 here. No self-minted fixture in this repo produces a link count
/// remotely like this.
#[test]
fn hard_link_count_is_preserved() {
    let part = oracle!();
    let sb = sb_of(&part);

    let inode = read_inode(&part, &sb, 1668).expect("inode 1668 must parse");
    assert_eq!(
        inode.nlink, 146,
        "`stat -f %l /mnt/t/rescue/[` reported 146 links to inode 1668"
    );
}

/// Inline symlink targets must match `readlink`.
#[test]
fn inline_symlink_targets_match_readlink() {
    let part = oracle!();
    let sb = sb_of(&part);

    // `readlink` on the mount; all are <= 120 bytes, so UFS2 stores the target
    // inside the inode rather than in a data block.
    for (ino, target) in [
        (940u64, "mail/aliases"),
        (997, "../var/run/os-release"),
        (1024, "../usr/sbin/rmt"),
    ] {
        let inode = read_inode(&part, &sb, ino).expect("symlink inode must parse");
        let got = inode
            .symlink_target()
            .unwrap_or_else(|| panic!("inode {ino} must expose an inline target"));
        assert_eq!(
            String::from_utf8_lossy(got),
            target,
            "inode {ino} symlink target"
        );
    }
}
