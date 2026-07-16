//! `ufs-core` — a pure-Rust, from-scratch UFS/FFS filesystem reader.
//!
//! UFS = the Unix File System, a.k.a. the Berkeley Fast File System (FFS).
//! Parses the on-disk UFS structures a forensic tool needs — superblock and
//! geometry, cylinder-group headers and allocation bitmaps, inodes,
//! directories, and file content — over any byte source. The reader targets
//! both **UFS1** (4.4BSD/FreeBSD legacy, 128-byte inodes, 32-bit block pointers,
//! superblock at byte 8192, magic `0x00011954`) and **UFS2** (FreeBSD 5+,
//! 256-byte inodes, 64-bit block pointers, superblock at byte 65536, magic
//! `0x19540119`).
//!
//! Import path is `ufs` (see `[lib] name`): `use ufs::Superblock;`.
//!
//! UFS is endianness-agnostic on disk — the byte order is that of the host that
//! created the filesystem, and the superblock magic disambiguates it. The
//! reader supports both little- and big-endian images, selecting the order by
//! which interpretation makes the magic match (see [`Endian`]).
//!
//! # Safety and robustness
//!
//! This crate parses untrusted, attacker-controllable disk images. It is
//! `#![forbid(unsafe_code)]` and every integer is read through bounds-checked
//! readers that yield `0`/`None` out of range rather than panic (the Paranoid
//! Gatekeeper standard).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod bytes;
mod cg;
mod error;
mod superblock;

pub use bytes::Endian;
pub use cg::{CylinderGroup, CG_MAGIC};
pub use error::UfsError;
pub use superblock::{
    Superblock, UfsVersion, FS_UFS1_MAGIC, FS_UFS2_MAGIC, SBLOCK_UFS1, SBLOCK_UFS2, UFS_ROOTINO,
};
