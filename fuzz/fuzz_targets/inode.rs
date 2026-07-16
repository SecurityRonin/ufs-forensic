#![no_main]
//! A dinode is attacker-controlled — `Inode::parse` must never panic across
//! both on-disk layouts (UFS1 128-byte / UFS2 256-byte) and both byte orders,
//! and neither must the type/mode helpers driven from the parsed dinode.
use libfuzzer_sys::fuzz_target;
use ufs::{Endian, Inode, UfsVersion};

fuzz_target!(|data: &[u8]| {
    for version in [UfsVersion::Ufs1, UfsVersion::Ufs2] {
        for endian in [Endian::Little, Endian::Big] {
            if let Ok(inode) = Inode::parse(data, version, endian) {
                let _ = inode.is_dir();
                let _ = inode.is_regular();
                let _ = inode.is_symlink();
                let _ = inode.symlink_target();
            }
        }
    }
});
