#![no_main]
//! Directory-block decode over an arbitrary "partition": a hostile `struct
//! direct` stream (lying `d_reclen`, out-of-block `d_namlen`, `d_ino == 0`
//! slack) must never panic the directory walk. The input is treated as a whole
//! partition; if a superblock parses at either primary offset, the root
//! directory is walked (the forensic-relevant `list_dir_all` superset, which
//! also surfaces deleted slots) and a path is resolved.
use libfuzzer_sys::fuzz_target;
use ufs::{list_dir_all, read_by_path, Superblock, SBLOCK_UFS1, SBLOCK_UFS2, UFS_ROOTINO};

fuzz_target!(|data: &[u8]| {
    for base in [SBLOCK_UFS2, SBLOCK_UFS1] {
        if let Some(slice) = data.get(base..) {
            if let Ok(sb) = Superblock::parse(slice) {
                let _ = list_dir_all(data, &sb, UFS_ROOTINO);
                let _ = read_by_path(data, &sb, "a_directory/another_file");
            }
        }
    }
});
