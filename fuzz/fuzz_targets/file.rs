#![no_main]
//! File block-map / indirect-chain assembly over an arbitrary "partition": the
//! block-map walk (12 direct + single/double/triple indirect) driven by a
//! hostile `di_size` and hostile block pointers must never panic, over-read, or
//! allocate unbounded. The input is treated as a whole partition; if a
//! superblock parses at either primary offset, every inode in the first
//! cylinder group is read as a file, and the sweep resolves a path to content
//! (exercising `read_by_path` + `read_inode_file` + `read_symlink_target`).
use libfuzzer_sys::fuzz_target;
use ufs::{
    read_file, read_inode, read_path_content, read_symlink_target, Superblock, SBLOCK_UFS1,
    SBLOCK_UFS2,
};

fuzz_target!(|data: &[u8]| {
    for base in [SBLOCK_UFS2, SBLOCK_UFS1] {
        if let Some(slice) = data.get(base..) {
            if let Ok(sb) = Superblock::parse(slice) {
                // Cap the inode sweep so a hostile fs_ipg cannot make the fuzzer
                // spin; the point is the block-map walk, not exhaustive coverage.
                let ipg = sb.ipg.clamp(0, 256) as u64;
                for ino in 2..2 + ipg {
                    let _ = read_file(data, &sb, ino);
                    if let Ok(inode) = read_inode(data, &sb, ino) {
                        let _ = read_symlink_target(data, &sb, &inode);
                    }
                }
                let _ = read_path_content(data, &sb, "passwords.txt");
            }
        }
    }
});
