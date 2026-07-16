#![no_main]
//! The superblock block is fully attacker-controlled — `Superblock::parse` must
//! never panic on any byte string, including the endian-disambiguation path
//! (the magic is read in both orders) and the derived geometry accessors it
//! feeds.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sb) = ufs::Superblock::parse(data) {
        // Exercise the geometry accessors the reader derives from the parsed
        // superblock (they must not panic on any parsed-but-hostile geometry).
        let _ = sb.inode_size();
        let _ = sb.primary_offset();
    }
});
