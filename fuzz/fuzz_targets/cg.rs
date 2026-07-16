#![no_main]
//! A cylinder-group header is attacker-controlled — `CylinderGroup::parse` (in
//! both byte orders) and its bitmap-offset accessors must never panic. The
//! bitmap offsets (`inosused_off` / `blksfree_off`) come straight from the
//! header and are used to slice into the image, so they are exercised too.
use libfuzzer_sys::fuzz_target;
use ufs::{CylinderGroup, Endian};

fuzz_target!(|data: &[u8]| {
    for endian in [Endian::Little, Endian::Big] {
        if let Ok(cg) = CylinderGroup::parse(data, endian) {
            let _ = cg.inosused_off();
            let _ = cg.blksfree_off();
        }
    }
});
