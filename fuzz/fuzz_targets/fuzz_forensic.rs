#![no_main]
//! Full inspect/audit + carve pipeline over an arbitrary "image": the auditor
//! (`audit_image` / `audit_findings`) and the deleted-file / deleted-dirent
//! recovery (`recover_deleted`) must never panic on any byte string — this is
//! the end-to-end forensic front door driven by attacker-controlled disk bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Structural anomaly audit (typed anomalies + graded findings).
    let _ = ufs_forensic::audit_image(data);
    let _ = ufs_forensic::audit_findings(data, "fuzz");
    // Deleted-file / deleted-dirent recovery — sweeps freed dinodes and
    // d_ino==0 directory slots.
    let _ = ufs_forensic::recover_deleted(data);
});
