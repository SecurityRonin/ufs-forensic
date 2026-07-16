# ufs-forensic

**A from-scratch UFS/FFS reader and a graded anomaly auditor — walk the superblock, cylinder groups, inodes, directories, and file block-maps of a UFS1 or UFS2 image over any byte source, then turn its residue into evidence: diverged backup superblocks, bad cylinder-group magics, orphaned inodes, and deleted files still carvable from freed-but-intact dinodes.**

UFS is the **Unix File System**, a.k.a. the Berkeley **Fast File System (FFS)** — the native filesystem of FreeBSD, the historic BSDs, and Solaris. This workspace reads both on-disk generations: **UFS1** (128-byte inodes, 32-bit block pointers, superblock at byte 8192, magic `0x00011954`) and **UFS2** (256-byte inodes, 64-bit block pointers, superblock at byte 65536, magic `0x19540119`), in either byte order.

Two crates, one workspace:

- **[`ufs-core`](https://crates.io/crates/ufs-core)** — the reader: superblock + geometry, cylinder-group headers and allocation bitmaps, UFS1/UFS2 dinode decode, `struct direct` directory walking, path resolution, and block-map → file content (12 direct + single/double/triple indirect chains), over any byte slice. No `unsafe`, no C bindings.
- **[`ufs-forensic`](https://crates.io/crates/ufs-forensic)** — the auditor: turns parsed UFS structures into severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s, and recovers deleted files and directory entries, so a UFS volume's anomalies aggregate uniformly with the partition and container layers.

## Audit a UFS image in 30 seconds

```toml
[dependencies]
ufs-forensic = "0.1"   # pulls in ufs-core
```

```rust
use ufs_forensic::audit_findings;

// Feed it the raw filesystem-partition bytes; get back graded findings.
for finding in audit_findings(&partition_bytes, "ufs") {
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(High)] UFS-BACKUP-SUPERBLOCK-DIVERGENCE — cylinder group 2 backup superblock: fs_ipg = 64 differs from the primary 128 …
}
```

`audit_findings` parses the superblock, cylinder groups, and inode/directory tree in place and grades what it finds. A structurally invalid image yields no findings (corruption is surfaced as its own finding, never a panic).

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | What it observes |
|---|---|---|
| `UFS-SUPERBLOCK-MAGIC-INVALID` | High | `fs_magic` matches neither UFS1 nor UFS2 in either byte order — consistent with corruption or an overwritten superblock |
| `UFS-BACKUP-SUPERBLOCK-DIVERGENCE` | High | A per-cylinder-group backup superblock field differs from the primary — consistent with a spliced or edited image |
| `UFS-CG-MAGIC-INVALID` | High | A cylinder-group header's `cg_magic` is not `0x00090255` — consistent with corruption or a tampered allocation map |
| `UFS-IMPOSSIBLE-GEOMETRY` | High | A geometry field beyond what the image can hold — a corruption / allocation-bomb guard |
| `UFS-ORPHANED-INODE` | Medium | An allocated inode reachable by no directory entry from root — an inode unlinked while open, or a corruption lead |

Deleted-item recovery is separate: `recover_deleted(&partition)` sweeps every cylinder group's inode table for inodes that are **free** in the cg bitmap yet still carry an intact `di_mode`/`di_size`/`di_db`, re-assembles their content, and walks the directory tree for `d_ino == 0` slots whose residual `d_name` survives. It returns each carved `RecoveredItem` — a `DeletedFile` (name, inode, size, content, and the content's sha256 recovery gate; conceptually `UFS-DELETED-FILE-CARVED`) or a `DeletedDirent` (residual name + inode; conceptually `UFS-DELETED-DIRENT`).

## The reader: navigate an image

`ufs-core` (imported as `ufs`) reads a UFS1/UFS2 filesystem partition over any byte slice:

```rust
use ufs::{Superblock, read_path_content, list_dir};

let sb = Superblock::parse(&partition[65536..])?;
let entries = list_dir(&partition, &sb, ufs::UFS_ROOTINO)?;
let bytes = read_path_content(&partition, &sb, "etc/passwd")?;
# Ok::<(), ufs::UfsError>(())
```

The bare crate name `ufs` on crates.io is an unrelated, obscure file-embedding utility, so this on-disk reader publishes as `ufs-core` and imports as `ufs`.

## Trust but verify

- **`#![forbid(unsafe_code)]`** in both crates — no `unsafe`, no C bindings.
- **Panic-free** — every integer / length / offset / block-pointer field is read through bounds-checked helpers; a malformed image degrades to an empty / typed result, never a panic.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (superblock, cg, inode, dir, file) plus a `fuzz_forensic` target driving the full `audit_image` / `recover_deleted` pipeline. See [Validation](validation.md).
- **Tier-1 validated** — the UFS2 reader is checked against a real third-party dfvfs image whose ground truth comes from The Sleuth Kit (`fsstat` / `fls` / `istat` / `icat`), a wholly separate implementation, down to per-file `icat | sha256`. The indirect-block chains are validated by an independent block-map walker cross-check; the UFS1 path is spec-derived. See [Validation](validation.md).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd.
