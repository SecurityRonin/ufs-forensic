# ufs-forensic

[![ufs-core](https://img.shields.io/crates/v/ufs-core.svg?label=ufs-core)](https://crates.io/crates/ufs-core)
[![ufs-forensic](https://img.shields.io/crates/v/ufs-forensic.svg?label=ufs-forensic)](https://crates.io/crates/ufs-forensic)
[![Docs.rs](https://img.shields.io/docsrs/ufs-forensic?label=docs.rs)](https://docs.rs/ufs-forensic)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/ufs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ufs-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lines-brightgreen.svg)](https://securityronin.github.io/ufs-forensic/validation/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Security audit](https://img.shields.io/badge/security-cargo--deny-brightgreen.svg)](deny.toml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://securityronin.github.io/ufs-forensic/)

**A from-scratch UFS/FFS reader and a graded anomaly auditor — walk the superblock, cylinder groups, inodes, directories, and file block-maps of a UFS1 or UFS2 image over any byte source, then turn its residue into evidence: diverged backup superblocks, bad cylinder-group magics, orphaned inodes, and deleted files still carvable from freed-but-intact dinodes.**

UFS is the **Unix File System**, a.k.a. the Berkeley **Fast File System (FFS)** — the native filesystem of FreeBSD, the historic BSDs, and Solaris. This workspace reads both on-disk generations: **UFS1** (128-byte inodes, 32-bit block pointers, superblock at byte 8192, magic `0x00011954`) and **UFS2** (256-byte inodes, 64-bit block pointers, superblock at byte 65536, magic `0x19540119`), in either byte order (the on-disk order is the creating host's; the magic disambiguates it).

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

`audit_findings` parses the superblock, cylinder groups, and inode/directory tree in place and grades what it finds. A structurally invalid image yields no findings (corruption is surfaced as its own finding, never a panic). For the typed form, `audit_image(&partition)` returns `Vec<Anomaly>` — each `anomaly.to_finding(source)` converts to a `report::Finding`.

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | What it observes |
|---|---|---|
| `UFS-SUPERBLOCK-MAGIC-INVALID` | High | `fs_magic` matches neither UFS1 nor UFS2 in either byte order — consistent with corruption or an overwritten superblock |
| `UFS-BACKUP-SUPERBLOCK-DIVERGENCE` | High | A per-cylinder-group backup superblock field differs from the primary — consistent with a spliced or edited image |
| `UFS-CG-MAGIC-INVALID` | High | A cylinder-group header's `cg_magic` is not `0x00090255` — consistent with corruption or a tampered allocation map |
| `UFS-IMPOSSIBLE-GEOMETRY` | High | A geometry field beyond what the image can hold — a corruption / allocation-bomb guard |
| `UFS-ORPHANED-INODE` | Medium | An allocated inode (`di_nlink > 0`) reachable by no directory entry from root — an inode unlinked while open, or a corruption lead |

Deleted-item recovery is separate: `recover_deleted(&partition)` sweeps every cylinder group's inode table for inodes that are **free** in the cg bitmap yet still carry an intact `di_mode`/`di_size`/`di_db`, re-assembles their content, and walks the directory tree for `d_ino == 0` slots whose residual `d_name` survives. It returns each carved `RecoveredItem` — a `DeletedFile` (name, inode, size, content, and the content's sha256 recovery gate; conceptually `UFS-DELETED-FILE-CARVED`) or a `DeletedDirent` (residual name + inode; conceptually `UFS-DELETED-DIRENT`). Recovery is state-dependent — it succeeds only while the freed dinode and data blocks are un-reallocated, and returns nothing rather than fabricate once the residue is gone.

## The reader: navigate an image

`ufs-core` (imported as `ufs`) reads a UFS1/UFS2 filesystem partition over any byte slice:

```rust
use ufs::{Superblock, read_path_content, list_dir};

// The primary superblock lives at byte 65536 on UFS2 (8192 on UFS1); parse it,
// then resolve a slash-separated path from the root inode to its file bytes,
// walking the block map (direct + indirect chains) transparently.
let sb = Superblock::parse(&partition[65536..])?;
let entries = list_dir(&partition, &sb, ufs::UFS_ROOTINO)?;      // root directory
let bytes = read_path_content(&partition, &sb, "etc/passwd")?;   // file content
# Ok::<(), ufs::UfsError>(())
```

The bare crate name `ufs` on crates.io is an unrelated, obscure file-embedding utility, so this on-disk reader publishes as `ufs-core` and **imports as `ufs`** (via `[lib] name = "ufs"`) — consumers write `use ufs::…`.

## What makes this different from a general-purpose UFS reader

Most UFS readers answer one question: "what files are on this volume?" This workspace answers the questions a digital forensics examiner actually needs:

| Capability | General-purpose UFS reader | this workspace |
|---|---|---|
| UFS1 + UFS2 superblock / geometry | ✅ | ✅ |
| Endianness auto-detect (LE + BE images) | partial | ✅ |
| Cylinder-group headers + allocation bitmaps | ✅ | ✅ |
| UFS1 (128-byte) + UFS2 (256-byte) dinode decode | ✅ | ✅ |
| Directory walking + path resolution | ✅ | ✅ |
| Block-map → file content (direct + single/double/triple indirect) | ✅ | ✅ |
| Fast (inline) + slow symlink targets | ✅ | ✅ |
| Backup-superblock divergence detection (splice tell) | — | ✅ |
| Cylinder-group magic verification | — | ✅ |
| Orphaned-inode enumeration | — | ✅ |
| Deleted-file recovery from freed-but-intact dinodes | — | ✅ |
| Deleted-dirent (`d_ino == 0` slack) recovery | — | ✅ |
| Impossible-geometry / allocation-bomb guards | — | ✅ |
| Severity-graded `report::Finding` output | — | ✅ |
| `#![forbid(unsafe_code)]` | — | ✅ |

## Trust but verify

- **`#![forbid(unsafe_code)]`** in both crates — no `unsafe`, no C bindings.
- **Panic-free** — every integer / length / offset / block-pointer field is read through bounds-checked helpers; a malformed image degrades to an empty or typed result, never a panic.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (`superblock`, `cg`, `inode`, `dir`, `file`) plus a `fuzz_forensic` target driving the full `audit_image` / `recover_deleted` pipeline. `fuzz.yml` builds every target on each push and deep-fuzzes each for 10 minutes weekly.
- **Tier-1 validated** — the UFS2 reader is checked against a real third-party image, `test_data/ufs2.raw` from [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) (Apache-2.0), whose ground truth comes from **The Sleuth Kit** (`fsstat` / `fls` / `istat` / `icat`), a wholly separate implementation, down to per-file `icat | sha256` content. The single / double / triple **indirect** block chains — which no publicly available real UFS image exercises — are validated by an **independent block-map walker** cross-check over a crafted image (two decoders agreeing on the artifact), and the UFS1 path is spec-derived (FreeBSD `sys/ufs/ffs/fs.h`), lifted to Tier-1 in a follow-on against a real FreeBSD image. See [`docs/validation.md`](https://securityronin.github.io/ufs-forensic/validation/).

## Reader API (`ufs-core`)

| Item | Purpose |
|---|---|
| `Superblock::parse` | UFS1/UFS2 superblock geometry + addressing, with endian auto-detect from the magic |
| `CylinderGroup::parse` | Cylinder-group header + inode/block allocation-bitmap offsets |
| `read_inode` / `Inode::parse` | Locate + decode a UFS1 (128-byte) or UFS2 (256-byte) dinode |
| `list_dir` / `list_dir_all` / `read_by_path` | `struct direct` entries (live, or the deleted-slot superset), path resolution |
| `read_file` / `read_path_content` | Block-map → file bytes (12 direct + single/double/triple indirect), truncated to `di_size` |
| `read_symlink_target` | Fast (inline) or slow (data-block) symlink target |

---

[Privacy Policy](https://securityronin.github.io/ufs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ufs-forensic/terms/) · © 2026 Security Ronin Ltd
