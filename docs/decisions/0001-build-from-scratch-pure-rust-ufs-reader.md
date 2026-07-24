# 1. Build a from-scratch, pure-Rust UFS/FFS reader

Date: 2026-07-24
Status: Accepted

## Context

UFS — the Unix File System, a.k.a. the Berkeley Fast File System (FFS) — is the
native on-disk format of FreeBSD, the historic BSDs, and Solaris, in two
generations (UFS1 and UFS2). A forensic fleet that reads NTFS, ext4, APFS, and
XFS images needs a UFS reader to cover BSD/Solaris evidence.

The Research-First survey (`docs/RESEARCH.md` §2) established the build-vs-reuse
picture on the real host:

- The bare `ufs` crate on crates.io is *"ufs embed files and read from disk"*
  (v0.1.2, 53 downloads) — an unrelated file-embedding utility, **not** a
  filesystem reader. No forensic-grade, or even read-oriented, UFS/FFS
  filesystem crate exists in the Rust ecosystem.
- The Sleuth Kit's `tsk/fs/ffs.c` is a mature C reader, but it is C (in-kernel
  drivers are GPL/BSD C), and the fleet policy is a pure-Rust, `forbid(unsafe)`,
  single-static-binary posture with no C bindings.

The fleet constitution (`ronin-issen/CLAUDE.md`, "Dependency Preference — prefer
our own crates") makes building a first-party crate the default when no suitable
equivalent exists.

## Decision

Build two first-party pure-Rust crates from the FreeBSD kernel on-disk headers
(`sys/ufs/ffs/fs.h`, `sys/ufs/ufs/dinode.h`, `sys/ufs/ufs/dir.h`; cited in
`docs/RESEARCH.md` §1): `ufs-core` (the reader) and `ufs-forensic` (the auditor).
No C bindings, no `libtsk` linkage.

The Sleuth Kit is used **as an independent oracle, never as a dependency** — its
`fsstat`/`fls`/`istat`/`icat` output is the answer key that validates our reader
(see ADR 0007), keeping the two implementations wholly separate.

## Consequences

- The fleet owns the full UFS decode path and can extend it toward the forensic
  residue (deleted-inode carving, backup-superblock divergence) that a
  general-purpose reader does not expose (ADR 0008).
- No `unsafe`, no C toolchain, no FFI surface — the crate ships as a pure-Rust
  static library (ADR 0005).
- The cost of building from scratch is borne by validation: correctness must be
  proven against the TSK oracle on a real image rather than inherited from a
  battle-tested C library (ADR 0007).
- The bare `ufs` name being taken forced a publish-name workaround (ADR 0003).
