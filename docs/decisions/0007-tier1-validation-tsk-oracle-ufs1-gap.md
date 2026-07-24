# 7. Tier-1 validation against TSK + a real dfvfs image; UFS1 labelled untested

Date: 2026-07-24
Status: Accepted

## Context

The fleet Evidence-Based Rigor discipline tiers every correctness claim by *who
authored the artifact and its answer key*, not by whether data is "synthetic":
Tier-1 = an independent third party authored both the artifact and the key (or it
is real-world data); Tier-3 = we authored both the fixture and the expected
answer. A value-producing, oracle-feasible path (a filesystem reader that emits
file bytes) must not rest on Tier-3 alone (the "LZNT1 trap"). The Doer-Checker
and Test-Data Provenance standards require validating against a real artifact +
an independent oracle before declaring correctness.

## Decision

Validate the reader at the highest tier the available data allows, and label the
gaps honestly (`docs/validation.md`, README "Trust but verify"):

- **Tier-1 (UFS2).** Validate against `tests/data/ufs2.raw` — a genuine
  third-party UFS2 image from log2timeline/dfvfs (Apache-2.0, committed, md5
  `19216a75a7933dfdac9ded5ff591fe82`) — with **The Sleuth Kit** as the
  independent oracle: `fsstat`/`fls`/`istat`/`icat` on the real bytes, down to
  per-file `icat | sha256` content hashes the reader must reproduce (e.g. inode
  4 `/passwords.txt`). Env-gated oracle tests (`UFS2_DFVFS_ORACLE`) plus
  always-on committed-slice fixtures (`core/tests/fixture.rs`) so a bare `cargo
  test` still exercises P0–P2. `forensic/tests/integrity.rs` asserts the clean
  image raises **no** false anomalies.
- **Tier-2 (indirect chains).** No public real UFS image exercises the single/
  double/triple indirect block chains, and Linux `mkfs` cannot write UFS on the
  build host. So `core/tests/file_indirect.rs` crafts an image whose block map
  spans all three indirect levels and validates it with **two independent
  decoders agreeing** — the known content pattern and a separately-written
  block-map walker — not a self-encoded round-trip.
- **Tier-3 (detection rules + carve).** The `ufs-forensic` anomaly detectors use
  crafted single-corruption fixtures where correctness is defined by spec + rule.
  The F-CARVE deletion test records a pre-delete SHA-256 as a
  construction-derived answer key **independent of the reader**, so a wrong carve
  cannot pass by matching a fixture encoded to the bug.
- **UFS1 — spec-derived, not yet Tier-1.** The dfvfs corpus ships no UFS1 image
  and the host cannot mint one, so the UFS1 code path (offsets from FreeBSD
  `sys/ufs/ffs/fs.h`) is driven only by unit tests and is **explicitly labelled
  untested / not Tier-1** until a real FreeBSD UFS1 image lands, with TSK
  `-f ufs1` as the future oracle. Documented, never silently skipped.

## Consequences

- The UFS2 read path — including per-file content — is proven against an artifact
  and answer key neither of which we authored, the strongest tier.
- The highest-risk indirect-block walk is covered without a real large-file image
  by an independent-walker cross-check, avoiding the LZNT1 trap.
- The UFS1 tier gap is surfaced in the README, `docs/RESEARCH.md`, and
  `docs/validation.md`, so no reader mistakes spec-derived UFS1 support for
  Tier-1-validated support.
