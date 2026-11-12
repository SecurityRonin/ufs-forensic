# Changelog

All notable changes to `ufs-core` (the reader) are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/SecurityRonin/ufs-forensic/compare/ufs-core-v0.1.5...ufs-core-v0.2.0) - 2026-11-12

### Added

- *(xattr)* GREEN - decode the UFS2 extattr area

### Fixed

- *(xattr)* report an attribute area the inode cannot deliver, not "no attributes"
- *(vfs)* [**breaking**] implement forensic-vfs 0.10, the trait the engine links against
- *(test)* make the Tier-1 skip actually visible, not just written

### Other

- *(test-data)* keep the FreeBSD 15.0 corpus in tests/data, gitignored

## [0.1.5](https://github.com/SecurityRonin/ufs-forensic/compare/ufs-core-v0.1.4...ufs-core-v0.1.5) - 2026-07-24

### Documentation

- reverse-write PRD + ADRs; mkdocs excludes governance docs (fleet standard)

## [0.1.3]

### Fixed

- bump forensic-vfs to 0.5
