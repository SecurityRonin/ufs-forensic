# Changelog

All notable changes to the `ufs-forensic` workspace are documented here. The
`ufs-core` reader and `ufs-forensic` analyzer are versioned independently.

## ufs-core 0.1.1

- Add forensic-vfs `FileSystem` adapter (`FsKind::UFS`) behind the optional
  `vfs` feature: `UfsFs` mounts a UFS1/UFS2 volume onto the `forensic_vfs`
  navigation contract (`kind`/`root`/`sector_sizes`/`timestamp_zone`,
  `read_dir`/`lookup`/`meta`/`read_at`/`extents`/`read_link`,
  `deleted`/`unallocated`), plus a `ufs_probe` superblock-magic prober
  (UFS2 `0x19540119` @ 66908, UFS1 `0x00011954` @ 9564, either byte order).
  Named streams and foreign `FileId`s are refused loud; the whole surface is
  covered by a self-describing in-memory UFS2 image test.
