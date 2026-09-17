

#### ufs2_xattr.img.gz — UFS2 with extended attributes

- **Source / Identity:** a self-minted 64 MiB UFS2 filesystem (`newfs -U -L
  UFSXATTR`), created and populated **inside a FreeBSD 15.0-RELEASE arm64 guest**
  running under qemu with HVF acceleration.
- **Why a FreeBSD VM was necessary.** UFS2 extended attributes are a FreeBSD
  feature. Linux mounts UFS read-only and has no extattr support, so neither the
  macOS host, the podman machine VM, nor the remote Linux box can create or read
  one. `setextattr`/`getextattr`/`lsextattr` exist only on FreeBSD.
- **Generator (verbatim)** — run as root in the guest:

  ```sh
  truncate -s 64M ufs.img
  MD=$(mdconfig -a -t vnode -f /root/ufs.img)
  newfs -U -L UFSXATTR /dev/$MD
  mount /dev/$MD /mnt/ufsx
  printf 'hello ufs2 xattrs\n' > /mnt/ufsx/file.txt
  setextattr user   small   'tiny-value'             /mnt/ufsx/file.txt
  setextattr user   comment 'a second attribute'     /mnt/ufsx/file.txt
  setextattr system sattr   'system-namespace-value' /mnt/ufsx/file.txt
  jot -b B -s '' 4000 > /tmp/big
  setextattr user big "$(cat /tmp/big)" /mnt/ufsx/file.txt
  mkdir /mnt/ufsx/adir
  setextattr user ondir 'on-a-directory' /mnt/ufsx/adir
  sync; umount /mnt/ufsx; mdconfig -d -u ${MD#md}
  gzip -9 < ufs.img > ufs2_xattr.img.gz
  ```

- **Contents.** `file.txt` is inode 4; `adir` is inode **6528**, deliberately in
  a different cylinder group, so the tests exercise per-cg inode addressing
  rather than only cg0.

  | inode | attribute | namespace | value bytes |
  |---|---|---|---|
  | 4 | `small` | user (1) | 10 |
  | 4 | `comment` | user (1) | 18 |
  | 4 | `big` | user (1) | 4000 |
  | 4 | `sattr` | **system (2)** | 22 |
  | 6528 | `ondir` | user (1) | 14 |

- **Ground truth:** `lsextattr -q` and `getextattr -q` read every attribute back
  through the FreeBSD kernel while the filesystem was mounted. Geometry
  (`bsize 32768`, `fsize 4096`, `iblkno 40`, `ipg 2176`, `fpg 4104`) came from
  `dumpfs`, which matters: a first attempt read the superblock by hand, got
  `bsize` and `fsize` transposed, and located inode 4 in empty space — which
  presents as "no attributes" rather than as an error.
- **Record layout confirmed on these bytes.** The content offset is
  `(8 + namelen + 7) & !7`, since `sizeof(struct extattr)` is 8 while the name
  starts at offset 7. Every record closes on it: `small` 32 = 16 base + 10 + 6
  pad; `comment` 40 = 16 + 18 + 6; `sattr` 40 = 16 + 22 + 2; `big` 4016 = 16 +
  4000 + 0; `ondir` 32 = 16 + 14 + 2.
- **Redistribution:** none — self-minted from a stock FreeBSD release image.
- **Committed gzipped** (64 MiB → 72 KiB); `flate2` is a dev-dependency.
- **MD5 (gz):** `c674bb2673b03e156983b7f8a5f52ac6`
- **MD5 (raw):** `55ac8c3df18a6c268c05d5e390b62c64`
- **Used by:** `core/tests/xattr.rs`
