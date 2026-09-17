//! UFS2 extended attributes — the inode's extattr area.
//!
//! `di_extsize` and `di_extb[2]` are the UFS2 inode fields that point at a
//! file's extended attributes. This crate parsed neither, so every UFS2 image
//! presented files with no extended attributes.
//!
//! ## The oracle is FreeBSD itself
//!
//! UFS2 extattrs are a FreeBSD feature. Linux mounts UFS read-only and has no
//! extattr support at all, so there is no way to write or verify these from
//! Linux — this fixture was minted inside a FreeBSD 15.0 VM, where the kernel
//! wrote every attribute and `lsextattr`/`getextattr` read them all back:
//!
//! ```text
//! -- user namespace on file.txt: small  comment  big
//! -- system namespace on file.txt: sattr
//! -- user on adir: ondir
//! ```
//!
//! ## The record layout, taken from these bytes
//!
//! ```text
//! 20 00 00 00 | 01 | 06 | 05 | 73 6d 61 6c 6c | 00 00 00 00 | 74 69 6e 79 2d 76 61 6c 75 65 | 00 x6
//! ea_length=32 | ns | padlen | namelen |  "small"   | align pad  |      "tiny-value"        | content pad
//! ```
//!
//! - `ea_length` (LE u32) is the whole record including both paddings.
//! - `ea_namespace` is **1 = user, 2 = system** — observed directly, since the
//!   fixture carries one of each.
//! - the content starts at `(8 + namelen + 7) & !7`, NOT at `7 + namelen`
//!   rounded up. `struct extattr` is 8 bytes because its trailing `ea_name[1]`
//!   pads the struct out, so the name begins at offset 7 while the base length
//!   counts from 8. The two formulas agree for every name length in this
//!   fixture and diverge at `namelen = 9`, which is exactly the kind of
//!   coincidence that ships a decoder that works only on its own sample.
//! - content length is `ea_length - base - ea_contentpadlen`.
//!
//! Every record in the fixture closes on that arithmetic:
//!
//! | name | `ea_length` | `namelen` | base | padlen | content |
//! |---|---|---|---|---|---|
//! | `small` | 32 | 5 | 16 | 6 | 10 |
//! | `comment` | 40 | 7 | 16 | 6 | 18 |
//! | `sattr` | 40 | 5 | 16 | 2 | 22 |
//! | `big` | 4016 | 3 | 16 | 0 | 4000 |
//! | `ondir` | 32 | 5 | 16 | 2 | 14 |

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read;

use ufs::{list_xattrs, Superblock, UfsNamespace};

/// Inode numbers from `stat -f %i` in the minting VM.
const FILE_INO: u64 = 4;
const DIR_INO: u64 = 6528;

fn image() -> Vec<u8> {
    let gz = include_bytes!("../../tests/data/ufs2_xattr.img.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .expect("fixture must decompress");
    out
}

fn attrs(img: &[u8], ino: u64) -> Vec<(UfsNamespace, String, usize)> {
    let sb = Superblock::parse(img).expect("fixture must parse as UFS2");
    list_xattrs(img, &sb, ino)
        .expect("listing must not error")
        .into_iter()
        .map(|x| (x.namespace, x.name.clone(), x.value.len()))
        .collect()
}

/// Every attribute FreeBSD wrote must be listed, in the right namespace.
#[test]
fn every_attribute_is_listed_with_its_namespace() {
    let img = image();
    let a = attrs(&img, FILE_INO);

    // Non-zero baseline before any per-name lookup.
    assert_eq!(
        a.len(),
        4,
        "lsextattr showed 3 user + 1 system attribute on file.txt: {a:?}"
    );

    let find = |n: &str| -> (UfsNamespace, usize) {
        a.iter()
            .find(|(_, name, _)| name == n)
            .map_or_else(|| panic!("missing {n}; got {a:?}"), |(ns, _, l)| (*ns, *l))
    };
    assert_eq!(find("small"), (UfsNamespace::User, 10));
    assert_eq!(find("comment"), (UfsNamespace::User, 18));
    assert_eq!(find("big"), (UfsNamespace::User, 4000));
    // UFS2 has exactly two namespaces and the fixture carries one of each, so a
    // decoder that ignored ea_namespace would report this as a user attribute.
    assert_eq!(find("sattr"), (UfsNamespace::System, 22));
}

/// Values must come back byte-exact.
#[test]
fn values_are_byte_exact() {
    let img = image();
    let sb = Superblock::parse(&img).unwrap();
    let list = list_xattrs(&img, &sb, FILE_INO).unwrap();
    let get = |n: &str| -> Vec<u8> {
        list.iter()
            .find(|x| x.name == n)
            .unwrap_or_else(|| panic!("no attribute {n}"))
            .value
            .clone()
    };

    assert_eq!(get("small"), b"tiny-value");
    assert_eq!(get("comment"), b"a second attribute");
    assert_eq!(get("sattr"), b"system-namespace-value");
    // All 4000: the content offset is a computed alignment, so an error there
    // yields the right LENGTH starting at the wrong byte.
    assert_eq!(get("big"), vec![b'B'; 4000]);
}

/// Directories carry attributes, and they live in a different cylinder group.
#[test]
fn directories_carry_attributes() {
    let img = image();
    let a = attrs(&img, DIR_INO);
    assert_eq!(a.len(), 1, "adir carries one attribute: {a:?}");
    assert_eq!(a[0].1, "ondir");
    assert_eq!(a[0].0, UfsNamespace::User);

    let sb = Superblock::parse(&img).unwrap();
    let list = list_xattrs(&img, &sb, DIR_INO).unwrap();
    assert_eq!(list[0].value, b"on-a-directory");
}

/// An inode with no extattr area lists nothing, and that is not an error.
#[test]
fn an_inode_without_an_extattr_area_lists_nothing() {
    let img = image();
    let sb = Superblock::parse(&img).unwrap();
    // The root directory was given no attributes.
    assert!(
        list_xattrs(&img, &sb, 2).expect("no extattr area is not an error").is_empty(),
        "the root directory has di_extsize == 0"
    );
}
