//! UFS2 extended attributes — the inode's extattr area.
//!
//! A UFS2 inode carries `di_extsize` (the byte length of its extended-attribute
//! area) and `di_extb[2]` (the fragment addresses holding it). The area is a
//! packed run of records with no terminator; the walk is bounded by
//! `di_extsize`.
//!
//! **UFS1 has no extattr area.** Its inode has no such fields, so
//! [`list_xattrs`] returns an empty list rather than reading whatever happens
//! to sit at those offsets.
//!
//! ## Record layout, read off a FreeBSD-written image
//!
//! ```text
//! 20 00 00 00 | 01 | 06 | 05 | "small" | 00 00 00 00 | "tiny-value" | 00 x6
//! ea_length   | ns | pad| nlen|        | align pad   |   content    | content pad
//! ```
//!
//! | offset | field |
//! |---|---|
//! | 0 | `ea_length` (u32) — the whole record, both paddings included |
//! | 4 | `ea_namespace` — **1 = user, 2 = system** |
//! | 5 | `ea_contentpadlen` — padding after the content |
//! | 6 | `ea_namelength` |
//! | 7 | `ea_name`, `ea_namelength` bytes |
//!
//! ## The one offset worth stating carefully
//!
//! The content begins at `(8 + namelen + 7) & !7` — **not** at `7 + namelen`
//! rounded up. `struct extattr` measures 8 bytes because its trailing
//! `ea_name[1]` pads the struct out, so the name starts at offset 7 while the
//! base length is computed from 8.
//!
//! The two formulas agree for every name length in the reference image and
//! first disagree at `namelen == 9`. A decoder built on the wrong one passes its
//! own fixture and then returns the right length starting one word early on
//! somebody's evidence.
//!
//! Content length is `ea_length - base - ea_contentpadlen`.

use crate::error::UfsError;
use crate::inode::read_inode;
use crate::superblock::Superblock;
use crate::UfsVersion;

/// `EXTATTR_NAMESPACE_USER`.
const NS_USER: u8 = 1;
/// `EXTATTR_NAMESPACE_SYSTEM`.
const NS_SYSTEM: u8 = 2;

/// Offset of `ea_name` within a record.
const NAME_OFF: usize = 7;
/// `sizeof(struct extattr)` — 7 bytes of fields plus the padding byte its
/// trailing `ea_name[1]` forces. The content offset is computed from this, not
/// from [`NAME_OFF`].
const EXTATTR_STRUCT_SIZE: usize = 8;

/// Smallest record that can carry anything: the fixed fields plus a one-byte
/// name, rounded to the 8-byte boundary.
const MIN_RECORD: usize = 8;

/// A ceiling on records from one area. `di_extsize` is a `u32` and every record
/// must advance the cursor, so a well-formed image cannot reach this; it caps
/// what a hostile `di_extsize` can allocate.
const MAX_RECORDS: usize = 8192;

/// Which of UFS2's two extended-attribute namespaces a record belongs to.
///
/// UFS2 has exactly these two. An unrecognised value is preserved verbatim
/// rather than folded into `User`, because reporting a `system.` attribute as a
/// `user.` one misstates who set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UfsNamespace {
    /// `user` — settable by the file's owner.
    User,
    /// `system` — settable only by the superuser.
    System,
    /// A namespace byte this reader does not recognise, carried as found.
    Unknown(u8),
}

impl UfsNamespace {
    /// Decode the `ea_namespace` byte.
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            NS_USER => Self::User,
            NS_SYSTEM => Self::System,
            other => Self::Unknown(other),
        }
    }

    /// The prefix FreeBSD's tools use for this namespace, when it is known.
    ///
    /// `None` for an unrecognised byte: a name cannot be qualified without
    /// knowing its namespace, and guessing would present the attribute under a
    /// namespace nothing observed.
    #[must_use]
    pub fn prefix(self) -> Option<&'static str> {
        match self {
            Self::User => Some("user."),
            Self::System => Some("system."),
            Self::Unknown(_) => None,
        }
    }
}

/// One UFS2 extended attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    /// The namespace this attribute lives in.
    pub namespace: UfsNamespace,
    /// The attribute's name, WITHOUT a namespace prefix — UFS2 stores the bare
    /// name and the namespace separately.
    pub name: String,
    /// The attribute's value.
    pub value: Vec<u8>,
}

impl Xattr {
    /// The attribute's name qualified by its namespace, e.g. `user.small`.
    ///
    /// `None` when the namespace byte was not recognised — see
    /// [`UfsNamespace::prefix`].
    #[must_use]
    pub fn full_name(&self) -> Option<String> {
        let prefix = self.namespace.prefix()?;
        let mut s = String::with_capacity(prefix.len() + self.name.len());
        s.push_str(prefix);
        s.push_str(&self.name);
        Some(s)
    }
}

/// List every extended attribute on inode `ino`.
///
/// An inode with no extattr area (`di_extsize == 0`), and every UFS1 inode,
/// yields an empty list. Neither is an error.
///
/// # Errors
///
/// Propagates [`read_inode`]'s errors — a corrupt superblock geometry or an
/// out-of-range inode number is surfaced rather than read as "no attributes".
/// [`UfsError::Truncated`] when the inode declares an area (`di_extsize`) that
/// its `di_extb` pointers cannot deliver in full: a damaged area is not an
/// empty one.
pub fn list_xattrs(partition: &[u8], sb: &Superblock, ino: u64) -> Result<Vec<Xattr>, UfsError> {
    let inode = read_inode(partition, sb, ino)?;
    if inode.version == UfsVersion::Ufs1 || inode.extsize == 0 {
        return Ok(Vec::new());
    }
    let fsize = usize::try_from(sb.fsize.max(0)).unwrap_or(0);
    if fsize == 0 {
        return Ok(Vec::new()); // cov:unreachable: read_inode (above) refuses fs_fsize <= 0, so fsize is positive here
    }

    // Both di_extb pointers are walked: the area may span two fragment runs,
    // and stopping at the first would silently drop the tail.
    let mut area = Vec::with_capacity(inode.extsize as usize);
    let want = inode.extsize as usize;
    for &blk in &inode.extb {
        if area.len() >= want || blk <= 0 {
            continue;
        }
        let Ok(start) = usize::try_from(blk) else {
            continue; // cov:unreachable: blk > 0 here, and a positive i64 fits usize on the 64-bit targets this crate supports
        };
        let Some(byte) = start.checked_mul(fsize) else {
            continue;
        };
        // A fragment address past the end of the image is a corrupt pointer,
        // not a reason to panic; take what is readable and stop.
        let end = byte.saturating_add(want - area.len()).min(partition.len());
        if byte >= partition.len() {
            continue;
        }
        area.extend_from_slice(&partition[byte..end]);
    }
    if area.len() < want {
        return Err(UfsError::Truncated {
            structure: "inode extended-attribute area (di_extsize via di_extb)",
            need: want,
            have: area.len(),
        });
    }

    Ok(parse_area(&area))
}

/// Walk a packed extattr area.
///
/// A record whose declared length is impossible — shorter than the minimum, or
/// overrunning the area — ENDS the walk. The records carry no terminator and
/// `ea_length` is the only thing that advances the cursor, so once it is
/// untrustworthy there is nowhere safe to resume; continuing would emit
/// attributes assembled from the wrong bytes.
#[must_use]
pub fn parse_area(area: &[u8]) -> Vec<Xattr> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + NAME_OFF <= area.len() && out.len() < MAX_RECORDS {
        let Some(hdr) = area.get(off..off + NAME_OFF) else {
            break; // cov:unreachable: the loop condition guarantees off + NAME_OFF <= area.len()
        };
        let ea_length = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let namespace = UfsNamespace::from_byte(hdr[4]);
        let contentpadlen = hdr[5] as usize;
        let namelen = hdr[6] as usize;

        if ea_length < MIN_RECORD || off + ea_length > area.len() {
            break;
        }
        // See the module docs: the base is measured from sizeof(struct extattr),
        // which is 8, while the name itself starts at 7.
        let base = (EXTATTR_STRUCT_SIZE + namelen + 7) & !7;
        let Some(content_len) = ea_length.checked_sub(base + contentpadlen) else {
            break;
        };
        let name_end = off + NAME_OFF + namelen;
        let content_start = off + base;
        let (Some(name), Some(value)) = (
            area.get(off + NAME_OFF..name_end),
            area.get(content_start..content_start + content_len),
        ) else {
            break; // cov:unreachable: name_end <= off + base and the value ends at off + ea_length - contentpadlen, both <= off + ea_length <= area.len() (checked above)
        };

        out.push(Xattr {
            namespace,
            name: String::from_utf8_lossy(name).into_owned(),
            value: value.to_vec(),
        });
        off += ea_length;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::parse_area;

    /// `parse_area` ends the walk at a record whose length cannot be right
    /// (documented: no terminator, so there is nowhere safe to resume).
    #[test]
    fn parse_area_stops_at_an_impossible_record_length() {
        // A well-formed 16-byte user record: ea_length 16, ns 1, padlen 0,
        // namelen 1 ("a"), base (8 + 1 + 7) & !7 = 16, so an empty value.
        let mut good = vec![0u8; 16];
        good[0] = 16;
        good[4] = 1;
        good[6] = 1;
        good[7] = b'a';
        assert_eq!(parse_area(&good).len(), 1);
        // ea_length below the 8-byte minimum.
        let mut short = good.clone();
        short[0] = 4;
        assert!(parse_area(&short).is_empty());
        // ea_length past the end of the area.
        let mut over = good.clone();
        over[0] = 200;
        assert!(parse_area(&over).is_empty());
        // A header claiming more than its record holds: namelen 40 makes the base
        // 48, larger than ea_length 16.
        let mut big_name = good;
        big_name[6] = 40;
        assert!(parse_area(&big_name).is_empty());
    }
}
