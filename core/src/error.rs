//! Error types for the UFS reader.

use thiserror::Error;

/// Errors surfaced while parsing UFS/FFS on-disk structures.
///
/// Every variant names the offending value so an "unknown/invalid" report hands
/// the investigator the evidence (raw bytes / offset), never a bare "invalid".
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum UfsError {
    /// The buffer was too small to hold the structure being parsed.
    #[error("buffer too small for {structure}: need {need} bytes, have {have}")]
    Truncated {
        /// Name of the structure that could not be read.
        structure: &'static str,
        /// Minimum byte length required.
        need: usize,
        /// Byte length actually available.
        have: usize,
    },

    /// The superblock magic matched neither UFS1 (`0x00011954`) nor UFS2
    /// (`0x19540119`) in either byte order.
    ///
    /// Carries the four bytes actually found at the magic offset in both
    /// interpretations so the caller can identify what the image really is
    /// (fail-loud with the offending value).
    #[error(
        "bad UFS superblock magic at offset {offset}: bytes {bytes:02x?} \
         (LE {le:#010x}, BE {be:#010x}); expected UFS1 0x00011954 or UFS2 0x19540119"
    )]
    BadMagic {
        /// Byte offset within the parsed buffer where the magic was read.
        offset: usize,
        /// The four raw bytes at the magic offset.
        bytes: [u8; 4],
        /// The value interpreted little-endian.
        le: u32,
        /// The value interpreted big-endian.
        be: u32,
    },

    /// A cylinder-group header's magic did not match `CG_MAGIC` (`0x00090255`).
    ///
    /// Carries the value found and the byte order used, so the caller sees the
    /// evidence rather than a bare "invalid cg".
    #[error(
        "bad cylinder-group magic: found {found:#010x} (endian {endian:?}), expected 0x00090255"
    )]
    BadCgMagic {
        /// The 32-bit value read at the cg magic offset.
        found: u32,
        /// The byte order used to read it (from the superblock).
        endian: crate::Endian,
    },

    /// A geometry field carried a value outside any sane bound for the image —
    /// consistent with corruption or an allocation-bomb. Names the field, the
    /// value, and the bound so the caller sees exactly what was rejected.
    #[error("impossible geometry: {field} = {value} exceeds bound {limit}")]
    ImpossibleGeometry {
        /// The geometry field that was out of range.
        field: &'static str,
        /// The value read from the image.
        value: u64,
        /// The sane bound it exceeded.
        limit: u64,
    },
}
