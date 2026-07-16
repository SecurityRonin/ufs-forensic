//! Bounds-checked readers for both byte orders (the Paranoid Gatekeeper
//! standard).
//!
//! UFS is endianness-agnostic on disk: the filesystem is written in the byte
//! order of the host that created it, and the superblock magic disambiguates
//! which order to read (like ZFS). So every reader comes in a little-endian and
//! a big-endian form, and the [`Endian`] selector picks between them once the
//! magic has resolved the order.
//!
//! Every reader yields `0` when the requested range lies outside the buffer, so
//! a malformed or truncated image can never panic a parser. Callers that need
//! to distinguish "field absent" from "field is zero" bounds-check the buffer
//! length up front and surface [`crate::UfsError::Truncated`].

/// On-disk byte order, resolved from the superblock magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// Least-significant byte first (x86, most modern hosts).
    Little,
    /// Most-significant byte first (SPARC, historic big-endian hosts).
    Big,
}

impl Endian {
    /// Read a `u16` at `off` in this byte order, or `0` if out of range.
    #[must_use]
    pub fn u16(self, data: &[u8], off: usize) -> u16 {
        match self {
            Endian::Little => le_u16(data, off),
            Endian::Big => be_u16(data, off),
        }
    }

    /// Read a `u32` at `off` in this byte order, or `0` if out of range.
    #[must_use]
    pub fn u32(self, data: &[u8], off: usize) -> u32 {
        match self {
            Endian::Little => le_u32(data, off),
            Endian::Big => be_u32(data, off),
        }
    }

    /// Read an `i32` at `off` in this byte order, or `0` if out of range.
    #[must_use]
    pub fn i32(self, data: &[u8], off: usize) -> i32 {
        self.u32(data, off) as i32
    }

    /// Read a `u64` at `off` in this byte order, or `0` if out of range.
    #[must_use]
    pub fn u64(self, data: &[u8], off: usize) -> u64 {
        match self {
            Endian::Little => le_u64(data, off),
            Endian::Big => be_u64(data, off),
        }
    }

    /// Read an `i64` at `off` in this byte order, or `0` if out of range.
    #[must_use]
    pub fn i64(self, data: &[u8], off: usize) -> i64 {
        self.u64(data, off) as i64
    }
}

/// Read a little-endian `u16` at `off`, or `0` if out of range.
#[must_use]
pub fn le_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off.saturating_add(2)) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

/// Read a big-endian `u16` at `off`, or `0` if out of range.
#[must_use]
pub fn be_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off.saturating_add(2)) {
        b.copy_from_slice(s);
    }
    u16::from_be_bytes(b)
}

/// Read a little-endian `u32` at `off`, or `0` if out of range.
#[must_use]
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off.saturating_add(4)) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

/// Read a big-endian `u32` at `off`, or `0` if out of range.
#[must_use]
pub fn be_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off.saturating_add(4)) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

/// Read a little-endian `u64` at `off`, or `0` if out of range.
#[must_use]
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off.saturating_add(8)) {
        b.copy_from_slice(s);
    }
    u64::from_le_bytes(b)
}

/// Read a big-endian `u64` at `off`, or `0` if out of range.
#[must_use]
pub fn be_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off.saturating_add(8)) {
        b.copy_from_slice(s);
    }
    u64::from_be_bytes(b)
}

/// Read a single byte at `off`, or `0` if out of range.
#[must_use]
pub fn u8_at(data: &[u8], off: usize) -> u8 {
    data.get(off).copied().unwrap_or(0)
}
