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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_decode_both_orders() {
        let d = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert_eq!(le_u16(&d, 0), 0x2211);
        assert_eq!(be_u16(&d, 0), 0x1122);
        assert_eq!(le_u32(&d, 0), 0x4433_2211);
        assert_eq!(be_u32(&d, 0), 0x1122_3344);
        assert_eq!(le_u64(&d, 0), 0x8877_6655_4433_2211);
        assert_eq!(be_u64(&d, 0), 0x1122_3344_5566_7788);
        assert_eq!(u8_at(&d, 3), 0x44);
    }

    #[test]
    fn readers_yield_zero_out_of_range() {
        assert_eq!(le_u16(&[0x12], 0), 0);
        assert_eq!(be_u16(&[0x12], 0), 0);
        assert_eq!(le_u32(&[0, 0, 0], 0), 0);
        assert_eq!(be_u32(&[0, 0, 0], 0), 0);
        assert_eq!(le_u64(&[0; 7], 0), 0);
        assert_eq!(be_u64(&[0; 7], 0), 0);
        assert_eq!(u8_at(&[], 0), 0);
    }

    #[test]
    fn endian_selector_dispatches_both_orders() {
        let d = [0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(Endian::Little.u16(&d, 0), 0xbbaa);
        assert_eq!(Endian::Big.u16(&d, 0), 0xaabb);
        assert_eq!(Endian::Little.u32(&d, 0), 0xddcc_bbaa);
        assert_eq!(Endian::Big.u32(&d, 0), 0xaabb_ccdd);
        assert_eq!(Endian::Little.i32(&d, 0), 0xddcc_bbaa_u32 as i32);
        assert_eq!(Endian::Big.i32(&d, 0), 0xaabb_ccdd_u32 as i32);
        assert_eq!(Endian::Little.u64(&d, 0), 0x0403_0201_ddcc_bbaa);
        assert_eq!(Endian::Big.u64(&d, 0), 0xaabb_ccdd_0102_0304);
        assert_eq!(Endian::Little.i64(&d, 0), 0x0403_0201_ddcc_bbaa_u64 as i64);
        assert_eq!(Endian::Big.i64(&d, 0), 0xaabb_ccdd_0102_0304_u64 as i64);
    }
}
