/* src/varint.rs */

use crate::error::Error;

/// Decode a QUIC variable-length integer from the start of `buf`.
///
/// Returns the decoded value and the number of bytes consumed (1, 2, 4, or 8).
/// The encoding is defined in RFC 9000 Section 16.
///
/// # Errors
///
/// Returns [`Error::InvalidVarint`] when `buf` is empty or too short for the
/// indicated encoding length.
#[must_use = "returns the decoded value without modifying the buffer"]
pub fn read_varint(buf: &[u8]) -> Result<(u64, usize), Error> {
	let &first = buf.first().ok_or(Error::InvalidVarint)?;
	let prefix = first >> 6;
	let len = 1usize << prefix;

	if buf.len() < len {
		return Err(Error::InvalidVarint);
	}

	let mut val = u64::from(first & 0x3f);
	for &b in &buf[1..len] {
		val = (val << 8) | u64::from(b);
	}
	Ok((val, len))
}
