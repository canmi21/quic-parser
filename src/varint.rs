/* src/varint.rs */

use crate::error::Error;

/// Decode a QUIC variable-length integer from `buf` starting at `offset`.
///
/// Returns the decoded value, updates offset.
/// The encoding is defined in RFC 9000 Section 16.
///
/// # Errors
///
/// Returns [`Error::BufferTooShort`] when `buf` is empty or too short for the
/// indicated encoding length.
#[must_use = "returns the decoded value without modifying the buffer"]
pub fn read_varint_at(buf: &[u8], offset: &mut usize) -> Result<u64, Error> {
	if *offset >= buf.len() { return Err(Error::BufferTooShort { need: *offset+1, have: buf.len() }) }
	let first = buf[*offset];
	let prefix = first >> 6;
	let len = 1usize << prefix;
	if buf.len() < *offset + len {
		return Err(Error::BufferTooShort { need: *offset + len, have: buf.len() });
	}
	let mut val = (first & 0x3f) as u64;
	for i in 1..len {
		val = (val << 8) | (buf[i + *offset] as u64);
	}
	*offset += len;
	Ok(val)
}
