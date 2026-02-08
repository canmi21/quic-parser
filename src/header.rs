/* src/header.rs */

use crate::error::Error;
use crate::varint::read_varint;

/// Parsed QUIC Initial packet header with zero-copy references into the
/// original packet buffer.
#[derive(Debug, Clone, PartialEq)]
pub struct InitialHeader<'a> {
	/// QUIC version field (e.g. `0x00000001` for v1, `0x6b3343cf` for v2).
	pub version: u32,
	/// Destination Connection ID bytes.
	pub dcid: &'a [u8],
	/// Source Connection ID bytes.
	pub scid: &'a [u8],
	/// Token bytes. An empty slice indicates no token was present.
	pub token: &'a [u8],
	/// Encrypted payload including the protected packet number.
	pub payload: &'a [u8],
	/// Raw header bytes from the first byte up to (but not including) the
	/// payload. Required when constructing the AEAD additional authenticated
	/// data during decryption.
	pub header_bytes: &'a [u8],
	/// The first byte of the packet, still under header protection.
	pub first_byte: u8,
}

/// Parse a QUIC Long Header Initial packet from a raw datagram.
///
/// Only the header fields are extracted; no decryption is performed. The
/// returned [`InitialHeader`] borrows directly from `packet`.
///
/// # Errors
///
/// Returns an error when the packet is too short, is not a long-header
/// Initial packet, or contains a connection ID length exceeding 20 bytes.
pub fn parse_initial(packet: &[u8]) -> Result<InitialHeader<'_>, Error> {
	if packet.len() < 7 {
		return Err(Error::BufferTooShort {
			need: 7,
			have: packet.len(),
		});
	}

	let first_byte = packet[0];

	if (first_byte & 0x80) == 0 {
		return Err(Error::NotLongHeader);
	}

	if (first_byte & 0x40) == 0 {
		return Err(Error::InvalidFixedBit);
	}

	let packet_type = (first_byte & 0x30) >> 4;

	let mut cursor = 1;

	let version = u32::from_be_bytes([
		packet[cursor],
		packet[cursor + 1],
		packet[cursor + 2],
		packet[cursor + 3],
	]);
	cursor += 4;

	// QUIC v2 (RFC 9369) remaps the type field: Initial = 0b01.
	let expected_initial_type = match version {
		0x6b33_43cf => 1,
		_ => 0,
	};
	if packet_type != expected_initial_type {
		return Err(Error::NotInitialPacket(packet_type));
	}

	let (dcid, cursor) = read_cid(packet, cursor)?;
	let (scid, cursor) = read_cid(packet, cursor)?;

	let (token_len, varint_len) =
		read_varint(packet.get(cursor..).ok_or(Error::BufferTooShort {
			need: cursor + 1,
			have: packet.len(),
		})?)?;
	let cursor = cursor + varint_len;
	let token_len = usize::try_from(token_len).map_err(|_| Error::BufferTooShort {
		need: usize::MAX,
		have: packet.len(),
	})?;

	let token_end = cursor.checked_add(token_len).ok_or(Error::BufferTooShort {
		need: usize::MAX,
		have: packet.len(),
	})?;
	if token_end > packet.len() {
		return Err(Error::BufferTooShort {
			need: token_end,
			have: packet.len(),
		});
	}
	let token = &packet[cursor..token_end];
	let cursor = token_end;

	let (remaining_len, varint_len) =
		read_varint(packet.get(cursor..).ok_or(Error::BufferTooShort {
			need: cursor + 1,
			have: packet.len(),
		})?)?;
	let cursor = cursor + varint_len;
	let remaining_len = usize::try_from(remaining_len).map_err(|_| Error::BufferTooShort {
		need: usize::MAX,
		have: packet.len(),
	})?;

	let payload_end = cursor
		.checked_add(remaining_len)
		.ok_or(Error::BufferTooShort {
			need: usize::MAX,
			have: packet.len(),
		})?;
	if payload_end > packet.len() {
		return Err(Error::BufferTooShort {
			need: payload_end,
			have: packet.len(),
		});
	}

	let header_bytes = &packet[..cursor];
	let payload = &packet[cursor..payload_end];

	Ok(InitialHeader {
		version,
		dcid,
		scid,
		token,
		payload,
		header_bytes,
		first_byte,
	})
}

/// Extract the Destination Connection ID from a QUIC Long Header packet
/// without performing a full parse.
///
/// Returns `None` when the buffer is too short or the CID length field is
/// zero or exceeds 20.
#[must_use]
pub fn peek_long_header_dcid(packet: &[u8]) -> Option<&[u8]> {
	if packet.len() < 6 {
		return None;
	}
	if (packet[0] & 0x80) == 0 {
		return None;
	}
	let dcid_len = packet[5] as usize;
	if dcid_len == 0 || dcid_len > 20 {
		return None;
	}
	packet.get(6..6 + dcid_len)
}

/// Extract the Destination Connection ID from a QUIC Short Header packet.
///
/// Short headers do not carry an explicit CID length, so the caller must
/// supply the expected `cid_len`. Returns `None` when the buffer is too
/// short.
#[must_use]
pub fn peek_short_header_dcid(packet: &[u8], cid_len: usize) -> Option<&[u8]> {
	packet.get(1..1 + cid_len)
}

fn read_cid(packet: &[u8], offset: usize) -> Result<(&[u8], usize), Error> {
	let &cid_len_byte = packet.get(offset).ok_or(Error::BufferTooShort {
		need: offset + 1,
		have: packet.len(),
	})?;
	if cid_len_byte > 20 {
		return Err(Error::InvalidCidLength(cid_len_byte));
	}
	let cid_len = cid_len_byte as usize;
	let start = offset + 1;
	let end = start + cid_len;
	if end > packet.len() {
		return Err(Error::BufferTooShort {
			need: end,
			have: packet.len(),
		});
	}
	Ok((&packet[start..end], end))
}
