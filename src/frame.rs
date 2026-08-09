/* src/frame.rs */

use crate::error::Error;
use crate::varint::read_varint_at;

/// A single CRYPTO frame extracted from decrypted QUIC payload.
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoFrame {
	/// Byte offset within the crypto stream where this fragment begins.
	pub offset: u64,
	/// The raw data carried by this frame.
	pub data: Vec<u8>,
}

/// Parse all CRYPTO frames from a decrypted Initial packet payload.
///
/// PADDING (0x00) and PING (0x01) frames are silently skipped. ACK frames
/// (0x02, 0x03) are skipped by consuming their fields. Parsing stops when an
/// unrecognised frame type is encountered or the buffer is exhausted.
///
/// # Errors
///
/// Returns [`Error::BufferTooShort`] if a CRYPTO frame extends beyond the
/// available data.
pub fn parse_crypto_frames(decrypted: &[u8]) -> Result<Vec<CryptoFrame>, Error> {
	let mut cursor = 0;
	let mut frames = Vec::new();

	while cursor < decrypted.len() {
		let frame_type = read_varint_at(decrypted, &mut cursor)?;

		match frame_type {
			0x06 => {
				let offset = read_varint_at(decrypted, &mut cursor)?;

				let length = read_varint_at(decrypted, &mut cursor)? as usize;

				if cursor + length > decrypted.len() {
					return Err(Error::BufferTooShort { need: cursor + length, have: decrypted.len() });
				}

				let data = decrypted[cursor..cursor + length].to_vec();
				frames.push(CryptoFrame { offset, data });
				cursor += length;
			}
			// PADDING / PING
			0x00 | 0x01 => {}
			// ACK (0x02) and ACK_ECN (0x03): consume all varint fields
			0x02 | 0x03 => {
				cursor = skip_ack_frame(decrypted, cursor, frame_type == 0x03)?;
			}
			_ => break,
		}
	}

	Ok(frames)
}

/// Skip over an ACK frame by consuming all its varint fields.
///
/// Layout (RFC 9000 Section 19.3):
///   Largest Acknowledged (i), ACK Delay (i), ACK Range Count (i),
///   First ACK Range (i), { Gap (i), ACK Range Length (i) } * count,
///   [ECN Counts: ECT0 (i), ECT1 (i), ECN-CE (i)]  — only for type 0x03.
fn skip_ack_frame(buf: &[u8], mut cursor: usize, has_ecn: bool) -> Result<usize, Error> {
	// Largest Acknowledged
	_ = read_varint_at(buf, &mut cursor)?;
	// ACK Delay
	_ = read_varint_at(buf, &mut cursor)?;
	// ACK Range Count
	let range_count = read_varint_at(buf, &mut cursor)?;
	// First ACK Range
	_ = read_varint_at(buf, &mut cursor)?;

	// Each additional ACK Range: Gap (i) + ACK Range Length (i)
	for _ in 0..range_count {
		_ = read_varint_at(buf, &mut cursor)?;
		_ = read_varint_at(buf, &mut cursor)?;
	}

	// ECN Counts (only for ACK_ECN, type 0x03)
	if has_ecn {
		for _ in 0..3 {
			_ = read_varint_at(buf, &mut cursor)?;
		}
	}

	Ok(cursor)
}

/// Reassemble CRYPTO frames into a contiguous byte stream.
///
/// Frames are sorted by offset and concatenated in order. Only contiguous
/// fragments starting from offset zero are included; gaps cause the
/// reassembly to stop at the gap boundary.
#[must_use]
pub fn reassemble_crypto_stream(frames: &[CryptoFrame]) -> Vec<u8> {
	let mut sorted: Vec<&CryptoFrame> = frames.iter().collect();
	sorted.sort_by_key(|f| f.offset);

	let mut stream = Vec::new();
	let mut next_offset: u64 = 0;

	for frame in sorted {
		if frame.offset == next_offset {
			stream.extend_from_slice(&frame.data);
			next_offset += frame.data.len() as u64;
		} else if frame.offset < next_offset {
			let skip = (next_offset - frame.offset) as usize;
			// Verify overlapping data matches (RFC 9000 §19.6).
			let overlap = skip.min(frame.data.len());
			let overlap_start = frame.offset as usize;
			if stream[overlap_start..overlap_start + overlap] != frame.data[..overlap] {
				break;
			}
			if skip < frame.data.len() {
				stream.extend_from_slice(&frame.data[skip..]);
				next_offset += (frame.data.len() - skip) as u64;
			}
		} else {
			break;
		}
	}

	stream
}
