/* src/frame.rs */

use crate::error::Error;
use crate::varint::read_varint;

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
/// Returns [`Error::TruncatedFrame`] if a CRYPTO frame extends beyond the
/// available data. Returns [`Error::InvalidVarint`] if a varint field is
/// malformed.
pub fn parse_crypto_frames(decrypted: &[u8]) -> Result<Vec<CryptoFrame>, Error> {
	let mut cursor = 0;
	let mut frames = Vec::new();

	while cursor < decrypted.len() {
		let (frame_type, len) = read_varint(&decrypted[cursor..])?;
		cursor += len;

		match frame_type {
			0x06 => {
				let (offset, off_len) =
					read_varint(decrypted.get(cursor..).ok_or(Error::TruncatedFrame {
						offset: cursor as u64,
					})?)?;
				cursor += off_len;

				let (length, len_len) =
					read_varint(decrypted.get(cursor..).ok_or(Error::TruncatedFrame {
						offset: cursor as u64,
					})?)?;
				cursor += len_len;
				let length = length as usize;

				if cursor + length > decrypted.len() {
					return Err(Error::TruncatedFrame { offset });
				}

				let data = decrypted[cursor..cursor + length].to_vec();
				frames.push(CryptoFrame { offset, data });
				cursor += length;
			}
			0x00 | 0x01 => {}
			_ => break,
		}
	}

	Ok(frames)
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
