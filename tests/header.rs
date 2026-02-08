/* tests/header.rs */

#![allow(missing_docs)]

use quic_parser::{Error, parse_initial, peek_long_header_dcid, peek_short_header_dcid};

fn build_initial(version: u32, dcid: &[u8], scid: &[u8], token: &[u8], payload: &[u8]) -> Vec<u8> {
	let mut pkt = Vec::new();
	pkt.push(0xc3);
	pkt.extend_from_slice(&version.to_be_bytes());
	pkt.push(dcid.len() as u8);
	pkt.extend_from_slice(dcid);
	pkt.push(scid.len() as u8);
	pkt.extend_from_slice(scid);
	push_varint(&mut pkt, token.len() as u64);
	pkt.extend_from_slice(token);
	push_varint(&mut pkt, payload.len() as u64);
	pkt.extend_from_slice(payload);
	pkt
}

/// Build a QUIC v2 Initial packet. V2 uses type bits 0b01 for Initial,
/// so first_byte = 0x80 | 0x40 | 0x10 | reserved = 0xD3.
fn build_initial_v2(dcid: &[u8], scid: &[u8], token: &[u8], payload: &[u8]) -> Vec<u8> {
	let mut pkt = Vec::new();
	// Long header (0x80) + fixed bit (0x40) + type 0b01 (0x10) + reserved 0x03
	pkt.push(0xd3);
	pkt.extend_from_slice(&0x6b33_43cf_u32.to_be_bytes());
	pkt.push(dcid.len() as u8);
	pkt.extend_from_slice(dcid);
	pkt.push(scid.len() as u8);
	pkt.extend_from_slice(scid);
	push_varint(&mut pkt, token.len() as u64);
	pkt.extend_from_slice(token);
	push_varint(&mut pkt, payload.len() as u64);
	pkt.extend_from_slice(payload);
	pkt
}

fn push_varint(buf: &mut Vec<u8>, val: u64) {
	if val < 64 {
		buf.push(val as u8);
	} else if val < 16384 {
		buf.push(0x40 | (val >> 8) as u8);
		buf.push(val as u8);
	} else if val < 1_073_741_824 {
		let bytes = (val as u32).to_be_bytes();
		buf.push(0x80 | bytes[0]);
		buf.extend_from_slice(&bytes[1..]);
	}
}

// =====================================================================
// Existing tests
// =====================================================================

#[test]
fn parse_v1_initial() {
	let dcid = [0x01, 0x02, 0x03, 0x04];
	let scid = [0xaa, 0xbb];
	let payload = vec![0xff; 30];
	let pkt = build_initial(0x0000_0001, &dcid, &scid, &[], &payload);

	let header = parse_initial(&pkt).unwrap();
	assert_eq!(header.version, 0x0000_0001);
	assert_eq!(header.dcid, &dcid);
	assert_eq!(header.scid, &scid);
	assert!(header.token.is_empty());
	assert_eq!(header.payload, &payload[..]);
	assert_eq!(header.first_byte, 0xc3);
}

#[test]
fn parse_with_token() {
	let dcid = [0x01];
	let token = [0xde, 0xad, 0xbe, 0xef];
	let payload = vec![0xaa; 20];
	let pkt = build_initial(0x0000_0001, &dcid, &[], &token, &payload);

	let header = parse_initial(&pkt).unwrap();
	assert_eq!(header.token, &token);
	assert_eq!(header.payload.len(), 20);
}

#[test]
fn reject_missing_fixed_bit() {
	let mut pkt = build_initial(1, &[0x01], &[], &[], &[0; 20]);
	pkt[0] = 0x80; // Long header but missing fixed bit
	assert!(matches!(parse_initial(&pkt), Err(Error::InvalidFixedBit)));
}

#[test]
fn reject_short_header() {
	let pkt = [0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
	assert!(matches!(parse_initial(&pkt), Err(Error::NotLongHeader)));
}

#[test]
fn reject_non_initial_type() {
	let mut pkt = build_initial(1, &[0x01], &[], &[], &[0; 20]);
	pkt[0] = 0xd0;
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::NotInitialPacket(_))
	));
}

#[test]
fn reject_too_short() {
	assert!(matches!(
		parse_initial(&[0xc0, 0x00]),
		Err(Error::BufferTooShort { .. })
	));
}

#[test]
fn reject_dcid_too_long() {
	let mut pkt = vec![0xc0];
	pkt.extend_from_slice(&1u32.to_be_bytes());
	pkt.push(21);
	pkt.extend_from_slice(&[0; 21]);
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::InvalidCidLength(21))
	));
}

#[test]
fn reject_truncated_payload() {
	let mut pkt = build_initial(1, &[0x01], &[], &[], &[0; 20]);
	pkt.truncate(pkt.len() - 5);
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::BufferTooShort { .. })
	));
}

#[test]
fn peek_long_header_dcid_normal() {
	let pkt = build_initial(1, &[0x01, 0x02, 0x03, 0x04], &[], &[], &[0; 20]);
	let dcid = peek_long_header_dcid(&pkt).unwrap();
	assert_eq!(dcid, &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn peek_long_header_dcid_too_short() {
	assert!(peek_long_header_dcid(&[0xc0, 0x00, 0x00]).is_none());
}

#[test]
fn peek_long_header_dcid_zero_len() {
	let pkt = build_initial(1, &[], &[], &[], &[0; 20]);
	assert!(peek_long_header_dcid(&pkt).is_none());
}

#[test]
fn peek_long_header_dcid_exceeds_20() {
	let mut pkt = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 21];
	pkt.extend_from_slice(&[0; 21]);
	assert!(peek_long_header_dcid(&pkt).is_none());
}

#[test]
fn peek_short_header_dcid_normal() {
	let pkt = [0x40, 0xaa, 0xbb, 0xcc, 0xdd];
	let dcid = peek_short_header_dcid(&pkt, 4).unwrap();
	assert_eq!(dcid, &[0xaa, 0xbb, 0xcc, 0xdd]);
}

#[test]
fn peek_short_header_dcid_too_short() {
	let pkt = [0x40, 0xaa];
	assert!(peek_short_header_dcid(&pkt, 4).is_none());
}

// =====================================================================
// New correct-path tests
// =====================================================================

#[test]
fn parse_v2_initial() {
	let dcid = [0x01, 0x02, 0x03, 0x04];
	let scid = [0xaa, 0xbb];
	let payload = vec![0xff; 30];
	let pkt = build_initial_v2(&dcid, &scid, &[], &payload);

	let header = parse_initial(&pkt).unwrap();
	assert_eq!(header.version, 0x6b33_43cf);
	assert_eq!(header.dcid, &dcid);
	assert_eq!(header.scid, &scid);
	assert!(header.token.is_empty());
	assert_eq!(header.payload, &payload[..]);
	// First byte: 0x80 | 0x40 | 0x10 | 0x03 = 0xD3
	assert_eq!(header.first_byte, 0xd3);
}

#[test]
fn parse_max_dcid() {
	let dcid = [0xaa; 20];
	let payload = vec![0xff; 10];
	let pkt = build_initial(0x0000_0001, &dcid, &[], &[], &payload);

	let header = parse_initial(&pkt).unwrap();
	assert_eq!(header.dcid.len(), 20);
	assert_eq!(header.dcid, &dcid);
}

#[test]
fn parse_max_scid() {
	let scid = [0xbb; 20];
	let payload = vec![0xff; 10];
	let pkt = build_initial(0x0000_0001, &[], &scid, &[], &payload);

	let header = parse_initial(&pkt).unwrap();
	assert_eq!(header.scid.len(), 20);
	assert_eq!(header.scid, &scid);
}

#[test]
fn parse_both_cids_max() {
	let dcid = [0xaa; 20];
	let scid = [0xbb; 20];
	let payload = vec![0xff; 10];
	let pkt = build_initial(0x0000_0001, &dcid, &scid, &[], &payload);

	let header = parse_initial(&pkt).unwrap();
	assert_eq!(header.dcid.len(), 20);
	assert_eq!(header.scid.len(), 20);
	assert_eq!(header.dcid, &dcid);
	assert_eq!(header.scid, &scid);
}

#[test]
fn parse_empty_cids() {
	let payload = vec![0xff; 10];
	let pkt = build_initial(0x0000_0001, &[], &[], &[], &payload);

	let header = parse_initial(&pkt).unwrap();
	assert!(header.dcid.is_empty());
	assert!(header.scid.is_empty());
}

#[test]
fn parse_large_token() {
	// Token length > 63 triggers 2-byte varint encoding
	let token = vec![0xab; 100];
	let payload = vec![0xff; 10];
	let pkt = build_initial(0x0000_0001, &[0x01], &[], &token, &payload);

	let header = parse_initial(&pkt).unwrap();
	assert_eq!(header.token.len(), 100);
	assert_eq!(header.token, &token[..]);
}

#[test]
fn parse_minimal_payload() {
	// remaining_len = 1 (smallest valid payload)
	let payload = vec![0xff; 1];
	let pkt = build_initial(0x0000_0001, &[0x01], &[], &[], &payload);

	let header = parse_initial(&pkt).unwrap();
	assert_eq!(header.payload.len(), 1);
}

#[test]
fn parse_zero_payload() {
	// remaining_len = 0 (empty payload, legal but cannot decrypt)
	let pkt = build_initial(0x0000_0001, &[0x01], &[], &[], &[]);

	let header = parse_initial(&pkt).unwrap();
	assert!(header.payload.is_empty());
}

#[test]
fn parse_preserves_header_bytes() {
	let dcid = [0x01, 0x02];
	let scid = [0xaa];
	let token = [0xde, 0xad];
	let payload = vec![0xff; 20];
	let pkt = build_initial(0x0000_0001, &dcid, &scid, &token, &payload);

	let header = parse_initial(&pkt).unwrap();
	// header_bytes should be exactly the bytes before the payload
	let expected_header_len = pkt.len() - payload.len();
	assert_eq!(header.header_bytes.len(), expected_header_len);
	assert_eq!(header.header_bytes, &pkt[..expected_header_len]);
}

#[test]
fn peek_long_dcid_len_one() {
	let pkt = build_initial(1, &[0xff], &[], &[], &[0; 20]);
	let dcid = peek_long_header_dcid(&pkt).unwrap();
	assert_eq!(dcid, &[0xff]);
}

#[test]
fn peek_long_dcid_len_twenty() {
	let dcid_bytes = [0xaa; 20];
	let pkt = build_initial(1, &dcid_bytes, &[], &[], &[0; 10]);
	let dcid = peek_long_header_dcid(&pkt).unwrap();
	assert_eq!(dcid, &dcid_bytes);
}

#[test]
fn peek_long_exact_buffer() {
	// Buffer is exactly 6 + dcid_len bytes (just enough for peek)
	let dcid_len = 4;
	let mut pkt = vec![0xc0, 0x00, 0x00, 0x00, 0x01]; // 5 bytes: first + version
	pkt.push(dcid_len as u8);
	pkt.extend_from_slice(&[0xaa; 4]); // exactly dcid_len bytes
	assert_eq!(pkt.len(), 10); // 6 + 4

	let dcid = peek_long_header_dcid(&pkt).unwrap();
	assert_eq!(dcid, &[0xaa; 4]);
}

#[test]
fn peek_short_cid_zero() {
	let pkt = [0x40, 0xaa, 0xbb, 0xcc];
	let dcid = peek_short_header_dcid(&pkt, 0).unwrap();
	assert!(dcid.is_empty());
}

#[test]
fn peek_short_large_cid() {
	let mut pkt = vec![0x40];
	pkt.extend_from_slice(&[0xbb; 20]);
	pkt.extend_from_slice(&[0x00; 10]); // extra bytes
	let dcid = peek_short_header_dcid(&pkt, 20).unwrap();
	assert_eq!(dcid.len(), 20);
	assert_eq!(dcid, &[0xbb; 20]);
}

// =====================================================================
// New error-path tests
// =====================================================================

#[test]
fn reject_v1_with_v2_type_bits() {
	// v1 version but type bits = 0b01 (which is v2 Initial type)
	// first_byte = 0x80 | 0x40 | 0x10 | 0x03 = 0xD3
	let mut pkt = build_initial(0x0000_0001, &[0x01], &[], &[], &[0; 20]);
	pkt[0] = 0xd3; // type bits = 0b01, but version is v1 (expects 0b00)
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::NotInitialPacket(1))
	));
}

#[test]
fn reject_v2_with_v1_type_bits() {
	// v2 version but type bits = 0b00 (which is v1 Initial type)
	// Use build_initial which sets first_byte = 0xC3 (type bits = 0b00)
	let pkt = build_initial(0x6b33_43cf, &[0x01], &[], &[], &[0; 20]);
	// 0xC3 has type bits 0b00, but v2 expects 0b01
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::NotInitialPacket(0))
	));
}

#[test]
fn reject_handshake_type() {
	// type bits = 0b10 → NotInitialPacket(2)
	let mut pkt = build_initial(0x0000_0001, &[0x01], &[], &[], &[0; 20]);
	pkt[0] = 0xe3; // 0x80 | 0x40 | 0x20 | 0x03 → type bits = 0b10
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::NotInitialPacket(2))
	));
}

#[test]
fn reject_retry_type() {
	// type bits = 0b11 → NotInitialPacket(3)
	let mut pkt = build_initial(0x0000_0001, &[0x01], &[], &[], &[0; 20]);
	pkt[0] = 0xf3; // 0x80 | 0x40 | 0x30 | 0x03 → type bits = 0b11
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::NotInitialPacket(3))
	));
}

#[test]
fn reject_scid_too_long() {
	// Manually construct a packet with SCID length = 21
	let mut pkt = vec![0xc3]; // first byte: long header + fixed bit + Initial type
	pkt.extend_from_slice(&1u32.to_be_bytes()); // version
	pkt.push(1); // DCID length = 1
	pkt.push(0x01); // DCID
	pkt.push(21); // SCID length = 21 (too long)
	pkt.extend_from_slice(&[0; 21]); // SCID data
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::InvalidCidLength(21))
	));
}

#[test]
fn reject_exactly_six_bytes() {
	// 6 bytes is < 7 minimum → BufferTooShort
	assert!(matches!(
		parse_initial(&[0xc3, 0x00, 0x00, 0x00, 0x01, 0x00]),
		Err(Error::BufferTooShort { .. })
	));
}

#[test]
fn reject_truncated_dcid() {
	// DCID length claims 10 but only a few bytes follow
	let mut pkt = vec![0xc3];
	pkt.extend_from_slice(&1u32.to_be_bytes());
	pkt.push(10); // DCID length = 10
	pkt.extend_from_slice(&[0x01; 3]); // only 3 bytes of DCID data
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::BufferTooShort { .. })
	));
}

#[test]
fn reject_truncated_scid() {
	// DCID OK but SCID data truncated
	let mut pkt = vec![0xc3];
	pkt.extend_from_slice(&1u32.to_be_bytes());
	pkt.push(1); // DCID length = 1
	pkt.push(0x01); // DCID
	pkt.push(5); // SCID length = 5
	pkt.extend_from_slice(&[0x02; 2]); // only 2 bytes of SCID data
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::BufferTooShort { .. })
	));
}

#[test]
fn reject_truncated_token() {
	// Token length varint says 10 but data is truncated
	let mut pkt = vec![0xc3];
	pkt.extend_from_slice(&1u32.to_be_bytes());
	pkt.push(1); // DCID length = 1
	pkt.push(0x01); // DCID
	pkt.push(0); // SCID length = 0
	pkt.push(10); // token length = 10 (1-byte varint)
	pkt.extend_from_slice(&[0xaa; 3]); // only 3 bytes of token data
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::BufferTooShort { .. })
	));
}

#[test]
fn reject_token_len_overflow_32bit() {
	// Token length varint decodes to a very large value that causes
	// checked_add overflow → BufferTooShort
	let mut pkt = vec![0xc3];
	pkt.extend_from_slice(&1u32.to_be_bytes());
	pkt.push(1); // DCID length = 1
	pkt.push(0x01); // DCID
	pkt.push(0); // SCID length = 0
	// 8-byte varint with maximum value (2^62 - 1)
	pkt.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
	assert!(matches!(
		parse_initial(&pkt),
		Err(Error::BufferTooShort { .. })
	));
}

#[test]
fn peek_long_rejects_short_header() {
	// Bit 7 = 0 (short header) → peek_long_header_dcid returns None
	let mut pkt = vec![0x40]; // short header
	pkt.extend_from_slice(&0x0000_0001_u32.to_be_bytes());
	pkt.push(4); // dcid_len
	pkt.extend_from_slice(&[0xaa; 4]);
	assert!(peek_long_header_dcid(&pkt).is_none());
}

#[test]
fn peek_long_buffer_exact_five() {
	// Buffer is exactly 5 bytes (< 6 minimum) → None
	assert!(peek_long_header_dcid(&[0xc0, 0x00, 0x00, 0x00, 0x01]).is_none());
}

#[test]
fn peek_long_dcid_truncated() {
	// dcid_len = 10 but buffer only has 8 bytes total → None
	let mut pkt = vec![0xc0, 0x00, 0x00, 0x00, 0x01]; // 5 bytes
	pkt.push(10); // dcid_len = 10
	pkt.extend_from_slice(&[0xaa; 2]); // only 2 bytes of DCID (need 10)
	assert_eq!(pkt.len(), 8);
	assert!(peek_long_header_dcid(&pkt).is_none());
}
