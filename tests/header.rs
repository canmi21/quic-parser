/* tests/header.rs */

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