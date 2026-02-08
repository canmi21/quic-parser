/* tests/varint.rs */

#![allow(missing_docs)]

use quic_parser::{Error, read_varint};

#[test]
fn one_byte_zero() {
	let (val, len) = read_varint(&[0x00]).unwrap();
	assert_eq!(val, 0);
	assert_eq!(len, 1);
}

#[test]
fn one_byte_max() {
	let (val, len) = read_varint(&[0x3f]).unwrap();
	assert_eq!(val, 63);
	assert_eq!(len, 1);
}

#[test]
fn two_byte_min() {
	let (val, len) = read_varint(&[0x40, 0x00]).unwrap();
	assert_eq!(val, 0);
	assert_eq!(len, 2);
}

#[test]
fn two_byte_example() {
	// 0x7bbd = 0b01_111011_10111101 => value = 0x3bbd = 15293
	let (val, len) = read_varint(&[0x7b, 0xbd]).unwrap();
	assert_eq!(val, 15293);
	assert_eq!(len, 2);
}

#[test]
fn four_byte_example() {
	// 0x9d7f3e7d => prefix 10, value = 0x1d7f3e7d = 494878333
	let (val, len) = read_varint(&[0x9d, 0x7f, 0x3e, 0x7d]).unwrap();
	assert_eq!(val, 494_878_333);
	assert_eq!(len, 4);
}

#[test]
fn eight_byte_example() {
	// 0xc2197c5eff14e88c => prefix 11, value = 0x02197c5eff14e88c = 151288809941952652
	let (val, len) = read_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]).unwrap();
	assert_eq!(val, 151_288_809_941_952_652);
	assert_eq!(len, 8);
}

#[test]
fn empty_buffer_fails() {
	assert!(matches!(read_varint(&[]), Err(Error::InvalidVarint)));
}

#[test]
fn truncated_two_byte() {
	assert!(matches!(read_varint(&[0x40]), Err(Error::InvalidVarint)));
}

#[test]
fn truncated_four_byte() {
	assert!(matches!(
		read_varint(&[0x80, 0x00]),
		Err(Error::InvalidVarint)
	));
}

#[test]
fn truncated_eight_byte() {
	assert!(matches!(
		read_varint(&[0xc0, 0x00, 0x00]),
		Err(Error::InvalidVarint)
	));
}

#[test]
fn extra_bytes_ignored() {
	let buf = [0x25, 0xff, 0xff];
	let (val, len) = read_varint(&buf).unwrap();
	assert_eq!(val, 37);
	assert_eq!(len, 1);
}

// --- New boundary tests ---

#[test]
fn boundary_one_to_two_byte() {
	// Value 63 fits in 1 byte (max 1-byte value)
	let (val, len) = read_varint(&[0x3f]).unwrap();
	assert_eq!(val, 63);
	assert_eq!(len, 1);

	// Value 64 requires 2 bytes (first value that needs 2-byte encoding)
	// 64 = 0x40 in 2-byte: 01_000000 01000000 → 0x40 0x40
	let (val, len) = read_varint(&[0x40, 0x40]).unwrap();
	assert_eq!(val, 64);
	assert_eq!(len, 2);
}

#[test]
fn two_byte_max() {
	// Max 2-byte value: 16383 = 0x3FFF
	// Encoded: 01_111111 11111111 → 0x7F 0xFF
	let (val, len) = read_varint(&[0x7f, 0xff]).unwrap();
	assert_eq!(val, 16383);
	assert_eq!(len, 2);
}

#[test]
fn boundary_two_to_four_byte() {
	// Value 16384 requires 4 bytes
	// 16384 = 0x4000
	// Encoded: 10_000000 00000000 01000000 00000000 → 0x80 0x00 0x40 0x00
	let (val, len) = read_varint(&[0x80, 0x00, 0x40, 0x00]).unwrap();
	assert_eq!(val, 16384);
	assert_eq!(len, 4);
}

#[test]
fn four_byte_max() {
	// Max 4-byte value: 1,073,741,823 = 0x3FFFFFFF
	// Encoded: 10_111111 11111111 11111111 11111111 → 0xBF 0xFF 0xFF 0xFF
	let (val, len) = read_varint(&[0xbf, 0xff, 0xff, 0xff]).unwrap();
	assert_eq!(val, 1_073_741_823);
	assert_eq!(len, 4);
}

#[test]
fn boundary_four_to_eight_byte() {
	// Value 1,073,741,824 requires 8 bytes
	// 1,073,741,824 = 0x40000000
	// Encoded: 11_000000 00000000 00000000 00000000 01000000 00000000 00000000 00000000
	let (val, len) =
		read_varint(&[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]).unwrap();
	assert_eq!(val, 1_073_741_824);
	assert_eq!(len, 8);
}

#[test]
fn eight_byte_max() {
	// Max varint value: 2^62 - 1 = 4,611,686,018,427,387,903 = 0x3FFFFFFFFFFFFFFF
	// Encoded: 11_111111 11111111 11111111 11111111 11111111 11111111 11111111 11111111
	let (val, len) =
		read_varint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap();
	assert_eq!(val, 4_611_686_018_427_387_903);
	assert_eq!(len, 8);
}

#[test]
fn non_canonical_two_byte_zero() {
	// Value 0 encoded in 2 bytes (non-canonical but valid): 0x40 0x00
	let (val, len) = read_varint(&[0x40, 0x00]).unwrap();
	assert_eq!(val, 0);
	assert_eq!(len, 2);
}

// --- New truncation error tests ---

#[test]
fn truncated_four_byte_at_two() {
	// 4-byte varint (prefix 10) with only 2 bytes provided
	assert!(matches!(
		read_varint(&[0x80, 0x01]),
		Err(Error::InvalidVarint)
	));
}

#[test]
fn truncated_four_byte_at_three() {
	// 4-byte varint (prefix 10) with only 3 bytes provided
	assert!(matches!(
		read_varint(&[0x80, 0x01, 0x02]),
		Err(Error::InvalidVarint)
	));
}

#[test]
fn truncated_eight_byte_at_four() {
	// 8-byte varint (prefix 11) with only 4 bytes provided
	assert!(matches!(
		read_varint(&[0xc0, 0x01, 0x02, 0x03]),
		Err(Error::InvalidVarint)
	));
}

#[test]
fn truncated_eight_byte_at_seven() {
	// 8-byte varint (prefix 11) with only 7 bytes provided
	assert!(matches!(
		read_varint(&[0xc0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
		Err(Error::InvalidVarint)
	));
}
