/* tests/varint.rs */

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