/* tests/decrypt.rs */

#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]
#![allow(missing_docs)]

use quic_parser::{
	CryptoFrame, Error, decrypt_initial, parse_crypto_frames, parse_initial, reassemble_crypto_stream,
};

fn hex_decode(s: &str) -> Vec<u8> {
	(0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
		.collect()
}

fn rfc9001_client_initial() -> Vec<u8> {
	hex_decode(concat!(
		"c000000001088394c8f03e515708",
		"0000449e",
		"7b9aec34d1b1c98dd7689fb8ec11",
		"d242b123dc9bd8bab936b47d92ec356c",
		"0bab7df5976d27cd449f63300099f399",
		"1c260ec4c60d17b31f8429157bb35a12",
		"82a643a8d2262cad67500cadb8e7378c",
		"8eb7539ec4d4905fed1bee1fc8aafba1",
		"7c750e2c7ace01e6005f80fcb7df6212",
		"30c83711b39343fa028cea7f7fb5ff89",
		"eac2308249a02252155e2347b63d58c5",
		"457afd84d05dfffdb20392844ae81215",
		"4682e9cf012f9021a6f0be17ddd0c208",
		"4dce25ff9b06cde535d0f920a2db1bf3",
		"62c23e596dee38f5a6cf3948838a3aec",
		"4e15daf8500a6ef69ec4e3feb6b1d98e",
		"610ac8b7ec3faf6ad760b7bad1db4ba3",
		"485e8a94dc250ae3fdb41ed15fb6a8e5",
		"eba0fc3dd60bc8e30c5c4287e53805db",
		"059ae0648db2f64264ed5e39be2e20d8",
		"2df566da8dd5998ccabdae053060ae6c",
		"7b4378e846d29f37ed7b4ea9ec5d82e7",
		"961b7f25a9323851f681d582363aa5f8",
		"9937f5a67258bf63ad6f1a0b1d96dbd4",
		"faddfcefc5266ba6611722395c906556",
		"be52afe3f565636ad1b17d508b73d874",
		"3eeb524be22b3dcbc2c7468d54119c74",
		"68449a13d8e3b95811a198f3491de3e7",
		"fe942b330407abf82a4ed7c1b311663a",
		"c69890f4157015853d91e923037c227a",
		"33cdd5ec281ca3f79c44546b9d90ca00",
		"f064c99e3dd97911d39fe9c5d0b23a22",
		"9a234cb36186c4819e8b9c592772663229",
		"1d6a418211cc2962e20fe47feb3edf33",
		"0f2c603a9d48c0fcb5699dbfe5896425",
		"c5bac4aee82e57a85aaf4e2513e4f057",
		"96b07ba2ee47d80506f8d2c25e50fd14",
		"de71e6c418559302f939b0e1abd576f2",
		"79c4b2e0feb85c1f28ff18f58891ffef",
		"132eef2fa09346aee33c28eb130ff28f",
		"5b766953334113211996d20011a198e3",
		"fc433f9f2541010ae17c1bf202580f60",
		"47472fb36857fe843b19f5984009ddc3",
		"24044e847a4f4a0ab34f719595de3725",
		"2d6235365e9b84392b061085349d7320",
		"3a4a13e96f5432ec0fd4a1ee65accdd5",
		"e3904df54c1da510b0ff20dcc0c77fcb",
		"2c0e0eb605cb0504db87632cf3d8b4da",
		"e6e705769d1de354270123cb11450efc",
		"60ac47683d7b8d0f811365565fd98c4c",
		"8eb936bcab8d069fc33bd801b03adea2",
		"e1fbc5aa463d08ca19896d2bf59a071b",
		"851e6c239052172f296bfb5e72404790",
		"a2181014f3b94a4e97d117b438130368",
		"cc39dbb2d198065ae3986547926cd216",
		"2f40a29f0c3c8745c0f50fba3852e566",
		"d44575c29d39a03f0cda721984b6f440",
		"591f355e12d439ff150aab7613499dbd",
		"49adabc8676eef023b15b65bfc5ca069",
		"48109f23f350db82123535eb8a7433bd",
		"abcb909271a6ecbcb58b936a88cd4e8f",
		"2e6ff5800175f113253d8fa9ca8885c2",
		"f552e657dc603f252e1a8e308f76f0be",
		"79e2fb8f5d5fbbe2e30ecadd220723c8",
		"c0aea8078cdfcb3868263ff8f0940054",
		"da48781893a7e49ad5aff4af300cd804",
		"a6b6279ab3ff3afb64491c85194aab76",
		"0d58a606654f9f4400e8b38591356fbf",
		"6425aca26dc85244259ff2b19c41b9f9",
		"6f3ca9ec1dde434da7d2d392b905ddf3",
		"d1f9af93d1af5950bd493f5aa731b405",
		"6df31bd267b6b90a079831aaf579be0a",
		"39013137aac6d404f518cfd46840647e",
		"78bfe706ca4cf5e9c5453e9f7cfd2b8b",
		"4c8d169a44e55c88d4a9a7f947424110",
		"92abbdf8b889e5c199d096e3f24788",
	))
}

/// Encode a value as a QUIC varint and append to buf.
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
	} else {
		let bytes = val.to_be_bytes();
		buf.push(0xc0 | bytes[0]);
		buf.extend_from_slice(&bytes[1..]);
	}
}

// =====================================================================
// Existing tests
// =====================================================================

#[test]
fn decrypt_rfc9001_v1_client_initial() {
	let packet = rfc9001_client_initial();
	assert_eq!(packet.len(), 1200);

	let header = parse_initial(&packet).unwrap();
	assert_eq!(header.version, 0x0000_0001);
	assert_eq!(header.dcid, hex_decode("8394c8f03e515708").as_slice());
	assert!(header.scid.is_empty());
	assert_eq!(header.payload.len(), 1182);

	let decrypted = decrypt_initial(&header).unwrap();
	assert!(!decrypted.is_empty());

	let frames = parse_crypto_frames(&decrypted).unwrap();
	assert!(!frames.is_empty());

	let stream = reassemble_crypto_stream(&frames);
	assert!(!stream.is_empty());

	// TLS ClientHello: type=0x01, version=0x0303
	assert_eq!(stream[0], 0x01);
	assert_eq!(&stream[4..6], &[0x03, 0x03]);
}

#[test]
fn decrypt_wrong_version_fails() {
	let packet = rfc9001_client_initial();
	let mut header = parse_initial(&packet).unwrap();
	header.version = 0xdeadbeef;

	assert!(decrypt_initial(&header).is_err());
}

#[test]
fn frame_parse_padding_only() {
	let decrypted = vec![0x00; 100];
	let frames = parse_crypto_frames(&decrypted).unwrap();
	assert!(frames.is_empty());
}

#[test]
fn frame_parse_single_crypto() {
	let mut payload = Vec::new();
	payload.push(0x06);
	payload.push(0x00);
	payload.push(0x05);
	payload.extend_from_slice(b"hello");
	let frames = parse_crypto_frames(&payload).unwrap();
	assert_eq!(frames.len(), 1);
	assert_eq!(frames[0].offset, 0);
	assert_eq!(frames[0].data, b"hello");
}

#[test]
fn frame_parse_multiple_crypto() {
	let mut payload = Vec::new();
	// First CRYPTO frame: offset=0, data="ab"
	payload.push(0x06);
	payload.push(0x00);
	payload.push(0x02);
	payload.extend_from_slice(b"ab");
	// PADDING
	payload.push(0x00);
	// Second CRYPTO frame: offset=2, data="cd"
	payload.push(0x06);
	payload.push(0x02);
	payload.push(0x02);
	payload.extend_from_slice(b"cd");

	let frames = parse_crypto_frames(&payload).unwrap();
	assert_eq!(frames.len(), 2);
}

#[test]
fn frame_parse_truncated_crypto() {
	let mut payload = Vec::new();
	payload.push(0x06);
	payload.push(0x00);
	payload.push(0x10);
	payload.extend_from_slice(&[0xaa; 5]);

	assert!(parse_crypto_frames(&payload).is_err());
}

#[test]
fn reassemble_in_order() {
	let frames = vec![
		CryptoFrame {
			offset: 0,
			data: b"hello".to_vec(),
		},
		CryptoFrame {
			offset: 5,
			data: b" world".to_vec(),
		},
	];
	assert_eq!(reassemble_crypto_stream(&frames), b"hello world");
}

#[test]
fn reassemble_out_of_order() {
	let frames = vec![
		CryptoFrame {
			offset: 5,
			data: b" world".to_vec(),
		},
		CryptoFrame {
			offset: 0,
			data: b"hello".to_vec(),
		},
	];
	assert_eq!(reassemble_crypto_stream(&frames), b"hello world");
}

#[test]
fn reassemble_with_gap() {
	let frames = vec![
		CryptoFrame {
			offset: 0,
			data: b"hello".to_vec(),
		},
		CryptoFrame {
			offset: 10,
			data: b"world".to_vec(),
		},
	];
	assert_eq!(reassemble_crypto_stream(&frames), b"hello");
}

#[test]
fn reassemble_overlapping() {
	let frames = vec![
		CryptoFrame {
			offset: 0,
			data: b"hello".to_vec(),
		},
		CryptoFrame {
			offset: 3,
			data: b"lo world".to_vec(),
		},
	];
	assert_eq!(reassemble_crypto_stream(&frames), b"hello world");
}

#[test]
fn reassemble_empty() {
	let frames: Vec<CryptoFrame> = Vec::new();
	assert!(reassemble_crypto_stream(&frames).is_empty());
}

#[test]
fn frame_stops_at_unknown_type() {
	let mut payload = Vec::new();
	payload.push(0x06);
	payload.push(0x00);
	payload.push(0x02);
	payload.extend_from_slice(b"ab");
	payload.push(0x10);
	payload.extend_from_slice(&[0xff; 20]);

	let frames = parse_crypto_frames(&payload).unwrap();
	assert_eq!(frames.len(), 1);
}

// =====================================================================
// New correct-path: decryption
// =====================================================================

#[test]
fn decrypt_rfc9001_verify_crypto_content() {
	let packet = rfc9001_client_initial();
	let header = parse_initial(&packet).unwrap();
	let decrypted = decrypt_initial(&header).unwrap();
	let frames = parse_crypto_frames(&decrypted).unwrap();
	let stream = reassemble_crypto_stream(&frames);

	// TLS ClientHello structure verification
	// Handshake type: ClientHello = 0x01
	assert_eq!(stream[0], 0x01);

	// Handshake length (3 bytes, big-endian)
	let handshake_len = u32::from_be_bytes([0x00, stream[1], stream[2], stream[3]]) as usize;
	assert_eq!(stream.len(), 4 + handshake_len);

	// Protocol version: TLS 1.2 (0x0303) — used in ClientHello for backward compat
	assert_eq!(&stream[4..6], &[0x03, 0x03]);

	// 32 bytes of random follow version
	let random = &stream[6..38];
	assert_eq!(random.len(), 32);

	// Session ID length byte at offset 38
	let session_id_len = stream[38] as usize;
	// Cipher suites start after session ID
	let cipher_suites_offset = 39 + session_id_len;
	// Cipher suites length (2 bytes, big-endian)
	let cipher_suites_len = u16::from_be_bytes([
		stream[cipher_suites_offset],
		stream[cipher_suites_offset + 1],
	]) as usize;
	// Each cipher suite is 2 bytes; must have at least one
	assert!(cipher_suites_len >= 2);
	assert_eq!(cipher_suites_len % 2, 0);
}

// =====================================================================
// New correct-path: frame parsing
// =====================================================================

#[test]
fn frame_parse_ping() {
	// PING frame (0x01) should be skipped, followed by a CRYPTO frame
	let mut payload = Vec::new();
	payload.push(0x01); // PING
	payload.push(0x06); // CRYPTO
	payload.push(0x00); // offset = 0
	payload.push(0x03); // length = 3
	payload.extend_from_slice(b"abc");

	let frames = parse_crypto_frames(&payload).unwrap();
	assert_eq!(frames.len(), 1);
	assert_eq!(frames[0].data, b"abc");
}

#[test]
fn frame_parse_ack() {
	// ACK frame (0x02) followed by a CRYPTO frame
	let mut payload = Vec::new();
	// ACK frame type
	payload.push(0x02);
	// Largest Acknowledged = 10
	payload.push(10);
	// ACK Delay = 5
	payload.push(5);
	// ACK Range Count = 0
	payload.push(0);
	// First ACK Range = 0
	payload.push(0);
	// CRYPTO frame after ACK
	payload.push(0x06);
	payload.push(0x00); // offset = 0
	payload.push(0x02); // length = 2
	payload.extend_from_slice(b"hi");

	let frames = parse_crypto_frames(&payload).unwrap();
	assert_eq!(frames.len(), 1);
	assert_eq!(frames[0].data, b"hi");
}

#[test]
fn frame_parse_ack_ecn() {
	// ACK_ECN frame (0x03) + 3 ECN counts, followed by CRYPTO
	let mut payload = Vec::new();
	// ACK_ECN frame type
	payload.push(0x03);
	// Largest Acknowledged = 20
	payload.push(20);
	// ACK Delay = 3
	payload.push(3);
	// ACK Range Count = 0
	payload.push(0);
	// First ACK Range = 5
	payload.push(5);
	// ECN Counts: ECT0 = 1, ECT1 = 2, ECN-CE = 3
	payload.push(1);
	payload.push(2);
	payload.push(3);
	// CRYPTO frame
	payload.push(0x06);
	payload.push(0x00); // offset = 0
	payload.push(0x04); // length = 4
	payload.extend_from_slice(b"test");

	let frames = parse_crypto_frames(&payload).unwrap();
	assert_eq!(frames.len(), 1);
	assert_eq!(frames[0].data, b"test");
}

#[test]
fn frame_parse_ack_with_ranges() {
	// ACK frame with range_count > 0 (multiple Gap+Range pairs)
	let mut payload = Vec::new();
	// ACK frame type
	payload.push(0x02);
	// Largest Acknowledged = 50
	payload.push(50);
	// ACK Delay = 10
	payload.push(10);
	// ACK Range Count = 2
	payload.push(2);
	// First ACK Range = 3
	payload.push(3);
	// Range 1: Gap = 2, ACK Range Length = 1
	payload.push(2);
	payload.push(1);
	// Range 2: Gap = 5, ACK Range Length = 0
	payload.push(5);
	payload.push(0);
	// CRYPTO frame after ACK
	payload.push(0x06);
	payload.push(0x00);
	payload.push(0x03);
	payload.extend_from_slice(b"ack");

	let frames = parse_crypto_frames(&payload).unwrap();
	assert_eq!(frames.len(), 1);
	assert_eq!(frames[0].data, b"ack");
}

#[test]
fn frame_parse_empty_payload() {
	let frames = parse_crypto_frames(&[]).unwrap();
	assert!(frames.is_empty());
}

#[test]
fn frame_parse_crypto_zero_length() {
	// CRYPTO frame with offset=0, length=0 → valid frame with empty data
	let mut payload = Vec::new();
	payload.push(0x06); // CRYPTO
	payload.push(0x00); // offset = 0
	payload.push(0x00); // length = 0

	let frames = parse_crypto_frames(&payload).unwrap();
	assert_eq!(frames.len(), 1);
	assert_eq!(frames[0].offset, 0);
	assert!(frames[0].data.is_empty());
}

#[test]
fn frame_parse_crypto_large_offset() {
	// CRYPTO frame with a 4-byte varint offset
	let mut payload = Vec::new();
	payload.push(0x06); // CRYPTO
	// offset = 16384 (requires 4-byte varint: 0x80 0x00 0x40 0x00)
	push_varint(&mut payload, 16384);
	payload.push(0x03); // length = 3
	payload.extend_from_slice(b"big");

	let frames = parse_crypto_frames(&payload).unwrap();
	assert_eq!(frames.len(), 1);
	assert_eq!(frames[0].offset, 16384);
	assert_eq!(frames[0].data, b"big");
}

// =====================================================================
// New correct-path: reassembly
// =====================================================================

#[test]
fn reassemble_single_frame() {
	let frames = vec![CryptoFrame {
		offset: 0,
		data: b"single".to_vec(),
	}];
	assert_eq!(reassemble_crypto_stream(&frames), b"single");
}

#[test]
fn reassemble_single_frame_nonzero_offset() {
	// Single frame with offset > 0 → gap from 0, returns empty
	let frames = vec![CryptoFrame {
		offset: 5,
		data: b"later".to_vec(),
	}];
	assert!(reassemble_crypto_stream(&frames).is_empty());
}

#[test]
fn reassemble_exact_duplicate() {
	// Two identical frames (offset=0, same data) → deduplicated
	let frames = vec![
		CryptoFrame {
			offset: 0,
			data: b"dup".to_vec(),
		},
		CryptoFrame {
			offset: 0,
			data: b"dup".to_vec(),
		},
	];
	assert_eq!(reassemble_crypto_stream(&frames), b"dup");
}

#[test]
fn reassemble_three_contiguous() {
	let frames = vec![
		CryptoFrame {
			offset: 0,
			data: b"aaa".to_vec(),
		},
		CryptoFrame {
			offset: 3,
			data: b"bbb".to_vec(),
		},
		CryptoFrame {
			offset: 6,
			data: b"ccc".to_vec(),
		},
	];
	assert_eq!(reassemble_crypto_stream(&frames), b"aaabbbccc");
}

#[test]
fn reassemble_overlap_mismatch() {
	// Overlapping region has different data → stops at mismatch point
	let frames = vec![
		CryptoFrame {
			offset: 0,
			data: b"hello".to_vec(),
		},
		CryptoFrame {
			offset: 3,
			data: b"XX world".to_vec(),
		},
	];
	// "lo" vs "XX" at overlap → mismatch, reassembly stops
	let result = reassemble_crypto_stream(&frames);
	assert_eq!(result, b"hello");
}

#[test]
fn reassemble_contained_frame() {
	// Frame B is completely contained within frame A, data matches
	let frames = vec![
		CryptoFrame {
			offset: 0,
			data: b"abcdef".to_vec(),
		},
		CryptoFrame {
			offset: 1,
			data: b"bcde".to_vec(),
		},
	];
	// B is fully covered by A (skip=5 >= B.data.len()=4), nothing new appended
	assert_eq!(reassemble_crypto_stream(&frames), b"abcdef");
}

#[test]
fn reassemble_contained_frame_mismatch() {
	// Frame B is fully contained in A but data doesn't match → stops
	let frames = vec![
		CryptoFrame {
			offset: 0,
			data: b"abcdef".to_vec(),
		},
		CryptoFrame {
			offset: 1,
			data: b"XXXX".to_vec(),
		},
	];
	// Overlap check: stream[1..5] = "bcde" vs frame.data[0..4] = "XXXX" → mismatch
	let result = reassemble_crypto_stream(&frames);
	assert_eq!(result, b"abcdef");
}

// =====================================================================
// New error-path: decryption
// =====================================================================

#[test]
fn decrypt_payload_too_short() {
	// Payload less than 20 bytes → BufferTooShort
	let packet = rfc9001_client_initial();
	let mut header = parse_initial(&packet).unwrap();
	// Replace payload with something too short for header protection removal
	let short_payload = [0u8; 10];
	header.payload = &short_payload;

	assert!(matches!(
		decrypt_initial(&header),
		Err(Error::BufferTooShort { need: 20, have: 10 })
	));
}

#[test]
fn decrypt_corrupted_payload() {
	// Modify 1 byte of ciphertext → DecryptionFailed
	let mut packet = rfc9001_client_initial();
	// Corrupt a byte in the encrypted payload area (well past header protection sample)
	let payload_start = packet.len() - 100;
	packet[payload_start] ^= 0xff;

	let header = parse_initial(&packet).unwrap();
	assert!(matches!(
		decrypt_initial(&header),
		Err(Error::DecryptionFailed(_))
	));
}

#[test]
fn decrypt_wrong_dcid() {
	// Using a different DCID causes different key derivation → DecryptionFailed
	let packet = rfc9001_client_initial();
	let mut header = parse_initial(&packet).unwrap();
	let wrong_dcid = [0xff; 8];
	header.dcid = &wrong_dcid;

	assert!(matches!(
		decrypt_initial(&header),
		Err(Error::DecryptionFailed(_))
	));
}

#[test]
fn decrypt_version_zero() {
	// version = 0x00000000 → UnsupportedVersion
	let packet = rfc9001_client_initial();
	let mut header = parse_initial(&packet).unwrap();
	header.version = 0x0000_0000;

	assert!(matches!(
		decrypt_initial(&header),
		Err(Error::UnsupportedVersion(0x0000_0000))
	));
}

#[test]
fn decrypt_version_draft() {
	// Draft version → UnsupportedVersion
	let packet = rfc9001_client_initial();
	let mut header = parse_initial(&packet).unwrap();
	header.version = 0xff00_0020;

	assert!(matches!(
		decrypt_initial(&header),
		Err(Error::UnsupportedVersion(0xff00_0020))
	));
}

// =====================================================================
// New error-path: frame parsing
// =====================================================================

#[test]
fn frame_parse_truncated_offset() {
	// CRYPTO frame type byte then immediate truncation (no offset varint)
	let payload = [0x06]; // just the frame type, nothing else
	assert!(parse_crypto_frames(&payload).is_err());
}

#[test]
fn frame_parse_truncated_length() {
	// CRYPTO frame type + offset but no length varint
	let payload = [0x06, 0x00]; // type + offset, missing length
	assert!(parse_crypto_frames(&payload).is_err());
}

#[test]
fn frame_parse_ack_truncated() {
	// ACK frame that truncates after range_count (missing First ACK Range)
	let mut payload = Vec::new();
	payload.push(0x02); // ACK
	payload.push(10); // Largest Acknowledged
	payload.push(5); // ACK Delay
	payload.push(0); // ACK Range Count = 0
	// Missing First ACK Range → truncation error

	assert!(parse_crypto_frames(&payload).is_err());
}

#[test]
fn frame_parse_ack_ecn_truncated() {
	// ACK_ECN frame with ACK part complete but ECN counts truncated
	let mut payload = Vec::new();
	payload.push(0x03); // ACK_ECN
	payload.push(10); // Largest Acknowledged
	payload.push(5); // ACK Delay
	payload.push(0); // ACK Range Count = 0
	payload.push(0); // First ACK Range
	// ECN Counts: only 2 out of 3 provided → truncation
	payload.push(1); // ECT0
	payload.push(2); // ECT1
	// Missing ECN-CE

	assert!(parse_crypto_frames(&payload).is_err());
}
