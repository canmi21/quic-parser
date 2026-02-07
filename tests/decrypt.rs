#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]
/* tests/decrypt.rs */
#![allow(missing_docs)]

use quic_parser::{
	CryptoFrame, decrypt_initial, parse_crypto_frames, parse_initial, reassemble_crypto_stream,
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

#[test]
fn decrypt_rfc9001_v1_client_initial() {
	let packet = rfc9001_client_initial();
	assert_eq!(packet.len(), 1200);

	let header = parse_initial(&packet).unwrap();
	assert_eq!(header.version, 0x0000_0001);
	assert_eq!(header.dcid, hex_decode("8394c8f03e515708").as_slice());
	assert!(header.scid.is_empty());
	assert_eq!(header.payload.len(), 1182);

	let decrypted = decrypt_initial(&packet, &header).unwrap();
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

	assert!(decrypt_initial(&packet, &header).is_err());
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
