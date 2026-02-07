/* examples/parse_header.rs */

#![allow(missing_docs)]

// Demonstrates parsing a QUIC Initial packet header without any crypto
// dependency. This example works with all feature configurations including
// `--no-default-features`.

fn main() {
	// A minimal QUIC v1 Initial packet (truncated payload).
	// In practice this would come from a UDP socket.
	let packet: Vec<u8> = build_sample_initial();

	match quic_parser::parse_initial(&packet) {
		Ok(header) => {
			println!("QUIC Initial packet parsed successfully");
			println!("  version:      {:#010x}", header.version);
			println!("  dcid:         {}", hex(header.dcid));
			println!("  scid:         {}", hex(header.scid));
			println!("  token length: {}", header.token.len());
			println!("  payload size: {} bytes", header.payload.len());
		}
		Err(e) => {
			eprintln!("parse error: {e}");
		}
	}

	// Peek at the DCID without a full parse.
	if let Some(dcid) = quic_parser::peek_long_header_dcid(&packet) {
		println!("  peeked dcid:  {}", hex(dcid));
	}
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn build_sample_initial() -> Vec<u8> {
	let mut pkt = Vec::new();

	// First byte: long header (0x80) | fixed bit (0x40) | Initial type (0x00)
	// Lower 4 bits are reserved / packet number length (protected).
	pkt.push(0xc0);

	// Version: QUIC v1
	pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());

	// DCID length + DCID (8 bytes)
	let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
	pkt.push(dcid.len() as u8);
	pkt.extend_from_slice(&dcid);

	// SCID length + SCID (0 bytes)
	pkt.push(0x00);

	// Token length (varint 0)
	pkt.push(0x00);

	// Payload length (varint): 24 bytes of dummy payload.
	let payload_len: u8 = 24;
	pkt.push(payload_len);

	// Dummy encrypted payload (not decryptable, just for header parsing).
	pkt.extend_from_slice(&vec![0xAA; payload_len as usize]);

	pkt
}
