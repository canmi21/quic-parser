/// Errors that can occur during QUIC packet parsing and decryption.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// The input buffer is shorter than required.
	#[error("buffer too short: need at least {need} bytes, have {have}")]
	BufferTooShort {
		/// Minimum number of bytes required.
		need: usize,
		/// Actual number of bytes available.
		have: usize,
	},

	/// The packet does not have the long header form bit set.
	#[error("not a QUIC long header packet")]
	NotLongHeader,

	/// The packet is a long header but not an Initial packet.
	#[error("not an Initial packet (type bits: {0:#04x})")]
	NotInitialPacket(u8),

	/// A connection ID length field exceeds the protocol maximum of 20 bytes.
	#[error("connection ID length {0} exceeds maximum of 20")]
	InvalidCidLength(u8),

	/// The QUIC version is not supported for decryption.
	#[error("unsupported QUIC version for decryption: {0:#010x}")]
	UnsupportedVersion(u32),

	/// AEAD decryption or key derivation failed.
	#[error("decryption failed: {0}")]
	DecryptionFailed(String),

	/// A CRYPTO frame was truncated before its declared length.
	#[error("truncated CRYPTO frame at offset {offset}")]
	TruncatedFrame {
		/// The byte offset within the decrypted payload where truncation occurred.
		offset: u64,
	},

	/// The variable-length integer encoding is malformed.
	#[error("invalid varint encoding")]
	InvalidVarint,
}
