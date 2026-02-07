/* src/lib.rs */

//! Zero-copy QUIC Initial packet parser with optional payload decryption.
//!
//! This crate provides three layers of functionality:
//!
//! **Layer 1 — Header parsing** (always available, zero dependencies beyond `thiserror`):
//! parse QUIC Initial packet headers, peek at connection IDs, and decode varints.
//!
//! **Layer 2 — Decryption** (requires `ring` or `aws-lc-rs` feature):
//! derive keys and decrypt Initial packet payloads for QUIC v1 and v2.
//!
//! **Layer 3 — Frame extraction** (requires `ring` or `aws-lc-rs` feature):
//! extract CRYPTO frames from decrypted payloads and reassemble them into a
//! contiguous byte stream suitable for TLS ClientHello parsing.

#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
compile_error!(
	"features `ring` and `aws-lc-rs` are mutually exclusive; enable only one crypto backend"
);

mod error;
mod header;
mod varint;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
mod crypto;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
mod frame;

pub use error::Error;
pub use header::{InitialHeader, parse_initial, peek_long_header_dcid, peek_short_header_dcid};
pub use varint::read_varint;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub use crypto::decrypt_initial;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub use frame::{CryptoFrame, parse_crypto_frames, reassemble_crypto_stream};
