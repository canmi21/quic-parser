/* src/crypto.rs */

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit, array::Array};

use crate::error::Error;
use crate::header::InitialHeader;

use crate::header::{QUIC_V1, QUIC_V2};

const INITIAL_SALT_V1: [u8; 20] = [
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
];

const INITIAL_SALT_V2: [u8; 20] = [
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9,
];

struct VersionParams {
	salt: &'static [u8; 20],
	key_label: &'static [u8],
	iv_label: &'static [u8],
	hp_label: &'static [u8],
}

fn version_params(version: u32) -> Result<VersionParams, Error> {
	match version {
		QUIC_V1 => Ok(VersionParams {
			salt: &INITIAL_SALT_V1,
			key_label: b"quic key",
			iv_label: b"quic iv",
			hp_label: b"quic hp",
		}),
		QUIC_V2 => Ok(VersionParams {
			salt: &INITIAL_SALT_V2,
			key_label: b"quicv2 key",
			iv_label: b"quicv2 iv",
			hp_label: b"quicv2 hp",
		}),
		_ => Err(Error::UnsupportedVersion(version)),
	}
}

fn remove_header_protection(
	first_byte: u8,
	payload: &[u8],
	hp_key: &[u8; 16],
) -> Result<(u64, usize, u8), Error> {
	if payload.len() < 20 {
		return Err(Error::BufferTooShort {
			need: 20,
			have: payload.len(),
		});
	}

	let cipher = Aes128::new(Array::cast_from_core(hp_key));
	let mut mask = [0u8; 16];
	mask.copy_from_slice(&payload[4..20]);
	cipher.encrypt_block(Array::cast_from_core_mut(&mut mask));

	let unprotected_first = first_byte ^ (mask[0] & 0x0f);
	let pn_len = usize::from((unprotected_first & 0x03) + 1);

	if pn_len > payload.len() {
		return Err(Error::BufferTooShort {
			need: pn_len,
			have: payload.len(),
		});
	}

	let mut pn = 0u64;
	for i in 0..pn_len {
		pn = (pn << 8) | u64::from(payload[i] ^ mask[1 + i]);
	}

	Ok((pn, pn_len, unprotected_first))
}

mod backend {
	use crate::error::Error;

	#[cfg(feature = "ring")]
	use ring::{aead, hkdf};
	#[cfg(feature = "aws-lc-rs")]
	use aws_lc_rs::{aead, hkdf};

	struct HkdfLen(usize);

	impl hkdf::KeyType for HkdfLen {
		fn len(&self) -> usize {
			self.0
		}
	}

	pub(super) fn derive_client_initial_secret(salt: &[u8], dcid: &[u8], out: &mut [u8; 32]) -> Result<(), Error> {
		let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
		let initial_secret = salt.extract(dcid);
		expand_prk(initial_secret, b"client in", out)
	}

	pub(super) fn hkdf_expand_label<const LEN: usize>(
		secret: &[u8],
		label: &'static [u8],
		out: &mut [u8; LEN],
	) -> Result<(), Error> {
		let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
		expand_prk(prk, label, out)
	}

	fn expand_prk<const LEN: usize>(prk: hkdf::Prk, label: &'static [u8], out: &mut [u8; LEN]) -> Result<(), Error> {
		assert!(LEN <= u16::MAX as usize);
		assert!(label.len() <= (u8::MAX-6) as usize);
		prk
			.expand(&[
				&(LEN as u16).to_be_bytes(),
				&[6+label.len() as u8],
				b"tls13 ",
				label,
				&[0],
			], HkdfLen(LEN))
			.and_then(|okm| okm.fill(out))
			.map_err(|e| Error::DecryptionFailed(e.to_string()))
	}

	pub(super) fn aead_open(
		key: &[u8; 16],
		nonce_bytes: [u8; 12],
		aad: &[u8],
		buf: &mut Vec<u8>,
	) -> Result<(), Error> {
		let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, key)
			.map_err(|e| Error::DecryptionFailed(e.to_string()))?;
		let opening_key = aead::LessSafeKey::new(unbound);
		let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
		let plaintext_len = opening_key
			.open_in_place(nonce, aead::Aad::from(aad), buf)
			.map_err(|e| Error::DecryptionFailed(e.to_string()))?
			.len();
		buf.truncate(plaintext_len);
		Ok(())
	}
}

/// Decrypt a QUIC Initial packet payload.
///
/// Performs header protection removal (AES-ECB), key derivation (HKDF-SHA256),
/// and AEAD decryption (AES-128-GCM). Supports both QUIC v1 (RFC 9001) and
/// v2 (RFC 9369).
///
/// The returned bytes contain the decrypted frames (PADDING, CRYPTO, ACK, etc.).
///
/// # Errors
///
/// Returns [`Error::UnsupportedVersion`] if the version is not v1 or v2.
/// Returns [`Error::DecryptionFailed`] if any cryptographic operation fails.
/// Returns [`Error::BufferTooShort`] if the payload is too short for header
/// protection removal.
pub fn decrypt_initial(header: &InitialHeader<'_>) -> Result<Vec<u8>, Error> {
	let params = version_params(header.version)?;

	let mut client_secret = [0_u8; 32];
	let mut key = [0_u8; 16];
	let mut iv = [0_u8; 12];
	let mut hp = [0_u8; 16];

	backend::derive_client_initial_secret(params.salt, header.dcid, &mut client_secret)?;
	backend::hkdf_expand_label(&client_secret, params.key_label, &mut key)?;
	backend::hkdf_expand_label(&client_secret, params.iv_label, &mut iv)?;
	backend::hkdf_expand_label(&client_secret, params.hp_label, &mut hp)?;

	let (pn, pn_len, unprotected_first) =
		remove_header_protection(header.first_byte, header.payload, &hp)?;

	let mut aad = Vec::with_capacity(header.header_bytes.len() + pn_len);
	aad.push(unprotected_first);
	aad.extend_from_slice(&header.header_bytes[1..]);
	for i in 0..pn_len {
		aad.push((pn >> (8 * (pn_len - 1 - i))) as u8);
	}

	let mut nonce = iv;
	let pn_offset = 12 - pn_len;
	for i in 0..pn_len {
		nonce[pn_offset + i] ^= (pn >> (8 * (pn_len - 1 - i))) as u8;
	}

	let mut payload = header.payload[pn_len..].to_vec();

	#[cfg(feature = "tracing")]
	tracing::debug!(
		version = header.version,
		dcid_len = header.dcid.len(),
		payload_len = payload.len(),
		"decrypting QUIC Initial packet"
	);

	backend::aead_open(&key, nonce, &aad, &mut payload)?;
	Ok(payload)
}
