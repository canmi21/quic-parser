/* src/crypto.rs */

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

use crate::error::Error;
use crate::header::InitialHeader;

const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;

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

fn build_hkdf_label(label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, Error> {
	let full_label_len = 6 + label.len();
	let total = 2 + 1 + full_label_len + 1 + context.len();
	let mut out = Vec::with_capacity(total);
	let len_u16 =
		u16::try_from(len).map_err(|_| Error::DecryptionFailed("HKDF output length overflow".into()))?;
	let label_u8 = u8::try_from(full_label_len)
		.map_err(|_| Error::DecryptionFailed("HKDF label length overflow".into()))?;
	let ctx_u8 = u8::try_from(context.len())
		.map_err(|_| Error::DecryptionFailed("HKDF context length overflow".into()))?;
	out.extend_from_slice(&len_u16.to_be_bytes());
	out.push(label_u8);
	out.extend_from_slice(b"tls13 ");
	out.extend_from_slice(label);
	out.push(ctx_u8);
	out.extend_from_slice(context);
	Ok(out)
}

fn remove_header_protection(
	first_byte: u8,
	payload: &[u8],
	hp_key: &[u8],
) -> Result<(u64, usize, u8), Error> {
	if payload.len() < 20 {
		return Err(Error::BufferTooShort {
			need: 20,
			have: payload.len(),
		});
	}

	let cipher =
		Aes128::new_from_slice(hp_key).map_err(|e| Error::DecryptionFailed(format!("HP key: {e}")))?;
	let mut mask = [0u8; 16];
	mask.copy_from_slice(&payload[4..20]);
	cipher.encrypt_block(GenericArray::from_mut_slice(&mut mask));

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

#[cfg(feature = "ring")]
mod backend {
	use crate::error::Error;
	use ring::{aead, hkdf};

	struct HkdfLen(usize);

	impl hkdf::KeyType for HkdfLen {
		fn len(&self) -> usize {
			self.0
		}
	}

	pub(super) fn derive_client_initial_secret(salt: &[u8], dcid: &[u8]) -> Result<Vec<u8>, Error> {
		let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
		let initial_secret = salt.extract(dcid);
		let label = super::build_hkdf_label(b"client in", &[], 32)?;
		expand_prk(&initial_secret, &label, 32)
	}

	pub(super) fn hkdf_expand_label(
		secret: &[u8],
		label: &[u8],
		len: usize,
	) -> Result<Vec<u8>, Error> {
		let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
		let info = super::build_hkdf_label(label, &[], len)?;
		expand_prk(&prk, &info, len)
	}

	fn expand_prk(prk: &hkdf::Prk, info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
		let mut out = vec![0u8; len];
		prk
			.expand(&[info], HkdfLen(len))
			.and_then(|okm| okm.fill(&mut out))
			.map_err(|_| Error::DecryptionFailed("HKDF expand failed".into()))?;
		Ok(out)
	}

	pub(super) fn aead_open(
		key: &[u8],
		nonce_bytes: &[u8; 12],
		aad: &[u8],
		ciphertext: &[u8],
	) -> Result<Vec<u8>, Error> {
		let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, key)
			.map_err(|_| Error::DecryptionFailed("invalid AES-GCM key".into()))?;
		let opening_key = aead::LessSafeKey::new(unbound);
		let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
			.map_err(|_| Error::DecryptionFailed("invalid nonce".into()))?;
		let mut buf = ciphertext.to_vec();
		let plaintext_len = opening_key
			.open_in_place(nonce, aead::Aad::from(aad), &mut buf)
			.map_err(|_| Error::DecryptionFailed("AEAD decryption failed".into()))?
			.len();
		buf.truncate(plaintext_len);
		Ok(buf)
	}
}

#[cfg(feature = "aws-lc-rs")]
mod backend {
	use crate::error::Error;
	use aws_lc_rs::{aead, hkdf};

	struct HkdfLen(usize);

	impl hkdf::KeyType for HkdfLen {
		fn len(&self) -> usize {
			self.0
		}
	}

	pub(super) fn derive_client_initial_secret(salt: &[u8], dcid: &[u8]) -> Result<Vec<u8>, Error> {
		let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
		let initial_secret = salt.extract(dcid);
		let label = super::build_hkdf_label(b"client in", &[], 32)?;
		expand_prk(&initial_secret, &label, 32)
	}

	pub(super) fn hkdf_expand_label(
		secret: &[u8],
		label: &[u8],
		len: usize,
	) -> Result<Vec<u8>, Error> {
		let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
		let info = super::build_hkdf_label(label, &[], len)?;
		expand_prk(&prk, &info, len)
	}

	fn expand_prk(prk: &hkdf::Prk, info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
		let mut out = vec![0u8; len];
		prk
			.expand(&[info], HkdfLen(len))
			.and_then(|okm| okm.fill(&mut out))
			.map_err(|_| Error::DecryptionFailed("HKDF expand failed".into()))?;
		Ok(out)
	}

	pub(super) fn aead_open(
		key: &[u8],
		nonce_bytes: &[u8; 12],
		aad: &[u8],
		ciphertext: &[u8],
	) -> Result<Vec<u8>, Error> {
		let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, key)
			.map_err(|_| Error::DecryptionFailed("invalid AES-GCM key".into()))?;
		let opening_key = aead::LessSafeKey::new(unbound);
		let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
			.map_err(|_| Error::DecryptionFailed("invalid nonce".into()))?;
		let mut buf = ciphertext.to_vec();
		let plaintext_len = opening_key
			.open_in_place(nonce, aead::Aad::from(aad), &mut buf)
			.map_err(|_| Error::DecryptionFailed("AEAD decryption failed".into()))?
			.len();
		buf.truncate(plaintext_len);
		Ok(buf)
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

	let client_secret = backend::derive_client_initial_secret(params.salt, header.dcid)?;
	let key = backend::hkdf_expand_label(&client_secret, params.key_label, 16)?;
	let iv = backend::hkdf_expand_label(&client_secret, params.iv_label, 12)?;
	let hp = backend::hkdf_expand_label(&client_secret, params.hp_label, 16)?;

	let (pn, pn_len, unprotected_first) =
		remove_header_protection(header.first_byte, header.payload, &hp)?;

	let mut aad = Vec::with_capacity(header.header_bytes.len() + pn_len);
	aad.push(unprotected_first);
	aad.extend_from_slice(&header.header_bytes[1..]);
	for i in 0..pn_len {
		aad.push((pn >> (8 * (pn_len - 1 - i))) as u8);
	}

	let mut nonce = <[u8; 12]>::try_from(iv.as_slice())
		.map_err(|_| Error::DecryptionFailed("unexpected IV length".into()))?;
	let pn_offset = 12 - pn_len;
	for i in 0..pn_len {
		nonce[pn_offset + i] ^= (pn >> (8 * (pn_len - 1 - i))) as u8;
	}

	let encrypted_payload = &header.payload[pn_len..];

	#[cfg(feature = "tracing")]
	tracing::debug!(
		version = header.version,
		dcid_len = header.dcid.len(),
		payload_len = encrypted_payload.len(),
		"decrypting QUIC Initial packet"
	);

	backend::aead_open(&key, &nonce, &aad, encrypted_payload)
}
