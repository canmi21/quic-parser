# Quic Parser

Zero-copy QUIC Initial packet parser with optional payload decryption.

`quic-parser` extracts headers, connection IDs, and tokens from QUIC Initial packets without allocating. When a crypto backend is enabled, it can also decrypt payloads and reassemble CRYPTO frames for both QUIC v1 (RFC 9001) and v2 (RFC 9369).

## Features

- **Header Parsing**: Zero-copy parsing of QUIC Initial packet headers with no crypto dependencies.
- **Connection ID Peek**: Fast extraction of Destination Connection IDs from both Long and Short Header packets.
- **VarInt Decoding**: QUIC variable-length integer decoder (RFC 9000 Section 16).
- **Payload Decryption**: HKDF-SHA256 key derivation, AES-ECB header protection removal, and AES-128-GCM AEAD decryption.
- **Frame Extraction**: Parse CRYPTO frames from decrypted payloads and reassemble them into a contiguous byte stream.
- **Dual Crypto Backend**: Choose between `ring` and `aws-lc-rs` as the cryptographic provider.

## Usage Examples

Check the `examples` directory for runnable code:

- **Header Only**: [`examples/parse_header.rs`](examples/parse_header.rs) - Parse headers and peek at connection IDs without crypto.
- **Full Decrypt**: [`examples/decrypt_initial.rs`](examples/decrypt_initial.rs) - Decrypt a QUIC v1 Initial packet and extract the TLS ClientHello.

## Installation

```toml
[dependencies]
quic-parser = { version = "0.1", features = ["full"] }
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `ring` | Enables decryption using `ring` as the crypto backend (default). |
| `aws-lc-rs` | Enables decryption using `aws-lc-rs` as the crypto backend. |
| `tracing` | Enables optional tracing instrumentation for debugging. |
| `full` | Enables all features above. |

## License

Released under the MIT License © 2026 [Canmi](https://github.com/canmi21)
