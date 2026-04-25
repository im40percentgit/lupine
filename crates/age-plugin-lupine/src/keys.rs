//! Bech32 key encoding/decoding for age-compatible recipient and identity strings.
//!
//! - **Recipient** (public key): `age1lupine1<bech32_lower_no_checksum>`
//! - **Identity** (secret key): `AGE-PLUGIN-LUPINE-1<BECH32_UPPER_NO_CHECKSUM>`
//!
//! Identity encoding stores `sk_bytes || pk_bytes` so that the ML-KEM public
//! key cache can be restored on decode (required for KitchenSink combining
//! during decapsulation).
//!
//! @decision DEC-AGE-KEYS-001
//! @title Identity payload includes public key for decapsulation support
//! @status accepted
//! @rationale `HybridKemSecretKey768::from_bytes` leaves `mlkem_pk_bytes` empty,
//!   which causes `decapsulate` to fail with `InvalidKey`. By encoding the full
//!   public key alongside the secret key in the identity string, we can call
//!   `set_mlkem_pk_bytes` during decode and restore full decapsulation capability.
//!   The payload format is `sk_bytes (2464) || pk_bytes (1216)` = 3680 bytes.

use anyhow::{bail, Context, Result};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Hrp, NoChecksum};
use lupine_kem::hybrid::{HybridKemPublicKey768, HybridKemSecretKey768};

/// Human-readable part for recipient (public key) strings.
const RECIPIENT_HRP: &str = "age1lupine1";

/// Human-readable part for identity (secret key) strings (lowercase for encoding).
const IDENTITY_HRP: &str = "age-plugin-lupine-1";

/// Encode a hybrid public key as an age recipient string.
///
/// Format: `age1lupine1<bech32_lowercase_no_checksum>`
pub fn encode_recipient(pk: &HybridKemPublicKey768) -> String {
    let hrp = Hrp::parse(RECIPIENT_HRP).expect("valid HRP");
    let pk_bytes = pk.to_bytes();
    bech32::encode::<NoChecksum>(hrp, &pk_bytes).expect("bech32 encode cannot fail with NoChecksum")
}

/// Decode an age recipient string back to a hybrid public key.
///
/// Accepts lowercase `age1lupine1...` strings.
///
/// # Errors
///
/// Returns an error if the string is not valid bech32, has the wrong HRP,
/// or the decoded bytes are not a valid hybrid public key.
pub fn decode_recipient(s: &str) -> Result<HybridKemPublicKey768> {
    let s_lower = s.to_lowercase();
    let checked =
        CheckedHrpstring::new::<NoChecksum>(&s_lower).context("invalid bech32 recipient string")?;

    let hrp = checked.hrp();
    let expected = Hrp::parse(RECIPIENT_HRP).expect("valid HRP");
    if hrp != expected {
        bail!(
            "wrong HRP: expected '{}', got '{}'",
            RECIPIENT_HRP,
            hrp.as_str()
        );
    }

    let data: Vec<u8> = checked.byte_iter().collect();
    HybridKemPublicKey768::from_bytes(&data).context("invalid hybrid public key bytes")
}

/// Encode a hybrid secret key as an age identity string.
///
/// Format: `AGE-PLUGIN-LUPINE-1<BECH32_UPPERCASE_NO_CHECKSUM>`
///
/// The encoded payload is `sk_bytes || pk_bytes` so that the ML-KEM public
/// key cache can be restored on decode.
pub fn encode_identity(sk: &HybridKemSecretKey768, pk: &HybridKemPublicKey768) -> String {
    let hrp = Hrp::parse(IDENTITY_HRP).expect("valid HRP");
    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();
    let mut payload = Vec::with_capacity(sk_bytes.len() + pk_bytes.len());
    payload.extend_from_slice(&sk_bytes);
    payload.extend_from_slice(&pk_bytes);
    let encoded = bech32::encode::<NoChecksum>(hrp, &payload)
        .expect("bech32 encode cannot fail with NoChecksum");
    encoded.to_uppercase()
}

/// Decode an age identity string back to a hybrid secret key.
///
/// Accepts uppercase `AGE-PLUGIN-LUPINE-1...` strings.
///
/// # Errors
///
/// Returns an error if the string is not valid bech32, has the wrong HRP,
/// or the decoded bytes are not a valid hybrid secret key.
pub fn decode_identity(s: &str) -> Result<HybridKemSecretKey768> {
    let s_lower = s.to_lowercase();
    let checked =
        CheckedHrpstring::new::<NoChecksum>(&s_lower).context("invalid bech32 identity string")?;

    let hrp = checked.hrp();
    let expected = Hrp::parse(IDENTITY_HRP).expect("valid HRP");
    if hrp != expected {
        bail!(
            "wrong HRP: expected '{}', got '{}'",
            IDENTITY_HRP,
            hrp.as_str()
        );
    }

    let data: Vec<u8> = checked.byte_iter().collect();

    // The payload is sk_bytes || pk_bytes.
    // SK for ML-KEM-768 hybrid: 32 (x25519 sk) + 32 (x25519 pk) + 2400 (ml-kem-768 dk) = 2464
    // PK for ML-KEM-768 hybrid: 32 (x25519 pk) + 1184 (ml-kem-768 ek) = 1216
    const SK_LEN: usize = 2464;
    const PK_LEN: usize = 1216;
    if data.len() != SK_LEN + PK_LEN {
        bail!(
            "identity payload wrong length: expected {}, got {}",
            SK_LEN + PK_LEN,
            data.len()
        );
    }

    let sk_bytes = &data[..SK_LEN];
    let pk_bytes = &data[SK_LEN..];

    let mut sk =
        HybridKemSecretKey768::from_bytes(sk_bytes).context("invalid hybrid secret key bytes")?;

    // Restore the ML-KEM public key bytes needed for KitchenSink combining.
    // The pk_bytes contain 32 bytes X25519 pk + 1184 bytes ML-KEM ek.
    // set_mlkem_pk_bytes expects just the ML-KEM portion.
    let mlkem_pk_bytes = pk_bytes[32..].to_vec();
    sk.set_mlkem_pk_bytes(mlkem_pk_bytes);

    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lupine_kem::hybrid::generate_keypair;
    use ml_kem::MlKem768;
    use rand::rngs::OsRng;

    #[test]
    fn recipient_round_trip() {
        let (_, pk) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen");
        let encoded = encode_recipient(&pk);
        assert!(
            encoded.starts_with("age1lupine1"),
            "recipient must start with age1lupine1, got: {}",
            &encoded[..30]
        );
        let pk2 = decode_recipient(&encoded).expect("decode recipient");
        assert_eq!(
            pk.to_bytes(),
            pk2.to_bytes(),
            "public key round-trip failed"
        );
    }

    #[test]
    fn identity_round_trip() {
        let (sk, pk) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen");
        let encoded = encode_identity(&sk, &pk);
        assert!(
            encoded.starts_with("AGE-PLUGIN-LUPINE-1"),
            "identity must start with AGE-PLUGIN-LUPINE-1, got: {}",
            &encoded[..30]
        );
        let sk2 = decode_identity(&encoded).expect("decode identity");
        // Verify by encapsulating to the public key and decapsulating with both keys.
        let (ct, ss1) = pk.encapsulate(&mut OsRng).expect("encapsulate");
        let ss2 = sk2.decapsulate(&ct).expect("decapsulate with decoded sk");
        assert_eq!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "decoded identity must produce same shared secret"
        );
    }

    #[test]
    fn decode_recipient_wrong_hrp() {
        let result = decode_recipient("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(result.is_err(), "wrong HRP should fail");
    }

    #[test]
    fn decode_identity_wrong_hrp() {
        let result = decode_identity("AGE-SECRET-KEY-1SOMETHING");
        assert!(result.is_err(), "wrong HRP should fail");
    }
}
