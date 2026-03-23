//! SLH-DSA (FIPS 205) wrapper for the Lupine PQC suite.
//!
//! Provides `SlhDsaSigningKey<P>`, `SlhDsaVerifyingKey<P>`, and
//! `SlhDsaSignature<P>` types that wrap the RustCrypto `slh-dsa` crate and
//! surface a Lupine-idiomatic API: byte-oriented key serialization and Lupine
//! `Error`/`Result` types.
//!
//! # Warning: Large signatures
//!
//! SLH-DSA signatures are substantially larger than classical or ML-DSA
//! signatures, ranging from ~7 KB (`*128s`) to ~50 KB (`*256f`).  The `s`
//! (small) variants minimize signature size at the cost of slower signing; the
//! `f` (fast) variants minimize signing time at the cost of larger signatures.
//!
//! # Parameter sets (12 total)
//!
//! | Alias                      | Hash   | Level | SK   | VK   | Sig    |
//! |----------------------------|--------|-------|------|------|--------|
//! | `SlhDsaSha2_128s*`         | SHA2   | 1     | 64 B | 32 B |  7856 B|
//! | `SlhDsaSha2_128f*`         | SHA2   | 1     | 64 B | 32 B | 17088 B|
//! | `SlhDsaSha2_192s*`         | SHA2   | 3     | 96 B | 48 B | 16224 B|
//! | `SlhDsaSha2_192f*`         | SHA2   | 3     | 96 B | 48 B | 35664 B|
//! | `SlhDsaSha2_256s*`         | SHA2   | 5     |128 B | 64 B | 29792 B|
//! | `SlhDsaSha2_256f*`         | SHA2   | 5     |128 B | 64 B | 49856 B|
//! | `SlhDsaShake128s*`         | SHAKE  | 1     | 64 B | 32 B |  7856 B|
//! | `SlhDsaShake128f*`         | SHAKE  | 1     | 64 B | 32 B | 17088 B|
//! | `SlhDsaShake192s*`         | SHAKE  | 3     | 96 B | 48 B | 16224 B|
//! | `SlhDsaShake192f*`         | SHAKE  | 3     | 96 B | 48 B | 35664 B|
//! | `SlhDsaShake256s*`         | SHAKE  | 5     |128 B | 64 B | 29792 B|
//! | `SlhDsaShake256f*`         | SHAKE  | 5     |128 B | 64 B | 49856 B|
//!
//! @decision DEC-SIGN-003
//! @title `Vec<u8>` for SLH-DSA signature bytes at the wrapper boundary
//! @status accepted
//! @rationale SLH-DSA signatures range from 7 856 to 49 856 bytes. The
//!   underlying `slh_dsa::Signature<P>` uses a fixed-size stack-allocated
//!   `hybrid_array::Array<u8, P::SigLen>`, which is fine for the native type.
//!   At the Lupine wrapper boundary we copy to `Vec<u8>` so callers never
//!   need to import or size `hybrid_array` types.  The one-time heap
//!   allocation is negligible compared to the cost of SLH-DSA signing itself
//!   (~1–10 ms for the 128s variant).
//!
//! @decision DEC-SIGN-004
//! @title Deterministic signing as the default for SLH-DSA wrappers
//! @status accepted
//! @rationale The `slh_dsa::SigningKey::try_sign` method (via the
//!   `signature::Signer` trait) uses deterministic signing (opt_rand = pk_seed).
//!   This is the simpler API and avoids requiring callers to supply an RNG for
//!   signing.  Randomized signing is available via `sign_randomized` for
//!   callers who need it.

extern crate alloc;

use alloc::vec::Vec;

use slh_dsa::{ParameterSet, SigningKey, VerifyingKey};
use slh_dsa::signature::{Keypair, Signer};
use rand_core::CryptoRng;
use zeroize::Zeroize;

use lupine_core::{Error, Result};

// ── SHA2 parameter set type aliases ──────────────────────────────────────────

/// SLH-DSA-SHA2-128s signing key — NIST level 1, small signatures.
pub type SlhDsaSha2_128sSigningKey   = SlhDsaSigningKey<slh_dsa::Sha2_128s>;
/// SLH-DSA-SHA2-128s verifying key.
pub type SlhDsaSha2_128sVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Sha2_128s>;
/// SLH-DSA-SHA2-128s signature.
pub type SlhDsaSha2_128sSignature    = SlhDsaSignature<slh_dsa::Sha2_128s>;

/// SLH-DSA-SHA2-128f signing key — NIST level 1, fast signing.
pub type SlhDsaSha2_128fSigningKey   = SlhDsaSigningKey<slh_dsa::Sha2_128f>;
/// SLH-DSA-SHA2-128f verifying key.
pub type SlhDsaSha2_128fVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Sha2_128f>;
/// SLH-DSA-SHA2-128f signature.
pub type SlhDsaSha2_128fSignature    = SlhDsaSignature<slh_dsa::Sha2_128f>;

/// SLH-DSA-SHA2-192s signing key — NIST level 3, small signatures.
pub type SlhDsaSha2_192sSigningKey   = SlhDsaSigningKey<slh_dsa::Sha2_192s>;
/// SLH-DSA-SHA2-192s verifying key.
pub type SlhDsaSha2_192sVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Sha2_192s>;
/// SLH-DSA-SHA2-192s signature.
pub type SlhDsaSha2_192sSignature    = SlhDsaSignature<slh_dsa::Sha2_192s>;

/// SLH-DSA-SHA2-192f signing key — NIST level 3, fast signing.
pub type SlhDsaSha2_192fSigningKey   = SlhDsaSigningKey<slh_dsa::Sha2_192f>;
/// SLH-DSA-SHA2-192f verifying key.
pub type SlhDsaSha2_192fVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Sha2_192f>;
/// SLH-DSA-SHA2-192f signature.
pub type SlhDsaSha2_192fSignature    = SlhDsaSignature<slh_dsa::Sha2_192f>;

/// SLH-DSA-SHA2-256s signing key — NIST level 5, small signatures.
pub type SlhDsaSha2_256sSigningKey   = SlhDsaSigningKey<slh_dsa::Sha2_256s>;
/// SLH-DSA-SHA2-256s verifying key.
pub type SlhDsaSha2_256sVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Sha2_256s>;
/// SLH-DSA-SHA2-256s signature.
pub type SlhDsaSha2_256sSignature    = SlhDsaSignature<slh_dsa::Sha2_256s>;

/// SLH-DSA-SHA2-256f signing key — NIST level 5, fast signing.
pub type SlhDsaSha2_256fSigningKey   = SlhDsaSigningKey<slh_dsa::Sha2_256f>;
/// SLH-DSA-SHA2-256f verifying key.
pub type SlhDsaSha2_256fVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Sha2_256f>;
/// SLH-DSA-SHA2-256f signature.
pub type SlhDsaSha2_256fSignature    = SlhDsaSignature<slh_dsa::Sha2_256f>;

// ── SHAKE parameter set type aliases ─────────────────────────────────────────

/// SLH-DSA-SHAKE-128s signing key — NIST level 1, small signatures.
pub type SlhDsaShake128sSigningKey   = SlhDsaSigningKey<slh_dsa::Shake128s>;
/// SLH-DSA-SHAKE-128s verifying key.
pub type SlhDsaShake128sVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Shake128s>;
/// SLH-DSA-SHAKE-128s signature.
pub type SlhDsaShake128sSignature    = SlhDsaSignature<slh_dsa::Shake128s>;

/// SLH-DSA-SHAKE-128f signing key — NIST level 1, fast signing.
pub type SlhDsaShake128fSigningKey   = SlhDsaSigningKey<slh_dsa::Shake128f>;
/// SLH-DSA-SHAKE-128f verifying key.
pub type SlhDsaShake128fVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Shake128f>;
/// SLH-DSA-SHAKE-128f signature.
pub type SlhDsaShake128fSignature    = SlhDsaSignature<slh_dsa::Shake128f>;

/// SLH-DSA-SHAKE-192s signing key — NIST level 3, small signatures.
pub type SlhDsaShake192sSigningKey   = SlhDsaSigningKey<slh_dsa::Shake192s>;
/// SLH-DSA-SHAKE-192s verifying key.
pub type SlhDsaShake192sVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Shake192s>;
/// SLH-DSA-SHAKE-192s signature.
pub type SlhDsaShake192sSignature    = SlhDsaSignature<slh_dsa::Shake192s>;

/// SLH-DSA-SHAKE-192f signing key — NIST level 3, fast signing.
pub type SlhDsaShake192fSigningKey   = SlhDsaSigningKey<slh_dsa::Shake192f>;
/// SLH-DSA-SHAKE-192f verifying key.
pub type SlhDsaShake192fVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Shake192f>;
/// SLH-DSA-SHAKE-192f signature.
pub type SlhDsaShake192fSignature    = SlhDsaSignature<slh_dsa::Shake192f>;

/// SLH-DSA-SHAKE-256s signing key — NIST level 5, small signatures.
pub type SlhDsaShake256sSigningKey   = SlhDsaSigningKey<slh_dsa::Shake256s>;
/// SLH-DSA-SHAKE-256s verifying key.
pub type SlhDsaShake256sVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Shake256s>;
/// SLH-DSA-SHAKE-256s signature.
pub type SlhDsaShake256sSignature    = SlhDsaSignature<slh_dsa::Shake256s>;

/// SLH-DSA-SHAKE-256f signing key — NIST level 5, fast signing.
pub type SlhDsaShake256fSigningKey   = SlhDsaSigningKey<slh_dsa::Shake256f>;
/// SLH-DSA-SHAKE-256f verifying key.
pub type SlhDsaShake256fVerifyingKey = SlhDsaVerifyingKey<slh_dsa::Shake256f>;
/// SLH-DSA-SHAKE-256f signature.
pub type SlhDsaShake256fSignature    = SlhDsaSignature<slh_dsa::Shake256f>;

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate an SLH-DSA keypair for parameter set `P`.
///
/// Returns `(signing_key, verifying_key)`.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if the RNG fails to produce entropy.
pub fn generate_keypair<P: ParameterSet>(
    rng: &mut impl CryptoRng,
) -> Result<(SlhDsaSigningKey<P>, SlhDsaVerifyingKey<P>)> {
    let native_sk = SigningKey::<P>::new(rng);
    let native_vk = native_sk.verifying_key();

    let sk_bytes = native_sk.to_bytes().to_vec();
    let vk_bytes = native_vk.to_bytes().to_vec();

    let signing_key = SlhDsaSigningKey {
        bytes: sk_bytes,
        native: native_sk,
    };
    let verifying_key = SlhDsaVerifyingKey {
        bytes: vk_bytes,
        native: native_vk,
    };

    Ok((signing_key, verifying_key))
}

// ── SlhDsaSigningKey ──────────────────────────────────────────────────────────

/// An SLH-DSA signing key, generic over the parameter set `P`.
///
/// Use the concrete type aliases (e.g. [`SlhDsaSha2_128sSigningKey`]) rather
/// than instantiating this type directly.
///
/// # Memory safety
///
/// `Drop` zeroizes the `bytes` field (the serialized key cache). The native
/// `SigningKey<P>` handles its own zeroization via `ZeroizeOnDrop` (activated
/// through the `slh-dsa/zeroize` feature).
#[derive(Clone)]
pub struct SlhDsaSigningKey<P: ParameterSet> {
    /// Serialized key bytes (cached to avoid re-serialization).
    bytes: Vec<u8>,
    /// Native signing key.
    native: SigningKey<P>,
}

/// @decision DEC-SIGN-006
/// @title Manual Drop for SlhDsaSigningKey instead of ZeroizeOnDrop derive
/// @status accepted
/// @rationale Same rationale as DEC-SIGN-005: `#[derive(ZeroizeOnDrop)]`
///   cannot verify that `SigningKey<P>` implements `Zeroize` because `Zeroize`
///   is not a supertrait of `ParameterSet`. A manual `Drop` zeroizes the
///   wrapper-owned `bytes` Vec; the native `SigningKey<P>` is handled by its
///   own `ZeroizeOnDrop` via `slh-dsa/zeroize`.
impl<P: ParameterSet> Drop for SlhDsaSigningKey<P> {
    fn drop(&mut self) {
        self.bytes.zeroize();
        // self.native: SigningKey<P> has ZeroizeOnDrop via slh-dsa/zeroize feature.
    }
}

impl<P: ParameterSet> SlhDsaSigningKey<P> {
    /// Deserialize a signing key from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if `bytes` is not the correct length for
    /// this parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let native = SigningKey::<P>::try_from(bytes)
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            native,
        })
    }

    /// Serialize this signing key to bytes.
    ///
    /// Treat the result as secret material — store it securely and zeroize
    /// after use.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Sign `message` using the deterministic SLH-DSA variant.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<SlhDsaSignature<P>> {
        let native_sig = self
            .native
            .try_sign(message)
            .map_err(|_| Error::Signing)?;
        let sig_bytes = native_sig.to_bytes().to_vec();
        Ok(SlhDsaSignature {
            bytes: sig_bytes,
            native: native_sig,
        })
    }

    /// Sign `message` using the randomized SLH-DSA variant.
    ///
    /// Randomized signing produces non-deterministic signatures and provides
    /// additional protection against fault attacks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] if signing fails (e.g. RNG failure).
    pub fn sign_randomized(
        &self,
        message: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<SlhDsaSignature<P>> {
        use slh_dsa::signature::RandomizedSigner;
        let native_sig = self
            .native
            .try_sign_with_rng(rng, message)
            .map_err(|_| Error::Signing)?;
        let sig_bytes = native_sig.to_bytes().to_vec();
        Ok(SlhDsaSignature {
            bytes: sig_bytes,
            native: native_sig,
        })
    }

    /// Derive the corresponding [`SlhDsaVerifyingKey`] from this signing key.
    pub fn verifying_key(&self) -> SlhDsaVerifyingKey<P> {
        let native_vk = self.native.verifying_key();
        let bytes = native_vk.to_bytes().to_vec();
        SlhDsaVerifyingKey { bytes, native: native_vk }
    }
}

impl<P: ParameterSet> core::fmt::Debug for SlhDsaSigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlhDsaSigningKey")
            .finish_non_exhaustive()
    }
}

// ── SlhDsaVerifyingKey ────────────────────────────────────────────────────────

/// An SLH-DSA verifying (public) key, generic over the parameter set `P`.
///
/// Use the concrete type aliases (e.g. [`SlhDsaSha2_128sVerifyingKey`]) rather
/// than instantiating this type directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaVerifyingKey<P: ParameterSet> {
    /// Encoded verifying key bytes (cached).
    bytes: Vec<u8>,
    /// Native verifying key.
    native: VerifyingKey<P>,
}

impl<P: ParameterSet> SlhDsaVerifyingKey<P> {
    /// Deserialize a verifying key from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if `bytes` is not the correct length for
    /// this parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let native = VerifyingKey::<P>::try_from(bytes)
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            native,
        })
    }

    /// Serialize this verifying key to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Verify `signature` over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &SlhDsaSignature<P>) -> Result<()> {
        use slh_dsa::signature::Verifier;
        self.native
            .verify(message, &signature.native)
            .map_err(|_| Error::Verification)
    }
}

// ── SlhDsaSignature ───────────────────────────────────────────────────────────

/// An SLH-DSA signature, generic over the parameter set `P`.
///
/// Signatures are 7856–49856 bytes depending on the parameter set.  They are
/// heap-allocated at the wrapper boundary to avoid callers dealing with
/// const-generic array types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhDsaSignature<P: ParameterSet> {
    /// Encoded signature bytes (heap-allocated Vec).
    bytes: Vec<u8>,
    /// Parsed native signature.
    native: slh_dsa::Signature<P>,
}

impl<P: ParameterSet> SlhDsaSignature<P> {
    /// Deserialize a signature from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] if `bytes` cannot be decoded as a
    /// valid signature for this parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let native = slh_dsa::Signature::<P>::try_from(bytes)
            .map_err(|_| Error::Verification)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            native,
        })
    }

    /// Serialize this signature to bytes.
    ///
    /// The returned slice is `P::SigLen` bytes long (7856–49856 bytes).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rng() -> rand::rngs::ThreadRng {
        rand::rng()
    }

    // ── Round-trip helpers ───────────────────────────────────────────────────

    fn roundtrip<P: ParameterSet>() {
        let (sk, vk) = generate_keypair::<P>(&mut make_rng())
            .expect("keygen must succeed");
        let msg = b"lupine slh-dsa test message";
        let sig = sk.sign(msg).expect("sign must succeed");
        vk.verify(msg, &sig).expect("verify must succeed");
    }

    fn tamper_detection<P: ParameterSet>() {
        let (sk, vk) = generate_keypair::<P>(&mut make_rng()).unwrap();
        let msg = b"tamper detection test";
        let sig = sk.sign(msg).unwrap();

        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes[0] ^= 0xFF;
        let tampered = SlhDsaSignature::<P>::from_bytes(&sig_bytes);
        match tampered {
            Err(_) => {} // decode rejected tampered bytes
            Ok(t) => {
                assert!(
                    vk.verify(msg, &t).is_err(),
                    "tampered signature must not verify"
                );
            }
        }
    }

    fn sk_serialization<P: ParameterSet>() {
        let (sk, _vk) = generate_keypair::<P>(&mut make_rng()).unwrap();
        let bytes = sk.to_bytes().to_vec();
        let sk2 = SlhDsaSigningKey::<P>::from_bytes(&bytes)
            .expect("sk round-trip must succeed");
        assert_eq!(sk.to_bytes(), sk2.to_bytes(), "sk bytes must round-trip");
    }

    fn vk_serialization<P: ParameterSet>() {
        let (_sk, vk) = generate_keypair::<P>(&mut make_rng()).unwrap();
        let bytes = vk.to_bytes().to_vec();
        let vk2 = SlhDsaVerifyingKey::<P>::from_bytes(&bytes)
            .expect("vk round-trip must succeed");
        assert_eq!(vk.to_bytes(), vk2.to_bytes(), "vk bytes must round-trip");
    }

    // ── SHA2 round-trip tests ────────────────────────────────────────────────

    #[test]
    fn roundtrip_sha2_128s() { roundtrip::<slh_dsa::Sha2_128s>(); }
    #[test]
    fn roundtrip_sha2_192s() { roundtrip::<slh_dsa::Sha2_192s>(); }
    #[test]
    fn roundtrip_sha2_256s() { roundtrip::<slh_dsa::Sha2_256s>(); }

    // ── SHAKE round-trip (one representative) ────────────────────────────────

    #[test]
    fn roundtrip_shake_128s() { roundtrip::<slh_dsa::Shake128s>(); }

    // ── Tamper detection ─────────────────────────────────────────────────────

    #[test]
    fn tamper_sha2_128s() { tamper_detection::<slh_dsa::Sha2_128s>(); }
    #[test]
    fn tamper_shake_128s() { tamper_detection::<slh_dsa::Shake128s>(); }

    // ── Key serialization ────────────────────────────────────────────────────

    #[test]
    fn sk_serialization_sha2_128s() { sk_serialization::<slh_dsa::Sha2_128s>(); }
    #[test]
    fn sk_serialization_sha2_192s() { sk_serialization::<slh_dsa::Sha2_192s>(); }
    #[test]
    fn sk_serialization_sha2_256s() { sk_serialization::<slh_dsa::Sha2_256s>(); }
    #[test]
    fn sk_serialization_shake_128s() { sk_serialization::<slh_dsa::Shake128s>(); }

    #[test]
    fn vk_serialization_sha2_128s() { vk_serialization::<slh_dsa::Sha2_128s>(); }
    #[test]
    fn vk_serialization_sha2_192s() { vk_serialization::<slh_dsa::Sha2_192s>(); }
    #[test]
    fn vk_serialization_sha2_256s() { vk_serialization::<slh_dsa::Sha2_256s>(); }
    #[test]
    fn vk_serialization_shake_128s() { vk_serialization::<slh_dsa::Shake128s>(); }

    // ── Wrong-key detection (SHAKE-128s as representative) ──────────────────

    #[test]
    fn wrong_key_detection_shake_128s() {
        let (sk_a, _vk_a) = generate_keypair::<slh_dsa::Shake128s>(&mut make_rng()).unwrap();
        let (_sk_b, vk_b) = generate_keypair::<slh_dsa::Shake128s>(&mut make_rng()).unwrap();
        let msg = b"signed with key A";
        let sig = sk_a.sign(msg).unwrap();
        assert!(
            vk_b.verify(msg, &sig).is_err(),
            "signature from key A must not verify with key B"
        );
    }

    // ── Invalid byte rejection ────────────────────────────────────────────────

    #[test]
    fn sk_from_bytes_wrong_length() {
        let result = SlhDsaSigningKey::<slh_dsa::Sha2_128s>::from_bytes(&[0u8; 10]);
        assert!(result.is_err(), "short bytes must be rejected");
    }

    #[test]
    fn vk_from_bytes_wrong_length() {
        let result = SlhDsaVerifyingKey::<slh_dsa::Sha2_128s>::from_bytes(&[0u8; 10]);
        assert!(result.is_err(), "short bytes must be rejected");
    }
}
