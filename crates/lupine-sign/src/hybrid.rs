//! Hybrid signatures: Ed25519 + ML-DSA with AND-verify (Phase 3).
//!
//! Combines classical Ed25519 with post-quantum ML-DSA so that a forger must
//! break *both* schemes simultaneously. Verification uses AND-semantics: both
//! component signatures must be valid; either failure causes the composite
//! verify to fail.
//!
//! # Protocol summary
//!
//! **Sign:** sign the message with both Ed25519 and ML-DSA independently;
//! concatenate the two signatures into a composite [`HybridSignature`].
//!
//! **Verify:** verify both component signatures; return `Ok(())` only if
//! both pass.
//!
//! # Serialization
//!
//! The composite signature is length-prefixed concatenation:
//! ```text
//! [4-byte LE len of Ed25519 sig] || [Ed25519 sig (64 bytes)]
//! || [4-byte LE len of ML-DSA sig] || [ML-DSA sig bytes]
//! ```
//! Fixed 4-byte LE length prefixes are used even though Ed25519 signatures
//! are always 64 bytes, for consistency and forward compatibility.
//!
//! @decision DEC-HYBRID-SIGN-001
//! @title AND-verify over threshold/OR semantics
//! @status accepted
//! @rationale AND-verify (both must pass) is the conservative choice: it means
//!   a valid hybrid signature requires the sender to hold both private keys.
//!   OR semantics (either passes) would degrade to the weaker scheme's security
//!   and would allow a classical-only attacker to forge signatures if Ed25519
//!   is broken. A threshold scheme (e.g. 1-of-2) is unnecessary complexity for
//!   a two-component hybrid. AND-verify is used by the NIST recommendations for
//!   hybrid digital signatures.
//!
//! @decision DEC-HYBRID-SIGN-002
//! @title Native API usage to avoid signature 2.x / 3.x conflict
//! @status accepted
//! @rationale ed25519-dalek 2.x internally depends on the stable `signature`
//!   2.x crate. The ML-DSA RC crates in lupine-sign use `signature` 3.x (RC).
//!   Rather than importing the `Signer`/`Verifier` traits (which would create a
//!   version conflict), we call the native methods directly:
//!   `signing_key.sign(msg)` and `verifying_key.verify(msg, &sig)` via the
//!   inherent methods on `ed25519_dalek::SigningKey` / `VerifyingKey`. Cargo
//!   compiles both `signature` versions independently; our wrapper only
//!   surfaces the Lupine `Error`/`Result` types at the boundary.

extern crate alloc;

use alloc::vec::Vec;

use ed25519_dalek::{
    Signature as Ed25519Signature,
    SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
    Signer as _,
    Verifier as _,
};
use ml_dsa::{KeyGen, MlDsaParams};
use rand_core::CryptoRng;

use lupine_core::{Error, Result};

use crate::mldsa::{MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey, generate_keypair as mldsa_keygen};

// ── Type aliases ─────────────────────────────────────────────────────────────

/// Hybrid (Ed25519 + ML-DSA-44) signing key.
pub type HybridSigningKey44 = HybridSigningKey<ml_dsa::MlDsa44>;
/// Hybrid (Ed25519 + ML-DSA-44) verifying key.
pub type HybridVerifyingKey44 = HybridVerifyingKey<ml_dsa::MlDsa44>;
/// Hybrid (Ed25519 + ML-DSA-44) signature.
pub type HybridSignature44 = HybridSignature<ml_dsa::MlDsa44>;

/// Hybrid (Ed25519 + ML-DSA-65) signing key.
pub type HybridSigningKey65 = HybridSigningKey<ml_dsa::MlDsa65>;
/// Hybrid (Ed25519 + ML-DSA-65) verifying key.
pub type HybridVerifyingKey65 = HybridVerifyingKey<ml_dsa::MlDsa65>;
/// Hybrid (Ed25519 + ML-DSA-65) signature.
pub type HybridSignature65 = HybridSignature<ml_dsa::MlDsa65>;

/// Hybrid (Ed25519 + ML-DSA-87) signing key.
pub type HybridSigningKey87 = HybridSigningKey<ml_dsa::MlDsa87>;
/// Hybrid (Ed25519 + ML-DSA-87) verifying key.
pub type HybridVerifyingKey87 = HybridVerifyingKey<ml_dsa::MlDsa87>;
/// Hybrid (Ed25519 + ML-DSA-87) signature.
pub type HybridSignature87 = HybridSignature<ml_dsa::MlDsa87>;

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate a hybrid Ed25519 + ML-DSA keypair for parameter set `P`.
///
/// Returns `(signing_key, verifying_key)`.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if the RNG fails.
pub fn generate_keypair<P: KeyGen + MlDsaParams>(
    rng: &mut impl CryptoRng,
) -> Result<(HybridSigningKey<P>, HybridVerifyingKey<P>)> {
    // ed25519-dalek 2.x uses rand_core 0.6 via its own dep; we use the rand
    // 0.8 OsRng / ThreadRng which implement rand_core 0.6 CryptoRng.
    // The `generate` method on Ed25519SigningKey takes `impl CryptoRngCore`
    // (rand_core 0.6).  lupine-sign's own rand is 0.10 (RC), so we cannot
    // pass our rng directly to ed25519-dalek.  Instead, generate a 32-byte
    // seed using our RNG and construct the key from it.
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let ed_sk = Ed25519SigningKey::from_bytes(&seed);
    let ed_pk = Ed25519VerifyingKey::from(&ed_sk);

    let (mldsa_sk, mldsa_vk) = mldsa_keygen::<P>(rng)?;

    let signing_key = HybridSigningKey { ed_sk, mldsa_sk };
    let verifying_key = HybridVerifyingKey { ed_pk, mldsa_vk };
    Ok((signing_key, verifying_key))
}

// ── HybridSigningKey ──────────────────────────────────────────────────────────

/// A hybrid Ed25519 + ML-DSA signing key, generic over the ML-DSA parameter set.
///
/// Use the type aliases [`HybridSigningKey44`], [`HybridSigningKey65`], or
/// [`HybridSigningKey87`] for concrete parameter sets.
pub struct HybridSigningKey<P: MlDsaParams> {
    /// Ed25519 signing key (32-byte seed representation).
    ed_sk: Ed25519SigningKey,
    /// ML-DSA signing key.
    mldsa_sk: MlDsaSigningKey<P>,
}

impl<P: MlDsaParams + KeyGen> HybridSigningKey<P> {
    /// Sign `message` with both Ed25519 and ML-DSA.
    ///
    /// Returns a [`HybridSignature`] containing both component signatures.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] if ML-DSA signing fails (Ed25519 signing is
    /// infallible given a valid key).
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature<P>> {
        let ed_sig = self.ed_sk.sign(message);
        let mldsa_sig = self.mldsa_sk.sign(message)?;
        Ok(HybridSignature { ed_sig, mldsa_sig })
    }

    /// Serialize this signing key to bytes.
    ///
    /// Format: 32 bytes Ed25519 seed || ML-DSA signing key bytes (32-byte seed).
    ///
    /// Treat the result as secret material.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(self.ed_sk.as_bytes());
        out.extend_from_slice(self.mldsa_sk.to_bytes());
        out
    }

    /// Deserialize a hybrid signing key from bytes.
    ///
    /// Format: 32 bytes Ed25519 seed || ML-DSA signing key bytes (32-byte seed).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the bytes are too short or malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 64 {
            return Err(Error::InvalidKey);
        }
        let ed_seed: [u8; 32] = bytes[..32].try_into().map_err(|_| Error::InvalidKey)?;
        let ed_sk = Ed25519SigningKey::from_bytes(&ed_seed);
        let mldsa_sk = MlDsaSigningKey::<P>::from_bytes(&bytes[32..])?;
        Ok(Self { ed_sk, mldsa_sk })
    }

    /// Derive the corresponding [`HybridVerifyingKey`] from this signing key.
    pub fn verifying_key(&self) -> HybridVerifyingKey<P> {
        let ed_pk = Ed25519VerifyingKey::from(&self.ed_sk);
        let mldsa_vk = self.mldsa_sk.verifying_key();
        HybridVerifyingKey { ed_pk, mldsa_vk }
    }
}

impl<P: MlDsaParams> core::fmt::Debug for HybridSigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSigningKey").finish_non_exhaustive()
    }
}

// ── HybridVerifyingKey ────────────────────────────────────────────────────────

/// A hybrid Ed25519 + ML-DSA verifying (public) key, generic over ML-DSA param set.
///
/// Use the type aliases [`HybridVerifyingKey44`], [`HybridVerifyingKey65`], or
/// [`HybridVerifyingKey87`] for concrete parameter sets.
#[derive(Clone, Debug)]
pub struct HybridVerifyingKey<P: MlDsaParams> {
    /// Ed25519 verifying key (32 bytes).
    ed_pk: Ed25519VerifyingKey,
    /// ML-DSA verifying key.
    mldsa_vk: MlDsaVerifyingKey<P>,
}

impl<P: MlDsaParams> HybridVerifyingKey<P> {
    /// Verify `signature` over `message` using AND-semantics.
    ///
    /// Both the Ed25519 and ML-DSA components must verify successfully.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] if either component signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature<P>) -> Result<()> {
        // AND-verify: both must pass. Check Ed25519 first (faster), then ML-DSA.
        self.ed_pk
            .verify(message, &signature.ed_sig)
            .map_err(|_| Error::Verification)?;
        self.mldsa_vk.verify(message, &signature.mldsa_sig)?;
        Ok(())
    }

    /// Serialize this verifying key to bytes.
    ///
    /// Format: 32 bytes Ed25519 verifying key || ML-DSA verifying key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mldsa_bytes = self.mldsa_vk.to_bytes();
        let mut out = Vec::with_capacity(32 + mldsa_bytes.len());
        out.extend_from_slice(self.ed_pk.as_bytes());
        out.extend_from_slice(mldsa_bytes);
        out
    }

    /// Deserialize a hybrid verifying key from bytes.
    ///
    /// Format: 32 bytes Ed25519 verifying key || ML-DSA verifying key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the bytes are too short or the Ed25519
    /// key is not on the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 {
            return Err(Error::InvalidKey);
        }
        let ed_bytes: [u8; 32] = bytes[..32].try_into().map_err(|_| Error::InvalidKey)?;
        let ed_pk = Ed25519VerifyingKey::from_bytes(&ed_bytes)
            .map_err(|_| Error::InvalidKey)?;
        let mldsa_vk = MlDsaVerifyingKey::<P>::from_bytes(&bytes[32..])?;
        Ok(Self { ed_pk, mldsa_vk })
    }
}

// ── HybridSignature ───────────────────────────────────────────────────────────

/// A hybrid Ed25519 + ML-DSA composite signature.
///
/// Serialization is length-prefixed concatenation:
/// `[4-byte LE len] || [ed25519 sig] || [4-byte LE len] || [mldsa sig]`
pub struct HybridSignature<P: MlDsaParams> {
    /// Ed25519 component signature (64 bytes).
    ed_sig: Ed25519Signature,
    /// ML-DSA component signature.
    mldsa_sig: MlDsaSignature<P>,
}

impl<P: MlDsaParams> HybridSignature<P> {
    /// Serialize this composite signature to bytes.
    ///
    /// Format: `[4-byte LE len(ed_sig)] || [ed_sig] || [4-byte LE len(mldsa_sig)] || [mldsa_sig]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let ed_bytes = self.ed_sig.to_bytes();
        let mldsa_bytes = self.mldsa_sig.to_bytes();
        let mut out = Vec::with_capacity(4 + ed_bytes.len() + 4 + mldsa_bytes.len());
        let ed_len = ed_bytes.len() as u32;
        out.extend_from_slice(&ed_len.to_le_bytes());
        out.extend_from_slice(&ed_bytes);
        let mldsa_len = mldsa_bytes.len() as u32;
        out.extend_from_slice(&mldsa_len.to_le_bytes());
        out.extend_from_slice(mldsa_bytes);
        out
    }

    /// Deserialize a composite signature from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] if the bytes are too short, a length
    /// prefix is invalid, or the Ed25519 signature cannot be decoded.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::Verification);
        }
        // Read Ed25519 length prefix.
        let ed_len = u32::from_le_bytes(
            bytes[..4].try_into().map_err(|_| Error::Verification)?
        ) as usize;
        if bytes.len() < 4 + ed_len + 4 {
            return Err(Error::Verification);
        }
        let ed_sig_bytes = &bytes[4..4 + ed_len];
        let ed_sig = Ed25519Signature::from_slice(ed_sig_bytes)
            .map_err(|_| Error::Verification)?;

        // Read ML-DSA length prefix.
        let mldsa_start = 4 + ed_len;
        let mldsa_len = u32::from_le_bytes(
            bytes[mldsa_start..mldsa_start + 4]
                .try_into()
                .map_err(|_| Error::Verification)?,
        ) as usize;
        let mldsa_sig_start = mldsa_start + 4;
        if bytes.len() < mldsa_sig_start + mldsa_len {
            return Err(Error::Verification);
        }
        let mldsa_sig = MlDsaSignature::<P>::from_bytes(&bytes[mldsa_sig_start..mldsa_sig_start + mldsa_len])?;

        Ok(Self { ed_sig, mldsa_sig })
    }
}

impl<P: MlDsaParams> core::fmt::Debug for HybridSignature<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSignature").finish_non_exhaustive()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rng() -> rand::rngs::ThreadRng {
        // rand::rng() is the rand 0.10 API (replaces thread_rng()).
        rand::rng()
    }

    /// Run `f` on a thread with a 32 MB stack.
    ///
    /// ML-DSA-87 operations use large on-stack intermediates in debug builds
    /// that exceed the default 8 MB thread stack. See mldsa.rs for details.
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── Round-trip: keygen → sign → verify ───────────────────────────────────

    fn roundtrip<P: KeyGen + MlDsaParams>() {
        let mut rng = make_rng();
        let (sk, vk) = generate_keypair::<P>(&mut rng).expect("keygen failed");
        let msg = b"lupine phase 3 hybrid signature test";
        let sig = sk.sign(msg).expect("sign failed");
        vk.verify(msg, &sig).expect("verify failed");
    }

    // Hybrid tests all use with_large_stack because parallel test threads
    // running ML-DSA operations exhaust the default stack even for _44 and _65
    // when combined with the Ed25519 overhead.
    #[test]
    fn roundtrip_44() { with_large_stack(|| roundtrip::<ml_dsa::MlDsa44>()); }
    #[test]
    fn roundtrip_65() { with_large_stack(|| roundtrip::<ml_dsa::MlDsa65>()); }
    #[test]
    fn roundtrip_87() { with_large_stack(|| roundtrip::<ml_dsa::MlDsa87>()); }

    // ── AND-verify: corrupt Ed25519 part only → fail ─────────────────────────

    fn and_verify_ed25519_corrupt<P: KeyGen + MlDsaParams>() {
        let mut rng = make_rng();
        let (sk, vk) = generate_keypair::<P>(&mut rng).expect("keygen failed");
        let msg = b"and-verify test";
        let sig = sk.sign(msg).expect("sign failed");

        // Serialize, flip a byte inside the Ed25519 portion (bytes 4..68).
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[4] ^= 0xFF; // flip first byte of Ed25519 signature
        let tampered = HybridSignature::<P>::from_bytes(&sig_bytes)
            .expect("deserialization must succeed even with corrupt ed25519 bytes");
        assert!(
            vk.verify(msg, &tampered).is_err(),
            "corrupted Ed25519 component must cause verify failure"
        );
    }

    #[test]
    fn and_verify_ed25519_corrupt_44() { with_large_stack(|| and_verify_ed25519_corrupt::<ml_dsa::MlDsa44>()); }
    #[test]
    fn and_verify_ed25519_corrupt_65() { with_large_stack(|| and_verify_ed25519_corrupt::<ml_dsa::MlDsa65>()); }
    #[test]
    fn and_verify_ed25519_corrupt_87() { with_large_stack(|| and_verify_ed25519_corrupt::<ml_dsa::MlDsa87>()); }

    // ── AND-verify: corrupt ML-DSA part only → fail ───────────────────────────

    fn and_verify_mldsa_corrupt<P: KeyGen + MlDsaParams>() {
        let mut rng = make_rng();
        let (sk, vk) = generate_keypair::<P>(&mut rng).expect("keygen failed");
        let msg = b"and-verify test";
        let sig = sk.sign(msg).expect("sign failed");

        // Serialize, flip a byte inside the ML-DSA portion (after bytes 4+64+4=72).
        let mut sig_bytes = sig.to_bytes();
        let mldsa_data_start = 4 + 64 + 4; // 4 (ed len) + 64 (ed sig) + 4 (mldsa len)
        sig_bytes[mldsa_data_start] ^= 0xFF;
        // ML-DSA from_bytes may fail (tamper detected at decode) or succeed with invalid sig.
        match HybridSignature::<P>::from_bytes(&sig_bytes) {
            Err(_) => {} // tamper detected at deserialization — correct
            Ok(tampered) => {
                assert!(
                    vk.verify(msg, &tampered).is_err(),
                    "corrupted ML-DSA component must cause verify failure"
                );
            }
        }
    }

    #[test]
    fn and_verify_mldsa_corrupt_44() { with_large_stack(|| and_verify_mldsa_corrupt::<ml_dsa::MlDsa44>()); }
    #[test]
    fn and_verify_mldsa_corrupt_65() { with_large_stack(|| and_verify_mldsa_corrupt::<ml_dsa::MlDsa65>()); }
    #[test]
    fn and_verify_mldsa_corrupt_87() { with_large_stack(|| and_verify_mldsa_corrupt::<ml_dsa::MlDsa87>()); }

    // ── Wrong key detection ───────────────────────────────────────────────────

    fn wrong_key<P: KeyGen + MlDsaParams>() {
        let mut rng = make_rng();
        let (sk_a, _vk_a) = generate_keypair::<P>(&mut rng).expect("keygen failed");
        let (_sk_b, vk_b) = generate_keypair::<P>(&mut rng).expect("keygen failed");
        let msg = b"signed with key A";
        let sig = sk_a.sign(msg).expect("sign failed");
        assert!(
            vk_b.verify(msg, &sig).is_err(),
            "signature from key A must not verify with key B"
        );
    }

    #[test]
    fn wrong_key_44() { with_large_stack(|| wrong_key::<ml_dsa::MlDsa44>()); }
    #[test]
    fn wrong_key_65() { with_large_stack(|| wrong_key::<ml_dsa::MlDsa65>()); }
    #[test]
    fn wrong_key_87() { with_large_stack(|| wrong_key::<ml_dsa::MlDsa87>()); }

    // ── Signature serialization round-trip ────────────────────────────────────

    fn sig_serialization<P: KeyGen + MlDsaParams>() {
        let mut rng = make_rng();
        let (sk, vk) = generate_keypair::<P>(&mut rng).expect("keygen failed");
        let msg = b"sig serialization round-trip";
        let sig = sk.sign(msg).expect("sign failed");
        let sig_bytes = sig.to_bytes();
        let sig2 = HybridSignature::<P>::from_bytes(&sig_bytes)
            .expect("sig from_bytes failed");
        // Verify the round-tripped signature.
        vk.verify(msg, &sig2).expect("round-tripped sig must verify");
        // Byte equality.
        assert_eq!(sig.to_bytes(), sig2.to_bytes(), "sig bytes round-trip failed");
    }

    #[test]
    fn sig_serialization_44() { with_large_stack(|| sig_serialization::<ml_dsa::MlDsa44>()); }
    #[test]
    fn sig_serialization_65() { with_large_stack(|| sig_serialization::<ml_dsa::MlDsa65>()); }
    #[test]
    fn sig_serialization_87() { with_large_stack(|| sig_serialization::<ml_dsa::MlDsa87>()); }

    // ── Verifying key serialization round-trip ────────────────────────────────

    fn vk_serialization<P: KeyGen + MlDsaParams>() {
        let mut rng = make_rng();
        let (sk, vk) = generate_keypair::<P>(&mut rng).expect("keygen failed");
        let vk_bytes = vk.to_bytes();
        let vk2 = HybridVerifyingKey::<P>::from_bytes(&vk_bytes)
            .expect("vk from_bytes failed");
        assert_eq!(vk.to_bytes(), vk2.to_bytes(), "vk bytes round-trip failed");
        // Sign with sk, verify with deserialized vk.
        let msg = b"vk round-trip sign+verify";
        let sig = sk.sign(msg).expect("sign failed");
        vk2.verify(msg, &sig).expect("deserialized vk must verify");
    }

    #[test]
    fn vk_serialization_44() { with_large_stack(|| vk_serialization::<ml_dsa::MlDsa44>()); }
    #[test]
    fn vk_serialization_65() { with_large_stack(|| vk_serialization::<ml_dsa::MlDsa65>()); }
    #[test]
    fn vk_serialization_87() { with_large_stack(|| vk_serialization::<ml_dsa::MlDsa87>()); }

    // ── Signing key serialization round-trip ──────────────────────────────────

    fn sk_serialization<P: KeyGen + MlDsaParams>() {
        let mut rng = make_rng();
        let (sk, vk) = generate_keypair::<P>(&mut rng).expect("keygen failed");
        let sk_bytes = sk.to_bytes();
        let sk2 = HybridSigningKey::<P>::from_bytes(&sk_bytes)
            .expect("sk from_bytes failed");
        // Both keys must produce identical signatures (both are deterministic).
        let msg = b"sk round-trip determinism";
        let sig1 = sk.sign(msg).expect("sign failed");
        let sig2 = sk2.sign(msg).expect("sign with deserialized sk failed");
        assert_eq!(sig1.to_bytes(), sig2.to_bytes(), "deserialized sk must produce identical sig");
        vk.verify(msg, &sig2).expect("deserialized sk sig must verify");
    }

    #[test]
    fn sk_serialization_44() { with_large_stack(|| sk_serialization::<ml_dsa::MlDsa44>()); }
    #[test]
    fn sk_serialization_65() { with_large_stack(|| sk_serialization::<ml_dsa::MlDsa65>()); }
    #[test]
    fn sk_serialization_87() { with_large_stack(|| sk_serialization::<ml_dsa::MlDsa87>()); }
}
