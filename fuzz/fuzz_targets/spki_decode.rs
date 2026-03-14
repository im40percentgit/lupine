//! Fuzz harness: SPKI (SubjectPublicKeyInfo) decoding.
//!
//! Feeds arbitrary bytes into the SPKI decode functions and asserts that none
//! of them panic. Invalid input must produce `Err`, not a panic.
//!
//! SPKI differs from plain DER in that the key material is encoded in a BIT
//! STRING rather than an OCTET STRING. The decoder must correctly handle:
//! - Wrong inner tag (OCTET STRING where BIT STRING expected, or vice versa)
//! - Incorrect BIT STRING unused-bits prefix byte
//! - OID values that don't correspond to any known algorithm
//! - Truncated or over-long tag-length-value sequences
//!
//! Run with: `cargo fuzz run spki_decode`

#![no_main]

use libfuzzer_sys::fuzz_target;
use lupine_serial::spki;

fuzz_target!(|data: &[u8]| {
    // Both decode functions must handle arbitrary bytes without panicking.

    // KEM SPKI decode
    let _ = spki::decode_kem_spki(data);

    // Signing SPKI decode
    let _ = spki::decode_sign_spki(data);
});
