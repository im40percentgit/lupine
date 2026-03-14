//! Fuzz harness: DER decoding of KEM and signing key structures.
//!
//! Feeds arbitrary bytes into all four DER decode functions and asserts that
//! none of them panic. Invalid input must produce an `Err` return, not a
//! panic. This catches issues like:
//!
//! - Integer overflow in length prefix parsing
//! - Slice-out-of-bounds in nested sequence handling
//! - Unwrap/expect calls on unvalidated input
//! - Stack overflow from deeply nested ASN.1 structures
//!
//! Run with: `cargo fuzz run der_decode`
//!
//! @decision DEC-TEST-FUZZ-001
//! @title Fuzz DER decode paths for all key types
//! @status accepted
//! @rationale The DER decoder parses untrusted bytes (e.g. network-received
//!   keys, user-supplied files). Any panic in the decode path is a potential
//!   denial-of-service. This harness exercises all four decode functions with
//!   the same arbitrary input, maximising coverage per fuzzing dollar. The
//!   `libfuzzer-sys` framework provides coverage-guided mutation so meaningful
//!   edge cases (correct DER prefix with wrong inner types, etc.) are found
//!   quickly. No-panic contract: all decode functions must return `Err` for
//!   invalid input, never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lupine_serial::der;

fuzz_target!(|data: &[u8]| {
    // All four decode functions must handle arbitrary bytes without panicking.
    // Invalid input must return Err, not panic.

    // KEM public key decode
    let _ = der::decode_kem_public_key_der(data);

    // KEM secret key decode
    let _ = der::decode_kem_secret_key_der(data);

    // Signing public key decode
    let _ = der::decode_sign_public_key_der(data);

    // Signing secret key decode
    let _ = der::decode_sign_secret_key_der(data);

    // Signature decode
    let _ = der::decode_signature_der(data);
});
