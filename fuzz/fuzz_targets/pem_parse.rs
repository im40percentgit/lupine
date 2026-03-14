//! Fuzz harness: PEM parsing.
//!
//! Feeds arbitrary bytes (interpreted as UTF-8 text where possible) into all
//! PEM decode functions and asserts that none of them panic. Invalid or
//! malformed PEM must produce `Err`, not a panic.
//!
//! PEM parsing is a text-layer format that sits above DER. This harness
//! targets the RFC 7468 label validation, base64 decode, and boundary
//! detection logic — all of which process untrusted text input.
//!
//! Common issues this harness can catch:
//! - Missing null terminator handling in base64 output
//! - Incorrect label matching ("PUBLIC KEY" vs "PRIVATE KEY")
//! - Panic on empty input, no-header input, or truncated base64
//! - Integer overflow in base64 decoded-length calculation
//!
//! Run with: `cargo fuzz run pem_parse`
//!
//! @decision DEC-TEST-FUZZ-002
//! @title PEM fuzz harness: string-coerce then decode all label variants
//! @status accepted
//! @rationale The `pem` module's decode functions take `&str` (RFC 7468 is a
//!   text format). We use `from_utf8_lossy` to coerce arbitrary bytes to a
//!   `Cow<str>` — this exercises the PEM parser on both valid UTF-8 and the
//!   replacement-character-substituted form of non-UTF-8 input. Calling all
//!   three label variants with the same input maximises decode-path coverage
//!   per fuzzing iteration.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lupine_serial::pem;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to a string — use lossy conversion so non-UTF-8 bytes
    // are represented as replacement characters. This exercises the PEM
    // parser on realistic-looking (but potentially malformed) text.
    let text = String::from_utf8_lossy(data);

    // All three label variants must handle arbitrary text without panicking.
    // Invalid/malformed PEM must return Err, never panic.
    let _ = pem::decode_public_key_pem(&text);
    let _ = pem::decode_private_key_pem(&text);
    let _ = pem::decode_signature_pem(&text);

    // Also exercise the generic decode_pem with an arbitrary label attempt.
    let _ = pem::decode_pem(&text);
});
