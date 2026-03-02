//! Dispatch macros for Lupine CLI algorithm dispatch.
//!
//! These macros expand a callback macro across all concrete type parameters
//! for each algorithm family. The callback pattern allows the body to reference
//! a concrete type parameter without requiring `type` aliases in match arms
//! (which Rust does not support).
//!
//! # Usage pattern
//!
//! ```rust,ignore
//! macro_rules! do_keygen {
//!     ($P:ty, $args:expr) => { /* uses $P as a type parameter */ };
//! }
//! dispatch_mlkem!(alg, do_keygen!(args));
//! ```
//!
//! Each `dispatch_*!` macro matches on a `CliAlgorithm` expression and invokes
//! the callback macro with the concrete RustCrypto type as the first token.
//!
//! @decision DEC-CLI-004
//! @title Callback-macro dispatch pattern for algorithm type parameters
//! @status accepted
//! @rationale Rust does not allow `type T = Foo` inside match arms as a
//!   generic type parameter for expressions. The standard workaround is to
//!   repeat the body in each arm, which is verbose with 24 variants. The
//!   callback macro pattern (dispatch_X!(alg, callback!(args...))) lets the
//!   dispatch macro substitute the concrete type as the first token of the
//!   callback invocation, keeping the implementation in one place while the
//!   dispatch macro handles the match. This is the same pattern used by the
//!   RustCrypto `digest` and `cipher` dispatch crates.

/// Dispatch over the three pure ML-KEM parameter sets.
///
/// Calls `$callback!($P, $($args)*)` where `$P` is one of
/// `ml_kem::MlKem512`, `ml_kem::MlKem768`, `ml_kem::MlKem1024`.
#[macro_export]
macro_rules! dispatch_mlkem {
    ($alg:expr, $callback:ident ! ($($args:tt)*)) => {
        match $alg {
            $crate::algorithm::CliAlgorithm::MlKem512 =>
                $callback!(::ml_kem::MlKem512, $($args)*),
            $crate::algorithm::CliAlgorithm::MlKem768 =>
                $callback!(::ml_kem::MlKem768, $($args)*),
            $crate::algorithm::CliAlgorithm::MlKem1024 =>
                $callback!(::ml_kem::MlKem1024, $($args)*),
            other => ::anyhow::bail!("not a pure ML-KEM algorithm: {}", other),
        }
    };
}

/// Dispatch over the three hybrid X25519+ML-KEM parameter sets.
///
/// Calls `$callback!($P, $($args)*)` where `$P` is the underlying ML-KEM
/// parameter set type.
#[macro_export]
macro_rules! dispatch_hybrid_kem {
    ($alg:expr, $callback:ident ! ($($args:tt)*)) => {
        match $alg {
            $crate::algorithm::CliAlgorithm::X25519MlKem512 =>
                $callback!(::ml_kem::MlKem512, $($args)*),
            $crate::algorithm::CliAlgorithm::X25519MlKem768 =>
                $callback!(::ml_kem::MlKem768, $($args)*),
            $crate::algorithm::CliAlgorithm::X25519MlKem1024 =>
                $callback!(::ml_kem::MlKem1024, $($args)*),
            other => ::anyhow::bail!("not a hybrid KEM algorithm: {}", other),
        }
    };
}

/// Dispatch over the three pure ML-DSA parameter sets.
///
/// Calls `$callback!($P, $($args)*)` where `$P` is one of
/// `ml_dsa::MlDsa44`, `ml_dsa::MlDsa65`, `ml_dsa::MlDsa87`.
#[macro_export]
macro_rules! dispatch_mldsa {
    ($alg:expr, $callback:ident ! ($($args:tt)*)) => {
        match $alg {
            $crate::algorithm::CliAlgorithm::MlDsa44 =>
                $callback!(::ml_dsa::MlDsa44, $($args)*),
            $crate::algorithm::CliAlgorithm::MlDsa65 =>
                $callback!(::ml_dsa::MlDsa65, $($args)*),
            $crate::algorithm::CliAlgorithm::MlDsa87 =>
                $callback!(::ml_dsa::MlDsa87, $($args)*),
            other => ::anyhow::bail!("not a pure ML-DSA algorithm: {}", other),
        }
    };
}

/// Dispatch over the three hybrid Ed25519+ML-DSA parameter sets.
///
/// Calls `$callback!($P, $($args)*)` where `$P` is the underlying ML-DSA
/// parameter set type.
#[macro_export]
macro_rules! dispatch_hybrid_sign {
    ($alg:expr, $callback:ident ! ($($args:tt)*)) => {
        match $alg {
            $crate::algorithm::CliAlgorithm::Ed25519MlDsa44 =>
                $callback!(::ml_dsa::MlDsa44, $($args)*),
            $crate::algorithm::CliAlgorithm::Ed25519MlDsa65 =>
                $callback!(::ml_dsa::MlDsa65, $($args)*),
            $crate::algorithm::CliAlgorithm::Ed25519MlDsa87 =>
                $callback!(::ml_dsa::MlDsa87, $($args)*),
            other => ::anyhow::bail!("not a hybrid sign algorithm: {}", other),
        }
    };
}

/// Dispatch over all 12 SLH-DSA parameter sets.
///
/// Calls `$callback!($P, $($args)*)` where `$P` is a `slh_dsa::*` type.
#[macro_export]
macro_rules! dispatch_slhdsa {
    ($alg:expr, $callback:ident ! ($($args:tt)*)) => {
        match $alg {
            $crate::algorithm::CliAlgorithm::SlhDsaSha2128s =>
                $callback!(::slh_dsa::Sha2_128s, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2128f =>
                $callback!(::slh_dsa::Sha2_128f, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2192s =>
                $callback!(::slh_dsa::Sha2_192s, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2192f =>
                $callback!(::slh_dsa::Sha2_192f, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2256s =>
                $callback!(::slh_dsa::Sha2_256s, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2256f =>
                $callback!(::slh_dsa::Sha2_256f, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake128s =>
                $callback!(::slh_dsa::Shake128s, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake128f =>
                $callback!(::slh_dsa::Shake128f, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake192s =>
                $callback!(::slh_dsa::Shake192s, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake192f =>
                $callback!(::slh_dsa::Shake192f, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake256s =>
                $callback!(::slh_dsa::Shake256s, $($args)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake256f =>
                $callback!(::slh_dsa::Shake256f, $($args)*),
            other => ::anyhow::bail!("not an SLH-DSA algorithm: {}", other),
        }
    };
}

/// Dispatch over all 6 KEM variants (3 pure ML-KEM + 3 hybrid X25519+ML-KEM).
///
/// For pure ML-KEM variants, calls `$kem_cb!($P, $($args)*)`.
/// For hybrid KEM variants, calls `$hybrid_cb!($P, $($args)*)`.
#[macro_export]
macro_rules! dispatch_kem {
    ($alg:expr, pure: $kem_cb:ident ! ($($kargs:tt)*), hybrid: $hybrid_cb:ident ! ($($hargs:tt)*)) => {
        match $alg {
            $crate::algorithm::CliAlgorithm::MlKem512 =>
                $kem_cb!(::ml_kem::MlKem512, $($kargs)*),
            $crate::algorithm::CliAlgorithm::MlKem768 =>
                $kem_cb!(::ml_kem::MlKem768, $($kargs)*),
            $crate::algorithm::CliAlgorithm::MlKem1024 =>
                $kem_cb!(::ml_kem::MlKem1024, $($kargs)*),
            $crate::algorithm::CliAlgorithm::X25519MlKem512 =>
                $hybrid_cb!(::ml_kem::MlKem512, $($hargs)*),
            $crate::algorithm::CliAlgorithm::X25519MlKem768 =>
                $hybrid_cb!(::ml_kem::MlKem768, $($hargs)*),
            $crate::algorithm::CliAlgorithm::X25519MlKem1024 =>
                $hybrid_cb!(::ml_kem::MlKem1024, $($hargs)*),
            other => ::anyhow::bail!("not a KEM algorithm: {}", other),
        }
    };
}

/// Dispatch over all 18 sign variants (3 ML-DSA + 3 hybrid + 12 SLH-DSA).
///
/// Calls the appropriate callback for each family.
#[macro_export]
macro_rules! dispatch_sign {
    (
        $alg:expr,
        mldsa: $mldsa_cb:ident ! ($($margs:tt)*),
        hybrid: $hybrid_cb:ident ! ($($hargs:tt)*),
        slhdsa: $slhdsa_cb:ident ! ($($sargs:tt)*)
    ) => {
        match $alg {
            // ML-DSA
            $crate::algorithm::CliAlgorithm::MlDsa44 =>
                $mldsa_cb!(::ml_dsa::MlDsa44, $($margs)*),
            $crate::algorithm::CliAlgorithm::MlDsa65 =>
                $mldsa_cb!(::ml_dsa::MlDsa65, $($margs)*),
            $crate::algorithm::CliAlgorithm::MlDsa87 =>
                $mldsa_cb!(::ml_dsa::MlDsa87, $($margs)*),
            // Hybrid Ed25519+ML-DSA
            $crate::algorithm::CliAlgorithm::Ed25519MlDsa44 =>
                $hybrid_cb!(::ml_dsa::MlDsa44, $($hargs)*),
            $crate::algorithm::CliAlgorithm::Ed25519MlDsa65 =>
                $hybrid_cb!(::ml_dsa::MlDsa65, $($hargs)*),
            $crate::algorithm::CliAlgorithm::Ed25519MlDsa87 =>
                $hybrid_cb!(::ml_dsa::MlDsa87, $($hargs)*),
            // SLH-DSA SHA-2
            $crate::algorithm::CliAlgorithm::SlhDsaSha2128s =>
                $slhdsa_cb!(::slh_dsa::Sha2_128s, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2128f =>
                $slhdsa_cb!(::slh_dsa::Sha2_128f, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2192s =>
                $slhdsa_cb!(::slh_dsa::Sha2_192s, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2192f =>
                $slhdsa_cb!(::slh_dsa::Sha2_192f, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2256s =>
                $slhdsa_cb!(::slh_dsa::Sha2_256s, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaSha2256f =>
                $slhdsa_cb!(::slh_dsa::Sha2_256f, $($sargs)*),
            // SLH-DSA SHAKE
            $crate::algorithm::CliAlgorithm::SlhDsaShake128s =>
                $slhdsa_cb!(::slh_dsa::Shake128s, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake128f =>
                $slhdsa_cb!(::slh_dsa::Shake128f, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake192s =>
                $slhdsa_cb!(::slh_dsa::Shake192s, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake192f =>
                $slhdsa_cb!(::slh_dsa::Shake192f, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake256s =>
                $slhdsa_cb!(::slh_dsa::Shake256s, $($sargs)*),
            $crate::algorithm::CliAlgorithm::SlhDsaShake256f =>
                $slhdsa_cb!(::slh_dsa::Shake256f, $($sargs)*),
            other => ::anyhow::bail!("not a sign algorithm: {}", other),
        }
    };
}
