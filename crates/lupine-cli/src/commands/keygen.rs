//! `lupine keygen` — generate a keypair for the requested algorithm.
//!
//! Dispatches across all 24 algorithm variants using the callback-macro
//! pattern from `dispatch.rs`. Writes the public key and secret key to
//! separate files, using the requested format (raw/der/pem).
//!
//! @decision DEC-CLI-005
//! @title Inline callback macros per command rather than shared generic functions
//! @status accepted
//! @rationale Each command's callback macro captures local variables (rng, paths,
//!   format) by reference via the macro token tree. This avoids threading a large
//!   set of parameters through a function signature that would need to be generic
//!   over both the algorithm type parameter and the I/O details. The macros are
//!   defined inside the function that uses them, keeping them local to their call
//!   site and avoiding namespace pollution. The tradeoff is that compile errors
//!   inside macros can be harder to read, but the patterns are simple enough that
//!   this is acceptable.

use anyhow::Result;

use crate::algorithm::CliAlgorithm;
use crate::args::{Format, KeygenArgs};
use crate::format;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the keygen subcommand.
pub fn run(args: &KeygenArgs) -> Result<()> {
    let alg = args.algorithm;
    let fmt = args.format;

    // Build output paths: explicit flags win, then prefix, then algorithm name.
    let prefix = args.output.clone().unwrap_or_else(|| alg.to_string());
    let pub_path = args.out_pub.clone().unwrap_or_else(|| format!("{prefix}.pub"));
    let sec_path = args.out_sec.clone().unwrap_or_else(|| format!("{prefix}.sec"));

    if alg.is_pure_kem() {
        keygen_mlkem(alg, fmt, &pub_path, &sec_path)
    } else if alg.is_hybrid_kem() {
        keygen_hybrid_kem(alg, fmt, &pub_path, &sec_path)
    } else if alg.is_mldsa() {
        keygen_mldsa(alg, fmt, &pub_path, &sec_path)
    } else if alg.is_hybrid_sign() {
        keygen_hybrid_sign(alg, fmt, &pub_path, &sec_path)
    } else {
        keygen_slhdsa(alg, fmt, &pub_path, &sec_path)
    }
}

// ---------------------------------------------------------------------------
// Per-family implementations
// ---------------------------------------------------------------------------

fn keygen_mlkem(alg: CliAlgorithm, fmt: Format, pub_path: &str, sec_path: &str) -> Result<()> {
    use lupine_kem::generate_keypair;
    use rand::rngs::OsRng;

    macro_rules! do_mlkem_keygen {
        ($P:ty, $alg:expr, $fmt:expr, $pub_path:expr, $sec_path:expr) => {{
            let mut rng = OsRng;
            let (sk, pk) = generate_keypair::<$P>(&mut rng)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let pk_bytes = pk.to_bytes().to_vec();
            let sk_bytes = sk.to_bytes().to_vec();
            format::write_public_key($pub_path, &pk_bytes, $alg, $fmt)?;
            format::write_secret_key($sec_path, &sk_bytes, $alg, $fmt, None)?;
            eprintln!(
                "Generated {} keypair\n  public key : {}\n  secret key : {}",
                $alg, $pub_path, $sec_path
            );
            Ok(())
        }};
    }

    crate::dispatch_mlkem!(alg, do_mlkem_keygen!(alg, fmt, pub_path, sec_path))
}

fn keygen_hybrid_kem(alg: CliAlgorithm, fmt: Format, pub_path: &str, sec_path: &str) -> Result<()> {
    use lupine_kem::hybrid_generate_keypair;
    use rand::rngs::OsRng;

    macro_rules! do_hybrid_kem_keygen {
        ($P:ty, $alg:expr, $fmt:expr, $pub_path:expr, $sec_path:expr) => {{
            let mut rng = OsRng;
            let (sk, pk) = hybrid_generate_keypair::<$P>(&mut rng)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let pk_bytes = pk.to_bytes();
            let sk_bytes = sk.to_bytes();
            format::write_public_key($pub_path, &pk_bytes, $alg, $fmt)?;
            format::write_secret_key($sec_path, &sk_bytes, $alg, $fmt, Some(&pk_bytes))?;
            eprintln!(
                "Generated {} keypair\n  public key : {}\n  secret key : {}",
                $alg, $pub_path, $sec_path
            );
            Ok(())
        }};
    }

    crate::dispatch_hybrid_kem!(alg, do_hybrid_kem_keygen!(alg, fmt, pub_path, sec_path))
}

fn keygen_mldsa(alg: CliAlgorithm, fmt: Format, pub_path: &str, sec_path: &str) -> Result<()> {
    use lupine_sign::ml_dsa_generate_keypair;
    macro_rules! do_mldsa_keygen {
        ($P:ty, $alg:expr, $fmt:expr, $pub_path:expr, $sec_path:expr) => {{
            let mut rng = rand_010::rng();
            let (sk, vk) = ml_dsa_generate_keypair::<$P>(&mut rng)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let vk_bytes = vk.to_bytes().to_vec();
            let sk_bytes = sk.to_bytes().to_vec();
            format::write_public_key($pub_path, &vk_bytes, $alg, $fmt)?;
            format::write_secret_key($sec_path, &sk_bytes, $alg, $fmt, None)?;
            eprintln!(
                "Generated {} keypair\n  public key : {}\n  secret key : {}",
                $alg, $pub_path, $sec_path
            );
            Ok(())
        }};
    }

    crate::dispatch_mldsa!(alg, do_mldsa_keygen!(alg, fmt, pub_path, sec_path))
}

fn keygen_hybrid_sign(alg: CliAlgorithm, fmt: Format, pub_path: &str, sec_path: &str) -> Result<()> {
    use lupine_sign::hybrid_generate_keypair as hybrid_sign_generate_keypair;
    macro_rules! do_hybrid_sign_keygen {
        ($P:ty, $alg:expr, $fmt:expr, $pub_path:expr, $sec_path:expr) => {{
            let mut rng = rand_010::rng();
            let (sk, vk) = hybrid_sign_generate_keypair::<$P>(&mut rng)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let vk_bytes = vk.to_bytes();
            let sk_bytes = sk.to_bytes();
            format::write_public_key($pub_path, &vk_bytes, $alg, $fmt)?;
            format::write_secret_key($sec_path, &sk_bytes, $alg, $fmt, None)?;
            eprintln!(
                "Generated {} keypair\n  public key : {}\n  secret key : {}",
                $alg, $pub_path, $sec_path
            );
            Ok(())
        }};
    }

    crate::dispatch_hybrid_sign!(alg, do_hybrid_sign_keygen!(alg, fmt, pub_path, sec_path))
}

fn keygen_slhdsa(alg: CliAlgorithm, fmt: Format, pub_path: &str, sec_path: &str) -> Result<()> {
    use lupine_sign::slh_dsa_generate_keypair;
    macro_rules! do_slhdsa_keygen {
        ($P:ty, $alg:expr, $fmt:expr, $pub_path:expr, $sec_path:expr) => {{
            let mut rng = rand_010::rng();
            let (sk, vk) = slh_dsa_generate_keypair::<$P>(&mut rng)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let vk_bytes = vk.to_bytes();
            let sk_bytes = sk.to_bytes();
            format::write_public_key($pub_path, &vk_bytes, $alg, $fmt)?;
            format::write_secret_key($sec_path, &sk_bytes, $alg, $fmt, None)?;
            eprintln!(
                "Generated {} keypair\n  public key : {}\n  secret key : {}",
                $alg, $pub_path, $sec_path
            );
            Ok(())
        }};
    }

    crate::dispatch_slhdsa!(alg, do_slhdsa_keygen!(alg, fmt, pub_path, sec_path))
}
