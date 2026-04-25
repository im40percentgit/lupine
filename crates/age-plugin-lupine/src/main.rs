//! age-plugin-lupine binary — post-quantum key generation for the age ecosystem.
//!
//! When run with no arguments, generates a new hybrid X25519+ML-KEM-768 keypair
//! and prints it in the standard age keygen format.
//!
//! @decision DEC-AGE-MAIN-001
//! @title Deferred plugin protocol — keygen-only binary for now
//! @status accepted
//! @rationale The full age plugin protocol (recipient-v1, identity-v1) requires
//!   a state machine over stdin/stdout. We defer this complexity and focus on
//!   the core crypto: keygen + wrap/unwrap library functions. Users can encrypt
//!   and decrypt via `canus-lupus age` instead.

use age_plugin_lupine::generate_keypair;
use age_plugin_lupine::keys::{encode_identity, encode_recipient};
use anyhow::Result;
use clap::Parser;
use ml_kem::MlKem768;
use rand::rngs::OsRng;

/// Post-quantum age plugin using hybrid X25519+ML-KEM-768.
#[derive(Parser)]
#[command(name = "age-plugin-lupine", version, about)]
struct Cli {
    /// age plugin protocol mode (deferred — not yet implemented).
    #[arg(long = "age-plugin")]
    age_plugin: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(protocol) = &cli.age_plugin {
        eprintln!("age plugin protocol '{}' is not yet implemented.", protocol);
        eprintln!("Use `canus-lupus age encrypt` / `canus-lupus age decrypt` instead.");
        std::process::exit(1);
    }

    // Default: keygen
    keygen()
}

/// Generate a new hybrid keypair and print it in age keygen format.
fn keygen() -> Result<()> {
    let (sk, pk) = generate_keypair::<MlKem768>(&mut OsRng)?;

    let recipient = encode_recipient(&pk);
    let identity = encode_identity(&sk, &pk);

    let now = chrono_lite_now();

    println!("# created: {}", now);
    println!("# public key: {}", recipient);
    println!("{}", identity);

    Ok(())
}

/// Minimal ISO 8601 UTC timestamp without pulling in chrono.
fn chrono_lite_now() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert epoch seconds to ISO 8601 date-time.
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since 1970-01-01 to Y-M-D (simplified leap year calculation).
    let (year, month, day) = epoch_days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's civil_from_days.
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_valid_output() {
        let (sk, pk) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen");
        let recipient = encode_recipient(&pk);
        let identity = encode_identity(&sk, &pk);

        assert!(
            recipient.starts_with("age1lupine1"),
            "recipient format wrong"
        );
        assert!(
            identity.starts_with("AGE-PLUGIN-LUPINE-1"),
            "identity format wrong"
        );

        // Verify the identity can decode and decapsulate.
        let sk2 = age_plugin_lupine::keys::decode_identity(&identity).expect("decode identity");
        let (ct, ss1) = pk.encapsulate(&mut OsRng).expect("encapsulate");
        let ss2 = sk2.decapsulate(&ct).expect("decapsulate");
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn chrono_lite_produces_valid_timestamp() {
        let ts = chrono_lite_now();
        // Basic format check: YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20, "timestamp wrong length: {}", ts);
        assert!(ts.ends_with('Z'), "timestamp must end with Z: {}", ts);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }

    #[test]
    fn epoch_known_date() {
        // 2026-03-26 = day 20538 since epoch (approximately)
        // Let's test a known date: 2000-01-01 = day 10957
        let (y, m, d) = epoch_days_to_ymd(10957);
        assert_eq!((y, m, d), (2000, 1, 1), "2000-01-01 check");
    }
}
