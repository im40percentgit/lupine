//! CLI entry point for the Lupine PQC suite.
//!
//! Provides command-line access to key generation, encapsulation,
//! decapsulation, signing, and verification operations. Phase 5 of the
//! Lupine implementation roadmap.
//!
//! # Stack size
//!
//! SLH-DSA operations require a large stack in debug builds (>8 MB for some
//! parameter sets). All work is dispatched to a dedicated thread with a 32 MB
//! stack to avoid stack overflows regardless of the host OS default.
//!
//! @decision DEC-CLI-010
//! @title Large-stack thread wrapper for SLH-DSA compatibility
//! @status accepted
//! @rationale SLH-DSA (FIPS 205) signs by constructing a full XMSS/FORS tree
//!   on the stack in debug mode. For the larger parameter sets this exceeds
//!   the default 8 MB Linux stack. Spawning a single 32 MB worker thread at
//!   startup covers all parameter sets with one allocation and keeps main()
//!   simple. An alternative (link flags to increase the default stack size)
//!   would affect all threads and is less portable. A third option (heap
//!   allocation in lupine-sign) would require changes to the upstream
//!   RustCrypto slh-dsa crate. The thread approach is self-contained.

#![allow(unused_extern_crates)]

extern crate rand_010;
extern crate rand_core_010;

mod algorithm;
mod args;
mod commands;
mod dispatch;
mod format;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = args::Cli::parse();

    // Spawn work on a large-stack thread so SLH-DSA (which uses deep recursion
    // in debug builds) does not overflow the OS default stack.
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32 MiB
        .name("lupine-main".into())
        .spawn(move || run(cli))
        .expect("failed to spawn lupine-main thread")
        .join()
        .expect("lupine-main thread panicked")
}

fn run(cli: args::Cli) -> anyhow::Result<()> {
    match cli.command {
        args::Command::Keygen(ref a) => commands::keygen::run(a),
        args::Command::Encapsulate(ref a) => commands::encapsulate::run(a),
        args::Command::Decapsulate(ref a) => commands::decapsulate::run(a),
        args::Command::Sign(ref a) => commands::sign::run(a),
        args::Command::Verify(ref a) => commands::verify::run(a),
    }
}
