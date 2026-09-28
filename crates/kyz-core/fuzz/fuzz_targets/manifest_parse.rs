//! Fuzz target for `Manifest::parse` (v5 `vault.json`).
//!
//! Feeds arbitrary bytes into structural validation only (no MAC / key
//! check). The harness deliberately discards `Err` results so that
//! expected parse failures are not reported as crashes; only panics,
//! aborts, or UB in `Manifest::parse` / `validate` become findings.

#![no_main]

use kyz_core::vault_v5::Manifest;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = Manifest::parse(data);
});
