//! Fuzz target for v5 entry-file loading (`EntryFile::parse`).
//!
//! Exercises the no-DK structural path of `load_entry_file`: schema
//! version, vault-id encoding, and op-log structure (op-id encodings,
//! parent resolution, duplicate ids, cycle-freedom). MAC/name checks need
//! the DK and are out of scope here. `Err` results are discarded so
//! expected parse failures do not become false-positive crashes.

#![no_main]

use kyz_core::vault_v5::EntryFile;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = EntryFile::parse(data);
});
