//! Fuzz target for v4 `merge_ops`.
//!
//! Feeds an arbitrary `{ target, source }` pair of `OpLog`s into
//! `merge_ops` under a fixed DK. The harness forces both logs onto the
//! same vault id so the merger reaches its core logic (parent graph,
//! conflict resolution, canonicalization) rather than bailing at the
//! same-origin check. `Err` results are discarded so expected merge
//! rejections (bad blobs, unresolvable parents, duplicate-id conflicts)
//! do not become false-positive crashes — only panics/aborts/UB matter.

#![no_main]

use kyz_core::vault_v4::{merge_ops, OpLog};
use serde::Deserialize;

#[derive(Deserialize)]
struct MergeInput {
    target: OpLog,
    source: OpLog,
}

const VAULT_ID: &str = "0123456789abcdef0123456789abcdef";

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(input) = serde_json::from_slice::<MergeInput>(data) else {
        return;
    };
    let mut target = input.target;
    let mut source = input.source;
    target.vault_id = VAULT_ID.to_string();
    source.vault_id = VAULT_ID.to_string();
    let dk = [0x42u8; 32];
    let _ = merge_ops(&mut target, &source, &dk);
});
