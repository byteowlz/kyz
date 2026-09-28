# kyz-core fuzz targets (cargo-fuzz)

Coverage-guided fuzzing for the v4/v5 vault formats, per [trx-dgqe.5].

## Targets

| Target            | Entry point                                | What it exercises                                                        |
| ----------------- | ------------------------------------------ | ------------------------------------------------------------------------ |
| `manifest_parse`  | `kyz_core::vault_v5::Manifest::parse`      | Structural validation of `vault.json` (version, slot ids, KDF bounds, active-slot requirement). No MAC/key check. |
| `entry_file_load` | `kyz_core::vault_v5::EntryFile::parse`     | No-DK structural path of `load_entry_file`: version, vault-id encoding, op-log structure (id encodings, parent resolution, duplicate ids, cycle-freedom). |
| `merge_ops`       | `kyz_core::vault_v4::merge_ops`            | v4 op-log merge under a fixed DK with both logs forced to one vault id so the merger reaches its core graph/conflict logic. |

All harnesses discard `Result::Err` so that expected parse/merge rejections
(bad JSON, bad ids, invalid blobs, wrong KDF values, graph violations) are
**not** reported as crashes. Only panics, aborts, or UB become findings —
that is exactly the malicious-input surface the review cares about.

The `merge_ops` and `entry_file_load` fuzzers deserialize arbitrary bytes
into structured input, so hostile structures (huge parent sets, deep chains,
duplicate ids, oversized allocations) feed directly into the validation
routines that must not panic.

## Prerequisites

- A nightly toolchain (`rustup toolchain install nightly`) with the `rust-src`
  component and `cargo-fuzz` (`cargo install cargo-fuzz --locked`).

## Build

```sh
cd crates/kyz-core/fuzz
cargo +nightly fuzz build
```

## Run

Each target ships a hand-authored valid seed in `corpus/<target>/` to give the
fuzzer a real starting point. `cargo fuzz run` picks up the corpus directory
for the target automatically.

```sh
cargo +nightly fuzz run manifest_parse
cargo +nightly fuzz run entry_file_load
cargo +nightly fuzz run merge_ops
```

A short smoke run against the seeds (no long campaign):

```sh
cargo +nightly fuzz run merge_ops -- -max_total_time=5
```

`cargo fuzz run <target> -- -max_total_time=600` is the 10-minute clean-run
gate referenced by trx-dgqe.5.

## Notes

- Seeds are kept deliberately minimal and hand-authored so they are easy to
  audit; libFuzzer-generated mutations are gitignored.
- `fuzz/Cargo.toml` declares its own `[workspace]` so the fuzz crate is not
  pulled into the kyz workspace (and so `cargo fuzz`/`cargo check` from this
  directory work standalone).