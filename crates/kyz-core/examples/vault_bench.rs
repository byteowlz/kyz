#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    reason = "benchmark binary: aborting on setup failure and printing results is the point"
)]
//! Growth and latency benchmark for the v4 vault format (trx-dgqe.2).
//!
//! Builds a throwaway vault with `ENTRIES` entries, then rewrites every
//! entry `VERSIONS - 1` more times, reporting file size and per-op latency
//! after each round. Finishes with deletes, list, and a replica merge.
//!
//! ```bash
//! cargo run --release -p kyz-core --example vault_bench -- 1000 50 200
//! ```

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kyz_core::store::{SecretEntry, SecretStore as _, VaultStore};

const PASS: &str = "a-very-strong-passphrase-123";

fn arg(n: usize, default: usize) -> usize {
    std::env::args()
        .nth(n)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn size_mb(path: &PathBuf) -> f64 {
    std::fs::metadata(path).map_or(0.0, |m| m.len() as f64 / 1_048_576.0)
}

fn value(i: usize, v: usize) -> String {
    format!("secret-value-{i:05}-v{v:03}-{}", "x".repeat(32))
}

fn main() {
    let entries = arg(1, 1000);
    let versions = arg(2, 50);
    let deletes = arg(3, 200).min(entries);

    kyz_core::paths::isolate_state_dir().expect("isolate state dir");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.json");
    let store = VaultStore::new(path.clone());
    store.init(PASS, false).expect("init");

    let t = Instant::now();
    store.unlock(PASS, 3600).expect("unlock");
    println!("unlock (empty)            {:>9.1} ms", ms(t.elapsed()));

    println!("round  versions  file_MB   avg_set_ms  max_set_ms  avg_get_ms");
    for v in 0..versions {
        let mut total = Duration::ZERO;
        let mut max = Duration::ZERO;
        for i in 0..entries {
            let e = SecretEntry::single("bench", &format!("k{i:05}"), &value(i, v));
            let t = Instant::now();
            store.set("bench", &format!("k{i:05}"), &e).expect("set");
            let d = t.elapsed();
            total += d;
            max = max.max(d);
        }
        let t = Instant::now();
        let samples = 20.min(entries);
        for i in 0..samples {
            store.get("bench", &format!("k{i:05}")).expect("get");
        }
        let get_avg = t.elapsed() / u32::try_from(samples.max(1)).unwrap_or(1);
        if v == 0 || (v + 1) % 5 == 0 || v + 1 == versions {
            println!(
                "{:>5}  {:>8}  {:>7.2}  {:>11.2}  {:>10.2}  {:>10.2}",
                v + 1,
                v + 1,
                size_mb(&path),
                ms(total / u32::try_from(entries).unwrap_or(1)),
                ms(max),
                ms(get_avg),
            );
        }
    }

    let replica = dir.path().join("replica.json");
    std::fs::copy(&path, &replica).expect("copy replica");

    let t = Instant::now();
    for i in 0..deletes {
        store.delete("bench", &format!("k{i:05}")).expect("delete");
    }
    println!(
        "delete x{deletes:<5}              avg {:>9.2} ms   file {:.2} MB",
        ms(t.elapsed() / u32::try_from(deletes.max(1)).unwrap_or(1)),
        size_mb(&path)
    );

    let t = Instant::now();
    let listed = store.list("bench").expect("list").len();
    println!(
        "list ({listed} visible)          {:>9.1} ms",
        ms(t.elapsed())
    );

    store.lock().expect("lock");
    let t = Instant::now();
    store.unlock(PASS, 3600).expect("unlock");
    println!("unlock (full)             {:>9.1} ms", ms(t.elapsed()));

    let t = Instant::now();
    let report = store.merge_vault_from(&replica, true, false);
    println!(
        "merge dry-run (replica)   {:>9.1} ms   ok={}",
        ms(t.elapsed()),
        report.is_ok()
    );
}
