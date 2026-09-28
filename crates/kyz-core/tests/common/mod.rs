//! Shared helpers for kyz-core integration tests.

/// Point the state directory at an isolated per-process temp dir.
///
/// v4 writes allocate op ids through the global actor-state directory;
/// without this, `cargo test -p kyz-core` accumulates counters for random
/// vault ids in the developer's real `actor-state.json` and contends with
/// a running `kyz` for the actor lock. Every test that writes through
/// [`kyz_core::store::VaultStore`] must call this first. The
/// implementation is shared with the crate's unit tests via the
/// `test-util` feature.
///
/// # Panics
///
/// Panics if the isolated temp directory cannot be created.
pub fn isolate_state_dir() {
    kyz_core::paths::isolate_state_dir().expect("isolate state dir");
}
