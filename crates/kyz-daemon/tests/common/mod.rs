//! Shared fixtures for daemon integration tests.
//!
//! Provides an isolated per-test environment (XDG-style temp dirs, a real
//! v3 vault with one secret), an in-process daemon start/stop helper, and
//! a canary scanner asserting that secret material never reaches the
//! daemon's on-disk logs.
//!
//! Proxy-specific test doubles (scripted HTTPS mock upstream, raw HTTP
//! client) live with the proxy test binary under `tests/proxy_http/`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use secrecy::SecretString;
use tokio::sync::MutexGuard;

use kyz_core::store::{SecretEntry, VaultSession};
use kyz_daemon::lifecycle::{DaemonHandle, DaemonOptions};
use kyz_daemon::upstream::UpstreamClient;

/// A running daemon plus the test serialization lock keeping it exclusive.
pub struct GuardedDaemon {
    /// The running daemon.
    pub handle: DaemonHandle,
    /// Holds the cross-test lock until this value drops.
    pub _guard: MutexGuard<'static, ()>,
}

impl GuardedDaemon {
    /// Stop the daemon gracefully and release the serialization lock.
    ///
    /// Tests that start another daemon afterwards **must** go through this
    /// method: keeping `self` alive while calling [`Fixture::start`] again
    /// self-deadlocks on the non-reentrant mutex.
    pub async fn shutdown(self) {
        self.handle.stop();
        let _ = self.handle.wait().await;
    }
}

/// Strong fixture passphrase (satisfies the strength policy).
pub const FIXTURE_PASSPHRASE: &str = "integration-fixture-passphrase-123456";

/// Canary marker prefix baked into the fixture secret value.
pub const CANARY_PREFIX: &str = "KYZ_TEST_SECRET_";

/// Serialize daemon tests within one test binary.
///
/// Windows named pipes are named per-username, so concurrent daemons in the
/// same process would collide on `first_pipe_instance`. The guard is held
/// across awaits for the daemon's whole lifetime, so the lock is the async
/// (Send-guard) kind.
pub async fn daemon_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

/// An isolated daemon test environment.
pub struct Fixture {
    /// Base state dir (`<tmp>/state`); the daemon owns `<tmp>/state/daemon`.
    pub state_dir: PathBuf,
    /// Vault file with one secret: service `app`, key `api`, field `token`.
    pub vault_path: PathBuf,
    /// Minimal valid configuration file.
    pub config_path: PathBuf,
    /// The secret value stored in the vault (the canary).
    pub secret_value: String,
}

impl Fixture {
    /// Build the fixture: temp dirs, config, and a locked v3 vault holding
    /// one secret. Isolation comes from the tempdir, not from any label.
    pub fn new() -> Self {
        let base = tempfile::tempdir().expect("tempdir for fixture");
        // Leak the tempdir: tests are short-lived and the daemon files must
        // outlive this constructor's scope.
        let base = base.keep();

        let state_dir = base.join("state");
        let vault_path = base.join("vault").join("vault.json");
        let config_path = base.join("config").join("config.toml");

        std::fs::create_dir_all(vault_path.parent().expect("vault parent")).expect("mkdir vault");
        std::fs::create_dir_all(config_path.parent().expect("config parent")).expect("mkdir cfg");

        std::fs::write(
            &config_path,
            "profile = \"default\"\n\n[daemon]\ntimeout_secs = 0\n",
        )
        .expect("write config");

        let secret_value = format!("{CANARY_PREFIX}{}", unique_suffix());
        // Build the v3 vault directly (one scrypt, no session file, no OS
        // keyring) so parallel test threads never contend on the Windows
        // Credential Manager. The entry exposes the canary under both the
        // generic `value` field and the credential-proxy-style `token`
        // field.
        let secret = SecretString::from(FIXTURE_PASSPHRASE.to_string());
        let (mut vault, dk) =
            kyz_core::vault_v3::VaultFileV3::create(&secret).expect("create fixture vault");
        vault.passphrase_policy_checked = true;
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "value".to_string(),
            SecretString::from(secret_value.clone()),
        );
        fields.insert(
            "token".to_string(),
            SecretString::from(secret_value.clone()),
        );
        vault
            .set_with_retention(&SecretEntry::new("app", "api", fields), &dk, 0)
            .expect("set fixture secret");
        let serialized = serde_json::to_string_pretty(&vault).expect("serialize fixture vault");
        std::fs::write(&vault_path, serialized).expect("write fixture vault");

        Self {
            state_dir,
            vault_path,
            config_path,
            secret_value,
        }
    }

    /// Daemon options pointing at this fixture.
    pub fn options(&self, timeout_override: Option<u64>) -> DaemonOptions {
        DaemonOptions {
            vault_path: self.vault_path.clone(),
            passphrase: SecretString::from(FIXTURE_PASSPHRASE.to_string()),
            config_path: self.config_path.clone(),
            state_dir: self.state_dir.clone(),
            timeout_override,
        }
    }

    /// Start an in-process daemon while holding the serialization lock.
    ///
    /// Keep the returned [`GuardedDaemon`] alive for as long as the daemon
    /// runs; dropping it releases the lock.
    pub async fn start(&self, timeout_override: Option<u64>) -> GuardedDaemon {
        self.start_with_client(timeout_override, None).await
    }

    /// Like [`Fixture::start`], substituting the daemon's upstream client
    /// (proxy tests trust the mock CA).
    pub async fn start_with_client(
        &self,
        timeout_override: Option<u64>,
        test_upstream_client: Option<UpstreamClient>,
    ) -> GuardedDaemon {
        let guard = daemon_test_lock().await;
        let options = self.options(timeout_override);
        let handle = match test_upstream_client {
            Some(client) => kyz_daemon::run_daemon_with_upstream(options, client).await,
            None => kyz_daemon::run_daemon(options).await,
        }
        .expect("daemon should start");
        GuardedDaemon {
            handle,
            _guard: guard,
        }
    }

    /// Daemon paths for this fixture.
    pub fn daemon_paths(&self) -> kyz_daemon::DaemonPaths {
        kyz_daemon::DaemonPaths::new(&self.state_dir)
    }

    /// Read the management IPC token left by a running daemon.
    pub fn ipc_token(&self) -> String {
        std::fs::read_to_string(self.daemon_paths().ipc_token_path())
            .expect("ipc token file")
            .trim()
            .to_string()
    }

    /// Assert that no secret material (fixture value, passphrase, IPC or
    /// proxy token) appears anywhere under the daemon state directory.
    ///
    /// Must run after a graceful shutdown: the token files legitimately
    /// hold the tokens while the daemon runs and are removed on stop.
    pub fn assert_no_secret_leaks(&self) {
        let mut failures = Vec::new();
        scan_dir_for(&self.daemon_paths().dir, &self.secret_value, &mut failures);
        scan_dir_for(&self.daemon_paths().dir, FIXTURE_PASSPHRASE, &mut failures);
        scan_dir_for(
            &self.daemon_paths().dir,
            &Self::token_if_present(&self.daemon_paths().ipc_token_path()),
            &mut failures,
        );
        scan_dir_for(
            &self.daemon_paths().dir,
            &Self::token_if_present(&self.daemon_paths().proxy_token_path()),
            &mut failures,
        );
        assert!(
            failures.is_empty(),
            "secret material leaked into daemon state files: {failures:?}"
        );
    }

    fn token_if_present(path: &Path) -> String {
        std::fs::read_to_string(path)
            .map(|raw| raw.trim().to_string())
            .unwrap_or_default()
    }

    /// Assert no vault session file or keyring-backed session was created.
    pub fn assert_no_session_artifacts(&self) {
        let session_file =
            VaultSession::session_file_for(&self.vault_path).expect("session file path");
        assert!(
            !session_file.exists(),
            "daemon must not create a vault session file"
        );
    }
}

fn scan_dir_for(dir: &Path, needle: &str, failures: &mut Vec<String>) {
    if needle.is_empty() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir_for(&path, needle, failures);
            continue;
        }
        let Ok(contents) = std::fs::read(&path) else {
            continue;
        };
        if contents
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
        {
            failures.push(path.display().to_string());
        }
    }
}

fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{:x}-{}", nanos, std::process::id())
}
