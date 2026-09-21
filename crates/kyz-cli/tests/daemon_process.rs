#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::panic_in_result_fn,
        reason = "tests assert outcomes: expect/unwrap/panic are the failure mechanism"
    )
)]
//! Process-level daemon tests driving the real `kyz` binary.
//!
//! Covers the background launcher: passphrase via environment (launcher
//! only), bootstrap-pipe handoff with a scrubbed child environment,
//! handshake semantics, stop, lifecycle timeout, and crash recovery.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use secrecy::SecretString;

const PASSPHRASE: &str = "process-test-passphrase-1234567890";

struct ProcFixture {
    base: PathBuf,
    vault_path: PathBuf,
    config_path: PathBuf,
    state_dir: PathBuf,
}

impl ProcFixture {
    fn new() -> Self {
        let base = tempfile::tempdir().expect("tempdir").keep();
        let vault_path = base.join("vault").join("vault.json");
        let config_path = base.join("config").join("config.toml");
        std::fs::create_dir_all(vault_path.parent().expect("vault parent")).expect("mkdir");
        std::fs::create_dir_all(config_path.parent().expect("config parent")).expect("mkdir");
        std::fs::write(
            &config_path,
            "profile = \"default\"\n\n[daemon]\ntimeout_secs = 0\n",
        )
        .expect("write config");

        let secret = SecretString::from(PASSPHRASE.to_string());
        let (vault, _dk) = kyz_core::vault_v3::VaultFileV3::create(&secret).expect("create vault");
        std::fs::write(
            &vault_path,
            serde_json::to_string_pretty(&vault).expect("serialize vault"),
        )
        .expect("write vault");

        Self {
            state_dir: base.join("state"),
            base,
            vault_path,
            config_path,
        }
    }

    fn kyz(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kyz"));
        command
            .arg("--config")
            .arg(&self.config_path)
            .arg("--vault")
            .arg(&self.vault_path)
            .args(args)
            .env("XDG_CONFIG_HOME", self.base.join("xdg-config"))
            .env("XDG_DATA_HOME", self.base.join("xdg-data"))
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("KYZ_VAULT_PASSWORD", PASSPHRASE)
            .env_remove("KYZ_ENV");
        command
    }

    /// Start the daemon and wait for the launcher to finish.
    ///
    /// The launcher's stdio goes to files (not pipes): on Windows a piped
    /// grandchild keeps inherited pipe handles open, and `Command::output`
    /// would block until the detached daemon exits.
    fn start(&self, extra: &[&str]) -> Output {
        use std::process::Stdio;

        let mut args = vec!["daemon", "start"];
        args.extend_from_slice(extra);
        let stdout = Stdio::from(
            std::fs::File::create(self.base.join("launcher.out")).expect("launcher log"),
        );
        let stderr = Stdio::from(
            std::fs::File::create(self.base.join("launcher.err")).expect("launcher log"),
        );
        let child = self
            .kyz(&args)
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .expect("spawn kyz daemon start");
        child.wait_with_output().expect("wait for launcher")
    }

    fn launcher_output(&self) -> String {
        std::fs::read_to_string(self.base.join("launcher.out")).unwrap_or_else(|_| String::new())
    }

    fn status_json(&self) -> serde_json::Value {
        let output = self
            .kyz(&["daemon", "status", "--json"])
            .output()
            .expect("run kyz daemon status");
        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "status output is not JSON ({e}): {stdout} / stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }

    fn stop(&self) -> Output {
        self.kyz(&["daemon", "stop"])
            .output()
            .expect("run kyz daemon stop")
    }
}

/// Wait until the daemon reports a pid, or fail with daemon.log context.
fn wait_running(fixture: &ProcFixture, timeout: Duration) -> u32 {
    let deadline = Instant::now() + timeout;
    loop {
        let status = fixture.status_json();
        if status.get("pid").is_some() {
            return status["pid"].as_u64().expect("pid") as u32;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not start; status: {status}"
        );
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn wait_not_running(fixture: &ProcFixture, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let status = fixture.status_json();
        if status.get("pid").is_none() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not stop; status: {status}"
        );
        std::thread::sleep(Duration::from_millis(150));
    }
}

#[test]
fn background_start_status_stop_roundtrip() {
    let fixture = ProcFixture::new();

    let start = fixture.start(&[]);
    assert!(
        start.status.success(),
        "daemon start failed: {}",
        fixture.launcher_output()
    );

    let pid = wait_running(&fixture, Duration::from_secs(30));
    assert!(pid > 0);

    fixture.stop();
    wait_not_running(&fixture, Duration::from_secs(10));

    let daemon_dir = fixture.state_dir.join("kyz").join("daemon");
    assert!(daemon_dir.join("daemon.lock").exists(), "lock file remains");
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_child_environment_has_no_passphrase() {
    let fixture = ProcFixture::new();
    let start = fixture.start(&[]);
    assert!(
        start.status.success(),
        "start failed: {}",
        fixture.launcher_output()
    );
    let pid = wait_running(&fixture, Duration::from_secs(30));

    let environ = std::fs::read_to_string(format!("/proc/{pid}/environ"))
        .expect("read daemon environ")
        .replace('\0', "\n");
    assert!(
        !environ.contains(PASSPHRASE),
        "daemon child must not carry the passphrase"
    );
    assert!(
        !environ.contains("KYZ_VAULT_PASSWORD"),
        "daemon child must not carry KYZ_VAULT_PASSWORD"
    );

    fixture.stop();
    wait_not_running(&fixture, Duration::from_secs(10));
}

#[test]
fn lifecycle_timeout_exits_the_daemon_process() {
    let fixture = ProcFixture::new();
    let start = fixture.start(&["--timeout", "1"]);
    assert!(
        start.status.success(),
        "start failed: {}",
        fixture.launcher_output()
    );

    let pid = wait_running(&fixture, Duration::from_secs(30));
    wait_not_running(&fixture, Duration::from_secs(20));

    // Timeout cleanup removed the pid file even though nobody called stop.
    let daemon_dir = fixture.state_dir.join("kyz").join("daemon");
    assert!(!daemon_dir.join("daemon.pid").exists(), "pid file cleaned");
    let _ = pid;
}

#[cfg(unix)]
#[test]
fn kill9_leaves_stale_files_but_restart_recovers() {
    let fixture = ProcFixture::new();
    let start = fixture.start(&[]);
    assert!(
        start.status.success(),
        "start failed: {}",
        fixture.launcher_output()
    );
    let pid = wait_running(&fixture, Duration::from_secs(30));

    // Hard kill: no cleanup handlers run.
    let kill = Command::new("kill").arg("-9").arg(pid.to_string()).output();
    assert!(kill.is_ok(), "sending SIGKILL failed");
    std::thread::sleep(Duration::from_millis(500));

    let daemon_dir = fixture.state_dir.join("kyz").join("daemon");
    // Stale pid/socket remain (SIGKILL ran no cleanup); the next start must recover.
    assert!(
        daemon_dir.join("daemon.pid").exists(),
        "kill -9 must leave the stale pid file behind"
    );
    let restart = fixture.start(&[]);
    assert!(
        restart.status.success(),
        "restart after kill -9 failed: {}",
        fixture.launcher_output()
    );
    let new_pid = wait_running(&fixture, Duration::from_secs(30));
    assert_ne!(new_pid, pid, "a fresh daemon process must be running");

    fixture.stop();
    wait_not_running(&fixture, Duration::from_secs(10));
}

#[test]
fn second_start_while_running_fails_with_log_context() {
    let fixture = ProcFixture::new();
    let start = fixture.start(&[]);
    assert!(
        start.status.success(),
        "start failed: {}",
        fixture.launcher_output()
    );
    let pid = wait_running(&fixture, Duration::from_secs(30));

    // A second start must fail (the child loses the instance-lock race);
    // it must not report the FIRST daemon's answers as its own success.
    let second = fixture.start(&[]);
    assert!(
        !second.status.success(),
        "second start must fail while the first daemon runs"
    );
    let stderr =
        std::fs::read_to_string(fixture.base.join("launcher.err")).expect("launcher stderr");
    assert!(
        stderr.contains("daemon exited during startup"),
        "failure should be attributed to the child: {stderr}"
    );
    assert!(
        stderr.contains("daemon.log"),
        "failure should include run-log context: {stderr}"
    );
    assert_eq!(
        fixture.status_json()["pid"].as_u64(),
        Some(u64::from(pid)),
        "the original daemon must still be the one running"
    );

    fixture.stop();
    wait_not_running(&fixture, Duration::from_secs(10));
}

#[test]
fn foreground_dry_run_starts_nothing() {
    let fixture = ProcFixture::new();
    let output = fixture
        .kyz(&["daemon", "start", "--foreground", "--dry-run"])
        .output()
        .expect("run foreground dry-run");

    assert!(
        output.status.success(),
        "dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let daemon_dir = fixture.state_dir.join("kyz").join("daemon");
    assert!(
        !daemon_dir.join("daemon.pid").exists(),
        "dry-run must not write runtime files"
    );
    assert!(
        fixture.status_json().get("pid").is_none(),
        "dry-run must leave no daemon running"
    );
}

#[test]
fn absurd_timeout_flag_is_rejected() {
    let fixture = ProcFixture::new();
    let output = fixture
        .kyz(&["daemon", "start", "--timeout", "9223372036854775807"])
        .output()
        .expect("run start with absurd timeout");

    assert!(!output.status.success(), "must exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exceeds the maximum"),
        "error should explain the cap: {stderr}"
    );
}

#[test]
fn reload_supports_yaml_output() {
    let fixture = ProcFixture::new();
    let start = fixture.start(&[]);
    assert!(
        start.status.success(),
        "start failed: {}",
        fixture.launcher_output()
    );
    wait_running(&fixture, Duration::from_secs(30));

    let output = fixture
        .kyz(&["daemon", "reload", "--yaml"])
        .output()
        .expect("run yaml reload");
    assert!(
        output.status.success(),
        "reload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hash:") && stdout.contains("timeout_secs:"),
        "--yaml must print the machine-readable snapshot summary, got: {stdout}"
    );

    fixture.stop();
    wait_not_running(&fixture, Duration::from_secs(10));
}

#[test]
fn reload_via_cli_reports_validation_errors() {
    let fixture = ProcFixture::new();
    let start = fixture.start(&[]);
    assert!(
        start.status.success(),
        "start failed: {}",
        fixture.launcher_output()
    );
    wait_running(&fixture, Duration::from_secs(30));

    // Break the config, reload must fail loudly.
    std::fs::write(
        &fixture.config_path,
        "[[proxy.rules]]\nname = \"bad\"\nhost = \"a.*.b\"\nupstream = \"https://x\"\n",
    )
    .expect("write invalid config");
    let reload = fixture.kyz(&["daemon", "reload"]).output().expect("reload");
    assert!(
        !reload.status.success(),
        "invalid reload must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&reload.stderr);
    assert!(
        stderr.contains("rejected reload"),
        "reload error should mention rejection: {stderr}"
    );

    // The daemon keeps serving the previous snapshot after a rejected reload.
    wait_running(&fixture, Duration::from_secs(5));

    fixture.stop();
    wait_not_running(&fixture, Duration::from_secs(10));
}
