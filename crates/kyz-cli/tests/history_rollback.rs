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
//! Process-level tests locking the `kyz history` ↔ `kyz rollback --to`
//! contract across vault formats: every `#n` sequence the display offers
//! must resolve in both formats, the v3 live entry (which v3 rollback
//! cannot target) must not advertise one, and the conflict footnote must
//! count the stored log rather than the truncated display window.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kyz_core::VaultSession;
use secrecy::SecretString;

const PASSPHRASE: &str = "history-test-passphrase-1234567890";

struct HistoryFixture {
    base: PathBuf,
    config_path: PathBuf,
}

impl HistoryFixture {
    fn new() -> Self {
        Self::with_config("profile = \"default\"\n")
    }

    fn with_config(config: &str) -> Self {
        let base = tempfile::tempdir().expect("tempdir").keep();
        let config_path = base.join("config").join("config.toml");
        std::fs::create_dir_all(config_path.parent().expect("config parent")).expect("mkdir");
        std::fs::write(&config_path, config).expect("write config");
        Self { base, config_path }
    }

    fn vault_path(&self, name: &str) -> PathBuf {
        self.base.join(name).join("vault.json")
    }

    fn command(&self, vault: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kyz"));
        command
            .arg("--config")
            .arg(&self.config_path)
            .arg("--vault")
            .arg(vault)
            .args(args)
            .env("XDG_CONFIG_HOME", self.base.join("xdg-config"))
            .env("XDG_DATA_HOME", self.base.join("xdg-data"))
            .env("XDG_STATE_HOME", self.base.join("state"))
            .env_remove("KYZ_ENV");
        command
    }

    fn run(&self, vault: &Path, args: &[&str]) -> Output {
        self.command(vault, args).output().expect("run kyz")
    }

    /// Run with the passphrase piped to stdin (`vault create` / `vault
    /// unlock` read it from a non-terminal stdin).
    fn run_with_passphrase(&self, vault: &Path, args: &[&str]) -> Output {
        let mut child = self
            .command(vault, args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kyz");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(PASSPHRASE.as_bytes())
            .expect("pipe passphrase");
        child.wait_with_output().expect("wait kyz")
    }

    fn assert_ok(output: &Output, context: &str) {
        assert!(
            output.status.success(),
            "{context} failed: {} / {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

fn history_json(fixture: &HistoryFixture, vault: &Path, secret: &str) -> serde_json::Value {
    let out = fixture.run(vault, &["history", secret, "--json"]);
    HistoryFixture::assert_ok(&out, "history --json");
    serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("history JSON")
}

#[test]
fn v4_history_seqs_resolve_in_rollback() {
    let fixture = HistoryFixture::new();
    let vault = fixture.vault_path("vault");

    HistoryFixture::assert_ok(
        &fixture.run_with_passphrase(&vault, &["vault", "create"]),
        "vault create",
    );
    HistoryFixture::assert_ok(
        &fixture.run_with_passphrase(&vault, &["vault", "unlock"]),
        "vault unlock",
    );
    for round in 1..=3 {
        HistoryFixture::assert_ok(
            &fixture.run(
                &vault,
                &[
                    "set",
                    "--service",
                    "svc",
                    "--field",
                    &format!("f{round}=v{round}"),
                    "hist-key",
                ],
            ),
            "set",
        );
    }

    let payload = history_json(&fixture, &vault, "svc/hist-key");
    let rows = payload["history"].as_array().expect("history array");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["role"], "current");
    // Newest-first display, sequence counting from the oldest operation.
    let seqs: Vec<u64> = rows
        .iter()
        .map(|row| row["seq"].as_u64().expect("seq is a number"))
        .collect();
    assert_eq!(seqs, vec![3, 2, 1]);

    // Every displayed sequence must be an accepted `--to` target — and
    // stays one as the rollbacks themselves append new operations.
    for seq in &seqs {
        HistoryFixture::assert_ok(
            &fixture.run(
                &vault,
                &["rollback", "svc/hist-key", "--to", &seq.to_string()],
            ),
            "rollback",
        );
    }
}

// Ignored on macOS: the in-process `VaultSession::save` stores the DK in
// the OS keyring, and macOS keychain items are app-bound — the `kyz`
// subprocess reading one planted by this test binary blocks on an
// authorization prompt that CI (and any headless run) can never answer.
// Linux and Windows keep the coverage; unblocking macOS needs an explicit
// fallback-session save path in kyz-core.
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "cross-binary keychain read blocks on a macOS authorization prompt"
)]
fn v3_live_entry_has_no_seq_and_archived_seqs_resolve() {
    let fixture = HistoryFixture::new();
    let vault = fixture.vault_path("vault");

    // Build a legacy v3 vault directly: three writes archive versions
    // 1 and 2, the live entry would be the (nonexistent) version 3.
    std::fs::create_dir_all(vault.parent().expect("vault parent")).expect("mkdir");
    let secret = SecretString::from(PASSPHRASE.to_string());
    let (mut v3, dk) = kyz_core::vault_v3::VaultFileV3::create(&secret).expect("create v3 vault");
    for round in 1..=3 {
        let entry = kyz_core::SecretEntry::new(
            "svc",
            "hist-key",
            std::collections::BTreeMap::from([(
                format!("f{round}"),
                SecretString::from(format!("v{round}")),
            )]),
        );
        v3.set_with_retention(&entry, &dk, 10).expect("v3 set");
    }
    std::fs::write(
        &vault,
        serde_json::to_string_pretty(&v3).expect("serialize v3 vault"),
    )
    .expect("write v3 vault");

    // An active session alongside a still-v3 file (the restore-from-
    // backup state): v3 history needs no session, v3 rollback does.
    VaultSession::new(dk, &vault, 600)
        .save()
        .expect("save session");

    let payload = history_json(&fixture, &vault, "svc/hist-key");
    let rows = payload["history"].as_array().expect("history array");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["role"], "current");
    // The live entry is not a v3 rollback target; it must not claim a
    // sequence (the pre-v4 renderer never numbered it either).
    assert!(rows[0]["seq"].is_null());
    let seqs: Vec<u64> = rows[1..]
        .iter()
        .map(|row| row["seq"].as_u64().expect("seq is a number"))
        .collect();
    assert_eq!(seqs, vec![2, 1]);

    let human = fixture.run(&vault, &["history", "svc/hist-key"]);
    HistoryFixture::assert_ok(&human, "history");
    let stdout = String::from_utf8_lossy(&human.stdout);
    let current_line = stdout.lines().nth(1).expect("current row line");
    assert!(
        current_line.contains("[current") && !current_line.contains('#'),
        "live entry renders without a sequence handle: {stdout}"
    );

    for seq in &seqs {
        HistoryFixture::assert_ok(
            &fixture.run(
                &vault,
                &["rollback", "svc/hist-key", "--to", &seq.to_string()],
            ),
            "rollback",
        );
    }
}

#[test]
fn v3_tampered_version_number_does_not_panic_history() {
    let fixture = HistoryFixture::new();
    let vault = fixture.vault_path("vault");

    let secret = SecretString::from(PASSPHRASE.to_string());
    let (mut v3, dk) = kyz_core::vault_v3::VaultFileV3::create(&secret).expect("create v3 vault");
    std::fs::create_dir_all(vault.parent().expect("vault parent")).expect("mkdir");
    let entry = kyz_core::SecretEntry::new(
        "svc",
        "hist-key",
        std::collections::BTreeMap::from([(
            String::from("f1"),
            SecretString::from(String::from("v1")),
        )]),
    );
    v3.set_with_retention(&entry, &dk, 10).expect("v3 set");
    v3.set_with_retention(&entry, &dk, 10).expect("v3 set");
    std::fs::write(
        &vault,
        serde_json::to_string_pretty(&v3).expect("serialize v3 vault"),
    )
    .expect("write v3 vault");

    // The version number is unauthenticated plaintext metadata; u32::MAX
    // used to overflow the display path's `version + 1`.
    let mut tampered: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vault).expect("read vault"))
            .expect("parse vault");
    tampered["entries"]["svc/hist-key"]["history"][0]["version"] =
        serde_json::json!(u64::from(u32::MAX));
    std::fs::write(
        &vault,
        serde_json::to_string_pretty(&tampered).expect("serialize vault"),
    )
    .expect("write tampered vault");

    for args in [
        vec!["history", "svc/hist-key"],
        vec!["history", "svc/hist-key", "--json"],
    ] {
        let out = fixture.run(&vault, &args);
        HistoryFixture::assert_ok(&out, "history on tampered vault");
    }
}

#[test]
fn conflict_footnote_counts_stored_log_beyond_display_window() {
    let fixture = HistoryFixture::with_config("profile = \"default\"\n\nhistory_retention = 2\n");
    let vault = fixture.vault_path("vault-a");
    let replica = fixture.vault_path("vault-b");

    HistoryFixture::assert_ok(
        &fixture.run_with_passphrase(&vault, &["vault", "create"]),
        "vault create",
    );
    HistoryFixture::assert_ok(
        &fixture.run_with_passphrase(&vault, &["vault", "unlock"]),
        "vault unlock",
    );
    HistoryFixture::assert_ok(
        &fixture.run(
            &vault,
            &["set", "--service", "svc", "--field", "f=base", "conf"],
        ),
        "base set",
    );

    // A replica diverges: the replica records two writes after the base
    // so that, once merged, the losing concurrent op ends up two
    // sequences below the display window's edge while still being a
    // frontier conflict (only a new write on this vault could resolve
    // it, and none follows).
    copy_vault(&vault, &replica);
    HistoryFixture::assert_ok(
        &fixture.run_with_passphrase(&replica, &["vault", "unlock"]),
        "unlock replica",
    );
    HistoryFixture::assert_ok(
        &fixture.run(
            &vault,
            &["set", "--service", "svc", "--field", "f=side-a", "conf"],
        ),
        "set on A",
    );
    HistoryFixture::assert_ok(
        &fixture.run(
            &replica,
            &["set", "--service", "svc", "--field", "f=b1", "conf"],
        ),
        "set on B",
    );
    HistoryFixture::assert_ok(
        &fixture.run(
            &replica,
            &["set", "--service", "svc", "--field", "f=b2", "conf"],
        ),
        "set on B",
    );
    HistoryFixture::assert_ok(
        &fixture.run(&vault, &["vault", "merge", &replica.to_string_lossy()]),
        "merge replica",
    );
    // Stored ops oldest→newest: base(1), side-a(2 — the concurrent loser,
    // still a frontier conflict), replica's first write(3), replica's
    // second write(4, current).

    // Display window holds only sequences 4 and 3; the stored (and
    // rollback-able) conflict at sequence 2 must still be counted.
    let payload = history_json(&fixture, &vault, "svc/conf");
    let rows = payload["history"].as_array().expect("history array");
    assert_eq!(rows.len(), 2, "retention trims display only: {payload}");

    let human = fixture.run(&vault, &["history", "svc/conf"]);
    HistoryFixture::assert_ok(&human, "history");
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        stdout.contains("! 1 concurrent write(s) kept for rollback"),
        "footnote counts the stored conflict: {stdout}"
    );

    // The out-of-window conflict stays rollback-able by its stable seq.
    HistoryFixture::assert_ok(
        &fixture.run(&vault, &["rollback", "svc/conf", "--to", "2"]),
        "rollback to conflict",
    );
}

/// trx-dgqe.3 / trx-dgqe.4: replica A deletes an entry while replica B
/// edits it concurrently. After merging B into A the entry is deleted
/// (delete wins); history must not call B's edit `current`, and the merge
/// report must name the edit it hid.
#[test]
fn edit_lost_to_concurrent_delete_is_reported_and_not_current() {
    let fixture = HistoryFixture::new();
    let vault = fixture.vault_path("vault-a");
    let replica = fixture.vault_path("vault-b");
    let run_ok = |path: &Path, args: &[&str], what: &str| {
        HistoryFixture::assert_ok(&fixture.run(path, args), what);
    };

    HistoryFixture::assert_ok(
        &fixture.run_with_passphrase(&vault, &["vault", "create"]),
        "vault create",
    );
    HistoryFixture::assert_ok(
        &fixture.run_with_passphrase(&vault, &["vault", "unlock"]),
        "vault unlock",
    );
    run_ok(
        &vault,
        &["set", "--service", "svc", "todel", "base"],
        "base set",
    );
    copy_vault(&vault, &replica);
    HistoryFixture::assert_ok(
        &fixture.run_with_passphrase(&replica, &["vault", "unlock"]),
        "unlock replica",
    );
    run_ok(
        &vault,
        &["delete", "--service", "svc", "todel", "--yes"],
        "delete on A",
    );
    run_ok(
        &replica,
        &["set", "--service", "svc", "todel", "edited-on-b"],
        "edit on B",
    );

    let merge = fixture.run(
        &vault,
        &["vault", "merge", &replica.to_string_lossy(), "--json"],
    );
    HistoryFixture::assert_ok(&merge, "merge");
    let report: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&merge.stdout)).expect("merge JSON");
    let lost = report["lost_to_delete"].as_array().expect("lost_to_delete");
    assert_eq!(
        lost.len(),
        1,
        "edit hidden by the delete must be reported: {report}"
    );
    assert_eq!(lost[0]["entry"], "svc/todel");
    assert_eq!(lost[0]["losing"].as_array().map(Vec::len), Some(1));
    assert_eq!(lost[0]["tombstones"].as_array().map(Vec::len), Some(1));

    let payload = history_json(&fixture, &vault, "svc/todel");
    let mut roles: Vec<String> = payload["history"]
        .as_array()
        .expect("history")
        .iter()
        .map(|row| row["role"].as_str().expect("role").to_string())
        .collect();
    roles.sort();
    assert_eq!(
        roles,
        vec!["ancestor", "conflict", "tombstone"],
        "{payload}"
    );

    let human = fixture.run(&vault, &["history", "svc/todel"]);
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(!stdout.contains("[current"), "{stdout}");
    assert!(stdout.contains("entry is deleted"), "{stdout}");

    // The lost edit is recoverable: rolling back to it revives the entry.
    let conflict_seq = payload["history"]
        .as_array()
        .expect("history")
        .iter()
        .find(|row| row["role"] == "conflict")
        .and_then(|row| row["seq"].as_u64())
        .expect("conflict seq")
        .to_string();
    run_ok(
        &vault,
        &["rollback", "svc/todel", "--to", &conflict_seq],
        "rollback",
    );
    let listed = fixture.run(&vault, &["list", "--service", "svc"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("todel"));
}

/// Copy a vault replica: the manifest plus its sibling entries directory.
fn copy_vault(from: &Path, to: &Path) {
    let entries = |p: &Path| p.with_file_name("vault.entries");
    std::fs::create_dir_all(entries(to)).expect("mkdir replica entries");
    std::fs::copy(from, to).expect("copy manifest");
    for item in std::fs::read_dir(entries(from)).expect("read entries") {
        let item = item.expect("entry");
        std::fs::copy(item.path(), entries(to).join(item.file_name())).expect("copy entry");
    }
}
