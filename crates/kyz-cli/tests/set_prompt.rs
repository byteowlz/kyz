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
//! `kyz set` field prompting: bare `-f NAME` reads hidden input (terminal) or
//! stdin, `--interactive` edits existing fields, partial updates merge.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kyz_core::VaultStore;
use secrecy::{ExposeSecret as _, SecretString};

const PASSPHRASE: &str = "set-prompt-test-passphrase-1234567890";

struct Fixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    vault: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().to_owned();
        std::fs::write(base.join("config.toml"), "profile = \"default\"\n").expect("config");
        let fixture = Self {
            vault: base.join("vault").join("vault.json"),
            base,
            _temp: temp,
        };
        for args in [["vault", "create"], ["vault", "unlock"]] {
            assert_ok(&fixture.run_stdin(&args, PASSPHRASE), "prepare vault");
        }
        fixture
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kyz"));
        command
            .args(self.global_args())
            .args(args)
            .env("XDG_CONFIG_HOME", self.base.join("xdg-config"))
            .env("XDG_DATA_HOME", self.base.join("xdg-data"))
            .env("XDG_STATE_HOME", self.base.join("state"))
            .env_remove("KYZ_ENV")
            .env_remove("KYZ_NO_READ");
        command
    }

    fn global_args(&self) -> Vec<String> {
        vec![
            "--config".into(),
            self.base.join("config.toml").display().to_string(),
            "--vault".into(),
            self.vault.display().to_string(),
        ]
    }

    fn run_stdin(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kyz");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write stdin");
        child.wait_with_output().expect("wait kyz")
    }

    /// Field values read through the library, never through CLI output.
    fn fields(&self, key: &str) -> BTreeMap<String, String> {
        let vault = VaultStore::new(self.vault.clone())
            .open_in_memory(&SecretString::from(PASSPHRASE.to_owned()))
            .expect("open vault");
        vault
            .get("svc", key)
            .expect("entry")
            .fields
            .iter()
            .map(|(name, value)| (name.clone(), value.expose_secret().to_owned()))
            .collect()
    }

    fn vault_bytes(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).expect("read dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_none_or(|ext| ext != "lock") {
                    out.insert(path.clone(), std::fs::read(&path).expect("read"));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(self.vault.parent().expect("vault dir"), &mut out);
        out
    }
}

fn assert_ok(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed: {} / {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn bare_field_reads_piped_stdin_and_partial_updates_merge() {
    let fixture = Fixture::new();
    assert_ok(
        &fixture.run_stdin(
            &[
                "set",
                "--service",
                "svc",
                "app",
                "-f",
                "user=alice",
                "-f",
                "password",
            ],
            "piped-secret\n",
        ),
        "set with bare field",
    );
    assert_eq!(
        fixture.fields("app"),
        map(&[("password", "piped-secret"), ("user", "alice")])
    );

    assert_ok(
        &fixture.run_stdin(&["set", "--service", "svc", "app", "-f", "user=bob"], ""),
        "partial update",
    );
    assert_eq!(
        fixture.fields("app"),
        map(&[("password", "piped-secret"), ("user", "bob")])
    );
}

#[test]
fn piped_stdin_refuses_multiple_bare_fields_and_interactive_without_writing() {
    let fixture = Fixture::new();
    assert_ok(
        &fixture.run_stdin(&["set", "--service", "svc", "app", "-f", "user=alice"], ""),
        "seed",
    );
    let before = fixture.vault_bytes();
    for args in [
        ["set", "--service", "svc", "app", "-f", "a", "-f", "b"].as_slice(),
        ["set", "--service", "svc", "app", "--interactive"].as_slice(),
    ] {
        let output = fixture.run_stdin(args, "x\ny\n");
        assert!(!output.status.success(), "{args:?} must fail");
    }
    assert_eq!(fixture.vault_bytes(), before);
}

/// Drives `kyz` inside a real pseudo-terminal via util-linux `script`.
#[cfg(target_os = "linux")]
struct Terminal {
    child: std::process::Child,
    output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

#[cfg(target_os = "linux")]
impl Terminal {
    fn spawn(fixture: &Fixture, args: &[&str]) -> Option<Self> {
        use std::io::Read as _;
        if Command::new("script").arg("--version").output().is_err() {
            eprintln!("skipping: util-linux script unavailable");
            return None;
        }
        let quote = |s: &str| format!("'{}'", s.replace('\'', r"'\''"));
        let line = std::iter::once(env!("CARGO_BIN_EXE_kyz").to_owned())
            .chain(fixture.global_args())
            .chain(args.iter().map(|s| (*s).to_owned()))
            .map(|s| quote(&s))
            .collect::<Vec<_>>()
            .join(" ");
        let base = fixture.command(&[]);
        let mut command = Command::new("script");
        command.args(["-qefc", &line, "/dev/null"]);
        for (key, value) in base.get_envs() {
            match value {
                Some(value) => command.env(key, value),
                None => command.env_remove(key),
            };
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn script");
        let mut stdout = child.stdout.take().expect("stdout");
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buf = [0_u8; 512];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Some(Self { child, output })
    }

    fn transcript(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    /// Wait for the `occurrence`-th appearance of `prompt`, then type `line`.
    fn answer(&mut self, prompt: &str, occurrence: usize, line: &str) {
        let started = std::time::Instant::now();
        while self.transcript().matches(prompt).count() < occurrence {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(30),
                "prompt {prompt:?} not shown; transcript: {}",
                self.transcript()
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let stdin = self.child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(format!("{line}\r").as_bytes())
            .expect("type");
        stdin.flush().expect("flush");
    }

    fn finish(mut self) -> (bool, String) {
        drop(self.child.stdin.take());
        let status = self.child.wait().expect("wait script");
        std::thread::sleep(std::time::Duration::from_millis(50));
        (status.success(), self.transcript())
    }
}

#[test]
#[cfg(target_os = "linux")]
fn terminal_prompt_is_hidden_and_confirmed() {
    let fixture = Fixture::new();
    let Some(mut term) = Terminal::spawn(
        &fixture,
        &["set", "--service", "svc", "app", "-f", "password"],
    ) else {
        return;
    };
    term.answer("password: ", 1, "tty-secret-value");
    term.answer("Confirm password: ", 1, "tty-secret-value");
    let (ok, transcript) = term.finish();
    assert!(ok, "set failed: {transcript}");
    assert!(!transcript.contains("tty-secret-value"), "value echoed");
    assert_eq!(
        fixture.fields("app"),
        map(&[("password", "tty-secret-value")])
    );

    let before = fixture.vault_bytes();
    let mut term = Terminal::spawn(
        &fixture,
        &["set", "--service", "svc", "app", "-f", "password"],
    )
    .expect("terminal");
    term.answer("password: ", 1, "first-value");
    term.answer("Confirm password: ", 1, "different-value");
    let (ok, transcript) = term.finish();
    assert!(!ok, "mismatched confirmation must fail: {transcript}");
    assert_eq!(fixture.vault_bytes(), before);
}

#[test]
#[cfg(target_os = "linux")]
fn interactive_and_bare_set_edit_existing_fields() {
    let fixture = Fixture::new();
    assert_ok(
        &fixture.run_stdin(
            &[
                "set",
                "--service",
                "svc",
                "app",
                "-f",
                "user=alice",
                "-f",
                "password=old",
            ],
            "",
        ),
        "seed",
    );
    // Fields are prompted in name order: password, then user.
    let Some(mut term) = Terminal::spawn(&fixture, &["set", "--service", "svc", "app", "-i"])
    else {
        return;
    };
    term.answer("password (Enter keeps current): ", 1, "rotated-secret");
    term.answer("Confirm password: ", 1, "rotated-secret");
    term.answer("user (Enter keeps current): ", 1, "");
    let (ok, transcript) = term.finish();
    assert!(ok, "interactive set failed: {transcript}");
    assert!(!transcript.contains("rotated-secret"), "value echoed");
    assert_eq!(
        fixture.fields("app"),
        map(&[("password", "rotated-secret"), ("user", "alice")])
    );

    // Bare `kyz set KEY` on a multi-field entry edits fields, never adds `value`.
    let mut term =
        Terminal::spawn(&fixture, &["set", "--service", "svc", "app"]).expect("terminal");
    term.answer("password (Enter keeps current): ", 1, "");
    term.answer("user (Enter keeps current): ", 1, "carol");
    term.answer("Confirm user: ", 1, "carol");
    let (ok, transcript) = term.finish();
    assert!(ok, "bare set failed: {transcript}");
    assert_eq!(
        fixture.fields("app"),
        map(&[("password", "rotated-secret"), ("user", "carol")])
    );
}
