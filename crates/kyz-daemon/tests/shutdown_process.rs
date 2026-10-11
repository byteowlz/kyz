#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::significant_drop_tightening,
        reason = "tests assert outcomes and hold fixtures until shutdown"
    )
)]
//! Verify actual process exit, including Tokio blocking-pool teardown.
#[expect(
    dead_code,
    reason = "shared fixture has helpers for other integration suites"
)]
mod common;
#[expect(
    dead_code,
    reason = "shared HTTP test doubles have helpers for other suites"
)]
#[path = "proxy_http/support.rs"]
mod support;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_MARKER: &str = "KYZ_SHUTDOWN_REGRESSION_MARKER";

#[test]
fn finite_upstream_shutdown_child() {
    let Some(marker) = std::env::var_os(CHILD_MARKER) else {
        return;
    };
    let marker = PathBuf::from(marker);
    // Keep the mock alive outside block_on and through Runtime::drop. Dropping
    // it early would close the upstream socket and hide stuck blocking work.
    let pf = support::ProxyFixture::new();
    let root = pf
        .fixture
        .vault_path
        .parent()
        .expect("vault parent")
        .parent()
        .expect("fixture root");
    std::fs::write(
        marker.with_extension("root"),
        root.to_string_lossy().as_bytes(),
    )
    .expect("root marker");
    pf.write_config(&format!(
        "[[proxy.rules]]\nname=\"shutdown-test\"\nhost=\"api.example.com\"\nupstream=\"{}\"\n[[proxy.rules.credentials]]\nalias=\"app\"\nservice=\"app\"\nkey=\"api\"\nfields=[\"token\"]\n[proxy.rules.headers]\n\"X-Api-Key\"=\"{{{{app.token}}}}\"\n", pf.mock.url
    ));
    let config = std::fs::read_to_string(&pf.fixture.config_path).expect("config");
    std::fs::write(
        &pf.fixture.config_path,
        config.replace("timeout = 30", "timeout = 1"),
    )
    .expect("finite deadline");
    // A real socket read, not a Tokio sleep in the daemon's own runtime.
    pf.mock
        .push_response(support::ScriptedResponse::status(200).delayed(Duration::from_mins(2)));
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let client = pf.test_client(1, 1024, None);
        let daemon = pf.fixture.start_with_client(None, Some(client)).await;
        let addr = pf.proxy_addr().await;
        let token = pf.proxy_token();
        let request = tokio::spawn(async move {
            support::send_http(
                addr,
                "GET",
                "api.example.com",
                "/",
                &[("X-Kyz-Proxy-Token".to_owned(), token)],
                b"",
            )
            .await
        });
        pf.mock.wait_for_requests(1).await;
        daemon.shutdown().await;
        assert_eq!(
            request
                .await
                .expect("request join")
                .expect("HTTP response")
                .status,
            504
        );
        assert!(!pf.fixture.daemon_paths().pid_path().exists());
        std::fs::write(&marker, b"daemon wait completed").expect("shutdown marker");
    });
    drop(runtime);
    std::fs::write(&marker, b"runtime dropped").expect("runtime marker");
    pf.fixture.assert_no_secret_leaks();
    pf.fixture.assert_no_session_artifacts();
    pf.mock.stop();
}

#[test]
fn hanging_upstream_with_finite_timeout_allows_process_exit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("shutdown-marker");
    let mut child = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "finite_upstream_shutdown_child"])
        .env(CHILD_MARKER, &marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn synthetic child");
    let started = Instant::now();
    let exited = loop {
        if child.try_wait().expect("poll child").is_some() {
            break true;
        }
        if started.elapsed() > Duration::from_secs(30) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    if !exited {
        child.kill().expect("kill hung synthetic child");
    }
    let output = child.wait_with_output().expect("reap child");
    let final_marker = std::fs::read(&marker).ok();
    if let Ok(root) = std::fs::read_to_string(marker.with_extension("root")) {
        std::fs::remove_dir_all(root).expect("remove synthetic fixture");
    }
    assert!(
        exited,
        "process failed to exit after bounded upstream shutdown"
    );
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(final_marker, Some(b"runtime dropped".to_vec()));
}
