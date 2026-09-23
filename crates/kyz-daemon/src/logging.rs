//! Run log (`daemon.log`) with size-based rotation.
//!
//! The run log is for diagnostics and is strictly separate from the audit
//! log. Rotation and write failures drop the offending line — they never
//! fall back to stderr, which could leak into service journals.
//!
//! `log` permits exactly one logger per process, while integration tests
//! run several daemons in one process — each with its own `daemon.log`.
//! The process-global [`DaemonLogger`] therefore fans every record out to
//! all registered sinks; a sink joins via [`DaemonLogger::install`] and
//! leaves when its [`LogSinkGuard`] drops.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use log::{LevelFilter, Record};

/// Default maximum log file size before rotation (10 `MiB`).
pub const DEFAULT_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Default number of rotated files retained.
pub const DEFAULT_LOG_RETAINED: u32 = 5;

/// Append-only file writer with size-based rotation.
///
/// Every failure mode degrades to "drop the line": a daemon must keep
/// running even when its log directory is broken, and the alternative
/// (writing elsewhere) risks leaking sensitive context.
pub struct RotatingWriter {
    path: PathBuf,
    max_bytes: u64,
    retained: u32,
    file: Option<File>,
    written: u64,
}

impl RotatingWriter {
    /// Create a writer for `path` (does not open the file yet).
    #[must_use]
    pub fn new(path: &Path, max_bytes: u64, retained: u32) -> Self {
        Self {
            path: path.to_path_buf(),
            max_bytes: max_bytes.max(1024),
            retained: retained.max(1),
            file: None,
            written: 0,
        }
    }

    /// Append one line (a trailing newline is added). Best effort.
    pub fn write_line(&mut self, line: &str) {
        if self.file.is_none() && self.open().is_err() {
            return;
        }
        let payload = format!("{line}\n");
        if self.written + payload.len() as u64 > self.max_bytes {
            self.rotate();
        }
        let Some(file) = self.file.as_mut() else {
            return;
        };
        match file
            .write_all(payload.as_bytes())
            .and_then(|()| file.flush())
        {
            Ok(()) => {
                self.written += payload.len() as u64;
            }
            Err(_) => {
                // Force a reopen attempt on the next line.
                self.file = None;
            }
        }
    }

    /// Flush the currently open file, if any. Best effort.
    pub fn flush_current(&mut self) {
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
    }

    fn open(&mut self) -> std::io::Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        // Log files may carry sensitive context; they are private (0600)
        // like every other file under the daemon state dir. A chmod
        // failure fails the open so no line is ever written to a
        // world-readable file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        }
        self.written = file.metadata().map_or(0, |m| m.len());
        self.file = Some(file);
        Ok(())
    }

    fn rotate(&mut self) {
        self.file = None;
        for index in (1..self.retained).rev() {
            let from = format!("{}.{index}", self.path.display());
            let to = format!("{}.{}", self.path.display(), index + 1);
            let _ = fs::rename(&from, &to);
        }
        let _ = fs::rename(&self.path, format!("{}.1", self.path.display()));
        self.written = 0;
        let _ = self.open();
    }
}

impl std::fmt::Debug for RotatingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatingWriter")
            .field("path", &self.path)
            .field("max_bytes", &self.max_bytes)
            .field("retained", &self.retained)
            .field("open", &self.file.is_some())
            .field("written", &self.written)
            .finish()
    }
}

/// One registered run-log destination: a rotating writer plus its level.
struct Sink {
    writer: Mutex<RotatingWriter>,
    level: Mutex<LevelFilter>,
}

impl Sink {
    fn effective_level(&self) -> LevelFilter {
        self.level.lock().map_or(LevelFilter::Off, |level| *level)
    }
}

/// Registered run-log sinks of this process (see the module doc).
static SINKS: OnceLock<Mutex<Vec<Arc<Sink>>>> = OnceLock::new();

/// Whether the fan-out logger has been installed as the process logger.
static ROUTER_INSTALLED: OnceLock<()> = OnceLock::new();

fn sinks() -> &'static Mutex<Vec<Arc<Sink>>> {
    SINKS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Raise `log::set_max_level` to the most verbose registered sink so
/// records reach the logger before per-sink filtering.
fn refresh_max_level() {
    let max = sinks().lock().map_or(LevelFilter::Off, |sinks| {
        sinks
            .iter()
            .map(|sink| sink.effective_level())
            .max()
            .unwrap_or(LevelFilter::Off)
    });
    log::set_max_level(max);
}

fn format_record(record: &Record<'_>) -> String {
    let ts = humantime::format_rfc3339_seconds(std::time::SystemTime::now());
    format!(
        "{ts} {} {}: {}",
        record.level(),
        record.target(),
        record.args()
    )
}

/// `log::Log` implementation fanning records out to every registered run
/// log sink. Never writes to stderr.
#[derive(Debug, Clone, Copy)]
pub struct DaemonLogger;

impl DaemonLogger {
    /// Register a run-log sink at `path` and return the guard that
    /// deregisters it on drop.
    ///
    /// Best effort by design: a broken log path must never block daemon
    /// startup, so installation cannot fail — lines are simply dropped
    /// until the path works (see [`RotatingWriter`]).
    #[must_use]
    pub fn install(path: &Path, level: LevelFilter) -> LogSinkGuard {
        ROUTER_INSTALLED.get_or_init(|| {
            // Another logger (e.g. env_logger in tests) may already be
            // installed; in that case records keep going there and the
            // sinks below stay silent — never a daemon-process condition.
            let _ = log::set_boxed_logger(Box::new(Self));
        });
        let sink = Arc::new(Sink {
            writer: Mutex::new(RotatingWriter::new(
                path,
                DEFAULT_LOG_MAX_BYTES,
                DEFAULT_LOG_RETAINED,
            )),
            level: Mutex::new(level),
        });
        if let Ok(mut sinks) = sinks().lock() {
            sinks.push(Arc::clone(&sink));
        }
        refresh_max_level();
        LogSinkGuard {
            sink: Arc::downgrade(&sink),
        }
    }

    /// Flush every registered sink. Best effort.
    pub fn flush_global() {
        if let Ok(sinks) = sinks().lock() {
            for sink in sinks.iter() {
                if let Ok(mut writer) = sink.writer.lock() {
                    writer.flush_current();
                }
            }
        }
    }
}

impl log::Log for DaemonLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        sinks().lock().is_ok_and(|sinks| {
            sinks
                .iter()
                .any(|sink| metadata.level() <= sink.effective_level())
        })
    }

    fn log(&self, record: &Record<'_>) {
        if let Ok(sinks) = sinks().lock() {
            for sink in sinks.iter() {
                if record.level() <= sink.effective_level()
                    && let Ok(mut writer) = sink.writer.lock()
                {
                    writer.write_line(&format_record(record));
                }
            }
        }
    }

    fn flush(&self) {
        Self::flush_global();
    }
}

/// Ownership of one registered run-log sink; dropping it deregisters the
/// sink (daemon shutdown).
pub struct LogSinkGuard {
    sink: Weak<Sink>,
}

impl LogSinkGuard {
    /// Change the sink's level (e.g. `logging.level` changed on reload).
    pub fn set_level(&self, level: LevelFilter) {
        if let Some(sink) = self.sink.upgrade()
            && let Ok(mut current) = sink.level.lock()
        {
            *current = level;
        }
        refresh_max_level();
    }
}

impl Drop for LogSinkGuard {
    fn drop(&mut self) {
        let Some(sink) = self.sink.upgrade() else {
            return;
        };
        if let Ok(mut sinks) = sinks().lock() {
            sinks.retain(|candidate| !Arc::ptr_eq(candidate, &sink));
        }
        refresh_max_level();
    }
}

impl std::fmt::Debug for LogSinkGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogSinkGuard")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The router mutates process-global logger state; serialize the
    /// tests that exercise it so parallel max-level updates cannot race.
    fn router_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn rotation_retains_n_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("rotate.log");
        let mut writer = RotatingWriter::new(&path, 1024, 3);

        // ~40 bytes/line, 1024-byte cap: rotation triggers repeatedly.
        for i in 0..200 {
            writer.write_line(&format!("line-{i:04}-padding-padding-padding"));
        }

        assert!(path.exists(), "active log exists");
        assert!(tmp.path().join("rotate.log.1").exists(), "first rotation");
        assert!(tmp.path().join("rotate.log.2").exists(), "second rotation");
        assert!(tmp.path().join("rotate.log.3").exists(), "third rotation");
        assert!(
            !tmp.path().join("rotate.log.4").exists(),
            "retention limit respected"
        );
    }

    #[test]
    fn write_failure_does_not_panic() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Point the writer at a path whose parent is a regular file so
        // opening fails; lines must be dropped silently.
        let blocker = tmp.path().join("blocker");
        fs::write(&blocker, b"x").expect("write blocker");
        let path = tmp.path().join("blocker").join("daemon.log");
        let mut writer = RotatingWriter::new(&path, 1024, 2);
        writer.write_line("this line is dropped");
    }

    #[test]
    fn second_sink_gets_its_own_file() {
        let _guard = router_test_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = tmp.path().join("first.log");
        let second = tmp.path().join("second.log");

        let first_sink = DaemonLogger::install(&first, LevelFilter::Info);
        log::info!("to the first sink");
        let _second_sink = DaemonLogger::install(&second, LevelFilter::Info);
        log::warn!("to both sinks");
        drop(first_sink);
        log::error!("only to the second sink");

        let first_text = fs::read_to_string(&first).unwrap_or_default();
        let second_text = fs::read_to_string(&second).unwrap_or_default();
        assert!(first_text.contains("to the first sink"));
        assert!(first_text.contains("to both sinks"));
        assert!(
            !first_text.contains("only to the second sink"),
            "deregistered sink must not receive records: {first_text}"
        );
        assert!(second_text.contains("to both sinks"));
        assert!(second_text.contains("only to the second sink"));
    }

    #[test]
    fn set_level_changes_what_the_sink_captures() {
        let _guard = router_test_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("level.log");

        let sink = DaemonLogger::install(&path, LevelFilter::Warn);
        log::info!("dropped below the level");
        sink.set_level(LevelFilter::Info);
        log::info!("kept at the level");
        drop(sink);

        let text = fs::read_to_string(&path).unwrap_or_default();
        assert!(!text.contains("dropped below the level"), "got: {text}");
        assert!(text.contains("kept at the level"), "got: {text}");
    }
}
