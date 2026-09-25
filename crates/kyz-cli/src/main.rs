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
//! CLI interface for kyz - a cross-platform secrets manager.

use anyhow::{Context, Result, anyhow};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use env_logger::fmt::WriteStyle;
use log::{LevelFilter, debug, info};
use secrecy::{ExposeSecret as _, SecretString};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{self, IsTerminal, Read as _, Write as _};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{
    io::{BufRead as _, BufReader},
    os::unix::net::UnixStream,
};

#[cfg(unix)]
use kyz_core::jit::now_unix;
use kyz_core::paths::write_default_config;
use kyz_core::store::{DEFAULT_SERVICE, DEFAULT_SESSION_TIMEOUT_SECS};
use kyz_core::{
    AppConfig, AppPaths, HistoryRole, HistoryView, OpKind, SecretEntry, SecretStore, VaultStore,
    default_cache_dir,
};

/// Application name from Cargo.toml package name.
const APP_NAME: &str = env!("CARGO_PKG_NAME");

/// Fields that should use hidden input when prompting interactively.
#[cfg(feature = "mask-output")]
const SENSITIVE_FIELDS: &[&str] = &["password", "token", "secret", "key", "api_key", "value"];

#[cfg(not(feature = "mask-output"))]
const SENSITIVE_FIELDS: &[&str] = &[];

fn main() -> anyhow::Result<()> {
    try_main()
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();

    let ctx = RuntimeContext::new(cli.common.clone())?;
    // In-process daemon modes install their own rotating file logger;
    // wiring env_logger first would send daemon diagnostics to the
    // redirected stderr stream without rotation. A dry run never starts
    // the daemon, so the CLI logger (and `-v`) stays active there.
    let daemon_in_process = matches!(
        &cli.command,
        Command::Daemon {
            command: DaemonCommand::Start(args)
        } if args.runs_in_process() && !cli.common.dry_run
    );
    if !daemon_in_process {
        ctx.init_logging()?;
    }
    debug!("resolved paths: {:#?}", ctx.paths);

    match cli.command {
        Command::Set(cmd) => handle_set(&ctx, cmd),
        Command::Get(cmd) => handle_get(&ctx, &cmd),
        Command::Delete(cmd) => handle_delete(&ctx, &cmd),
        Command::List(cmd) => handle_list(&ctx, &cmd),
        Command::Export(cmd) => handle_export(&ctx, &cmd),
        Command::Import(cmd) => handle_import(&ctx, &cmd),
        Command::Vault { command } => handle_vault(&ctx, command),
        Command::Env(_) => handle_env(&ctx),
        Command::Init(cmd) => handle_init(&ctx, cmd),
        Command::Config { command } => handle_config(&ctx, command),
        Command::Scan(cmd) => handle_scan(&ctx, &cmd),
        Command::History(cmd) => handle_history(&ctx, &cmd),
        Command::Rollback(cmd) => handle_rollback(&ctx, &cmd),
        Command::Exec(cmd) => handle_exec(&ctx, &cmd),
        Command::Pipe(cmd) => handle_pipe(&ctx, &cmd),
        Command::Wrap(cmd) => handle_wrap(&ctx, &cmd),
        Command::Ipc { command } => handle_ipc(&ctx, command),
        Command::Daemon { command } => handle_daemon(&ctx, command),
        Command::Ctx(_) => handle_ctx(&ctx),
        Command::Completions { shell } => {
            handle_completions(shell);
            Ok(())
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "kyz - a cross-platform secrets manager",
    propagate_version = true
)]
struct Cli {
    /// Common options shared across all subcommands.
    #[command(flatten)]
    common: CommonOpts,
    /// Subcommand to execute.
    #[command(subcommand)]
    command: Command,
}

/// Common CLI options shared across all subcommands.
#[derive(Debug, Clone, Args)]
pub struct CommonOpts {
    /// Override the config file path.
    #[arg(long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,
    /// Explicit vault file path (overrides auto-discovery).
    #[arg(long, value_name = "PATH", global = true)]
    pub vault: Option<PathBuf>,
    /// Named environment (dev, staging, prod). Selects the vault at
    /// `$XDG_DATA_HOME/kyz/envs/<name>/vault.json`. Also set via `KYZ_ENV`.
    #[arg(long = "env", value_name = "NAME", global = true, env = "KYZ_ENV")]
    pub env_name: Option<String>,
    /// Reduce output to only errors.
    #[arg(short, long, action = clap::ArgAction::SetTrue, global = true)]
    pub quiet: bool,
    /// Increase logging verbosity (stackable).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
    /// Enable debug logging (equivalent to -vv).
    #[arg(long, global = true)]
    pub debug: bool,
    /// Enable trace logging (overrides other levels).
    #[arg(long, global = true)]
    pub trace: bool,
    /// Output machine readable JSON.
    #[arg(long, global = true, conflicts_with = "yaml")]
    pub json: bool,
    /// Output machine readable YAML.
    #[arg(long, global = true)]
    pub yaml: bool,
    /// Disable ANSI colors in output.
    #[arg(long = "no-color", global = true, conflicts_with = "color")]
    pub no_color: bool,
    /// Control color output (auto, always, never).
    #[arg(long, value_enum, default_value_t = ColorOption::Auto, global = true)]
    pub color: ColorOption,
    /// Do not change anything on disk.
    #[arg(long = "dry-run", global = true)]
    pub dry_run: bool,
    /// Assume "yes" for interactive prompts.
    #[arg(short = 'y', long = "yes", global = true)]
    pub assume_yes: bool,
    /// Never prompt for input; fail if confirmation would be required.
    #[arg(long = "no-input", global = true)]
    pub no_input: bool,
    /// Maximum seconds to allow an operation to run.
    #[arg(long = "timeout", value_name = "SECONDS", global = true)]
    pub timeout: Option<u64>,
    /// Override the degree of parallelism.
    #[arg(long = "parallel", value_name = "N", global = true)]
    pub parallel: Option<usize>,
    /// Disable progress indicators.
    #[arg(long = "no-progress", global = true)]
    pub no_progress: bool,
    /// Emit additional diagnostics for troubleshooting.
    #[arg(long = "diagnostics", global = true)]
    pub diagnostics: bool,
}

/// Color output mode.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ColorOption {
    /// Detect terminal capabilities automatically.
    Auto,
    /// Always emit ANSI color codes.
    Always,
    /// Never emit ANSI color codes.
    Never,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Store a secret (reads value from stdin if not provided).
    Set(SetCommand),
    /// Retrieve a secret by key.
    Get(GetCommand),
    /// Remove a secret by key.
    Delete(DeleteCommand),
    /// List all secret keys in a service namespace.
    List(ListCommand),
    /// Export secrets as JSON (values included).
    Export(ExportCommand),
    /// Import secrets from a JSON file or stdin.
    Import(ImportCommand),
    /// Manage the encrypted vault.
    Vault {
        /// Vault subcommand.
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Create config directories and default files.
    Init(InitCommand),
    /// List named environments.
    Env(EnvCommand),
    /// Inspect and manage configuration.
    Config {
        /// Configuration subcommand.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Wrap a command with secrets injected as environment variables.
    Exec(ExecCommand),
    /// Pipe a secret into a command's stdin (never touches env or args).
    Pipe(PipeCommand),
    /// Scan git-tracked files for leaked vault secret values.
    Scan(ScanCommand),
    /// Show version history for a secret.
    History(HistoryCommand),
    /// Rollback a secret to a previous version.
    Rollback(RollbackCommand),
    /// Wrap an agent with pre-approved secret access and policy enforcement.
    Wrap(WrapCommand),
    /// IPC client helpers for local one-time secret submission and JIT grants.
    Ipc {
        /// IPC subcommand.
        #[command(subcommand)]
        command: IpcCommand,
    },
    /// Start, inspect, reload, or stop the credential daemon.
    Daemon {
        /// Daemon subcommand.
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Print effective `AGENT_CTX` runtime metadata observed from the environment.
    Ctx(CtxCommand),
    /// Generate shell completions.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Clone, Copy, Args)]
struct CtxCommand {}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// Create a new encrypted vault.
    Create(VaultCreateCommand),
    /// Unlock the vault (starts a timed session).
    Unlock(VaultUnlockCommand),
    /// Lock the vault (ends the session).
    Lock,
    /// Show vault status.
    Status,
    /// Merge operations from another replica of this vault (v4).
    Merge(VaultMergeCommand),
}

#[derive(Debug, Clone, Args)]
struct VaultCreateCommand {
    /// Overwrite existing vault.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Clone, Args)]
struct VaultUnlockCommand {
    /// Session timeout in seconds (default: 1800 = 30 minutes).
    #[arg(long, default_value_t = DEFAULT_SESSION_TIMEOUT_SECS)]
    timeout: u64,
}

#[derive(Debug, Clone, Args)]
struct VaultMergeCommand {
    /// Path to a v4 replica of this vault (e.g. a Syncthing conflict copy).
    #[arg(value_name = "PATH")]
    source: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct SetCommand {
    /// Name of the secret entry.
    #[arg(value_name = "KEY")]
    key: String,
    /// Secret value (for single-value entries; omit to prompt or use --field).
    #[arg(value_name = "VALUE")]
    value: Option<String>,
    /// Service namespace for the secret.
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
    /// Set a named field (repeatable, format: name=value).
    #[arg(long = "field", short = 'f', value_name = "NAME=VALUE")]
    fields: Vec<String>,
    /// Assign a tag to this secret (repeatable).
    #[arg(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

#[derive(Debug, Clone, Args)]
struct GetCommand {
    /// Name of the secret entry.
    #[arg(value_name = "KEY")]
    key: String,
    /// Service namespace for the secret.
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
    /// Retrieve a specific field only (prints raw value).
    #[arg(long = "field", short = 'f', value_name = "NAME")]
    field: Option<String>,
}

#[derive(Debug, Clone, Args)]
struct DeleteCommand {
    /// Name of the secret to remove.
    #[arg(value_name = "KEY")]
    key: String,
    /// Service namespace for the secret.
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
}

#[derive(Debug, Clone, Args)]
struct ListCommand {
    /// Service namespace to list secrets from (default: kyz).
    #[arg(long, default_value = DEFAULT_SERVICE, conflicts_with = "all")]
    service: String,
    /// List secrets from all services.
    #[arg(long, short = 'a')]
    all: bool,
}

#[derive(Debug, Clone, Args)]
struct ExportCommand {
    /// Service namespace to export (omit to export all).
    #[arg(long)]
    service: Option<String>,
}

#[derive(Debug, Clone, Args)]
struct ImportCommand {
    /// Path to a JSON file (omit to read from stdin).
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,
    /// Service namespace to import into (overrides the service in the file).
    #[arg(long)]
    service: Option<String>,
}

#[derive(Debug, Clone, Copy, Args)]
struct EnvCommand;

#[derive(Debug, Clone, Copy, Args)]
struct InitCommand {
    /// Recreate configuration even if it already exists.
    #[arg(long = "force")]
    force: bool,
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum ConfigCommand {
    /// Output the effective configuration.
    Show,
    /// Print the resolved config file path.
    Path,
    /// Print all resolved paths (config, data, state, cache).
    Paths,
    /// Print the JSON schema for the config file.
    Schema,
    /// Regenerate the default configuration file.
    Reset,
}

#[derive(Debug, Clone, Args)]
struct ScanCommand {
    /// Only scan staged files (for pre-commit hooks).
    #[arg(long)]
    staged: bool,
    /// Scan a specific directory instead of the current directory.
    #[arg(long, value_name = "DIR")]
    path: Option<PathBuf>,
    /// Output suitable for git pre-commit hook (exit code 1 on match, minimal output).
    #[arg(long)]
    hook: bool,
}

#[derive(Debug, Clone, Args)]
struct HistoryCommand {
    /// Secret reference as service/key.
    #[arg(value_name = "SERVICE/KEY")]
    secret: String,
    /// Service namespace (used if secret doesn't contain '/').
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
}

#[derive(Debug, Clone, Args)]
struct RollbackCommand {
    /// Secret reference as service/key.
    #[arg(value_name = "SERVICE/KEY")]
    secret: String,
    /// Target version: the `#n` sequence shown by `kyz history` (1 =
    /// oldest; stable as new writes append). Advanced: also accepts a
    /// v4 operation id (`actor:counter`), which stays stable across
    /// concurrent writes.
    #[arg(long = "to", value_name = "VERSION")]
    target: String,
    /// Service namespace (used if secret doesn't contain '/').
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
}

#[derive(Debug, Clone, Args)]
struct ExecCommand {
    /// Path to a policy file (overrides auto-discovery).
    #[arg(long, value_name = "PATH")]
    policy: Option<PathBuf>,

    /// Disable all policy checks (use with caution).
    #[arg(long)]
    no_policy: bool,

    /// Named alias from config.toml [aliases.<name>].
    #[arg(long, short = 'a', value_name = "ALIAS")]
    alias: Option<String>,

    /// Explicit env mapping: `ENV_VAR=service/key:field` (repeatable).
    #[arg(long = "env", short = 'e', value_name = "ENV=SERVICE/KEY:FIELD")]
    env_maps: Vec<String>,

    /// Include all secrets matching this tag (repeatable).
    #[arg(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,

    /// Include all secrets for this service/key (repeatable, format: service/key).
    #[arg(long = "secret", short = 's', value_name = "SERVICE/KEY")]
    secrets: Vec<String>,

    /// Interactive fzf picker for secret selection.
    #[arg(long = "pick", short = 'p')]
    pick: bool,

    /// Run a shell command string (passed to sh -c). Variables like $VAR
    /// are expanded by the shell after secrets are injected.
    #[arg(
        long = "shell-command",
        short = 'c',
        value_name = "CMD",
        conflicts_with = "command"
    )]
    shell_command: Option<String>,

    /// Command and arguments to execute (use -- to separate from kyz flags).
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Debug, Clone, Args)]
struct PipeCommand {
    /// Path to a policy file (overrides auto-discovery).
    #[arg(long, value_name = "PATH")]
    policy: Option<PathBuf>,

    /// Disable all policy checks (use with caution).
    #[arg(long)]
    no_policy: bool,

    /// Secret reference: service/key or service/key:field.
    #[arg(value_name = "SERVICE/KEY[:FIELD]")]
    secret: String,

    /// Append a trailing newline to the piped value.
    #[arg(long)]
    newline: bool,

    /// Command and arguments to execute.
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Clone, Args)]
struct WrapCommand {
    /// Secret names to pre-approve (comma-separated, or '*' for all).
    #[arg(long, value_delimiter = ',', required = true)]
    allow: Vec<String>,

    /// Best-effort no-read mode: sets `KYZ_NO_READ` to discourage kyz
    /// get/export inside the wrapped session (the wrapped process can unset
    /// environment variables; this is a guardrail, not a security boundary).
    #[arg(long, default_value_t = true)]
    no_read: bool,

    /// Command and arguments to execute in the wrapped session.
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Clone, Subcommand)]
enum IpcCommand {
    /// Submit a one-time secret payload to local IPC.
    Submit(IpcSubmitCommand),
    /// Issue a brokered JIT grant token (fails if a live grant with the same
    /// token exists: grants cannot be overwritten while active).
    Grant(IpcGrantCommand),
    /// Consume one-time secret or validate a grant usage.
    Use(IpcUseCommand),
}

#[derive(Debug, Clone, Args)]
struct IpcSubmitCommand {
    /// Caller-provided one-time request id. Optional: when omitted, the
    /// daemon generates a high-entropy id and returns it (recommended over
    /// predictable ids like "req-123").
    #[arg(long, value_name = "ID")]
    request_id: Option<String>,
    /// Secret service namespace.
    #[arg(long, value_name = "SERVICE")]
    service: String,
    /// Secret key.
    #[arg(long, value_name = "KEY")]
    key: String,
    /// Secret value. If omitted, reads from stdin.
    #[arg(long, value_name = "VALUE")]
    value: Option<String>,
    /// TTL in seconds from now.
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    ttl: u64,
    /// Optional origin source label.
    #[arg(long, value_name = "SOURCE")]
    source: Option<String>,
    /// Optional origin process id.
    #[arg(long, value_name = "PID")]
    process_id: Option<String>,
    /// Optional origin host.
    #[arg(long, value_name = "HOST")]
    host: Option<String>,
    /// IPC socket path (defaults to state-dir/kyz-ipc.sock).
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct IpcGrantCommand {
    /// Grant token identifier.
    #[arg(long, value_name = "TOKEN")]
    token: String,
    /// Allowed secret references (repeatable, SERVICE/KEY[:FIELD]).
    #[arg(long = "secret", short = 's', value_name = "SERVICE/KEY[:FIELD]")]
    secrets: Vec<String>,
    /// Allowed command basenames (repeatable).
    #[arg(long = "command", short = 'c', value_name = "CMD")]
    commands: Vec<String>,
    /// Allowed workspaces (repeatable).
    #[arg(long = "workspace", short = 'w', value_name = "WORKSPACE")]
    workspaces: Vec<String>,
    /// TTL in seconds from now.
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    ttl: u64,
    /// Allowed use count.
    #[arg(long, value_name = "N", default_value_t = 1)]
    use_count: u32,
    /// IPC socket path (defaults to state-dir/kyz-ipc.sock).
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct IpcUseCommand {
    /// Request id for one-time secret resolve.
    #[arg(long, value_name = "ID", conflicts_with = "token")]
    request_id: Option<String>,
    /// Grant token for validation.
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
    /// Secret reference for grant validation.
    #[arg(long, value_name = "SERVICE/KEY[:FIELD]", requires = "token")]
    secret: Option<String>,
    /// Command basename for grant validation.
    #[arg(long, value_name = "CMD", requires = "token")]
    command: Option<String>,
    /// Workspace for grant validation.
    #[arg(long, value_name = "WORKSPACE", requires = "token")]
    workspace: Option<String>,
    /// Reveal secret value in output (default: redacted).
    #[arg(long, default_value_t = false)]
    reveal_value: bool,
    /// IPC socket path (defaults to state-dir/kyz-ipc.sock).
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Debug, Clone, Subcommand)]
enum DaemonCommand {
    /// Start the credential daemon (background by default).
    Start(DaemonStartArgs),
    /// Report daemon status and the active configuration snapshot.
    Status,
    /// Validate and atomically reload the daemon configuration.
    Reload,
    /// Gracefully stop the daemon.
    Stop,
}

#[derive(Debug, Clone, Args)]
struct DaemonStartArgs {
    /// Daemon lifetime in seconds; 0 disables the timeout. Overrides
    /// `daemon.timeout_secs` from the config file.
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,
    /// Run the daemon in the foreground (for systemd/launchd/services).
    #[arg(long)]
    foreground: bool,
    /// Command that prints the vault passphrase on its first stdout line
    /// (used when no TTY is available). Never passed to the daemon child.
    #[arg(long, value_name = "COMMAND")]
    askpass: Option<String>,
    /// Hidden: read a length-prefixed passphrase from stdin. This is the
    /// one-shot bootstrap pipe used by the background launcher.
    #[arg(long, hide = true)]
    bootstrap: bool,
}

impl DaemonStartArgs {
    /// Whether this invocation runs the daemon inside the current process
    /// (and therefore must not install the CLI's `env_logger`: the daemon
    /// installs its own rotating file logger).
    const fn runs_in_process(&self) -> bool {
        self.foreground || self.bootstrap
    }
}

#[derive(Debug, Clone)]
struct RuntimeContext {
    common: CommonOpts,
    paths: AppPaths,
    config: AppConfig,
}

impl RuntimeContext {
    fn new(common: CommonOpts) -> Result<Self> {
        let paths = AppPaths::discover(common.config.as_deref())?;
        let config = AppConfig::load(&paths, common.dry_run)?;
        let paths = paths.apply_overrides(&config)?;
        let ctx = Self {
            common,
            paths,
            config,
        };
        ctx.ensure_directories()?;
        Ok(ctx)
    }

    fn init_logging(&self) -> Result<()> {
        if self.common.quiet {
            log::set_max_level(LevelFilter::Off);
            return Ok(());
        }

        let mut builder =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));

        builder.filter_level(self.effective_log_level());

        let force_color = matches!(self.common.color, ColorOption::Always)
            || env::var_os("FORCE_COLOR").is_some();
        let disable_color = self.common.no_color
            || matches!(self.common.color, ColorOption::Never)
            || env::var_os("NO_COLOR").is_some()
            || (!force_color && !io::stderr().is_terminal());

        if disable_color {
            builder.write_style(WriteStyle::Never);
        } else if force_color {
            builder.write_style(WriteStyle::Always);
        } else {
            builder.write_style(WriteStyle::Auto);
        }

        if self.common.diagnostics {
            builder.format_timestamp_millis();
            builder.format_module_path(true);
            builder.format_target(true);
        }

        builder.try_init().or_else(|err| {
            if self.common.verbose > 0 {
                eprintln!("logger already initialized: {err}");
            }
            Ok(())
        })
    }

    const fn effective_log_level(&self) -> LevelFilter {
        if self.common.trace {
            LevelFilter::Trace
        } else if self.common.debug {
            LevelFilter::Debug
        } else {
            match self.common.verbose {
                0 => LevelFilter::Info,
                1 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            }
        }
    }

    fn ensure_directories(&self) -> Result<()> {
        if self.common.dry_run {
            self.paths.log_dry_run();
            return Ok(());
        }
        self.paths.ensure_directories()
    }

    /// Resolve the vault store from CLI options (--vault, --env, or auto-discover).
    ///
    /// When no explicit vault/env is provided, an `AGENT_CTX_WORKSPACE_PATH`
    /// value (if present) is used as a workspace hint so wrapped agent
    /// processes whose cwd does not match the user's workspace still find
    /// the expected workspace vault. CLI flags always take precedence.
    fn vault_store(&self) -> Result<VaultStore> {
        let agent_ctx = kyz_core::AgentContext::from_env();
        let store = VaultStore::resolve_with_env(
            self.common.vault.as_deref(),
            self.common.env_name.as_deref(),
            agent_ctx.workspace_path.as_deref(),
        )
        .map_err(|e| anyhow!("{e}"))?;
        Ok(store)
    }

    /// Get a `dyn SecretStore` based on the resolved vault.
    fn secret_store(&self) -> Result<Box<dyn SecretStore>> {
        let store = self.vault_store()?;
        Ok(Box::new(store))
    }
}

fn handle_vault(ctx: &RuntimeContext, command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Create(cmd) => handle_vault_create(ctx, &cmd),
        VaultCommand::Unlock(cmd) => handle_vault_unlock(ctx, &cmd),
        VaultCommand::Lock => handle_vault_lock(ctx),
        VaultCommand::Status => handle_vault_status(ctx),
        VaultCommand::Merge(cmd) => handle_vault_merge(ctx, &cmd),
    }
}

fn handle_vault_create(ctx: &RuntimeContext, cmd: &VaultCreateCommand) -> Result<()> {
    let store = ctx.vault_store()?;

    let passphrase = prompt_new_passphrase()?;

    if ctx.common.dry_run {
        info!(
            "dry-run: would create vault at {}",
            store.vault_path().display()
        );
        return Ok(());
    }

    store
        .init(&passphrase, cmd.force)
        .map_err(|e| anyhow!("{e}"))?;

    if !ctx.common.quiet {
        println!("Created vault at {}", store.vault_path().display());
    }
    Ok(())
}

/// Trust-on-first-use gate for workspace vaults (`<dir>/.kyz/vault.json`).
///
/// Workspace vaults are repository-supplied: without this gate a hostile repo
/// could silently substitute secret values for anyone who unlocks it. First
/// use (and any later content change) requires explicit confirmation; the
/// fingerprint is pinned in `$XDG_STATE_HOME/kyz/trusted-workspace-vaults.json`.
fn ensure_workspace_vault_trusted(
    ctx: &RuntimeContext,
    vault_store: &kyz_core::VaultStore,
    assume_yes: bool,
) -> Result<()> {
    let path = vault_store.vault_path();
    if !kyz_core::is_workspace_vault_path(path) {
        return Ok(());
    }
    if kyz_core::workspace_vault_is_trusted(&ctx.paths, path) {
        return Ok(());
    }
    let fingerprint = kyz_core::workspace_vault_fingerprint(path).map_err(|e| anyhow!("{e}"))?;
    let short: String = fingerprint.chars().take(12).collect();
    if !assume_yes {
        if !io::stdin().is_terminal() {
            return Err(anyhow!(
                "workspace vault {} was never trusted. Re-run interactively to confirm, or pass --yes",
                path.display()
            ));
        }
        print!(
            "First use of workspace vault {} (fingerprint {short}…). Trust it? [y/N] ",
            path.display()
        );
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            return Err(anyhow!("workspace vault not trusted; aborting"));
        }
    }
    kyz_core::workspace_vault_record_trust(&ctx.paths, path).map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

/// Base `service/key` of a `service/key:field` reference.
fn secret_policy_key(field_ref: &str) -> &str {
    match field_ref.split_once(':') {
        Some((base, _)) => base,
        None => field_ref,
    }
}

fn handle_vault_unlock(ctx: &RuntimeContext, cmd: &VaultUnlockCommand) -> Result<()> {
    let store = ctx.vault_store()?;

    ensure_workspace_vault_trusted(ctx, &store, ctx.common.assume_yes)?;
    let passphrase = prompt_passphrase(&format!(
        "Vault passphrase ({}): ",
        store.vault_path().display()
    ))?;

    let session_path = store
        .unlock(&passphrase, cmd.timeout)
        .map_err(|e| anyhow!("{e}"))?;

    if !ctx.common.quiet {
        println!("Vault unlocked (session: {})", session_path.display());
        println!("Session expires in {} minutes", cmd.timeout / 60);
    }
    Ok(())
}

fn handle_vault_lock(ctx: &RuntimeContext) -> Result<()> {
    let store = ctx.vault_store()?;
    store.lock().map_err(|e| anyhow!("{e}"))?;

    if !ctx.common.quiet {
        println!("Vault locked");
    }
    Ok(())
}

/// Human-readable summary of a v4 merge report (no secret values).
fn merge_report_json(report: &kyz_core::MergeReport, dry_run: bool) -> serde_json::Value {
    serde_json::json!({
        "source": {
            "path_vault_id": report.source_vault_id,
            "digest": report.source_digest,
            "operations": report.source_ops,
        },
        "dry_run": dry_run,
        "written": !dry_run && report.changed,
        "changed": report.changed,
        "ops_added": report.ops_added,
        "ops_already_present": report.ops_already_present,
        "new_entries": report.new_entries,
        "legacy_resurrections": report.legacy_resurrections,
        "updated_entries": report.updated_entries,
        "deleted_entries": report.deleted_entries,
        "conflicts": report
            .conflicts
            .iter()
            .map(|c| {
                serde_json::json!({
                    "entry": c.entry,
                    "kept": c.kept.to_string(),
                    "kept_updated_at": c.kept_updated_at,
                    "losing": c.losing.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn handle_vault_merge(ctx: &RuntimeContext, cmd: &VaultMergeCommand) -> Result<()> {
    let store = ctx.vault_store()?;
    let dry_run = ctx.common.dry_run;

    // `--yes` accepts entries that exist only in the source's pre-v4
    // history and are absent here: v3-era deletions leave no tombstone,
    // so they may be secrets deleted before one of the two sides
    // migrated. Without it such a merge fails without writing.
    let report = store
        .merge_vault_from(&cmd.source, dry_run, ctx.common.assume_yes)
        .map_err(|e| anyhow!("{e}"))?;

    if ctx.common.json || ctx.common.yaml {
        let payload = merge_report_json(&report, dry_run);
        if ctx.common.yaml {
            println!(
                "{}",
                serde_yaml::to_string(&payload).context("serializing merge report to YAML")?
            );
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .context("serializing merge report to JSON")?
            );
        }
        return Ok(());
    }

    if report.ops_added == 0 && !report.changed {
        println!(
            "Nothing to merge: all {} source operations already present",
            report.source_ops
        );
        return Ok(());
    }

    println!(
        "Merged {} operation(s) from {} (source digest {}…)",
        report.ops_added,
        cmd.source.display(),
        report.source_digest.chars().take(12).collect::<String>(),
    );
    if report.ops_already_present > 0 {
        println!("  already present: {0}", report.ops_already_present);
    }
    for entry in &report.new_entries {
        println!("  new entry:        {entry}");
    }
    for entry in &report.legacy_resurrections {
        println!(
            "  pre-v4 only:      {entry} (may have been deleted in v3; confirm before keeping)"
        );
    }
    for entry in &report.updated_entries {
        println!("  updated entry:    {entry}");
    }
    for entry in &report.deleted_entries {
        println!("  deleted (wins):   {entry}");
    }
    for conflict in &report.conflicts {
        println!(
            "  conflict:         {} kept {} (losing: {})",
            conflict.entry,
            conflict.kept,
            conflict
                .losing
                .iter()
                .map(kyz_core::OpId::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!(
        "Losing versions remain visible via `kyz history <service/key>` and can be restored with `kyz rollback`."
    );
    if dry_run {
        println!("dry-run: target vault not modified");
    } else if report.changed {
        println!("Vault updated at {}", store.vault_path().display());
    }
    if !dry_run {
        println!(
            "Source left untouched at {}; remove or archive it once satisfied.",
            cmd.source.display()
        );
    }
    Ok(())
}

fn handle_ctx(ctx: &RuntimeContext) -> Result<()> {
    let agent_ctx = kyz_core::AgentContext::from_env();

    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&agent_ctx).context("serializing agent context")?
        );
        return Ok(());
    }
    if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&agent_ctx).context("serializing agent context")?
        );
        return Ok(());
    }

    if agent_ctx.is_empty() {
        println!("no AGENT_CTX_* variables observed in the environment");
        return Ok(());
    }

    let tags = agent_ctx.audit_tags();
    let width = tags.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in tags {
        println!("{k:<width$}  {v}");
    }
    Ok(())
}

fn handle_vault_status(ctx: &RuntimeContext) -> Result<()> {
    let store = ctx.vault_store()?;
    let status = store.status().map_err(|e| anyhow!("{e}"))?;

    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).context("serializing status")?
        );
    } else if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&status).context("serializing status")?
        );
    } else {
        println!("vault:    {}", status.vault_path.display());
        println!("exists:   {}", status.exists);
        println!("unlocked: {}", status.unlocked);
        if let Some(remaining) = status.remaining_secs {
            let mins = remaining / 60;
            let secs = remaining % 60;
            println!("expires:  {mins}m {secs}s remaining");
        }
    }
    Ok(())
}

/// Parse --field arguments into a `BTreeMap`.
fn parse_fields(raw: &[String]) -> Result<BTreeMap<String, SecretString>> {
    let mut fields = BTreeMap::new();
    for f in raw {
        let (name, value) = f
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid field format '{f}', expected NAME=VALUE"))?;
        if name.is_empty() {
            return Err(anyhow!("field name must not be empty"));
        }
        fields.insert(name.to_string(), SecretString::from(value.to_string()));
    }
    Ok(fields)
}

/// Prompt for a passphrase (hidden input).
fn prompt_passphrase(prompt: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("reading passphrase from stdin")?;
        return Ok(buf.trim_end_matches('\n').to_string());
    }
    rpassword::prompt_password(prompt).context("reading passphrase")
}

/// Prompt for a new passphrase with confirmation.
///
/// When stdin is not a terminal (piped), reads a single passphrase without
/// confirmation (useful for scripting and agent use).
fn prompt_new_passphrase() -> Result<String> {
    let p1 = prompt_passphrase("New vault passphrase: ")?;
    if p1.is_empty() {
        return Err(anyhow!("passphrase must not be empty"));
    }

    // Skip confirmation when piped (non-interactive / agent use)
    if !io::stdin().is_terminal() {
        return Ok(p1);
    }

    let p2 = prompt_passphrase("Confirm passphrase: ")?;
    if p1 != p2 {
        return Err(anyhow!("passphrases do not match"));
    }
    Ok(p1)
}

/// Read a secret value: explicit arg > --field flags > stdin pipe > interactive prompt.
fn read_secret_value(explicit: Option<&str>) -> Result<String> {
    if let Some(v) = explicit {
        return Ok(v.to_string());
    }

    if io::stdin().is_terminal() {
        eprintln!("Enter secret value (input is hidden; for long values, pipe via stdin):");
        let value = rpassword::prompt_password("").context("reading secret from terminal")?;
        if value.is_empty() {
            return Err(anyhow!("secret value must not be empty"));
        }
        Ok(value)
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("reading secret from stdin")?;
        let trimmed = buf.trim_end_matches('\n').to_string();
        if trimmed.is_empty() {
            return Err(anyhow!("secret value must not be empty"));
        }
        Ok(trimmed)
    }
}

/// Determine if a field name holds sensitive data.
fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_lowercase();
    SENSITIVE_FIELDS.iter().any(|s| lower.contains(s))
}

fn mask_sensitive_fields(
    fields: &BTreeMap<String, SecretString>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    for (name, value) in fields {
        if is_sensitive_field(name) {
            out.insert(name.clone(), serde_json::Value::String("****".to_string()));
        } else {
            out.insert(
                name.clone(),
                serde_json::Value::String(value.expose_secret().to_string()),
            );
        }
    }
    out
}

fn handle_set(ctx: &RuntimeContext, cmd: SetCommand) -> Result<()> {
    let fields = if cmd.fields.is_empty() {
        let value = read_secret_value(cmd.value.as_deref())?;
        let mut m = BTreeMap::new();
        m.insert("value".to_string(), SecretString::from(value));
        m
    } else {
        parse_fields(&cmd.fields)?
    };

    let tags: BTreeSet<String> = cmd.tags.into_iter().collect();
    let entry = SecretEntry::new(&cmd.service, &cmd.key, fields).with_tags(tags);

    if ctx.common.dry_run {
        info!(
            "dry-run: would store secret '{}' in service '{}' with fields: {:?}",
            cmd.key,
            cmd.service,
            entry.fields.keys().collect::<Vec<_>>()
        );
        return Ok(());
    }

    let vault_store = ctx.vault_store()?;
    // --yes doubles as the explicit confirmation to rebuild a deleted
    // entry: without it, set on a deleted entry fails instead of silently
    // resurrecting it (previous values are unrecoverable in v4).
    vault_store
        .set_with_options(&cmd.service, &cmd.key, &entry, ctx.common.assume_yes)
        .map_err(|e| anyhow!("{e}"))?;

    if !ctx.common.quiet {
        let field_names: Vec<&str> = entry.fields.keys().map(String::as_str).collect();
        println!(
            "Stored '{}' in service '{}' (fields: {})",
            cmd.key,
            cmd.service,
            field_names.join(", ")
        );
    }
    Ok(())
}

fn handle_get(ctx: &RuntimeContext, cmd: &GetCommand) -> Result<()> {
    // No-read mode: block secret retrieval in wrapped agent sessions
    if std::env::var("KYZ_NO_READ").is_ok() {
        kyz_core::audit::audit(
            "get_blocked",
            Some(&format!("{}/{}", cmd.service, cmd.key)),
            None,
            Some("no-read mode active"),
        );
        return Err(anyhow!(
            "secret retrieval blocked: running in no-read mode (KYZ_NO_READ is set). Use kyz exec or kyz pipe to inject secrets into commands."
        ));
    }

    let store = ctx.secret_store()?;
    let entry = store
        .get(&cmd.service, &cmd.key)
        .map_err(|e| anyhow!("{e}"))?;

    if let Some(ref field_name) = cmd.field {
        let value = entry
            .field(field_name)
            .ok_or_else(|| anyhow!("field '{field_name}' not found in entry '{}'", cmd.key))?;
        if is_sensitive_field(field_name) {
            println!("****");
        } else {
            println!("{value}");
        }
        return Ok(());
    }

    if ctx.common.json {
        let obj = serde_json::json!({
            "service": entry.service,
            "key": entry.key,
            "fields": mask_sensitive_fields(&entry.fields),
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&obj).context("serializing to JSON")?
        );
    } else if ctx.common.yaml {
        let obj = serde_json::json!({
            "service": entry.service,
            "key": entry.key,
            "fields": mask_sensitive_fields(&entry.fields),
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        });
        println!(
            "{}",
            serde_yaml::to_string(&obj).context("serializing to YAML")?
        );
    } else if entry.fields.len() == 1 && entry.fields.contains_key("value") {
        if is_sensitive_field("value") {
            println!("****");
        } else if let Some(v) = entry.value() {
            println!("{v}");
        }
    } else {
        for (name, value) in &entry.fields {
            if is_sensitive_field(name) {
                println!("{name}: ****");
            } else {
                println!("{name}: {}", value.expose_secret());
            }
        }
    }
    Ok(())
}

fn handle_delete(ctx: &RuntimeContext, cmd: &DeleteCommand) -> Result<()> {
    if ctx.common.dry_run {
        info!(
            "dry-run: would delete secret '{}' from service '{}'",
            cmd.key, cmd.service
        );
        return Ok(());
    }

    let store = ctx.secret_store()?;
    store
        .delete(&cmd.service, &cmd.key)
        .map_err(|e| anyhow!("{e}"))?;

    if !ctx.common.quiet {
        println!(
            "Deleted secret '{}' from service '{}'",
            cmd.key, cmd.service
        );
    }
    Ok(())
}

fn handle_list(ctx: &RuntimeContext, cmd: &ListCommand) -> Result<()> {
    let store = ctx.secret_store()?;

    if cmd.all {
        let services = store.list_services().map_err(|e| anyhow!("{e}"))?;
        let mut by_service = BTreeMap::new();
        for service in services {
            let entries = store.list(&service).map_err(|e| anyhow!("{e}"))?;
            by_service.insert(service, entries);
        }

        if ctx.common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "all": true,
                    "services": by_service,
                }))
                .context("serializing to JSON")?
            );
        } else if ctx.common.yaml {
            println!(
                "{}",
                serde_yaml::to_string(&serde_json::json!({
                    "all": true,
                    "services": by_service,
                }))
                .context("serializing to YAML")?
            );
        } else if by_service.is_empty() {
            println!(
                "No secrets found. Tip: set secrets with --service <name> and list with --all."
            );
        } else {
            for (service, entries) in &by_service {
                println!("[{service}]");
                for entry in entries {
                    if entry.field_names.is_empty() {
                        println!("{}", entry.key);
                    } else {
                        println!("{}  [{}]", entry.key, entry.field_names.join(", "));
                    }
                }
                println!();
            }
        }
        return Ok(());
    }

    let entries = store.list(&cmd.service).map_err(|e| anyhow!("{e}"))?;

    if ctx.common.json {
        let obj = serde_json::json!({
            "service": cmd.service,
            "entries": entries,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&obj).context("serializing to JSON")?
        );
    } else if ctx.common.yaml {
        let obj = serde_json::json!({
            "service": cmd.service,
            "entries": entries,
        });
        println!(
            "{}",
            serde_yaml::to_string(&obj).context("serializing to YAML")?
        );
    } else if entries.is_empty() {
        if cmd.service == DEFAULT_SERVICE {
            println!(
                "Listing default service '{}'. No secrets found. Tip: use --service <name> or --all.",
                cmd.service
            );
        } else {
            println!(
                "No secrets found in service '{}'. Tip: try --service <name> or --all.",
                cmd.service
            );
        }
    } else {
        if cmd.service == DEFAULT_SERVICE {
            println!("Listing default service '{}':", cmd.service);
        }
        for entry in &entries {
            if entry.field_names.is_empty() {
                println!("{}", entry.key);
            } else {
                println!("{}  [{}]", entry.key, entry.field_names.join(", "));
            }
        }
    }
    Ok(())
}

fn handle_scan(ctx: &RuntimeContext, cmd: &ScanCommand) -> Result<()> {
    use kyz_core::scan;

    let store = ctx.vault_store()?;
    let dk = store.require_session_pub().map_err(|e| anyhow!("{e}"))?;

    let secret_index = match store.read_contents_pub().map_err(|e| anyhow!("{e}"))? {
        kyz_core::VaultContents::V3(vault) => {
            scan::build_secret_index(&vault, &dk).map_err(|e| anyhow!("{e}"))?
        }
        kyz_core::VaultContents::V4(vault) => {
            scan::build_secret_index_v4(&vault, &dk).map_err(|e| anyhow!("{e}"))?
        }
    };

    if secret_index.is_empty() {
        if !ctx.common.quiet {
            println!("No secrets in vault to scan for.");
        }
        return Ok(());
    }

    let opts = scan::ScanOptions {
        staged_only: cmd.staged,
        path: cmd.path.clone(),
    };
    let files = scan::get_files_to_scan(&opts).map_err(|e| anyhow!("{e}"))?;

    let base_dir = cmd
        .path
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_default();

    let result = scan::scan_files(&files, &secret_index, &base_dir).map_err(|e| anyhow!("{e}"))?;

    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).context("serializing scan result")?
        );
    } else if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&result).context("serializing scan result")?
        );
    } else if result.matches.is_empty() {
        if !ctx.common.quiet && !cmd.hook {
            println!(
                "✅ No leaked secrets found ({} files scanned, {} secrets checked)",
                result.files_scanned,
                secret_index.len()
            );
        }
    } else {
        if !cmd.hook {
            eprintln!(
                "⚠️  Found {} leaked secret(s) in {} file(s):",
                result.matches.len(),
                result.files_scanned
            );
        }
        for m in &result.matches {
            println!("{}:{}: {}", m.file.display(), m.line, m.secret_name);
        }
    }

    // Return error if matches found (for --hook / CI use)
    if !result.matches.is_empty() && cmd.hook {
        return Err(anyhow!("found {} leaked secret(s)", result.matches.len()));
    }

    Ok(())
}

/// Parse a secret reference that may or may not contain a '/'.
fn parse_secret_ref<'a>(secret: &'a str, default_service: &'a str) -> (&'a str, &'a str) {
    secret.split_once('/').unwrap_or((default_service, secret))
}

fn handle_history(ctx: &RuntimeContext, cmd: &HistoryCommand) -> Result<()> {
    let (service, key) = parse_secret_ref(&cmd.secret, &cmd.service);
    let store = ctx.vault_store()?;

    // Rows are newest-first. For v4 the stored log is never trimmed;
    // history_retention limits display only, and sequence numbers count
    // from the oldest operation so they stay stable as versions append —
    // older versions that fall out of the display window remain
    // reachable by op id (shown with -v or --json).
    let (rows, stored_conflicts) = match store.history(service, key).map_err(|e| anyhow!("{e}"))? {
        HistoryView::V4(mut items) => {
            let total = items.len();
            // Counted over the stored log, not the display window: every
            // kept conflict snapshot stays rollback-able even when it
            // falls outside the retention window.
            let stored_conflicts = items
                .iter()
                .filter(|item| item.role == HistoryRole::Conflict)
                .count();
            let limit = ctx.config.history_retention;
            if limit > 0 && total > limit as usize {
                items.truncate(limit as usize);
            }
            let rows = items
                .into_iter()
                .enumerate()
                .map(|(idx, item)| HistoryRow {
                    seq: Some(total - idx),
                    op_id: Some(item.op_id.to_string()),
                    role: item.role,
                    kind: item.kind,
                    changed_at: item.changed_at.phys,
                    field_names: item.field_names,
                    tags: item.tags,
                    has_snapshot: item.has_blob,
                })
                .collect();
            (rows, stored_conflicts)
        }
        // v3 rollback resolves archived versions by number, so those keep
        // their version as the sequence; the live entry is not a rollback
        // target in v3 and must not advertise a number.
        HistoryView::V3 { encrypted } => {
            let mut rows = vec![HistoryRow {
                seq: None,
                op_id: None,
                role: HistoryRole::Current,
                kind: OpKind::Put,
                changed_at: encrypted.updated_at,
                field_names: encrypted.field_names.clone(),
                tags: encrypted.tags.clone(),
                has_snapshot: true,
            }];
            rows.extend(encrypted.history.iter().map(|h| HistoryRow {
                seq: Some(h.version as usize),
                op_id: None,
                role: HistoryRole::Ancestor,
                kind: OpKind::Put,
                changed_at: h.archived_at,
                field_names: h.field_names.clone(),
                tags: BTreeSet::new(),
                has_snapshot: true,
            }));
            (rows, 0)
        }
    };
    print_history(ctx, service, key, &rows, stored_conflicts)
}

/// One display row of `kyz history`, normalized across vault formats.
struct HistoryRow {
    /// 1-based sequence counting from the oldest operation; matches the
    /// JSON `seq` and rollback's `--to`. `None` marks a row with no
    /// rollback handle — the live v3 entry, which v3 rollback (archived
    /// versions only) cannot target.
    seq: Option<usize>,
    /// Stable operation id (v4 only).
    op_id: Option<String>,
    role: HistoryRole,
    kind: OpKind,
    changed_at: u64,
    field_names: Vec<String>,
    tags: BTreeSet<String>,
    has_snapshot: bool,
}

/// `stored_conflicts` counts conflict snapshots in the stored log (which
/// retention never trims), not just the displayed window.
fn print_history(
    ctx: &RuntimeContext,
    service: &str,
    key: &str,
    rows: &[HistoryRow],
    stored_conflicts: usize,
) -> Result<()> {
    if rows.is_empty() {
        let payload = serde_json::json!({
            "service": service,
            "key": key,
            "history": [],
        });
        if ctx.common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).context("serializing history to JSON")?
            );
        } else if ctx.common.yaml {
            println!(
                "{}",
                serde_yaml::to_string(&payload).context("serializing history to YAML")?
            );
        } else {
            println!("No history for '{service}/{key}'");
        }
        return Ok(());
    }

    let items_json: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let mut item = serde_json::json!({
                "seq": row.seq,
                "role": row.role,
                "kind": if row.kind == OpKind::Put { "put" } else { "delete" },
                "changed_at": row.changed_at,
                "field_names": row.field_names,
                "tags": row.tags,
                "has_snapshot": row.has_snapshot,
            });
            if let Some(op_id) = &row.op_id {
                item["op_id"] = serde_json::json!(op_id);
            }
            item
        })
        .collect();
    let payload = serde_json::json!({
        "service": service,
        "key": key,
        "history": items_json,
    });
    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).context("serializing history to JSON")?
        );
    } else if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&payload).context("serializing history to YAML")?
        );
    } else {
        println!("History for '{service}/{key}':");
        for row in rows {
            let role = match row.role {
                HistoryRole::Current => "current",
                HistoryRole::Conflict => "CONFLICT",
                HistoryRole::Ancestor => "ancestor",
                HistoryRole::Tombstone => "deleted",
            };
            let details = if row.kind == OpKind::Put {
                format!("[{}]", row.field_names.join(", "))
            } else {
                "(tombstone)".to_string()
            };
            // The op id is a stable rollback handle but pure noise while
            // browsing; show it only for verbose runs.
            let op_id = match (&row.op_id, ctx.common.verbose > 0) {
                (Some(id), true) => format!("  {id}"),
                _ => String::new(),
            };
            // No `#n` for rows without a rollback handle (v3 live entry):
            // the rollback help promises every displayed `#n` resolves.
            let seq = row
                .seq
                .map_or_else(|| " - ".to_string(), |seq| format!("#{seq:<2}"));
            println!(
                "  {seq} [{:<8}]  {}  {details}{op_id}",
                role,
                format_timestamp(row.changed_at),
            );
        }
        if stored_conflicts > 0 {
            println!(
                "  ! {stored_conflicts} concurrent write(s) kept for rollback (kyz rollback --to <seq>)"
            );
        }
    }
    Ok(())
}

fn handle_rollback(ctx: &RuntimeContext, cmd: &RollbackCommand) -> Result<()> {
    let (service, key) = parse_secret_ref(&cmd.secret, &cmd.service);

    if ctx.common.dry_run {
        info!(
            "dry-run: would rollback '{service}/{key}' to version {}",
            cmd.target
        );
        return Ok(());
    }

    let store = ctx.vault_store()?;
    store
        .rollback(service, key, &cmd.target, ctx.config.history_retention)
        .map_err(|e| anyhow!("{e}"))?;

    if !ctx.common.quiet {
        println!("Rolled back '{service}/{key}' to version {}", cmd.target);
    }
    Ok(())
}

/// Format a Unix timestamp as a human-readable string.
///
/// The value is clamped to year 9999: v3 vaults carry plaintext,
/// unauthenticated timestamps, and a tampered value must not panic the
/// display path with a duration-overflow.
fn format_timestamp(ts: u64) -> String {
    const MAX_TS: u64 = 253_402_300_799; // 9999-12-31T23:59:59Z
    humantime::format_rfc3339_seconds(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts.min(MAX_TS)),
    )
    .to_string()
}

fn handle_env(ctx: &RuntimeContext) -> Result<()> {
    let envs = kyz_core::list_environments().map_err(|e| anyhow!("{e}"))?;

    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "environments": envs }))
                .context("serializing to JSON")?
        );
    } else if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&serde_json::json!({ "environments": envs }))
                .context("serializing to YAML")?
        );
    } else if envs.is_empty() {
        println!("No named environments found.");
        println!("Create one with: kyz --env <name> vault create");
    } else {
        println!("Named environments:");
        for env in &envs {
            let vault_path = kyz_core::env_vault_path(env).map_err(|e| anyhow!("{e}"))?;
            println!("  {env}  ({})", vault_path.display());
        }
    }
    Ok(())
}

fn handle_export(ctx: &RuntimeContext, cmd: &ExportCommand) -> Result<()> {
    if std::env::var("KYZ_NO_READ").is_ok() {
        return Err(anyhow!(
            "export blocked: running in no-read mode (KYZ_NO_READ is set)"
        ));
    }

    let store = ctx.secret_store()?;

    let services = if let Some(ref svc) = cmd.service {
        vec![svc.clone()]
    } else {
        store.list_services().map_err(|e| anyhow!("{e}"))?
    };

    let mut all_entries = Vec::new();
    for svc in &services {
        let summaries = store.list(svc).map_err(|e| anyhow!("{e}"))?;
        for summary in &summaries {
            let entry = store.get(svc, &summary.key).map_err(|e| anyhow!("{e}"))?;
            all_entries.push(entry);
        }
    }

    let export = serde_json::json!({
        "version": 1,
        "entries": all_entries,
    });

    if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&export).context("serializing to YAML")?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&export).context("serializing to JSON")?
        );
    }
    Ok(())
}

fn handle_import(ctx: &RuntimeContext, cmd: &ImportCommand) -> Result<()> {
    let json_str = if let Some(ref path) = cmd.file {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("reading from stdin")?;
        buf
    };

    let data: serde_json::Value = serde_json::from_str(&json_str).context("parsing import JSON")?;

    // Support both new multi-field format and legacy flat format
    let entries: Vec<SecretEntry> =
        if let Some(entries_arr) = data.get("entries").and_then(|v| v.as_array()) {
            // New format: {"entries": [SecretEntry, ...]}
            entries_arr
                .iter()
                .map(|v| serde_json::from_value(v.clone()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("parsing entries")?
        } else if let Some(secrets) = data.get("secrets").and_then(|v| v.as_object()) {
            // Legacy format: {"service": "x", "secrets": {"key": "value"}}
            let service = data
                .get("service")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_SERVICE);
            secrets
                .iter()
                .map(|(k, v)| {
                    let val = v.as_str().unwrap_or_default();
                    SecretEntry::single(cmd.service.as_deref().unwrap_or(service), k, val)
                })
                .collect()
        } else {
            return Err(anyhow!(
                "expected \"entries\" array or \"secrets\" object in import JSON"
            ));
        };

    if ctx.common.dry_run {
        info!("dry-run: would import {} entries", entries.len());
        return Ok(());
    }

    let store = ctx.secret_store()?;
    let mut count = 0usize;

    for entry in &entries {
        let svc = cmd.service.as_deref().unwrap_or(&entry.service);
        // `--yes` doubles as the explicit confirmation to recreate
        // tombstoned entries (matching `kyz set --yes`); without it a
        // deleted entry fails with a working --yes suggestion instead of
        // an unreachable one.
        let result = if ctx.common.assume_yes {
            store.set_recreating(svc, &entry.key, entry)
        } else {
            store.set(svc, &entry.key, entry)
        };
        result.map_err(|e| anyhow!("{e}"))?;
        count += 1;
    }

    if !ctx.common.quiet {
        println!(
            "Imported {count} entr{}",
            if count == 1 { "y" } else { "ies" }
        );
    }
    Ok(())
}

fn handle_init(ctx: &RuntimeContext, cmd: InitCommand) -> Result<()> {
    if ctx.paths.config_file.exists() && !(cmd.force || ctx.common.assume_yes) {
        return Err(anyhow!(
            "config already exists at {} (use --force to overwrite)",
            ctx.paths.config_file.display()
        ));
    }

    if ctx.common.dry_run {
        info!(
            "dry-run: would write default config to {}",
            ctx.paths.config_file.display()
        );
        return Ok(());
    }

    write_default_config(&ctx.paths.config_file)
}

fn handle_config(ctx: &RuntimeContext, command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Show => {
            if ctx.common.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ctx.config)
                        .context("serializing config to JSON")?
                );
            } else if ctx.common.yaml {
                println!(
                    "{}",
                    serde_yaml::to_string(&ctx.config).context("serializing config to YAML")?
                );
            } else {
                println!("{:#?}", ctx.config);
            }
            Ok(())
        }
        ConfigCommand::Path => {
            println!("{}", ctx.paths.config_file.display());
            Ok(())
        }
        ConfigCommand::Paths => {
            let cache_dir = default_cache_dir()?;
            if ctx.common.json {
                let paths = serde_json::json!({
                    "config": ctx.paths.config_file,
                    "data": ctx.paths.data_dir,
                    "state": ctx.paths.state_dir,
                    "cache": cache_dir,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&paths).context("serializing paths to JSON")?
                );
            } else if ctx.common.yaml {
                let paths = serde_json::json!({
                    "config": ctx.paths.config_file,
                    "data": ctx.paths.data_dir,
                    "state": ctx.paths.state_dir,
                    "cache": cache_dir,
                });
                println!(
                    "{}",
                    serde_yaml::to_string(&paths).context("serializing paths to YAML")?
                );
            } else {
                println!("config: {}", ctx.paths.config_file.display());
                println!("data:   {}", ctx.paths.data_dir.display());
                println!("state:  {}", ctx.paths.state_dir.display());
                println!("cache:  {}", cache_dir.display());
            }
            Ok(())
        }
        ConfigCommand::Schema => {
            println!("{}", include_str!("../../../examples/config.schema.json"));
            Ok(())
        }
        ConfigCommand::Reset => {
            if ctx.common.dry_run {
                info!(
                    "dry-run: would reset config at {}",
                    ctx.paths.config_file.display()
                );
                return Ok(());
            }
            write_default_config(&ctx.paths.config_file)
        }
    }
}

fn handle_completions(shell: Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, APP_NAME, &mut io::stdout());
}

fn handle_ipc(ctx: &RuntimeContext, command: IpcCommand) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (ctx, command);
        Err(anyhow!(
            "kyz ipc is currently supported on Unix platforms only"
        ))
    }

    #[cfg(unix)]
    {
        match command {
            IpcCommand::Submit(cmd) => handle_ipc_submit(ctx, &cmd),
            IpcCommand::Grant(cmd) => handle_ipc_grant(ctx, &cmd),
            IpcCommand::Use(cmd) => handle_ipc_use(ctx, &cmd),
        }
    }
}

#[cfg(unix)]
fn handle_ipc_submit(ctx: &RuntimeContext, cmd: &IpcSubmitCommand) -> Result<()> {
    let value = read_secret_value(cmd.value.as_deref())?;
    let expires_at = now_unix().saturating_add(cmd.ttl);
    let payload = serde_json::json!({
        "type": "submit_secret",
        "request_id": cmd.request_id,
        "service": cmd.service,
        "key": cmd.key,
        "value": value,
        "expires_at": expires_at,
        "origin": {
            "source": cmd.source.clone(),
            "process_id": cmd.process_id,
            "host": cmd.host.clone(),
        }
    });

    let response = ipc_roundtrip(ctx, cmd.socket.as_deref(), &payload)?;
    print_ipc_response(ctx, &response, false)?;
    Ok(())
}

#[cfg(unix)]
fn handle_ipc_grant(ctx: &RuntimeContext, cmd: &IpcGrantCommand) -> Result<()> {
    if cmd.secrets.is_empty() {
        return Err(anyhow!("at least one --secret is required"));
    }

    let payload = serde_json::json!({
        "type": "issue_grant",
        "token": cmd.token,
        "secret_refs": cmd.secrets,
        "commands": cmd.commands,
        "workspaces": cmd.workspaces,
        "expires_at": now_unix().saturating_add(cmd.ttl),
        "use_count": cmd.use_count,
    });

    let response = ipc_roundtrip(ctx, cmd.socket.as_deref(), &payload)?;
    if response.get("ok").and_then(serde_json::Value::as_bool) == Some(false)
        && response.get("reason").and_then(serde_json::Value::as_str) == Some("already_exists")
    {
        return Err(anyhow!(
            "a live grant with token '{}' already exists; grants cannot be overwritten while active (wait for expiry or pick a new token)",
            cmd.token
        ));
    }
    print_ipc_response(ctx, &response, false)?;
    Ok(())
}

#[cfg(unix)]
fn handle_ipc_use(ctx: &RuntimeContext, cmd: &IpcUseCommand) -> Result<()> {
    let payload = if let Some(request_id) = &cmd.request_id {
        serde_json::json!({
            "type": "resolve_secret",
            "request_id": request_id,
        })
    } else if let Some(token) = &cmd.token {
        let secret = cmd
            .secret
            .as_deref()
            .ok_or_else(|| anyhow!("--secret is required when using --token"))?;
        let command = cmd
            .command
            .as_deref()
            .ok_or_else(|| anyhow!("--command is required when using --token"))?;
        let workspace = cmd
            .workspace
            .as_deref()
            .ok_or_else(|| anyhow!("--workspace is required when using --token"))?;
        serde_json::json!({
            "type": "validate_grant",
            "token": token,
            "secret_ref": secret,
            "command": command,
            "workspace": workspace,
        })
    } else {
        return Err(anyhow!(
            "provide either --request-id (resolve) or --token (validate grant)"
        ));
    };

    let response = ipc_roundtrip(ctx, cmd.socket.as_deref(), &payload)?;
    print_ipc_response(ctx, &response, cmd.reveal_value)?;
    Ok(())
}

#[cfg(unix)]
fn ipc_roundtrip(
    ctx: &RuntimeContext,
    socket_override: Option<&std::path::Path>,
    payload: &serde_json::Value,
) -> Result<serde_json::Value> {
    let socket_path = socket_override.map_or_else(
        || ctx.paths.state_dir.join("kyz-ipc.sock"),
        std::path::Path::to_path_buf,
    );

    let mut stream = UnixStream::connect(&socket_path)
        .with_context(|| format!("connecting to IPC socket {}", socket_path.display()))?;

    let mut wire = serde_json::to_vec(payload).context("serializing IPC payload")?;
    wire.push(b'\n');
    stream.write_all(&wire).context("writing IPC request")?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader
        .read_line(&mut line)
        .context("reading IPC response")?;

    serde_json::from_str(&line).context("parsing IPC response")
}

#[cfg(unix)]
fn print_ipc_response(
    ctx: &RuntimeContext,
    response: &serde_json::Value,
    reveal_value: bool,
) -> Result<()> {
    let output = sanitized_ipc_output(response, reveal_value)?;
    let ok = output
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| anyhow!("invalid IPC response: missing bool 'ok'"))?;

    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serializing IPC response JSON")?
        );
    } else if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&output).context("serializing IPC response YAML")?
        );
    } else if ok {
        let service = output
            .get("service")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let key = output
            .get("key")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let value = output
            .get("value")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let value_redacted = output
            .get("value_redacted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        if let Some(id) = output.get("request_id").and_then(serde_json::Value::as_str) {
            println!("request id: {id}");
            println!("share this id with the process that should redeem the secret");
        }
        if let (Some(svc), Some(secret_key)) = (service, key) {
            if value_redacted {
                println!("IPC ok: resolved {svc}/{secret_key} (value redacted)");
            } else {
                println!("IPC ok: resolved {svc}/{secret_key}");
                if let Some(v) = value {
                    println!("{v}");
                }
            }
        } else {
            println!("IPC ok");
        }
    } else {
        let msg = output
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        return Err(anyhow!("IPC denied: {msg}"));
    }

    Ok(())
}

#[cfg(unix)]
fn sanitized_ipc_output(
    response: &serde_json::Value,
    reveal_value: bool,
) -> Result<serde_json::Value> {
    let ok = response
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| anyhow!("invalid IPC response: missing bool 'ok'"))?;

    let reason = response
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let service = response
        .get("service")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let key = response
        .get("key")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let value = response
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let value_redacted = value.as_ref().is_some_and(|_| !reveal_value);
    let printable_value = if reveal_value { value } else { None };

    let request_id = response
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    Ok(serde_json::json!({
        "ok": ok,
        "reason": reason,
        "request_id": request_id,
        "service": service,
        "key": key,
        "value": printable_value,
        "value_redacted": value_redacted,
    }))
}

/// Environment map plus the `service/key` refs of every secret that fed it.
pub type ExecEnv = (BTreeMap<String, String>, Vec<String>);

/// Resolve all secrets for an exec invocation into a flat env map, plus the
/// `service/key` references of every secret that was resolved (used for
/// policy checks and audit, regardless of which flag supplied the secret).
fn resolve_exec_env(
    store: &dyn SecretStore,
    ctx: &RuntimeContext,
    cmd: &ExecCommand,
) -> Result<ExecEnv> {
    let mut env = BTreeMap::new();
    let mut entries: Vec<kyz_core::SecretEntry> = Vec::new();
    let mut resolved_refs: Vec<String> = Vec::new();

    // 1. Resolve from alias
    if let Some(ref alias_name) = cmd.alias {
        let alias = ctx
            .config
            .aliases
            .get(alias_name)
            .ok_or_else(|| anyhow!("alias '{alias_name}' not found in config"))?;

        for secret_ref in &alias.secrets {
            if let Some(entry) = resolve_secret_ref(store, secret_ref)? {
                entries.push(entry);
                resolved_refs.push(secret_policy_key(secret_ref).to_string());
            }
        }

        for entry in resolve_by_tags(store, &alias.tags)? {
            resolved_refs.push(format!("{}/{}", entry.service, entry.key));
            entries.push(entry);
        }

        for (env_var, field_ref) in &alias.env_map {
            if !kyz_core::is_safe_exec_env_name(env_var) {
                return Err(anyhow!(
                    "refusing to inject unsafe env var name '{env_var}' from alias '{alias_name}'"
                ));
            }
            let value = resolve_field_ref(store, field_ref)?;
            env.insert(env_var.clone(), value);
            resolved_refs.push(secret_policy_key(field_ref).to_string());
        }
    }

    // 2. Explicit --secret refs
    for secret_ref in &cmd.secrets {
        if let Some(entry) = resolve_secret_ref(store, secret_ref)? {
            entries.push(entry);
            resolved_refs.push(secret_policy_key(secret_ref).to_string());
        }
    }

    // 3. Tag-based --tag refs
    for entry in resolve_by_tags(store, &cmd.tags)? {
        resolved_refs.push(format!("{}/{}", entry.service, entry.key));
        entries.push(entry);
    }

    // 4. Interactive picker
    if cmd.pick {
        for entry in fzf_pick_secrets(store)? {
            resolved_refs.push(format!("{}/{}", entry.service, entry.key));
            entries.push(entry);
        }
    }

    // 5. Explicit --env mappings (highest priority)
    for mapping in &cmd.env_maps {
        let (var, field_ref) = mapping.split_once('=').ok_or_else(|| {
            anyhow!("invalid --env format '{mapping}', expected ENV=service/key:field")
        })?;
        if !kyz_core::is_safe_exec_env_name(var) {
            return Err(anyhow!(
                "refusing to inject unsafe env var name '{var}' via --env"
            ));
        }
        let value = resolve_field_ref(store, field_ref)?;
        env.insert(var.to_string(), value);
        resolved_refs.push(secret_policy_key(field_ref).to_string());
    }

    // Convert collected entries to env vars (default: uppercase field names).
    // Field names come from secret metadata and must never introduce
    // process-behavior variables (LD_PRELOAD, PATH, ...).
    for entry in &entries {
        for (field_name, field_value) in &entry.fields {
            let env_var = field_name.to_uppercase();
            if !kyz_core::is_safe_exec_env_name(&env_var) {
                log::warn!(
                    "refusing to inject secret field '{field_name}' as env var '{env_var}' (unsafe name)"
                );
                continue;
            }
            // Don't overwrite explicit mappings
            env.entry(env_var)
                .or_insert_with(|| field_value.expose_secret().to_string());
        }
    }

    resolved_refs.sort();
    resolved_refs.dedup();
    Ok((env, resolved_refs))
}

/// Parse `"service/key"` and fetch the entry.
fn resolve_secret_ref(
    store: &dyn SecretStore,
    ref_str: &str,
) -> Result<Option<kyz_core::SecretEntry>> {
    let (service, key) = ref_str
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid secret reference '{ref_str}', expected service/key"))?;
    match store.get(service, key) {
        Ok(entry) => Ok(Some(entry)),
        Err(kyz_core::error::CoreError::SecretNotFound(_)) => {
            Err(anyhow!("secret '{ref_str}' not found"))
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

/// Parse `"service/key:field"` and return the field value.
fn resolve_field_ref(store: &dyn SecretStore, ref_str: &str) -> Result<String> {
    let (secret_part, field_name) = ref_str.split_once(':').ok_or_else(|| {
        anyhow!("invalid field reference '{ref_str}', expected service/key:field")
    })?;
    let (service, key) = secret_part
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid secret reference '{secret_part}', expected service/key"))?;
    let entry = store.get(service, key).map_err(|e| anyhow!("{e}"))?;
    entry
        .field(field_name)
        .map(String::from)
        .ok_or_else(|| anyhow!("field '{field_name}' not found in '{secret_part}'"))
}

/// Find all entries matching any of the given tags across all services.
fn resolve_by_tags(store: &dyn SecretStore, tags: &[String]) -> Result<Vec<kyz_core::SecretEntry>> {
    if tags.is_empty() {
        return Ok(Vec::new());
    }
    let services = store.list_services().map_err(|e| anyhow!("{e}"))?;
    let mut results = Vec::new();
    let mut seen = BTreeSet::new();

    for svc in &services {
        let summaries = store.list(svc).map_err(|e| anyhow!("{e}"))?;
        for summary in &summaries {
            let compound = format!("{}/{}", summary.service, summary.key);
            if seen.contains(&compound) {
                continue;
            }
            if summary.tags.iter().any(|t| tags.contains(t)) {
                let entry = store.get(svc, &summary.key).map_err(|e| anyhow!("{e}"))?;
                seen.insert(compound);
                results.push(entry);
            }
        }
    }
    Ok(results)
}

/// Interactive fzf picker for multi-selecting secrets.
fn fzf_pick_secrets(store: &dyn SecretStore) -> Result<Vec<kyz_core::SecretEntry>> {
    use std::process::{Command as Cmd, Stdio};

    // Build list of all secrets
    let services = store.list_services().map_err(|e| anyhow!("{e}"))?;
    let mut lines = Vec::new();
    for svc in &services {
        let summaries = store.list(svc).map_err(|e| anyhow!("{e}"))?;
        for s in &summaries {
            let tags_str = if s.tags.is_empty() {
                String::new()
            } else {
                format!(
                    " [{}]",
                    s.tags.iter().cloned().collect::<Vec<_>>().join(", ")
                )
            };
            let fields_str = s.field_names.join(", ");
            lines.push(format!(
                "{}/{}\t{{{fields_str}}}{tags_str}",
                s.service, s.key
            ));
        }
    }

    if lines.is_empty() {
        return Err(anyhow!("no secrets found in store"));
    }

    let input = lines.join("\n");
    let mut child = Cmd::new("fzf")
        .args([
            "--multi",
            "--ansi",
            "--header",
            "Select secrets (TAB to multi-select, ENTER to confirm)",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to start fzf (is it installed?)")?;

    {
        use std::io::Write as _;
        let stdin = child.stdin.as_mut().context("failed to open fzf stdin")?;
        stdin
            .write_all(input.as_bytes())
            .context("failed to write to fzf")?;
    }

    let output = child.wait_with_output().context("fzf failed")?;
    if !output.status.success() {
        return Err(anyhow!("fzf cancelled"));
    }

    let selected = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();
    for line in selected.lines() {
        let ref_str = line.split('\t').next().unwrap_or(line).trim();
        if ref_str.is_empty() {
            continue;
        }
        if let Some(entry) = resolve_secret_ref(store, ref_str)? {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Default kyz-api base URL for headless auth flow.
const DEFAULT_API_URL: &str = "http://127.0.0.1:3000";

/// Resolve secrets via the remote kyz-api auth flow (headless/no-TTY mode).
///
/// Submit an auth request and wait for approval via WebSocket.
///
/// 1. Collects the secret scopes needed from alias/tags/secrets
/// 2. Creates an auth request via POST `/auth/request`
/// 3. Waits via WebSocket `/auth/wait/:id` for approval
/// 4. On approval, the secrets are delivered in the response
fn submit_and_wait_auth_request(
    api_url: &str,
    api_token: Option<&String>,
    scopes: &[String],
    reason: &str,
) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    let requester = std::env::var("KYZ_REQUESTER")
        .unwrap_or_else(|_| format!("kyz-exec-{}", std::process::id()));

    // Client-generated pickup capability: the request id alone must never be
    // enough to redeem the approved secrets.
    let capability = kyz_core::generate_pickup_capability().map_err(|e| anyhow!("{e}"))?;
    let create_body = serde_json::json!({
        "requester": requester,
        "scopes": scopes,
        "reason": reason,
        "ttl_seconds": 300,
        "pickup_capability": capability,
    });

    let mut req = ureq::post(&format!("{api_url}/auth/request"));
    if let Some(token) = api_token {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }

    let resp: serde_json::Value = req
        .send_json(&create_body)
        .context("failed to create auth request")?
        .body_mut()
        .read_json()
        .context("failed to parse auth request response")?;

    let request_id = resp["id"]
        .as_str()
        .ok_or_else(|| anyhow!("missing request id in response"))?;

    eprintln!("⏳ Waiting for approval of auth request: {request_id}");
    eprintln!("   Approve at: {api_url}/auth/approve/{request_id}");

    // Wait via WebSocket
    let ws_url = format!(
        "{}/auth/wait/{request_id}",
        api_url
            .replace("http://", "ws://")
            .replace("https://", "wss://")
    );

    let (mut ws_socket, _) =
        tungstenite::connect(&ws_url).context("failed to connect WebSocket for auth wait")?;

    let status = loop {
        let msg = ws_socket.read().context("WebSocket read error")?;
        match msg {
            tungstenite::Message::Text(text) => {
                let event: serde_json::Value =
                    serde_json::from_str(&text).context("invalid WS message")?;
                if let Some(s) = event["status"].as_str() {
                    break s.to_string();
                }
            }
            tungstenite::Message::Close(_) => {
                return Err(anyhow!("WebSocket closed without status update"));
            }
            _ => {}
        }
    };

    if status != "approved" {
        return Err(anyhow!("auth request {request_id} was {status}"));
    }

    // Pick up secrets (one-time; requires the capability generated above)
    let mut pickup_req = ureq::get(&format!(
        "{api_url}/auth/secrets/{request_id}?capability={capability}"
    ));
    if let Some(token) = api_token {
        pickup_req = pickup_req.header("Authorization", &format!("Bearer {token}"));
    }

    let stashed: BTreeMap<String, BTreeMap<String, String>> = pickup_req
        .call()
        .context("failed to pick up secrets")?
        .body_mut()
        .read_json()
        .context("failed to parse secrets response")?;

    eprintln!(
        "✅ Auth request {request_id} approved — received {} scope(s)",
        stashed.len()
    );

    Ok(stashed)
}

fn resolve_exec_env_headless(ctx: &RuntimeContext, cmd: &ExecCommand) -> Result<ExecEnv> {
    let api_url = std::env::var("KYZ_API_URL").unwrap_or_else(|_| DEFAULT_API_URL.to_string());
    let api_token = std::env::var("KYZ_API_TOKEN").ok();

    // 1. Collect scopes from alias/tags/secrets/env_maps
    let mut scopes: Vec<String> = Vec::new();

    if let Some(ref alias_name) = cmd.alias {
        let alias = ctx
            .config
            .aliases
            .get(alias_name)
            .ok_or_else(|| anyhow!("alias '{alias_name}' not found in config"))?;
        scopes.extend(alias.secrets.clone());
        for field_ref in alias.env_map.values() {
            scopes.push(field_ref.clone());
        }
    }
    scopes.extend(cmd.secrets.clone());
    for mapping in &cmd.env_maps {
        if let Some((_, field_ref)) = mapping.split_once('=') {
            scopes.push(field_ref.to_string());
        }
    }

    if scopes.is_empty() {
        return Err(anyhow!(
            "headless mode requires explicit secret scopes (--alias, --secret, or --env)"
        ));
    }

    let reason = format!("kyz exec headless: {:?}", cmd.command);
    let stashed = submit_and_wait_auth_request(&api_url, api_token.as_ref(), &scopes, &reason)
        .map_err(|e| anyhow!("{e}"))?;

    // Flatten into env vars
    let mut env = BTreeMap::new();

    // Apply alias env_map if present
    if let Some(ref alias_name) = cmd.alias
        && let Some(alias) = ctx.config.aliases.get(alias_name)
    {
        for (env_var, field_ref) in &alias.env_map {
            if !kyz_core::is_safe_exec_env_name(env_var) {
                return Err(anyhow!(
                    "refusing to inject unsafe env var name '{env_var}' from alias '{alias_name}'"
                ));
            }
            if let Some(values) = stashed.get(field_ref) {
                for v in values.values() {
                    env.insert(env_var.clone(), v.clone());
                }
            }
        }
    }

    // Apply explicit --env mappings
    for mapping in &cmd.env_maps {
        if let Some((var, field_ref)) = mapping.split_once('=') {
            if !kyz_core::is_safe_exec_env_name(var) {
                return Err(anyhow!(
                    "refusing to inject unsafe env var name '{var}' via --env"
                ));
            }
            if let Some(values) = stashed.get(field_ref) {
                for v in values.values() {
                    env.insert(var.to_string(), v.clone());
                }
            }
        }
    }

    // Default: uppercase field names for any remaining secrets. Field names
    // are secret metadata and must never introduce process-behavior variables.
    for values in stashed.values() {
        for (field_name, field_value) in values {
            let env_var = field_name.to_uppercase();
            if !kyz_core::is_safe_exec_env_name(&env_var) {
                log::warn!(
                    "refusing to inject secret field '{field_name}' as env var '{env_var}' (unsafe name)"
                );
                continue;
            }
            env.entry(env_var).or_insert_with(|| field_value.clone());
        }
    }

    let mut refs: Vec<String> = scopes
        .iter()
        .map(|scope| secret_policy_key(scope).to_string())
        .collect();
    refs.sort();
    refs.dedup();
    Ok((env, refs))
}

fn handle_exec(ctx: &RuntimeContext, cmd: &ExecCommand) -> Result<()> {
    // Resolve the effective command: -c takes priority, then trailing args
    let (program, args) = resolve_exec_command(cmd)?;

    let store = ctx.secret_store()?;

    // Try resolving secrets; if vault is locked, handle interactively or headless
    let (env, secret_refs) = match resolve_exec_env(store.as_ref(), ctx, cmd) {
        Ok(result) => result,
        Err(e) if e.to_string().contains("vault is locked") => {
            if io::stdin().is_terminal() {
                // Interactive: prompt passphrase inline
                let vault_store = ctx.vault_store()?;
                ensure_workspace_vault_trusted(ctx, &vault_store, ctx.common.assume_yes)?;
                let passphrase = prompt_passphrase(&format!(
                    "Vault passphrase ({}): ",
                    vault_store.vault_path().display()
                ))?;
                vault_store
                    .unlock(&passphrase, kyz_core::store::DEFAULT_SESSION_TIMEOUT_SECS)
                    .map_err(|e| anyhow!("{e}"))?;
                resolve_exec_env(store.as_ref(), ctx, cmd)?
            } else {
                // Headless: use remote auth flow via kyz-api
                resolve_exec_env_headless(ctx, cmd)?
            }
        }
        Err(e) => return Err(e),
    };

    if ctx.common.dry_run {
        info!(
            "dry-run: would inject {} env vars and run: {} {:?}",
            env.len(),
            program,
            args
        );
        for k in env.keys() {
            println!("{k}=***");
        }
        return Ok(());
    }

    // Enforce command policy
    let pol = kyz_core::resolve_policy(cmd.policy.as_deref(), cmd.no_policy)
        .map_err(|e| anyhow!("{e}"))?;

    // Policy sees EVERY secret resolved for this invocation, whatever flag
    // supplied it (--secret/--tag/--alias/--env/--pick).
    if let Err(v) = pol.check_all(&program, &args, &secret_refs) {
        kyz_core::audit::audit_policy_violation(&program, &v.to_string());
        return Err(anyhow!("{v}"));
    }

    kyz_core::audit::audit_exec(&secret_refs, &program);

    let clean_env = scrubbed_env();

    // On Unix, use exec() to replace the process
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let err = std::process::Command::new(&program)
            .args(&args)
            .env_clear()
            .envs(clean_env.iter().map(|(k, v)| (k, v)))
            .envs(&env)
            .exec();
        // exec() only returns on error
        Err(anyhow!("failed to exec '{program}': {err}"))
    }

    #[cfg(not(unix))]
    {
        let status = std::process::Command::new(&program)
            .args(&args)
            .env_clear()
            .envs(clean_env.iter().map(|(k, v)| (k, v)))
            .envs(&env)
            .status()
            .context(format!("failed to run '{program}'"))?;
        #[expect(
            clippy::exit,
            reason = "propagates the wrapped process exit code; ExitCode plumbing would change every exec call site"
        )]
        {
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

/// Resolve the program and arguments from the exec command.
///
/// Priority:
/// 1. `-c 'shell command string'` -> runs via `sh -c "..."`
/// 2. Trailing positional args (`-- cmd arg1 arg2`)
fn resolve_exec_command(cmd: &ExecCommand) -> Result<(String, Vec<String>)> {
    cmd.shell_command.as_ref().map_or_else(
        || {
            if cmd.command.is_empty() {
                Err(anyhow!(
                    "no command specified; use -c 'command' or -- command [args...]"
                ))
            } else {
                let program = cmd.command[0].clone();
                let args = cmd.command[1..].to_vec();
                Ok((program, args))
            }
        },
        |shell_cmd| {
            // Determine the shell to use ($SHELL or fallback to sh)
            let shell = env::var("SHELL").unwrap_or_else(|_| "sh".to_string());
            Ok((shell, vec!["-c".to_string(), shell_cmd.clone()]))
        },
    )
}

/// Sensitive env var prefixes/names to strip from child processes.
const SCRUB_ENV_VARS: &[&str] = &["KYZ_VAULT_PASSWORD", "KYZ_API_TOKEN", "KYZ_PASSPHRASE"];

const SCRUB_ENV_PREFIXES: &[&str] = &["KYZ_VAULT_PASS", "KYZ_SESSION_"];

/// Whether an environment variable name is sensitive (exact names and
/// prefixes).
///
/// Windows environment variable names are case-insensitive, so matching
/// follows the platform's rules there — a lowercase `kyz_vault_password`
/// must be scrubbed just like the canonical spelling or the secret would
/// leak through `GetEnvironmentVariable`-style lookups in the child.
fn env_key_is_sensitive(key: &str) -> bool {
    let is_name = |candidate: &str| {
        if cfg!(windows) {
            key.eq_ignore_ascii_case(candidate)
        } else {
            key == candidate
        }
    };
    SCRUB_ENV_VARS.iter().any(|name| is_name(name))
        || SCRUB_ENV_PREFIXES.iter().any(|prefix| {
            let (key_bytes, prefix_bytes) = (key.as_bytes(), prefix.as_bytes());
            if cfg!(windows) {
                key_bytes.len() >= prefix_bytes.len()
                    && key_bytes[..prefix_bytes.len()].eq_ignore_ascii_case(prefix_bytes)
            } else {
                key_bytes.starts_with(prefix_bytes)
            }
        })
}

/// Build a scrubbed copy of the current environment, removing sensitive kyz vars.
fn scrubbed_env() -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(key, _)| !env_key_is_sensitive(key))
        .collect()
}

/// Minimal environment inherited by the detached daemon. Config/state
/// path expansion needs HOME/XDG_* (APPDATA on Windows); icacls needs
/// USERNAME and Windows process creation needs `SystemRoot`. Everything else,
/// including arbitrary application secrets, is excluded by default.
fn daemon_env_allowed(key: &std::ffi::OsStr) -> bool {
    let key = key.to_string_lossy();
    let normalized = if cfg!(windows) {
        key.to_ascii_uppercase()
    } else {
        key.to_string()
    };
    matches!(
        normalized.as_str(),
        "PATH"
            | "HOME"
            | "USERPROFILE"
            | "USERNAME"
            | "TMP"
            | "TEMP"
            | "TMPDIR"
            | "LANG"
            | "LANGUAGE"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "SYSTEMROOT"
            | "WINDIR"
    ) || normalized.starts_with("LC_")
        || normalized.starts_with("XDG_")
}

fn allowlist_daemon_env_from(
    command: &mut std::process::Command,
    env: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) {
    command.env_clear();
    for (key, value) in env {
        if daemon_env_allowed(&key) {
            command.env(key, value);
        }
    }
}

fn allowlist_daemon_env(command: &mut std::process::Command) {
    allowlist_daemon_env_from(command, std::env::vars_os());
}

fn handle_daemon(ctx: &RuntimeContext, command: DaemonCommand) -> Result<()> {
    match command {
        DaemonCommand::Start(cmd) => handle_daemon_start(ctx, &cmd),
        DaemonCommand::Status => handle_daemon_status(ctx),
        DaemonCommand::Reload => handle_daemon_reload(ctx),
        DaemonCommand::Stop => handle_daemon_stop(ctx),
    }
}

/// Resolve the daemon state paths for this invocation.
fn daemon_paths(ctx: &RuntimeContext) -> kyz_daemon::DaemonPaths {
    kyz_daemon::DaemonPaths::new(&ctx.paths.state_dir)
}

/// Read the management IPC token, if the daemon (or a stale file) left one.
fn read_daemon_ipc_token(paths: &kyz_daemon::DaemonPaths) -> Option<String> {
    std::fs::read_to_string(paths.ipc_token_path())
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|token| !token.is_empty())
}

fn handle_daemon_start(ctx: &RuntimeContext, cmd: &DaemonStartArgs) -> Result<()> {
    let store = ctx.vault_store()?;
    let vault_path = store.vault_path().to_path_buf();

    if let Some(timeout) = cmd.timeout
        && timeout > kyz_core::config::MAX_TIMEOUT_SECS
    {
        return Err(anyhow!(
            "--timeout {timeout} exceeds the maximum of {} seconds (use 0 to disable the timeout)",
            kyz_core::config::MAX_TIMEOUT_SECS
        ));
    }

    // Dry-run applies to both modes and must come before any passphrase
    // prompt: `daemon start --foreground --dry-run` must not unlock the
    // vault, write runtime files, or stay resident.
    if ctx.common.dry_run {
        let mode = if cmd.runs_in_process() {
            "foreground"
        } else {
            "background"
        };
        info!(
            "dry-run: would start the {mode} credential daemon for vault {}",
            vault_path.display()
        );
        return Ok(());
    }

    let passphrase = if cmd.bootstrap {
        read_bootstrap_passphrase()?
    } else {
        obtain_daemon_passphrase(cmd.askpass.as_deref())?
    };

    if cmd.runs_in_process() {
        return run_foreground_daemon(ctx, cmd, vault_path, passphrase);
    }
    spawn_background_daemon(ctx, cmd, &vault_path, passphrase)
}

/// Run the daemon inside this process (foreground / service mode).
fn run_foreground_daemon(
    ctx: &RuntimeContext,
    cmd: &DaemonStartArgs,
    vault_path: PathBuf,
    passphrase: SecretString,
) -> Result<()> {
    let opts = kyz_daemon::DaemonOptions {
        vault_path,
        passphrase,
        config_path: ctx.paths.config_file.clone(),
        state_dir: ctx.paths.state_dir.clone(),
        timeout_override: cmd.timeout,
    };
    kyz_daemon::run_blocking(opts).map_err(|e| anyhow!("{e}"))
}

/// Spawn the daemon as a detached background child.
///
/// The passphrase travels over a one-shot bootstrap pipe (the child's
/// stdin): length-prefixed bytes, then EOF. The child's environment is
/// scrubbed of sensitive kyz vars ([`SCRUB_ENV_VARS`] /
/// [`SCRUB_ENV_PREFIXES`]), its stdio points at `daemon.log`, and the
/// launcher only exits successfully after the daemon answers a management
/// `status` request.
fn spawn_background_daemon(
    ctx: &RuntimeContext,
    cmd: &DaemonStartArgs,
    vault_path: &Path,
    passphrase: SecretString,
) -> Result<()> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let paths = daemon_paths(ctx);
    paths.ensure().map_err(|e| anyhow!("{e}"))?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.daemon_log_path())
        .with_context(|| format!("opening {}", paths.daemon_log_path().display()))?;

    let exe = std::env::current_exe().context("resolving the kyz executable")?;
    let mut command = Command::new(&exe);
    command
        .arg("daemon")
        .arg("start")
        .arg("--foreground")
        .arg("--bootstrap")
        .arg("--vault")
        .arg(vault_path)
        .arg("--config")
        .arg(&ctx.paths.config_file);
    if let Some(timeout) = cmd.timeout {
        command.arg("--timeout").arg(timeout.to_string());
    }
    allowlist_daemon_env(&mut command);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::from(
            log.try_clone().context("cloning daemon.log handle")?,
        ))
        .stderr(Stdio::from(log));

    // Detach: own process group on Unix, no console + new process group on
    // Windows, so Ctrl-C in the launching shell never reaches the daemon.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    let mut child = command
        .spawn()
        .context("spawning the daemon child process")?;

    // Bootstrap pipe write, then drop the handle so the child sees EOF.
    {
        let mut stdin = child
            .stdin
            .take()
            .context("daemon child stdin was not piped")?;
        let bytes = passphrase.expose_secret().as_bytes();
        let length = u32::try_from(bytes.len()).context("passphrase too large")?;
        stdin
            .write_all(&length.to_le_bytes())
            .and_then(|()| stdin.write_all(bytes))
            .context("writing the bootstrap pipe")?;
    }
    drop(passphrase);

    let pid = wait_for_daemon_ready(&paths, &mut child)?;
    if !ctx.common.quiet {
        println!("Daemon started (pid {pid})");
    }
    Ok(())
}

/// Poll the daemon until the **spawned child** answers a management
/// request, the child exits, or the startup deadline passes.
///
/// The answering pid must match `child.id()`: a daemon that was already
/// running (the child is about to fail on the instance lock) or a stale
/// IPC token must never be reported as "started".
fn wait_for_daemon_ready(
    paths: &kyz_daemon::DaemonPaths,
    child: &mut std::process::Child,
) -> Result<u32> {
    let expected_pid = child.id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(anyhow!(
                "daemon exited during startup (status {status}){}",
                daemon_log_tail(paths)
            ));
        }
        if let Some(token) = read_daemon_ipc_token(paths)
            && let Ok(response) = kyz_daemon::send_request_blocking(
                paths,
                &token,
                kyz_daemon::ipc::IpcRequestKind::Status,
            )
            && response.ok
            && let Some(result) = response.result
            && let Ok(report) = serde_json::from_value::<kyz_daemon::ipc::StatusReport>(result)
            && report.pid == expected_pid
        {
            return Ok(report.pid);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            return Err(anyhow!(
                "daemon did not become ready within 30 seconds{}",
                daemon_log_tail(paths)
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The last few lines of the daemon run log, for startup failure context
/// (the child's real error, e.g. "another daemon holds the lock", is only
/// visible there).
fn daemon_log_tail(paths: &kyz_daemon::DaemonPaths) -> String {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let Ok(mut file) = std::fs::File::open(paths.daemon_log_path()) else {
        return String::new();
    };
    let len = file.metadata().map_or(0, |meta| meta.len());
    if file
        .seek(SeekFrom::Start(len.saturating_sub(2048)))
        .is_err()
    {
        return String::new();
    }
    let mut buffer = Vec::new();
    if file.read_to_end(&mut buffer).is_err() {
        return String::new();
    }
    let text = String::from_utf8_lossy(&buffer);
    let mut lines: Vec<&str> = text.lines().rev().take(5).collect();
    lines.reverse();
    if lines.is_empty() {
        return String::new();
    }
    format!(
        "\ndaemon.log (last lines):\n{}",
        lines
            .iter()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Read the length-prefixed passphrase from the bootstrap pipe (stdin).
fn read_bootstrap_passphrase() -> Result<SecretString> {
    use std::io::Read as _;

    let mut handle = io::stdin().lock();
    let mut length_bytes = [0u8; 4];
    handle
        .read_exact(&mut length_bytes)
        .context("reading the bootstrap pipe header")?;
    let length = u32::from_le_bytes(length_bytes) as usize;
    if length == 0 || length > 4096 {
        return Err(anyhow!("invalid bootstrap passphrase frame"));
    }
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; length]);
    handle
        .read_exact(&mut buffer)
        .context("reading the bootstrap pipe payload")?;
    drop(handle);
    // stdin() owns a process-global handle, so dropping its lock alone does
    // not close fd 0. Close it explicitly once the one-shot frame is read.
    #[cfg(unix)]
    nix::unistd::close(0).context("closing bootstrap stdin")?;
    let passphrase = std::str::from_utf8(&buffer).context("bootstrap passphrase is not UTF-8")?;
    Ok(SecretString::from(passphrase.to_owned()))
}

/// Obtain the vault passphrase: TTY prompt, askpass command, then the
/// launcher-only environment variable (never passed to the daemon child).
fn obtain_daemon_passphrase(askpass: Option<&str>) -> Result<SecretString> {
    if io::stdin().is_terminal() {
        return Ok(SecretString::from(prompt_passphrase("Vault passphrase: ")?));
    }
    if let Some(command) = askpass {
        return Ok(SecretString::from(run_askpass(command)?));
    }
    if let Ok(value) = env::var("KYZ_VAULT_PASSWORD")
        && !value.is_empty()
    {
        return Ok(SecretString::from(value));
    }
    Err(anyhow!(
        "no TTY available for the vault passphrase; use --askpass COMMAND or KYZ_VAULT_PASSWORD"
    ))
}

/// Run an askpass helper and return its first stdout line.
fn run_askpass(command: &str) -> Result<String> {
    let output = if cfg!(unix) {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
    } else {
        std::process::Command::new("cmd")
            .arg("/C")
            .arg(command)
            .output()
    }
    .with_context(|| format!("running askpass command '{command}'"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "askpass command failed with status {}",
            output.status
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        return Err(anyhow!("askpass command printed an empty passphrase"));
    }
    Ok(line.to_string())
}

/// Send one management request; `Ok(None)` means "not running".
fn daemon_ipc_request(
    ctx: &RuntimeContext,
    kind: kyz_daemon::ipc::IpcRequestKind,
) -> Result<Option<kyz_daemon::ipc::IpcResponse>> {
    let paths = daemon_paths(ctx);
    let Some(token) = read_daemon_ipc_token(&paths) else {
        return report_daemon_not_running(ctx, &paths).map(|()| None);
    };
    match kyz_daemon::send_request_blocking(&paths, &token, kind) {
        Ok(response) => Ok(Some(response)),
        Err(e) if kyz_daemon::ipc::is_not_running(&e) => {
            report_daemon_not_running(ctx, &paths).map(|()| None)
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

fn report_daemon_not_running(ctx: &RuntimeContext, paths: &kyz_daemon::DaemonPaths) -> Result<()> {
    let stale_pid = kyz_daemon::instance::read_pid(&paths.pid_path());
    let payload = serde_json::json!({
        "running": false,
        "stale_pid": stale_pid,
    });
    if ctx.common.json {
        println!("{payload}");
        return Ok(());
    }
    if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&payload).context("serializing status")?
        );
        return Ok(());
    }
    if !ctx.common.quiet {
        if let Some(pid) = stale_pid {
            println!("Daemon is not running (stale pid file references pid {pid})");
        } else {
            println!("Daemon is not running");
        }
    }
    Ok(())
}

fn handle_daemon_status(ctx: &RuntimeContext) -> Result<()> {
    let Some(response) = daemon_ipc_request(ctx, kyz_daemon::ipc::IpcRequestKind::Status)? else {
        return Ok(());
    };
    if !response.ok {
        return Err(anyhow!(
            "status request failed: {}",
            response.error_message()
        ));
    }
    let result = response.result.unwrap_or_else(|| serde_json::json!({}));

    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).context("serializing status")?
        );
        return Ok(());
    }
    if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&result).context("serializing status")?
        );
        return Ok(());
    }
    if !ctx.common.quiet {
        let Ok(report) = serde_json::from_value::<kyz_daemon::ipc::StatusReport>(result) else {
            return Err(anyhow!("daemon returned a malformed status report"));
        };

        println!("Daemon pid: {}", report.pid);
        println!("Uptime: {}s", report.uptime_secs);
        println!(
            "Vault: {}",
            if report.unlocked {
                "unlocked"
            } else {
                "locked/shutting down"
            }
        );
        match report.timeout_remaining_secs {
            Some(secs) => println!("Timeout: {secs}s remaining"),
            None => println!("Timeout: none"),
        }
        let snapshot = report.snapshot;
        println!(
            "Snapshot: rules={} credentials={} scripts={} hash={}",
            snapshot.rules, snapshot.credentials, snapshot.scripts, snapshot.hash,
        );
        // Prefer the actually bound address: the configured listen may be
        // `127.0.0.1:0`, which no client can connect to.
        if let Some(listen) = report
            .proxy_listen
            .as_deref()
            .or(snapshot.listen.as_deref())
        {
            println!("Proxy listen: {listen}");
        }
    }
    Ok(())
}

fn handle_daemon_reload(ctx: &RuntimeContext) -> Result<()> {
    let Some(response) = daemon_ipc_request(ctx, kyz_daemon::ipc::IpcRequestKind::Reload)? else {
        return Err(anyhow!("daemon is not running; nothing to reload"));
    };
    if !response.ok {
        // Keep the active snapshot; surface the full validation detail.
        return Err(anyhow!(
            "daemon rejected reload: {}",
            response.error_message()
        ));
    }
    let result = response.result.unwrap_or_else(|| serde_json::json!({}));
    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).context("serializing reload result")?
        );
    } else if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&result).context("serializing reload result")?
        );
    } else if !ctx.common.quiet {
        let hash = serde_json::from_value::<kyz_daemon::SnapshotSummary>(result)
            .map_or_else(|_| "-".to_string(), |summary| summary.hash);
        println!("Configuration reloaded (snapshot {hash})");
    }
    Ok(())
}

fn handle_daemon_stop(ctx: &RuntimeContext) -> Result<()> {
    let Some(response) = daemon_ipc_request(ctx, kyz_daemon::ipc::IpcRequestKind::Stop)? else {
        return Ok(());
    };
    if !response.ok {
        return Err(anyhow!("stop request failed: {}", response.error_message()));
    }
    if !ctx.common.quiet {
        println!("Daemon stopped");
    }
    Ok(())
}

fn handle_pipe(ctx: &RuntimeContext, cmd: &PipeCommand) -> Result<()> {
    let store = ctx.secret_store()?;

    // Parse secret reference: "service/key" or "service/key:field"
    let (secret_ref, field_name) = if let Some((s, f)) = cmd.secret.split_once(':') {
        (s, Some(f))
    } else {
        (cmd.secret.as_str(), None)
    };

    let (service, key) = secret_ref.split_once('/').ok_or_else(|| {
        anyhow!(
            "invalid secret reference '{}', expected service/key[:field]",
            cmd.secret
        )
    })?;

    let entry = store.get(service, key).map_err(|e| anyhow!("{e}"))?;

    let value = if let Some(field) = field_name {
        entry
            .field(field)
            .ok_or_else(|| anyhow!("field '{field}' not found in '{secret_ref}'"))?
            .to_string()
    } else {
        // Single-value entries: use "value" field. Multi-field: error.
        entry
            .value()
            .map(String::from)
            .ok_or_else(|| {
                anyhow!(
                    "secret '{secret_ref}' has multiple fields ({}). Specify a field with service/key:field",
                    entry.fields.keys().cloned().collect::<Vec<_>>().join(", ")
                )
            })?
    };

    if ctx.common.dry_run {
        info!(
            "dry-run: would pipe secret '{}' into {:?}",
            cmd.secret, cmd.command
        );
        return Ok(());
    }

    let program = &cmd.command[0];
    let args = &cmd.command[1..];

    // Enforce command policy
    let pol = kyz_core::resolve_policy(cmd.policy.as_deref(), cmd.no_policy)
        .map_err(|e| anyhow!("{e}"))?;

    let args_owned: Vec<String> = args.to_vec();
    if let Err(v) = pol.check_secret_command(&cmd.secret, program) {
        kyz_core::audit::audit_policy_violation(program, &v.to_string());
        return Err(anyhow!("{v}"));
    }
    if let Err(v) = pol.check_args(program, &args_owned) {
        kyz_core::audit::audit_policy_violation(program, &v.to_string());
        return Err(anyhow!("{v}"));
    }

    kyz_core::audit::audit_pipe(&cmd.secret, program);

    let clean_env = scrubbed_env();

    let mut child = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(clean_env.iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context(format!("failed to start '{program}'"))?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        stdin
            .write_all(value.as_bytes())
            .context("failed to write secret to stdin")?;
        if cmd.newline {
            stdin.write_all(b"\n").context("failed to write newline")?;
        }
        // stdin is dropped here, closing the pipe
    }

    let status = child.wait().context("failed to wait for child process")?;
    if !status.success() {
        return Err(anyhow!(
            "child process exited with code {}",
            status.code().unwrap_or(1)
        ));
    }
    Ok(())
}

fn handle_wrap(ctx: &RuntimeContext, cmd: &WrapCommand) -> Result<()> {
    let store = ctx.secret_store()?;
    let allow_all = cmd.allow.len() == 1 && cmd.allow[0] == "*";

    // Verify requested secrets exist
    if !allow_all {
        for name in &cmd.allow {
            // Parse as service/key
            let (service, key) = name.split_once('/').ok_or_else(|| {
                anyhow!("invalid secret reference '{name}', expected service/key")
            })?;
            store.get(service, key).map_err(|e| anyhow!("{e}"))?;
        }
    }

    // Get or prompt for passphrase
    let vault_store = ctx.vault_store()?;
    ensure_workspace_vault_trusted(ctx, &vault_store, ctx.common.assume_yes)?;

    // A valid session (e.g. inside an outer wrap or a prior unlock) makes the
    // passphrase unnecessary — and it must never be exported to the child.
    let already_unlocked = vault_store.status().is_ok_and(|s| s.unlocked);
    let passphrase = if already_unlocked {
        None
    } else if io::stdin().is_terminal() {
        Some(prompt_passphrase(&format!(
            "Vault passphrase ({}): ",
            vault_store.vault_path().display()
        ))?)
    } else {
        Some(
            std::env::var("KYZ_VAULT_PASSWORD")
                .map_err(|_| anyhow!("no TTY and KYZ_VAULT_PASSWORD not set"))?,
        )
    };

    // Ensure vault is unlocked
    if let Some(passphrase) = passphrase.as_ref() {
        let _ = vault_store
            .unlock(passphrase, kyz_core::store::DEFAULT_SESSION_TIMEOUT_SECS)
            .map_err(|e| anyhow!("{e}"))?;
    }

    if ctx.common.dry_run {
        info!(
            "dry-run: would wrap {:?} with access to {} secret(s)",
            cmd.command,
            if allow_all {
                "all".to_string()
            } else {
                cmd.allow.len().to_string()
            }
        );
        return Ok(());
    }

    kyz_core::audit::audit_wrap(&cmd.allow, &cmd.command[0]);

    // Build child environment. The master passphrase is deliberately NOT
    // exported to the child: the session created above (data key in the OS
    // keyring) already covers nested kyz usage, and exporting the passphrase
    // would hand the whole vault to the wrapped process.
    let mut child_env: Vec<(String, String)> = scrubbed_env();

    // Signal no-read mode to kyz inside the wrapped session (best-effort: the
    // child controls its own environment).
    if cmd.no_read {
        child_env.push(("KYZ_NO_READ".to_string(), "1".to_string()));
    }

    eprintln!(
        "[kyz] wrapping {} (best-effort scoping: no-read={}, allowed={} secret(s))",
        cmd.command[0],
        cmd.no_read,
        if allow_all {
            "all".to_string()
        } else {
            cmd.allow.len().to_string()
        }
    );

    let program = &cmd.command[0];
    let args = &cmd.command[1..];

    let status = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(child_env.iter().map(|(k, v)| (k, v)))
        .status()
        .context(format!("failed to run '{program}'"))?;

    if !status.success() {
        return Err(anyhow!(
            "wrapped process exited with code {}",
            status.code().unwrap_or(1)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{allowlist_daemon_env_from, env_key_is_sensitive};

    #[cfg(unix)]
    use super::sanitized_ipc_output;

    use super::format_timestamp;

    #[test]
    fn format_timestamp_clamps_out_of_range_values() {
        // A tampered v3 plaintext timestamp must not panic on the display
        // path (duration overflow at UNIX_EPOCH + u64::MAX secs).
        assert_eq!(
            format_timestamp(u64::MAX),
            format_timestamp(253_402_300_799),
            "values past year 9999 clamp instead of panicking"
        );
        assert!(format_timestamp(0).starts_with("1970-"));
        assert!(format_timestamp(1_758_000_000).starts_with("202"));
    }

    #[test]
    fn sensitive_env_names_match_platform_case_rules() {
        assert!(env_key_is_sensitive("KYZ_VAULT_PASSWORD"));
        assert!(env_key_is_sensitive("KYZ_API_TOKEN"));
        assert!(env_key_is_sensitive("KYZ_SESSION_ID"));
        assert!(env_key_is_sensitive("KYZ_VAULT_PASS_FOO"));
        assert!(!env_key_is_sensitive("KYZ_ENV"));
        assert!(!env_key_is_sensitive("HOME"));

        // Windows env names are case-insensitive; a lowercase spelling of
        // the password variable must be scrubbed there or the child reads
        // it right back through its own case-insensitive lookup.
        #[cfg(windows)]
        assert!(env_key_is_sensitive("kyz_vault_password"));
        #[cfg(unix)]
        assert!(!env_key_is_sensitive("kyz_vault_password"));
    }

    #[test]
    fn detached_daemon_env_excludes_unknown_launcher_secrets() {
        use std::ffi::OsString;
        use std::process::Command;

        let mut child = Command::new("kyz");
        allowlist_daemon_env_from(
            &mut child,
            [
                (OsString::from("PATH"), OsString::from("/bin")),
                (OsString::from("HOME"), OsString::from("/home/test")),
                (
                    OsString::from("UNRELATED_API_SECRET"),
                    OsString::from("private"),
                ),
                (
                    OsString::from("KYZ_VAULT_PASSWORD"),
                    OsString::from("passphrase"),
                ),
            ],
        );
        let child_env: Vec<_> = child.get_envs().collect();
        assert_eq!(child_env.len(), 2);
        assert!(child_env.iter().any(|(key, _)| *key == "PATH"));
        assert!(child_env.iter().any(|(key, _)| *key == "HOME"));
    }

    #[cfg(unix)]
    #[test]
    fn ipc_output_redacts_value_by_default() {
        let raw = serde_json::json!({
            "ok": true,
            "service": "svc",
            "key": "k",
            "value": "super-secret",
        });

        let out = sanitized_ipc_output(&raw, false).expect("sanitize");
        assert_eq!(out["value"], serde_json::Value::Null);
        assert_eq!(out["value_redacted"], serde_json::Value::Bool(true));
    }

    #[cfg(unix)]
    #[test]
    fn ipc_output_reveals_value_only_when_requested() {
        let raw = serde_json::json!({
            "ok": true,
            "service": "svc",
            "key": "k",
            "value": "super-secret",
        });

        let out = sanitized_ipc_output(&raw, true).expect("sanitize");
        assert_eq!(
            out["value"],
            serde_json::Value::String("super-secret".to_string())
        );
        assert_eq!(out["value_redacted"], serde_json::Value::Bool(false));
    }
}
