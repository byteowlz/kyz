//! CLI interface for kyz - a cross-platform secrets manager.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{self, IsTerminal, Read as _};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use env_logger::fmt::WriteStyle;
use log::{LevelFilter, debug, info};
use secrecy::{ExposeSecret as _, SecretString};

use kyz_core::paths::write_default_config;
use kyz_core::store::{DEFAULT_SERVICE, DEFAULT_SESSION_TIMEOUT_SECS};
use kyz_core::{AppConfig, AppPaths, SecretEntry, SecretStore, VaultStore, default_cache_dir};

/// Application name from Cargo.toml package name.
const APP_NAME: &str = env!("CARGO_PKG_NAME");

/// Fields that should use hidden input when prompting interactively.
const SENSITIVE_FIELDS: &[&str] = &["password", "token", "secret", "key", "api_key", "value"];

fn main() -> anyhow::Result<()> {
    try_main()
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();

    let ctx = RuntimeContext::new(cli.common.clone())?;
    ctx.init_logging()?;
    debug!("resolved paths: {:#?}", ctx.paths);

    match cli.command {
        Command::Set(cmd) => handle_set(&ctx, cmd),
        Command::Get(cmd) => handle_get(&ctx, cmd),
        Command::Delete(cmd) => handle_delete(&ctx, cmd),
        Command::List(cmd) => handle_list(&ctx, cmd),
        Command::Export(cmd) => handle_export(&ctx, cmd),
        Command::Import(cmd) => handle_import(&ctx, cmd),
        Command::Vault { command } => handle_vault(&ctx, command),
        Command::Init(cmd) => handle_init(&ctx, cmd),
        Command::Config { command } => handle_config(&ctx, command),
        Command::Exec(cmd) => handle_exec(&ctx, cmd),
        Command::Pipe(cmd) => handle_pipe(&ctx, cmd),
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
    /// Generate shell completions.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: Shell,
    },
}

// -- Vault commands -----------------------------------------------------------

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

// -- Secret commands ----------------------------------------------------------

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
    /// Service namespace to list secrets from (omit to list all services).
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
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

// -- Exec command -------------------------------------------------------------

#[derive(Debug, Clone, Args)]
struct ExecCommand {
    /// Named alias from config.toml [aliases.<name>].
    #[arg(long, short = 'a', value_name = "ALIAS")]
    alias: Option<String>,

    /// Explicit env mapping: ENV_VAR=service/key:field (repeatable).
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
    #[arg(long = "shell-command", short = 'c', value_name = "CMD", conflicts_with = "command")]
    shell_command: Option<String>,

    /// Command and arguments to execute (use -- to separate from kyz flags).
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

// -- Pipe command -------------------------------------------------------------

#[derive(Debug, Clone, Args)]
struct PipeCommand {
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

// -- Runtime context ----------------------------------------------------------

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

    /// Resolve the vault store from CLI options.
    fn vault_store(&self) -> Result<VaultStore> {
        let store =
            VaultStore::resolve(self.common.vault.as_deref()).map_err(|e| anyhow!("{e}"))?;
        Ok(store)
    }

    /// Get a `dyn SecretStore` based on the resolved vault.
    fn secret_store(&self) -> Result<Box<dyn SecretStore>> {
        let store = self.vault_store()?;
        Ok(Box::new(store))
    }
}

// -- Vault command handlers ---------------------------------------------------

fn handle_vault(ctx: &RuntimeContext, command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Create(cmd) => handle_vault_create(ctx, cmd),
        VaultCommand::Unlock(cmd) => handle_vault_unlock(ctx, cmd),
        VaultCommand::Lock => handle_vault_lock(ctx),
        VaultCommand::Status => handle_vault_status(ctx),
    }
}

fn handle_vault_create(ctx: &RuntimeContext, cmd: VaultCreateCommand) -> Result<()> {
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

fn handle_vault_unlock(ctx: &RuntimeContext, cmd: VaultUnlockCommand) -> Result<()> {
    let store = ctx.vault_store()?;

    let passphrase = prompt_passphrase("Vault passphrase: ")?;

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

// -- Secret command handlers --------------------------------------------------

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

fn fields_to_plain(fields: &BTreeMap<String, SecretString>) -> BTreeMap<String, String> {
    fields
        .iter()
        .map(|(name, value)| (name.clone(), value.expose_secret().to_string()))
        .collect()
}

fn handle_set(ctx: &RuntimeContext, cmd: SetCommand) -> Result<()> {
    let store = ctx.secret_store()?;

    // Build fields from --field args or fallback to positional value
    let fields = if !cmd.fields.is_empty() {
        parse_fields(&cmd.fields)?
    } else {
        let value = read_secret_value(cmd.value.as_deref())?;
        let mut m = BTreeMap::new();
        m.insert("value".to_string(), SecretString::from(value));
        m
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

    store
        .set(&cmd.service, &cmd.key, &entry)
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

fn handle_get(ctx: &RuntimeContext, cmd: GetCommand) -> Result<()> {
    let store = ctx.secret_store()?;
    let entry = store
        .get(&cmd.service, &cmd.key)
        .map_err(|e| anyhow!("{e}"))?;

    // If a specific field was requested, print just that value
    if let Some(ref field_name) = cmd.field {
        let value = entry
            .field(field_name)
            .ok_or_else(|| anyhow!("field '{field_name}' not found in entry '{}'", cmd.key))?;
        println!("{value}");
        return Ok(());
    }

    // Otherwise print the full entry
    if ctx.common.json {
        let obj = serde_json::json!({
            "service": entry.service,
            "key": entry.key,
            "fields": fields_to_plain(&entry.fields),
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
            "fields": fields_to_plain(&entry.fields),
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        });
        println!(
            "{}",
            serde_yaml::to_string(&obj).context("serializing to YAML")?
        );
    } else if entry.fields.len() == 1 && entry.fields.contains_key("value") {
        // Single-value entry: just print the value
        if let Some(v) = entry.value() {
            println!("{v}");
        }
    } else {
        // Multi-field: print each field
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

fn handle_delete(ctx: &RuntimeContext, cmd: DeleteCommand) -> Result<()> {
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

fn handle_list(ctx: &RuntimeContext, cmd: ListCommand) -> Result<()> {
    let store = ctx.secret_store()?;
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
        println!("No secrets found in service '{}'", cmd.service);
    } else {
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

fn handle_export(ctx: &RuntimeContext, cmd: ExportCommand) -> Result<()> {
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

fn handle_import(ctx: &RuntimeContext, cmd: ImportCommand) -> Result<()> {
    let json_str = match cmd.file {
        Some(ref path) => {
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
        }
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("reading from stdin")?;
            buf
        }
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
        store
            .set(svc, &entry.key, entry)
            .map_err(|e| anyhow!("{e}"))?;
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

// -- Config command handlers --------------------------------------------------

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

// -- Exec command handler -----------------------------------------------------

/// Resolve all secrets for an exec invocation into a flat env map.
fn resolve_exec_env(
    store: &dyn SecretStore,
    ctx: &RuntimeContext,
    cmd: &ExecCommand,
) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    let mut entries: Vec<kyz_core::SecretEntry> = Vec::new();

    // 1. Resolve from alias
    if let Some(ref alias_name) = cmd.alias {
        let alias = ctx
            .config
            .aliases
            .get(alias_name)
            .ok_or_else(|| anyhow!("alias '{alias_name}' not found in config"))?;

        // Explicit secret refs from alias
        for secret_ref in &alias.secrets {
            if let Some(entry) = resolve_secret_ref(store, secret_ref)? {
                entries.push(entry);
            }
        }

        // Tag-based resolution from alias
        for entry in resolve_by_tags(store, &alias.tags)? {
            entries.push(entry);
        }

        // Explicit env mappings from alias
        for (env_var, field_ref) in &alias.env_map {
            let value = resolve_field_ref(store, field_ref)?;
            env.insert(env_var.clone(), value);
        }
    }

    // 2. Explicit --secret refs
    for secret_ref in &cmd.secrets {
        if let Some(entry) = resolve_secret_ref(store, secret_ref)? {
            entries.push(entry);
        }
    }

    // 3. Tag-based --tag refs
    for entry in resolve_by_tags(store, &cmd.tags)? {
        entries.push(entry);
    }

    // 4. Interactive picker
    if cmd.pick {
        let picked = fzf_pick_secrets(store)?;
        entries.extend(picked);
    }

    // 5. Explicit --env mappings (highest priority)
    for mapping in &cmd.env_maps {
        let (var, field_ref) = mapping.split_once('=').ok_or_else(|| {
            anyhow!("invalid --env format '{mapping}', expected ENV=service/key:field")
        })?;
        let value = resolve_field_ref(store, field_ref)?;
        env.insert(var.to_string(), value);
    }

    // Convert collected entries to env vars (default: uppercase field names)
    for entry in &entries {
        for (field_name, field_value) in &entry.fields {
            let env_var = field_name.to_uppercase();
            // Don't overwrite explicit mappings
            env.entry(env_var)
                .or_insert_with(|| field_value.expose_secret().to_string());
        }
    }

    Ok(env)
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
/// 1. Collects the secret scopes needed from alias/tags/secrets
/// 2. Creates an auth request via POST /auth/request
/// 3. Waits via WebSocket /auth/wait/:id for approval
/// 4. On approval, the secrets are delivered in the response
fn resolve_exec_env_headless(
    ctx: &RuntimeContext,
    cmd: &ExecCommand,
) -> Result<BTreeMap<String, String>> {
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
        // env_map values are field refs like "service/key:field"
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

    // 2. Create auth request
    let requester = std::env::var("KYZ_REQUESTER")
        .unwrap_or_else(|_| format!("kyz-exec-{}", std::process::id()));

    let create_body = serde_json::json!({
        "requester": requester,
        "scopes": scopes,
        "reason": format!("kyz exec headless: {:?}", cmd.command),
        "ttl_seconds": 300
    });

    let mut req = ureq::post(&format!("{api_url}/auth/request"));
    if let Some(ref token) = api_token {
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

    // 3. Wait via WebSocket
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
            _ => continue,
        }
    };

    if status != "approved" {
        return Err(anyhow!("auth request {request_id} was {status}"));
    }

    // 4. Pick up secrets (one-time)
    let mut pickup_req = ureq::get(&format!("{api_url}/auth/secrets/{request_id}"));
    if let Some(ref token) = api_token {
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

    // 5. Flatten into env vars
    let mut env = BTreeMap::new();

    // Apply alias env_map if present
    if let Some(ref alias_name) = cmd.alias {
        if let Some(alias) = ctx.config.aliases.get(alias_name) {
            for (env_var, field_ref) in &alias.env_map {
                // Look up field_ref in stashed secrets
                if let Some(values) = stashed.get(field_ref) {
                    // field_ref is "service/key:field", values has {field: value}
                    for v in values.values() {
                        env.insert(env_var.clone(), v.clone());
                    }
                }
            }
        }
    }

    // Apply explicit --env mappings
    for mapping in &cmd.env_maps {
        if let Some((var, field_ref)) = mapping.split_once('=') {
            if let Some(values) = stashed.get(field_ref) {
                for v in values.values() {
                    env.insert(var.to_string(), v.clone());
                }
            }
        }
    }

    // Default: uppercase field names for any remaining secrets
    for (_scope, values) in &stashed {
        for (field_name, field_value) in values {
            let env_var = field_name.to_uppercase();
            env.entry(env_var).or_insert_with(|| field_value.clone());
        }
    }

    Ok(env)
}

fn handle_exec(ctx: &RuntimeContext, cmd: ExecCommand) -> Result<()> {
    // Resolve the effective command: -c takes priority, then trailing args
    let (program, args) = resolve_exec_command(&cmd)?;

    let store = ctx.secret_store()?;

    // Try resolving secrets; if vault is locked, handle interactively or headless
    let env = match resolve_exec_env(store.as_ref(), ctx, &cmd) {
        Ok(env) => env,
        Err(e) if e.to_string().contains("vault is locked") => {
            if io::stdin().is_terminal() {
                // Interactive: prompt passphrase inline
                let vault_store = ctx.vault_store()?;
                let passphrase = prompt_passphrase("Vault passphrase: ")?;
                vault_store
                    .unlock(&passphrase, kyz_core::store::DEFAULT_SESSION_TIMEOUT_SECS)
                    .map_err(|e| anyhow!("{e}"))?;
                resolve_exec_env(store.as_ref(), ctx, &cmd)?
            } else {
                // Headless: use remote auth flow via kyz-api
                resolve_exec_env_headless(ctx, &cmd)?
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
        for (k, _) in &env {
            println!("{k}=***");
        }
        return Ok(());
    }

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
        return Err(anyhow!("failed to exec '{}': {}", program, err));
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
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Resolve the program and arguments from the exec command.
///
/// Priority:
/// 1. `-c 'shell command string'` -> runs via `sh -c "..."`
/// 2. Trailing positional args (`-- cmd arg1 arg2`)
fn resolve_exec_command(cmd: &ExecCommand) -> Result<(String, Vec<String>)> {
    if let Some(ref shell_cmd) = cmd.shell_command {
        // Determine the shell to use ($SHELL or fallback to sh)
        let shell = env::var("SHELL").unwrap_or_else(|_| "sh".to_string());
        Ok((shell, vec!["-c".to_string(), shell_cmd.clone()]))
    } else if cmd.command.is_empty() {
        Err(anyhow!(
            "no command specified; use -c 'command' or -- command [args...]"
        ))
    } else {
        let program = cmd.command[0].clone();
        let args = cmd.command[1..].to_vec();
        Ok((program, args))
    }
}

/// Sensitive env var prefixes/names to strip from child processes.
const SCRUB_ENV_VARS: &[&str] = &["KYZ_VAULT_PASSWORD", "KYZ_API_TOKEN", "KYZ_PASSPHRASE"];

const SCRUB_ENV_PREFIXES: &[&str] = &["KYZ_VAULT_PASS", "KYZ_SESSION_"];

/// Build a scrubbed copy of the current environment, removing sensitive kyz vars.
fn scrubbed_env() -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(key, _)| {
            !SCRUB_ENV_VARS.iter().any(|s| key == *s)
                && !SCRUB_ENV_PREFIXES.iter().any(|p| key.starts_with(p))
        })
        .collect()
}

fn handle_pipe(ctx: &RuntimeContext, cmd: PipeCommand) -> Result<()> {
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
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}
