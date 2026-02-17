//! CLI interface for kyz - a cross-platform secrets manager.

use std::collections::BTreeMap;
use std::env;
use std::io::{self, IsTerminal, Read as _};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use env_logger::fmt::WriteStyle;
use log::{LevelFilter, debug, info};

use kyz_core::paths::write_default_config;
use kyz_core::store::{DEFAULT_SERVICE, DEFAULT_SESSION_TIMEOUT_SECS};
use kyz_core::{
    AppConfig, AppPaths, SecretEntry, SecretStore, VaultStore, default_cache_dir,
};

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
        let store = VaultStore::resolve(self.common.vault.as_deref())
            .map_err(|e| anyhow!("{e}"))?;
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
        println!(
            "Session expires in {} minutes",
            cmd.timeout / 60
        );
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
fn parse_fields(raw: &[String]) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for f in raw {
        let (name, value) = f
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid field format '{f}', expected NAME=VALUE"))?;
        if name.is_empty() {
            return Err(anyhow!("field name must not be empty"));
        }
        fields.insert(name.to_string(), value.to_string());
    }
    Ok(fields)
}

/// Prompt for a passphrase (hidden input).
fn prompt_passphrase(prompt: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).context("reading passphrase from stdin")?;
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
        let value = rpassword::prompt_password("Enter secret value: ")
            .context("reading secret from terminal")?;
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

fn handle_set(ctx: &RuntimeContext, cmd: SetCommand) -> Result<()> {
    let store = ctx.secret_store()?;

    // Build fields from --field args or fallback to positional value
    let fields = if !cmd.fields.is_empty() {
        parse_fields(&cmd.fields)?
    } else {
        let value = read_secret_value(cmd.value.as_deref())?;
        let mut m = BTreeMap::new();
        m.insert("value".to_string(), value);
        m
    };

    let entry = SecretEntry::new(&cmd.service, &cmd.key, fields);

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
            "fields": entry.fields,
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
            "fields": entry.fields,
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
                println!("{name}: {value}");
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
                println!(
                    "{}  [{}]",
                    entry.key,
                    entry.field_names.join(", ")
                );
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

    let data: serde_json::Value =
        serde_json::from_str(&json_str).context("parsing import JSON")?;

    // Support both new multi-field format and legacy flat format
    let entries: Vec<SecretEntry> = if let Some(entries_arr) = data.get("entries").and_then(|v| v.as_array()) {
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
                SecretEntry::single(
                    cmd.service.as_deref().unwrap_or(service),
                    k,
                    val,
                )
            })
            .collect()
    } else {
        return Err(anyhow!(
            "expected \"entries\" array or \"secrets\" object in import JSON"
        ));
    };

    if ctx.common.dry_run {
        info!(
            "dry-run: would import {} entries",
            entries.len()
        );
        return Ok(());
    }

    let store = ctx.secret_store()?;
    let mut count = 0usize;

    for entry in &entries {
        let svc = cmd
            .service
            .as_deref()
            .unwrap_or(&entry.service);
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
