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
use kyz_core::store::DEFAULT_SERVICE;
use kyz_core::{AppConfig, AppPaths, KeyringStore, SecretStore, default_cache_dir};

/// Application name from Cargo.toml package name.
const APP_NAME: &str = env!("CARGO_PKG_NAME");

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
    #[arg(short = 'y', long = "yes", alias = "force", global = true)]
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

// -- Secret commands ----------------------------------------------------------

#[derive(Debug, Clone, Args)]
struct SetCommand {
    /// Name of the secret to store.
    #[arg(value_name = "KEY")]
    key: String,
    /// Secret value (omit to be prompted or pipe via stdin).
    #[arg(value_name = "VALUE")]
    value: Option<String>,
    /// Service namespace for the secret.
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
}

#[derive(Debug, Clone, Args)]
struct GetCommand {
    /// Name of the secret to retrieve.
    #[arg(value_name = "KEY")]
    key: String,
    /// Service namespace for the secret.
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
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
    /// Service namespace to list secrets from.
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
}

#[derive(Debug, Clone, Args)]
struct ExportCommand {
    /// Service namespace to export secrets from.
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
}

#[derive(Debug, Clone, Args)]
struct ImportCommand {
    /// Path to a JSON file (omit to read from stdin).
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,
    /// Service namespace to import secrets into.
    #[arg(long, default_value = DEFAULT_SERVICE)]
    service: String,
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
}

// -- Secret command handlers --------------------------------------------------

/// Read a secret value from the user.
///
/// If an explicit value is supplied on the command line it is used directly.
/// Otherwise, if stdin is a TTY we prompt for a hidden password; if stdin is
/// piped we read the entire stream.
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

fn handle_set(ctx: &RuntimeContext, cmd: SetCommand) -> Result<()> {
    let value = read_secret_value(cmd.value.as_deref())?;

    if ctx.common.dry_run {
        info!(
            "dry-run: would store secret '{}' in service '{}'",
            cmd.key, cmd.service
        );
        return Ok(());
    }

    let store = KeyringStore::new();
    store
        .set(&cmd.service, &cmd.key, &value)
        .map_err(|e| anyhow!("{e}"))?;

    if !ctx.common.quiet {
        println!("Stored secret '{}' in service '{}'", cmd.key, cmd.service);
    }
    Ok(())
}

fn handle_get(ctx: &RuntimeContext, cmd: GetCommand) -> Result<()> {
    let store = KeyringStore::new();
    let value = store
        .get(&cmd.service, &cmd.key)
        .map_err(|e| anyhow!("{e}"))?;

    if ctx.common.json {
        let obj = serde_json::json!({
            "service": cmd.service,
            "key": cmd.key,
            "value": value,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&obj).context("serializing to JSON")?
        );
    } else if ctx.common.yaml {
        let obj = serde_json::json!({
            "service": cmd.service,
            "key": cmd.key,
            "value": value,
        });
        println!(
            "{}",
            serde_yaml::to_string(&obj).context("serializing to YAML")?
        );
    } else {
        println!("{value}");
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

    let store = KeyringStore::new();
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
    let store = KeyringStore::new();
    let entries = store.list(&cmd.service).map_err(|e| anyhow!("{e}"))?;

    if ctx.common.json {
        let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        let obj = serde_json::json!({
            "service": cmd.service,
            "keys": keys,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&obj).context("serializing to JSON")?
        );
    } else if ctx.common.yaml {
        let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        let obj = serde_json::json!({
            "service": cmd.service,
            "keys": keys,
        });
        println!(
            "{}",
            serde_yaml::to_string(&obj).context("serializing to YAML")?
        );
    } else if entries.is_empty() {
        println!("No secrets found in service '{}'", cmd.service);
    } else {
        for entry in &entries {
            println!("{}", entry.key);
        }
    }
    Ok(())
}

fn handle_export(ctx: &RuntimeContext, cmd: ExportCommand) -> Result<()> {
    let store = KeyringStore::new();
    let entries = store.list(&cmd.service).map_err(|e| anyhow!("{e}"))?;

    let mut secrets = BTreeMap::new();
    for entry in &entries {
        let value = store
            .get(&cmd.service, &entry.key)
            .map_err(|e| anyhow!("{e}"))?;
        secrets.insert(entry.key.clone(), value);
    }

    let export = serde_json::json!({
        "service": cmd.service,
        "secrets": secrets,
    });

    if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&export).context("serializing to YAML")?
        );
    } else {
        // Default to JSON for export (always structured)
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

    let secrets = data
        .get("secrets")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("expected a \"secrets\" object in the import JSON"))?;

    if ctx.common.dry_run {
        info!(
            "dry-run: would import {} secrets into service '{}'",
            secrets.len(),
            cmd.service
        );
        return Ok(());
    }

    let store = KeyringStore::new();
    let mut count = 0usize;

    for (key, value) in secrets {
        let val_str = value.as_str().ok_or_else(|| {
            anyhow!("secret value for key '{key}' must be a JSON string")
        })?;
        store
            .set(&cmd.service, key, val_str)
            .map_err(|e| anyhow!("{e}"))?;
        count += 1;
    }

    if !ctx.common.quiet {
        println!(
            "Imported {count} secret{} into service '{}'",
            if count == 1 { "" } else { "s" },
            cmd.service
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
