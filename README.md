# kyz

A cross-platform secrets manager with CLI, TUI, API server, and MCP server. Secrets are stored in an age-encrypted vault with timed unlock sessions, policy-controlled injection, and audit logging.

## Install

Install the latest stable Rust toolchain (`rustup default stable`), then:

```bash
cargo install --path crates/kyz-cli
```

Or build everything:

```bash
cargo build --release
```

## Quick Start

```bash
# Create config directories and default files
kyz init

# Create a new encrypted vault
kyz vault create

# Store a secret
kyz set my-api-key "sk-abc123" --service github

# Store a multi-field secret
kyz set db-creds --service postgres -f host=localhost -f user=admin -f password=secret

# Retrieve a secret
kyz get my-api-key --service github

# Retrieve a single field
kyz get db-creds --service postgres -f password

# List secrets in a namespace
kyz list --service github

# Tag secrets for group injection
kyz set deploy-key --service github -f token=ghp_xxx --tag deploy --tag ci
```

## Secret Injection

### kyz exec

Wrap a command with secrets injected as environment variables:

```bash
# Using a config alias
kyz exec --alias deploy -- make deploy

# Explicit secret references
kyz exec --secret github/deploy-key --secret aws/prod -- ./deploy.sh

# Explicit env-var mapping
kyz exec --env GITHUB_TOKEN=github/deploy-key:token -- gh pr create

# Tag-based: inject all secrets tagged "dev"
kyz exec --tag dev -- cargo test

# Interactive fzf picker (multi-select with TAB)
kyz exec --pick -- ./my-app
```

### kyz pipe

Pipe a single secret into a command's stdin (never touches env or args):

```bash
kyz pipe github/deploy-key:token -- docker login --password-stdin
```

### kyz wrap

Wrap an agent or long-running process with pre-approved secret access and policy enforcement:

```bash
kyz wrap --allow github/deploy-key,aws/prod -- ./agent.sh
kyz wrap --allow '*' -- ./trusted-script.sh
```

### Aliases

Define reusable secret sets in `config.toml`:

```toml
[aliases.deploy]
secrets = ["github/deploy-key", "aws/prod-creds"]
tags = ["deploy"]
env_map = { GITHUB_TOKEN = "github/deploy-key:token" }

[aliases.dev]
tags = ["dev"]
```

## Vault

Secrets are stored in an age-encrypted vault file. The vault uses timed unlock sessions so the passphrase is entered once, then cached for a configurable duration.

```bash
kyz vault create          # Create a new vault
kyz vault unlock          # Unlock (default: 30 minutes)
kyz vault unlock --timeout 3600  # Unlock for 1 hour
kyz vault lock            # Lock immediately
kyz vault status          # Show lock state and session info
```

## Policy Engine

kyz enforces command policies when injecting secrets. Policies block obvious exfiltration vectors — commands like `cat`, `echo`, `env`, and `printenv` that trivially leak values.

**This is a best-effort guardrail, not a security boundary.** Any sufficiently creative command can exfiltrate environment variables (writing to a file, sending over the network, spawning a subshell, etc.). The policy engine raises the bar and catches accidental leaks, but it cannot cover every possible path. Treat it as defense-in-depth alongside access controls, audit logging, and limiting which secrets are injected in the first place.

Policy files are discovered from:
1. `.kyz-policy.json` in the current directory
2. `.kyz-policy.json` in the workspace root
3. `$XDG_CONFIG_HOME/kyz/policy.json`

```json
{
  "deny_commands": ["cat", "echo", "env", "printenv"],
  "allow_commands": [],
  "deny_args": ["-c", "eval"],
  "secrets": {
    "prod/db-password": {
      "allow_commands": ["psql", "pg_dump"]
    }
  }
}
```

Bypass with `--no-policy` (use with caution).

## Audit Logging

All secret access through `exec`, `pipe`, and `wrap` is logged to syslog with operation type, secret names, and target commands.

## Import / Export

```bash
# Export secrets as JSON
kyz export --service github > secrets.json

# Import from file or stdin
kyz import secrets.json
cat secrets.json | kyz import -
```

## Workspace Structure

```
crates/
  kyz-core/    # Shared library: config, paths, vault, store, policy, audit
  kyz-cli/     # Command-line interface
  kyz-tui/     # Terminal user interface (ratatui)
  kyz-mcp/     # Model Context Protocol server
  kyz-api/     # HTTP API server (axum)
```

### kyz-core

Shared library providing:
- Age-encrypted vault backend with timed sessions
- OS keyring backend (desktop sessions)
- `SecretStore` trait abstracting both backends
- Multi-field secret entries with tags
- XDG-compliant path resolution
- Configuration loading via `config` crate
- Command policy engine
- Audit logging
- Auth request flow for headless/remote use

### kyz-cli

Command-line interface with subcommands: `set`, `get`, `delete`, `list`, `export`, `import`, `vault`, `exec`, `pipe`, `wrap`, `init`, `config`, `completions`.

Global flags: `-q`, `-v`, `--debug`, `--trace`, `--json`, `--yaml`, `--no-color`, `--dry-run`, `--yes`.

```bash
kyz --help
kyz completions bash > ~/.local/share/bash-completion/completions/kyz
```

### kyz-tui

Stub. The ratatui scaffolding is in place (three-pane layout, vim keybindings, help overlay) but it displays hardcoded placeholder items. No vault or secret browsing yet.

```bash
kyz-tui
```

### kyz-mcp

MCP server stub. Currently exposes only template tools (`get_profile`, `echo`, `get_runtime_config`). Secret management tools are not yet implemented.

```bash
kyz-mcp
```

### kyz-api

HTTP API server (axum) with auth request workflow for headless agents:

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Service info |
| `/health` | GET | Health check |
| `/config` | GET | Current configuration |
| `/auth/request` | POST | Create an auth request |
| `/auth/request` | GET | List auth requests |
| `/auth/request/{id}` | GET | Get auth request status |
| `/auth/approve/{id}` | POST | Approve an auth request |
| `/auth/deny/{id}` | POST | Deny an auth request |
| `/auth/secrets/{id}` | GET | Pick up approved secrets |
| `/auth/wait/{id}` | GET | WebSocket wait for approval |

```bash
kyz-api --port 3000
```

Set `KYZ_API_TOKEN` to require `Authorization: Bearer <token>` on all endpoints except `/health`.

## Configuration

Default config path: `$XDG_CONFIG_HOME/kyz/config.toml` (fallback: `~/.config/kyz/config.toml`).

Override with `--config <path>` or environment variables using the `KYZ__` prefix:

```bash
KYZ__LOGGING__LEVEL=debug kyz list
```

Manage configuration:

```bash
kyz config show     # Print current config
kyz config path     # Print config file path
kyz config paths    # Print all resolved paths
kyz config schema   # Print JSON schema
kyz config reset    # Reset to defaults
```

See `examples/config.toml` for all options.

## Development

```bash
cargo fmt                                    # Format code
cargo clippy --all-targets --all-features    # Lint
cargo test                                   # Run tests
cargo build --release                        # Release build
```

## License

MIT
