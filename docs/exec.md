# kyz exec

Wrap any command with secrets injected as environment variables. Secrets never
touch disk — they exist only in the child process environment.

## Quick start

```bash
# Unlock vault first
kyz vault unlock

# Run a command with a specific secret
kyz exec --secret github/deploy-key -- make deploy

# Interactive picker (requires fzf)
kyz exec --pick -- ./my-app
```

## Resolution modes

### Explicit secret (`--secret`)

Injects all fields of a secret as uppercase env vars:

```bash
kyz exec --secret github/deploy-key -- env
# → TOKEN=ghp_xxx  USERNAME=bot
```

### Explicit mapping (`--env`)

Map a specific field to a named env var:

```bash
kyz exec --env GITHUB_TOKEN=github/deploy-key:token -- gh pr create
```

Format: `ENV_VAR=service/key:field`

### Tag-based (`--tag`)

Inject all secrets with a matching tag across all services:

```bash
kyz exec --tag deploy -- ./deploy.sh
```

### Config alias (`--alias`)

Reference a named alias from `config.toml`:

```bash
kyz exec --alias deploy -- make deploy
```

### Interactive picker (`--pick`)

Opens fzf with all secrets listed. Use TAB for multi-select, ENTER to confirm.
Requires [fzf](https://github.com/junegunn/fzf) on PATH.

```bash
kyz exec --pick -- ./my-app
```

## Combining modes

All modes can be combined. Resolution order (later wins on conflict):

1. Alias secrets
2. Alias tags
3. Alias `env_map`
4. `--secret` flags
5. `--tag` flags
6. `--pick` selection
7. `--env` flags (highest priority)

## Dry run

Preview injected vars without executing:

```bash
kyz exec --alias deploy --dry-run -- make deploy
# GITHUB_TOKEN=***
# AWS_ACCESS_KEY_ID=***
```

## Config aliases

Define reusable secret sets in `config.toml`:

```toml
[aliases.deploy]
# Explicit secret references
secrets = ["github/deploy-key", "aws/prod-creds"]
# Include all secrets tagged "deploy"
tags = ["deploy"]
# Override specific env var names
env_map = { GITHUB_TOKEN = "github/deploy-key:token" }

[aliases.dev]
tags = ["dev"]

[aliases.ci]
secrets = ["github/ci-bot"]
tags = ["ci"]
env_map = { GH_TOKEN = "github/ci-bot:token", NPM_TOKEN = "npm/publish:token" }
```

### Alias fields

| Field     | Type                    | Description                                      |
|-----------|-------------------------|--------------------------------------------------|
| `secrets` | `["service/key", ...]`  | Explicit secret references to include             |
| `tags`    | `["tag", ...]`          | Include secrets matching any of these tags        |
| `env_map` | `{ VAR = "svc/key:f" }` | Map specific fields to named env vars             |

## Secret tags

Tags are optional labels on secrets for grouping:

```bash
# Set tags on creation
kyz set deploy-key --service github -f token=ghp_xxx --tag deploy --tag ci

# Tags are merged on update
kyz set deploy-key --service github -f user=bot --tag prod
# → tags: {ci, deploy, prod}
```

Tags appear in `kyz list` output and are used by `--tag` and alias `tags` resolution.

## Platform behavior

| Platform | Behavior                                               |
|----------|--------------------------------------------------------|
| Linux    | `exec()` replaces the kyz process with the child       |
| macOS    | `exec()` replaces the kyz process with the child       |
| Windows  | Spawns child process, exits with its status code       |
