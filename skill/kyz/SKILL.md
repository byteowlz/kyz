---
name: kyz
description: Use kyz secrets manager for secure credential storage and retrieval in agent workflows. Use when the agent needs to access secrets, store new credentials, manage workspace-scoped vaults, or work with kyz CLI during development tasks. Triggers include "get my github token", "store this API key", "use secrets from kyz", or any task requiring secure credential handling.
---

# kyz Secrets Manager

Guide for using kyz (cross-platform secrets manager) in agent workflows.

## Quick Reference

```bash
# Check vault status
kyz vault status

# Get a secret (works if vault is unlocked)
kyz get <key> --service <service> --field <field>

# Set a secret (vault must be unlocked)
kyz set <key> --service <service> -f <field>=<value>

# Unlock vault for session
kyz vault unlock

# Lock vault when done
kyz vault lock
```

## Vault Discovery Order

Kyz looks for vaults in this order:
1. Explicit `--vault <path>` flag
2. Workspace vault: `./.kyz/vault.json` (if exists)
3. Central vault: `~/.local/share/kyz/vault.json`

**For agents:** Prefer workspace vaults (`./.kyz/vault.json`) to keep credentials scoped to the project.

## Common Tasks

### Check if Vault Exists and is Unlocked

```bash
kyz vault status --json
```

Returns JSON with `exists`, `unlocked`, `vault_path`. Use this to determine next steps:
- If `exists: false` → Need to create vault or use different path
- If `unlocked: false` → Need to unlock (but can't prompt user in agent context)

### Get Secret for Scripting

```bash
# Get specific field (raw output, perfect for scripts)
TOKEN=$(kyz get deploy-key --service github --field token)
API_KEY=$(kyz get prod --service aws --field api_key)

# Multi-field entry
echo "Username: $(kyz get work --service db --field username)"
echo "Password: $(kyz get work --service db --field password)"
```

### Set Secret from Environment or Input

```bash
# Set from stdin (hidden input)
echo "$SECRET_VALUE" | kyz set <key> --service <service>

# Set multiple fields at once
kyz set <key> --service <service> \
  -f username=<user> \
  -f password=<pass> \
  -f url=<url>
```

### Workspace Vault Creation (Agent Setup)

```bash
# Create workspace vault in current project
mkdir -p .kyz
echo "<passphrase>" | kyz --vault ./.kyz/vault.json vault create

# Unlock it
echo "<passphrase>" | kyz --vault ./.kyz/vault.json vault unlock

# Add entries
kyz --vault ./.kyz/vault.json set github-token -f token=ghp_xxx

# Add to .gitignore
echo ".kyz/" >> .gitignore
```

## Data Model

Each secret entry has:
- `key`: The entry name (e.g., "work-account", "deploy-key")
- `service`: Namespace (e.g., "github", "aws", "npm")
- `fields`: Map of named fields (e.g., `{"username": "x", "token": "y"}`)
- `created_at`, `updated_at`: Unix timestamps

## Agent Context Patterns

### Pattern 1: Check Before Use

```bash
if kyz vault status | grep -q "unlocked: true"; then
  TOKEN=$(kyz get deploy --service github --field token)
else
  echo "Warning: kyz vault locked, cannot retrieve credentials"
  # Fallback or skip
fi
```

### Pattern 2: Explicit Workspace Vault

When working in `/home/user/projects/foo/`:

```bash
VAULT=/home/user/projects/foo/.kyz/vault.json

# Check if workspace vault exists
if [ -f "$VAULT" ]; then
  # Use workspace vault
  kyz --vault "$VAULT" get <key> --service <svc>
else
  # Fall back to central vault
  kyz get <key> --service <svc>
fi
```

### Pattern 3: Import from Environment

When the human provides credentials via env vars, store them for reuse:

```bash
# Store if not already present
if [ -n "$GITHUB_TOKEN" ]; then
  echo "$GITHUB_TOKEN" | kyz set token --service github
  echo "Stored GITHUB_TOKEN in kyz vault"
fi
```

## Important Notes

- **Session timeout**: Unlocked vaults auto-lock after 30 minutes (configurable with `--timeout`)
- **Session file location**: 
  - Preferred: `/run/user/<UID>/kyz/session-<hash>` (tmpfs, cleared on reboot)
  - Fallback: `/tmp/kyz-<username>/session-<hash>` (0700 perms, user-scoped)
- **Permissions**: Vault file 0600, session directory 0700, session file 0600
- **Non-interactive**: Agents must pipe passphrase via stdin; no confirmation prompt when piped
- **Sensitive fields**: Fields named `password`, `token`, `secret`, `key`, `api_key` are masked in plain output

## JSON/YAML Output

For structured data processing:

```bash
kyz get <key> --service <svc> --json
kyz list --service <svc> --json
kyz vault status --json
kyz export --service <svc> --json
```

## Error Handling

Common errors and solutions:

| Error | Cause | Solution |
|-------|-------|----------|
| `vault is locked` | No active session | Run `kyz vault unlock` (but needs passphrase) |
| `vault not found` | No vault at resolved path | Create with `kyz vault create` |
| `secret not found` | Entry doesn't exist | Check key/service names |
| `decryption failed` | Wrong passphrase | Verify passphrase and retry unlock |

## Security Best Practices

1. **Never commit vault files**: Add `.kyz/` to `.gitignore`
2. **Minimize session duration**: Lock vault when done: `kyz vault lock`
3. **Use workspace vaults**: Keeps credentials scoped per-project
4. **Sensitive fields**: Store tokens/passwords in fields named appropriately (auto-masked in output)
5. **Session files**: Rely on tmpfs auto-cleanup; session dies with user session
