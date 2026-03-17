# Changelog

All notable changes to this project will be documented in this file.

## [0.5.1] - 2026-03-17

### Fixed

- **`kyz exec` argument parsing**: Added `-c` / `--shell-command` flag to properly handle shell command strings with variable expansion. Previously, `kyz exec "echo $VAR"` would try to exec a program with the entire string as the name. Now use `kyz exec -c 'echo $VAR'` or separate kyz flags from command args with `--`.
- **`-p` flag positioning**: With `trailing_var_arg`, once a positional argument is encountered, all following args become command args (even `-p`). Now `-p` and other flags must come before the command, or use `-c` for shell evaluation.

### Changed

- `ExecCommand.command` is no longer required; use `-c` or `--` with args.

## [0.4.0] - 2026-03-16

### Added

- **`kyz exec`**: Wrap any command with secrets injected as environment variables.
  - `--alias <name>`: Resolve secrets from a named alias in `config.toml`.
  - `--secret <service/key>`: Inject all fields of a specific secret.
  - `--env VAR=service/key:field`: Map a specific field to an env var.
  - `--tag <tag>`: Inject all secrets matching a tag.
  - `--pick`: Interactive fzf multi-select picker for secrets.
  - `--dry-run`: Preview which env vars would be injected.
  - On Unix, uses `exec()` to replace the process (no parent lingering).
- **Secret tags**: `SecretEntry` now supports optional tags for categorization.
  - `kyz set <key> --tag <tag>` (repeatable) assigns tags on creation.
  - Tags are merged on update and included in list/summary output.
- **Config aliases** (`[aliases.<name>]` in `config.toml`):
  - `secrets`: List of explicit `service/key` references.
  - `tags`: Match secrets by tag (any match is included).
  - `env_map`: Explicit `{ ENV_VAR = "service/key:field" }` overrides.

### Security

- `SecretEntry` fields now use `secrecy::SecretString` — values are zeroed on drop and cannot be accidentally logged.
- `VaultSession` no longer stores the raw vault passphrase. Session files contain an HKDF-SHA256 derived key + random salt instead.
- Custom `Debug` implementations for `SecretEntry` (redacts field values) and `VaultSession` (redacts session key and salt).
- `kyz-api` bearer token validation uses constant-time comparison (`subtle::ConstantTimeEq`) to prevent timing side-channel attacks. Set `KYZ_API_TOKEN` to enable.

### Changed

- `encrypt_vault()` / `decrypt_vault()` now accept `&SecretString` instead of `&str`.
- `VaultSession` struct fields changed: `passphrase` → `session_key` + `salt`.
- `SecretSummary` now includes `tags` field.
- Config env prefix corrected to `KYZ__` in documentation.
- Default config path documented as `$XDG_CONFIG_HOME/kyz/config.toml`.

### Dependencies

- Added: `hkdf`, `sha2`, `rand`, `subtle`, `hex`, `zeroize`.
- `secrecy` now uses the `serde` feature.

## [0.3.0] - 2026-02-17

### Security

- Session passphrases are now stored in the OS keyring (macOS Keychain, Linux kernel keyutils, Windows Credential Manager) instead of on disk. The session file contains only non-sensitive metadata (expiry timestamp, vault path).
- Linux keyutils backend works headless (no D-Bus/desktop session required) -- credentials live in kernel memory, cleared on reboot.
- Falls back to age-encrypted session file if OS keyring is unavailable.

### Changed

- Switched Linux keyring backend from `sync-secret-service` (D-Bus) to `linux-native` (kernel keyutils) for headless compatibility.
- Session file format is now metadata-only JSON when keyring is available.
- Removed `--force` alias from `--yes` flag (conflicted with vault create `--force`).

## [0.2.0] - 2026-02-17

### Security

- Session files are now encrypted at rest using age encryption with a machine-bound key. The vault passphrase is never stored in plaintext on disk.

### Changed

- `VaultSession::save()` encrypts session data before writing to disk.
- `VaultSession::load()` decrypts session data on read; silently removes invalid/legacy sessions.
- `KeyringStore` index changed from `BTreeMap<String, ()>` to `BTreeSet<String>`.
- `VaultData::new()` and `VaultStore::new()` are now `const fn`.

### Added

- `hostname` crate dependency for machine-bound session key derivation.
