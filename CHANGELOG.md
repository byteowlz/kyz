# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **Vault format v5 — one file per entry, mergeable key slots** (`crates/kyz-core/src/vault_v5.rs`):
  - `vault.json` becomes a small manifest (vault id, key slots, MAC); entries live in `vault.entries/<id>.json`, one file per entry, each with its own MAC bound to its file name. `get`/`set`/`delete` read one entry file, so latency no longer grows with vault size (1000 entries × 10 versions: `set` 127 ms → 1.2 ms, `get` 85 ms → 0.9 ms; `just bench-vault`).
  - Entry file names are keyed hashes of `service/key`; service and key names are stored encrypted.
  - Key slots: the DK is wrapped once per slot. Replicas are identified by `vault_id` plus proof of the same DK, so replicas with different slots still merge; slot sets merge as a union where removal wins. `kyz vault passwd` changes the passphrase (new slot, old slot removed); `kyz vault slots` lists slots.
  - Sync conflict copies (`<id>.sync-conflict-….json`, `vault.sync-conflict-….json`) are read immediately, folded in on the next write of the entry or on unlock, and removed; unverifiable copies are ignored and kept.
  - `kyz vault merge` accepts a v5 vault or a legacy single-file v4 vault and writes only changed entry files.
  - Workspace-vault trust pins the manifest, so writes no longer require re-confirmation.
- **Operation-log merging (from the v4 design)** (`crates/kyz-core/src/vault_v4.rs`):
  - Every entry write becomes an operation (`put`/`delete`) with a globally unique id (`actor_id + counter`), causal parents (the observed frontier), and an HLC timestamp. The current entry state is a deterministic projection of the operation log: concurrent delete wins over concurrent puts; concurrent puts resolve by `(changed_at, id)` with losers visible in history.
  - `kyz vault merge <PATH>` merges a v4 replica (e.g. a Syncthing conflict copy) into the current vault. Reports new/updated/deleted entries and conflict versions (`--json`/`--yaml`, `--dry-run` supported); repeated merges of the same content write nothing.
  - All vault writes now use crash-safe atomic replacement (same-directory temp file + fsync + rename) and every file carries an HMAC-SHA256 over the canonical body, keyed via domain-separated HKDF from the DK. Merging refuses foreign vaults, tampered files, or blobs that fail AEAD.
  - Actor identity and per-vault op counters live in `$XDG_STATE_HOME/kyz/actor-state.json` under a dedicated process lock; a lost state file never re-issues ids.
  - See `docs/sync.md` for the multi-machine workflow.

### Changed

- New vaults are created as v5. Unlocking migrates v1/v2/v3 and single-file v4 vaults to v5 in the exclusive-lock transaction, preserving the DK and passphrase (the existing kdf/wrapped DK become the first key slot); migration ids derive deterministically from pre-migration data, so forked v3 copies migrating on different machines deduplicate their shared history on merge.
- `kyz history` lists operations with stable op ids (`actor:counter`) and roles (current / conflict / ancestor / tombstone); `kyz rollback --to` accepts a sequence number (counted from the oldest operation, matching v3 version numbers so a literal `--to N` keeps its meaning across migration) or an op id and always creates a new write. Version dispatch for history/rollback moved into the store (`VaultStore::history` returning `HistoryView`, `VaultStore::rollback`), one locked read/write transaction per command; the v3-specific `read_vault_file_pub`/`write_vault_file_pub`/`detect_format` APIs were removed from `kyz-core`.
- `kyz set` and `kyz delete` on a legacy v3 vault now upgrade it to v5 inside the same write transaction (a failed delete of a missing entry still writes nothing); rolling back a v3 vault keeps the v3 format until the next unlock/set/delete migrates it.
- `kyz set` on a deleted entry now fails unless `--yes` is passed (explicit rebuild from exactly the provided fields; previous values are not recoverable). `kyz import` honors the same flag to recreate tombstoned entries from a backup.
- `kyz vault merge` refuses, without `--yes`, merges that would introduce entries existing only in the source's pre-v4 history and absent from the target: v3-era deletions leave no tombstone, so those entries may be secrets deleted before migration. Dry-run reports them as `legacy_resurrections`.
- `history_retention` no longer trims stored history for v4 vaults; it only limits display (old replicas may re-deliver pruned versions, so the operation log is kept).

### Fixed

- Hostile op logs could force quadratic CPU before MAC verification: a duplicate op id disabled the linear frontier path (per-op ancestor walks), and canonicalization walked ancestors once per delete. Both are now O(ops + parents); cycles and dangling parents are detected by the same linear pass.
- `kyz history` labeled an edit as `current` while a concurrent delete hid the entry (`get` reported it missing). History now follows the projection: a deleted entry has no current version, and edits hidden by the delete are shown as conflicts (rollback-able). The human view notes that the entry is deleted.
- `kyz vault merge` gave no hint when an incoming edit lost to a delete already present in the target. The report now lists such entries under `lost_to_delete` (entry, tombstones, hidden edits).
- v3→v4 migration minted identical op ids for two snapshots with identical content inside the same unix second (`set A; set B; set A`); canonicalization's dedup then dropped the current version's op and `kyz get` silently returned the superseded value. Op id derivation now includes the snapshot's chain position.
- v4 compound keys split at the first `/`, misattributing entries whose service name itself contains `/` (possible in library-created v3 vaults) in `list`/`list_services` while `get` still resolved them. Both parts are now percent-escaped so the split is unambiguous.
- Unlocking a v4 vault whose `passphrase_policy_checked` flag was already set skipped the file MAC check; a corrupt vault unlocked "successfully" and only failed on the first get/list. Unlock now MAC-verifies the file (parse + AEAD unwrapping + MAC before any session is persisted).
- Unlocking a v3 vault derived the DK outside the lock and migrated a re-read file without checking the two reads agreed on kdf/wrapped_dk; a replacement during the scrypt window could sign foreign key material. A mismatch now fails with "vault changed while unlocking".
- Merging verified the source inside the target's exclusive lock, blocking concurrent reads for the whole O(source size) MAC+AEAD pass; verification now happens before the lock, matching the documented transaction shape.
- Duplicate op ids in one log could underflow the acyclicity fast path's edge accounting (debug-build panic); such sets now take the duplicate-tolerant slow path.
- Windows: scrubbing of sensitive `KYZ_*` environment variables (`kyz exec`/`pipe`/`wrap`) was case-sensitive, so a lowercase-spelled `kyz_vault_password` leaked into child processes; matching now follows the platform's case rules. The daemon state-dir ACL check substring-matched `users:` against `icacls` output, permanently failing on accounts whose name ends in `users`; it now parses trustee names and verifies the DACL grants the current user only.

### Security

- v4 vaults authenticate all merge-relevant plaintext metadata (service/key position, tags, field names, HLCs, parents, kind) via the file MAC; field values remain XChaCha20-Poly1305 under the DK with the operation header bound as AAD.

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
