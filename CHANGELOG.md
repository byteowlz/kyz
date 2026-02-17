# Changelog

All notable changes to this project will be documented in this file.

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

## Unreleased

