# Changelog

All notable changes to this project will be documented in this file.

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

