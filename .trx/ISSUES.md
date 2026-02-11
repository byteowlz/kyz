# Issues

## Open

### [trx-092h.1] Phase 1: Local secrets CLI (P1, epic)
Basic secret CRUD using OS keyring (gnome-keyring, macOS Keychain, Windows Credential Manager) via keyring crate

### [trx-092h] Cross-platform secrets manager CLI with P2P sync (P1, epic)
Lean FOSS secrets manager. keyring crate for OS-native storage, age encryption for portable vaults, iroh/libp2p for serverless P2P sync between devices.

### [trx-092h.1.15] kyz grant/revoke for provisioning workspace vaults (P2, task)

### [trx-092h.2.5] Backend selection: --backend keyring|vault in config (P2, task)

### [trx-092h.2.4] CLI: kyz vault create/unlock/lock, vault import/export (P2, task)

### [trx-092h.2.3] Implement vault backend (same store trait as keyring) (P2, task)

### [trx-092h.2.2] Implement vault file format (age-encrypted JSON with metadata) (P2, task)

### [trx-092h.2.1] Add age crate for file-level encryption (P2, task)

### [trx-092h.1.10] Update README, examples, justfile (P2, task)

### [trx-092h.1.8] MCP server: expose get/set/list tools for agent access (P2, task)

### [trx-092h.3] Phase 3: Serverless P2P sync (P2, epic)
Device pairing and encrypted sync via iroh (QUIC-based P2P). No server, no cloud. Automatic conflict resolution with CRDT or LWW.

### [trx-092h.2] Phase 2: Portable age-encrypted vault (P2, epic)
age-encrypted JSON vault file as alternative backend. Enables git-syncable, portable secrets.

### [trx-092h.3.6] CLI: kyz sync pair, kyz sync status, kyz sync now (P3, task)

### [trx-092h.3.5] Conflict resolution: last-writer-wins with vector clocks or CRDT (P3, task)

### [trx-092h.3.4] Encrypted sync protocol: diff + merge vault changes (P3, task)

### [trx-092h.3.3] Device pairing: QR code / OOB verification flow (P3, task)

### [trx-092h.3.2] Device identity: generate ed25519 keypair per device (P3, task)

### [trx-092h.3.1] Research iroh vs libp2p for Rust P2P networking (P3, task)

## Closed

- [trx-092h.1.14] Workspace vault support (per-directory .kyz/vault.json) (closed 2026-02-11)
- [trx-092h.1.13] Vault unlock/lock/status commands with session file (closed 2026-02-11)
- [trx-092h.1.12] File-based vault backend (age-encrypted JSON) (closed 2026-02-11)
- [trx-092h.1.11] Multi-field SecretEntry data model (closed 2026-02-11)
- [trx-092h.1.9] Remote build + fix all compiler errors (closed 2026-02-11)
- [trx-092h.1.7] Secure password prompt for interactive set (rpassword) (closed 2026-02-11)
- [trx-092h.1.6] Namespace/service support: kyz get --service lnkdn li_at (closed 2026-02-11)
- [trx-092h.1.5] CLI commands: set, get, delete, list, export, import (closed 2026-02-11)
- [trx-092h.1.4] Implement OS keyring backend via keyring crate (closed 2026-02-11)
- [trx-092h.1.3] Implement secret store abstraction trait (get/set/delete/list) (closed 2026-02-11)
- [trx-092h.1.2] Add keyring crate with platform feature flags (apple-native, windows-native, sync-secret-service) (closed 2026-02-11)
- [trx-092h.1.1] Adapt scaffold: APP_NAME=kyz, update config/schema/paths (closed 2026-02-11)
