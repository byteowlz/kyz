# Issues

## Open

### [trx-8dbe.2] Implement generic TOML-driven provider model in kyz-oauth (P1, task)

### [trx-8dbe.1] Create crates/kyz-oauth with config-first OAuth architecture (P1, task)

### [trx-8dbe] OAuth architecture: add kyz-oauth first, migrate eavs later (P1, epic)

### [trx-mg5q] kyz exec headless mode: detect no-TTY, create auth request, wait for approval, inject secrets (P1, task)

### [trx-34sn] WebSocket wait endpoint: WS /auth/wait/:id for real-time approval notification (P1, task)

### [trx-a29x] Auth approval API: POST /auth/approve/:id with passphrase, scoped decrypt, one-time secret delivery (P1, task)

### [trx-h9mf] Auth request API: POST /auth/request, GET /auth/request/:id, POST /auth/deny/:id (P1, task)

### [trx-7wnq] Remote auth flow for headless agent secret access (P1, epic)

### [trx-nn87] kyz exec: wrap processes with injected secrets as env vars (P1, epic)

### [trx-092h.1] Phase 1: Local secrets CLI (P1, epic)
Basic secret CRUD using OS keyring (gnome-keyring, macOS Keychain, Windows Credential Manager) via keyring crate

### [trx-092h] Cross-platform secrets manager CLI with P2P sync (P1, epic)
Lean FOSS secrets manager. keyring crate for OS-native storage, age encryption for portable vaults, iroh/libp2p for serverless P2P sync between devices.

### [trx-8dbe.5] Design agent-scoped OAuth alias/capability model for surgical token access (P2, feature)

### [trx-8dbe.4] Add builtin provider definitions and example provider TOMLs for kyz-oauth (P2, task)

### [trx-8dbe.3] Add 'kyz oauth' CLI subcommands on top of kyz-oauth (P2, task)

### [trx-3b5m] kyz sync: git push/pull for encrypted vault files (P2, feature)
Add git sync support for vault files, allowing teams to commit .kyz/vault.json to repos and share secrets with anyone who knows the passphrase. Inspired by pi-cryptex's cryptex_git_sync.\n\nSubcommands:\n- kyz sync push [--repo <url>] [--branch <branch>]\n- kyz sync pull --repo <url> [--branch <branch>]\n\nPush from current repo (omit --repo) or to a dedicated secrets repo.\n\nPrerequisite: passphrase strength enforcement (see linked issue).\n\nThe age encryption (scrypt KDF + ChaCha20-Poly1305) makes this safe for public repos if passphrase entropy is sufficient.

### [trx-gber] Auth request expiry and cleanup: auto-expire pending requests, garbage collect stale state (P2, task)

### [trx-kq62] macOS Touch ID integration: store vault passphrase in biometric-gated Keychain via security-framework (P2, task)

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

### [trx-8dbe.7] Evaluate and plan phased eavs migration to kyz-oauth (P3, task)

### [trx-8dbe.6] Expose agent-safe OAuth access via kyz-mcp / kyz-api (P3, task)

### [trx-ymjw] Audit log: record auth requests, approvals, denials with scope, requester, approver, timestamps (P3, task)

### [trx-092h.3.6] CLI: kyz sync pair, kyz sync status, kyz sync now (P3, task)

### [trx-092h.3.5] Conflict resolution: last-writer-wins with vector clocks or CRDT (P3, task)

### [trx-092h.3.4] Encrypted sync protocol: diff + merge vault changes (P3, task)

### [trx-092h.3.3] Device pairing: QR code / OOB verification flow (P3, task)

### [trx-092h.3.2] Device identity: generate ed25519 keypair per device (P3, task)

### [trx-092h.3.1] Research iroh vs libp2p for Rust P2P networking (P3, task)

## Closed

- [trx-ee9z] Enforce passphrase strength on vault init/unlock (closed 2026-03-24)
- [trx-dg9r] Scoped vault decryption: decrypt vault, filter entries by policy (secrets/tags/services), zero unmatched entries (closed 2026-03-16)
- [trx-p0q1] kyz exec inline auth: detect TTY, prompt passphrase/Touch ID directly, no persistent session needed (closed 2026-03-16)
- [trx-ne0b] Add fzf-based interactive secret picker with multi-select for kyz exec (closed 2026-03-16)
- [trx-905m] Implement kyz exec subcommand with alias, explicit, and tag-based resolution (closed 2026-03-16)
- [trx-a7tf] Add aliases config section with key/tag references and env mappings (closed 2026-03-16)
- [trx-gknz] Add optional tags field to SecretEntry (closed 2026-03-16)
- [trx-wrwg] Add constant-time token comparison for proxy/session validation (closed 2026-03-09)
- [trx-xkqj] Derive session key via HKDF instead of storing raw passphrase in session file (closed 2026-03-09)
- [trx-mjf1] Use secrecy::SecretString for passphrase and secret field storage (closed 2026-03-09)
- [trx-hkjy] Custom Debug impl for SecretEntry that redacts field values (closed 2026-03-09)
- [trx-2svx] Encrypt session file at rest - never store vault passphrase in plaintext (closed 2026-02-17)
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
