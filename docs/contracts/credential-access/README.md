# Credential access contract v1 (draft)

How a tool or agent (the **consumer**) gets a secret, a token, or the effect of a credential from a **broker**, without knowing which vault is behind it. kyz is one broker implementation; 1Password, Bitwarden or a browser-session owner can serve the same contract.

Status: **draft**, kept in the kyz repo until the shared contracts location is agreed (agent-messageboard `byteowlz-ecosystem-unification`). Tracker: kyz `trx-6gn4.1`, epic `trx-6gn4`.

Files:

- `credential-access.schema.json` — JSON Schema (draft 2020-12) for every message.
- `fixtures/valid/` — messages that must validate.
- `fixtures/invalid/` — messages that must not validate; each states `why`.
- Checked by `crates/kyz-core/tests/credential_contract_fixtures.rs`.

## Transport and caller identity

- One JSON object per line, request then response, over a **local authenticated transport**: a Unix socket (mode `0600` or peer-credential checked) or a Windows named pipe with an owner-only ACL. The broker's address is advertised by the discovery record from the ecosystem contracts; that record is a hint, never authority.
- **The caller is identified by the transport** (peer credentials, per-caller token established out of band), and grants are looked up for that identity. A message cannot name its caller: the schema rejects `caller`, `agent_ctx` and any other unknown field. `AGENT_CTX` may be logged as context, never used to authorize.
- `purpose` is untrusted text shown in approval prompts.
- Socket permissions and OS peer credentials alone do not distinguish agents running as the same OS user. Per-run authorization requires a runner-established channel/capability bound to the run; a caller-supplied session id is not sufficient. Do not expose parent credentials through readable config files while relying on an environment override to hide them.

## Operations

| op | Consumer gets | Use when |
|---|---|---|
| `resolve` | the secret value | The consumer must hold the value (legacy tools, config). Weakest option. |
| `token` | a bearer token for one audience, with `expires_at` and `can_refresh` | The consumer must call an API itself. |
| `use` | the effect only: login fields filled, a WebAuthn assertion, or an HTTP response | Preferred. The credential never reaches the consumer. |

`use` kinds:

- `fill` — the browser integration fills `fields` for `origin` inside the page. Values never return to the consumer. Limit: once filled, values sit in the page DOM, readable by anything with script access to that page.
- `webauthn_get` — the broker signs a WebAuthn assertion for `rp_id` after **one live human approval for this ceremony**. The authenticator sets UP/UV only when that gesture happened. There are no standing passkey grants.
- `http` — the broker performs one HTTPS request with the credential injected and returns the response. Consumers may not set `Authorization`, `Cookie` or `Proxy-Authorization`; the broker strips `Set-Cookie` and `Authorization` from responses. Cookie-based sessions (browser-session providers) are served only this way: the cookie jar never leaves the session owner.

## Responses

`status` is one of:

| status | reasons |
|---|---|
| `ok` | — (`result` present, `error` absent) |
| `needs_interaction` | `login_required`, `unlock_required`, `approval_required` |
| `denied` | `not_granted`, `approval_rejected`, `approval_timeout`, `policy` |
| `unavailable` | `not_found`, `audience_unavailable`, `scope_unavailable`, `cannot_refresh`, `backend_offline`, `unsupported`, `invalid_request` |

Non-`ok` responses never carry a `result`. `needs_interaction` may say where the human must act (`interaction.host`, `interaction.hint`). `receipt_id` refers to the value-free decision receipt recorded for the request.

## Secret references

`<scheme>:<body>`, parsed only by the shared resolver, never by consumers:

| scheme | body | example |
|---|---|---|
| `env` | environment variable name | `env:HSTRY_INGEST_TOKEN` |
| `kyz` | `service/key[:field]` (same as the kyz CLI) | `kyz:github/deploy-token:value` |
| `op` | 1Password `op://` path without the scheme | `op://Private/GitHub/token` |
| `bw` | Bitwarden item id or name, optional `:field` | `bw:github-deploy:password` |

Plain literal values are a config-file convenience, not a reference; brokers never accept them.

## Rules (all implementations)

1. **Never refresh a credential you do not own.** A broker serving a token owned by another tool (Codex/Claude CLI auth files, a browser-session owner) reads it read-only and never redeems its refresh token. Rotating refresh tokens would log the owner out. (kyz `trx-8dbe.8`)
2. **One session owner per identity.** Refreshes of a browser session are serialized in the process that owns that browser; consumers never drive it.
3. **Tokens are served per audience.** A request for an audience the broker does not have gets `unavailable/audience_unavailable`, never a token for a different audience. Missing scopes give `unavailable/scope_unavailable`, not a weaker token.
4. **`expires_at` is always stated and honest.** `can_refresh` is false on hosts that cannot renew without a human (for example a Linux host without a device broker).
5. **Prefer `use` over `token` over `resolve`.** Brokers may refuse `resolve`/`token` by policy where `use` is available.
6. **One interaction alert per account and failure episode**; only a fresh successful fetch resets it. (kyz `trx-8dbe.11`)
7. **Secrets never appear in errors, logs or receipts.**

## Conformance beyond the schema

The schema checks message shape. Implementations must additionally pass these behavioural cases (to be run against kyz and a mock backend once the broker exists):

- wrong audience → `audience_unavailable`, and no token is returned;
- expired token that the broker cannot renew → `needs_interaction/login_required` or `unavailable/cannot_refresh`, never the expired token;
- ungranted caller → `denied/not_granted`, independent of any claim in the message;
- replayed or expired grant → `denied`;
- borrowed token file is unchanged byte-for-byte after any number of requests (rule 1);
- `use/http` to an origin not declared for that credential → `denied/policy`;
- HTTP URLs are parsed and normalized at runtime: reject userinfo and ambiguous hosts, enforce configured destination/network policy after DNS resolution, and disable redirects by default. Any explicitly permitted redirect is reauthorized before credentials are attached; HTTPS syntax alone is not an SSRF defense;
- WebAuthn origin/RP-id binding and the browser-observed ceremony are verified by the trusted integration; a caller-supplied hash does not establish that binding;
- same-user callers cannot impersonate another run; revoked run capabilities and concurrent exhausted-use grants fail closed;
- arbitrary remote response bodies may echo injected credentials. Header filtering does not guarantee secret-free HTTP results; restrict destinations to trusted profile endpoints and document this residual risk;
- response `id` equals request `id`; `result.kind` matches the request `op`/`use.kind`;
- broker unreachable → consumers treat it as `unavailable/backend_offline` and degrade; protected actions fail closed.

## Versioning

`v` is the contract version. The v1 schema is strict (unknown fields are rejected, which is what blocks spoofed caller fields), so any new field, reason or reference scheme is a coordinated schema change: update the schema and fixtures first, then consumers, then brokers. Incompatible changes get `v: 2`.
