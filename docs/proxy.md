# HTTP credential proxy

Route requests to an upstream API through the kyz credential daemon. The
daemon listens on loopback, resolves credentials from the unlocked vault,
injects them as upstream headers, and forwards over HTTPS. Clients never see
the API key: it exists only in the encrypted vault and daemon memory.

## How it works

- The proxy listens only when `[daemon] listen` is set; the address must be
  loopback.
- Requests are routed by their `Host` header (plus optional `path_prefix`
  and `methods` allowlist) to a rule. Exact host beats wildcard
  (`*.example.com`); longer path prefix wins.
- The forwarded URL is the rule's fixed `upstream` (must be `https://`,
  no userinfo) joined with the client path and query.
- Client `Authorization`, `Cookie`, `Proxy-Authorization`, and every header
  named in the rule's injected `headers` are always stripped before injection,
  even with `strip = []`. `strip` adds further names (default: `X-Api-Key`).
  Header values are templates of literal text plus `{{alias.field}}`
  substitutions — no functions, no encoding.
- `CONNECT` and `TRACE` are always rejected.
- Every request is audited to `state_dir/daemon/audit.log` (rule name,
  host, outcome; never secret values).

## Store the credential

If the API takes the key as a header value, store it directly:

```bash
kyz vault unlock
kyz set api-key --service example     # omit the value to be prompted (hidden)
```

If the API uses HTTP Basic auth (e.g. Tinify), the header carries
`base64("user:<key>")` — a derived value. Templates substitute literally,
so store the derived value:

```bash
printf 'api:YOUR_API_KEY' | base64    # PowerShell: [Convert]::ToBase64String(
                                      #   [Text.Encoding]::UTF8.GetBytes("api:YOUR_API_KEY"))
kyz set api-key --service tinify
```

## Configure the proxy

`config.toml`:

```toml
[daemon]
listen = "127.0.0.1:8477"   # unset = no proxy listener

[proxy]
auth = "token"              # "none" skips client authentication (single-user local use)

# Key-as-header API
[[proxy.rules]]
name = "example"
host = "api.example.com"
upstream = "https://api.example.com"

[[proxy.rules.credentials]]
alias = "example"
service = "example"
key = "api-key"
fields = ["value"]

[proxy.rules.headers]
X-Api-Key = "{{example.value}}"

# Basic-auth API (Tinify)
[[proxy.rules]]
name = "tinify"
host = "api.tinify.com"
upstream = "https://api.tinify.com"

[[proxy.rules.credentials]]
alias = "tinify"
service = "tinify"
key = "api-key"
fields = ["value"]

[proxy.rules.headers]
Authorization = "Basic {{tinify.value}}"
```

`credentials` is an explicit allowlist: templates may reference only the
listed `alias.field` pairs. Image or file uploads may need
`[daemon] request_body_limit_bytes` raised above the 10 MiB default.

## Start the daemon

```bash
kyz daemon start     # prompts for the vault passphrase, then detaches
kyz daemon status    # confirm proxy_listen
```

With `auth = "token"` the per-daemon bearer token is written to
`state_dir/daemon/proxy.token` (regenerated on every start). Configuration
changes require `kyz daemon reload` — the daemon never watches the file.
Secret updates do not: the vault file is re-read per request, so a
`kyz set` from another shell takes effect immediately.

## Send requests

Point the request at the daemon's listen address and set `Host` to the
rule's host:

```bash
TOKEN=$(cat "${XDG_STATE_HOME:-$HOME/.local/state}/kyz/daemon/proxy.token")

curl http://127.0.0.1:8477/shrink \
  -H "Host: api.tinify.com" \
  -H "x-kyz-proxy-token: $TOKEN" \
  --data-binary @image.png
```

Drop the `-H "x-kyz-proxy-token: ..."` line when `auth = "none"`.

PowerShell (state dir `%LOCALAPPDATA%\kyz\daemon`):

```powershell
$TOKEN = Get-Content "$env:LOCALAPPDATA\kyz\daemon\proxy.token" -Raw
curl.exe http://127.0.0.1:8477/shrink -H "Host: api.tinify.com" `
  -H "x-kyz-proxy-token: $TOKEN" --data-binary "@image.png"
```

Tools that accept a custom base URL work the same way: base
`http://127.0.0.1:8477`, `Host` header set to the upstream host.

## Troubleshooting

| Symptom                     | Cause                                                      |
|-----------------------------|------------------------------------------------------------|
| Connection refused          | Daemon not running or `daemon.listen` unset — `kyz daemon status` |
| 401 from the upstream       | Stored value is not what the header must carry (e.g. the bare key instead of the base64 Basic value) |
| `field 'value' not found`   | No secret at the rule's `service`/`key`                    |
| Request body rejected       | Raise `[daemon] request_body_limit_bytes`                  |
| Start/reload rejects config | Rule validation failed; the error names the rule           |
