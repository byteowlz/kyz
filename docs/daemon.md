# kyz daemon

The credential daemon (`kyzd`) holds an unlocked vault in memory so that the
HTTP credential proxy (PR-02) and pinned script grants (PR-03) can resolve
fields without re-prompting. The data key (DK) never leaves process memory;
no vault session file or keyring entry is ever created.

## Commands

```bash
kyz daemon start [--timeout SECONDS] [--foreground] [--vault PATH] [--askpass COMMAND]
kyz daemon status [--json]
kyz daemon reload
kyz daemon stop
```

- `start` prompts for the vault passphrase once (TTY prompt, `--askpass`
  helper, or `KYZ_VAULT_PASSWORD` in the launching process only), then
  detaches. The passphrase travels to the daemon child over a one-shot
  bootstrap pipe; the child environment never contains the passphrase.
- `--timeout N` (0 = unlimited) starts a lifecycle countdown; on expiry the
  daemon drains in-flight work, zeroizes the DK, and exits normally.
- `--foreground` runs the daemon in the calling process (for services).
- `reload` fully validates the candidate configuration and swaps it in
  atomically; on failure the active configuration is untouched and the
  validation errors are reported.
- `stop` performs a graceful shutdown over the management IPC channel
  (Unix domain socket at `state_dir/daemon/kyzd.sock`, Windows named pipe
  `\\.\pipe\kyzd-<user>-<hash>`). Single-instance enforcement uses an OS
  file lock on `state_dir/daemon/daemon.lock`; the PID file is diagnostics
  only. After a `kill -9`, the next `start` recovers stale files.

## State directory

`$XDG_STATE_HOME/kyz/daemon/` (0700 on Unix, current-user-only ACL on
Windows) holds `daemon.lock`, `daemon.pid`, `kyzd.sock` (Unix),
`ipc.token`, `proxy.token` (PR-02), `audit.log` (JSON Lines, field
whitelist enforced by the typed event API), and `daemon.log` (run log,
size-rotated; write failures drop the line rather than falling back to
stderr). Secret values, passphrases, and tokens never appear in either log.

## Running as a service

Recommended modes per platform are listed below. In all cases use
`kyz daemon start --foreground` as the service command and provide the
passphrase via the askpass helper or a protected environment source; the
daemon itself must never read the passphrase from a persisted file.

### systemd (Linux)

`/etc/systemd/system/kyzd.service`:

```ini
[Unit]
Description=kyz credential daemon
After=network-online.target

[Service]
Type=simple
User=%i
ExecStart=/usr/local/bin/kyz daemon start --foreground
Restart=on-failure
RestartSec=5
# Passphrase source: point askpass at a root-owned helper, e.g.
# ExecStart=/usr/local/bin/kyz daemon start --foreground --askpass /usr/local/lib/kyz-askpass
TimeoutStopSec=30

[Install]
WantedBy=default.target
```

Enable with `systemctl enable --now kyzd@<user>.service`. `Type=simple`
with `--foreground` gives systemd full lifecycle control (SIGTERM triggers
the same graceful shutdown as `kyz daemon stop`).

### launchd (macOS)

`~/Library/LaunchAgents/com.byteowlz.kyzd.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.byteowlz.kyzd</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/kyz</string>
    <string>daemon</string>
    <string>start</string>
    <string>--foreground</string>
    <string>--askpass</string>
    <string>/usr/local/lib/kyz-askpass</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
```

Load with `launchctl load ~/Library/LaunchAgents/com.byteowlz.kyzd.plist`.

### Windows Task Scheduler

Task Scheduler gives an unattended, auto-restarting service-like entry
without writing a Windows service wrapper:

```powershell
$action    = New-ScheduledTaskAction -Execute "C:\Users\<user>\.cargo\bin\kyz.exe" `
             -Argument "daemon start --foreground"
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User "<user>"
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
             -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
             -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
Register-ScheduledTask -TaskName "kyzd" -Action $action -Trigger $trigger `
             -Settings $settings -User "<user>"
```

Notes:

- `--foreground` keeps the daemon inside the task's process so Task
  Scheduler reports failures and honors Stop-Task (which the daemon treats
  like a shutdown signal).
- For a true Windows Service, wrap `kyz daemon start --foreground` with a
  service shim (e.g. `winSW`/`NSSM`) — the daemon does not speak the SCM
  protocol itself.
- The management IPC named pipe is authenticated with the per-daemon
  `ipc.token`; the pipe's default DACL cannot be narrowed without unsafe
  Win32 calls, which kyz deliberately does not make.

## Configuration

See `examples/config.toml` and the `[daemon]` / `[proxy]` / `[scripts]`
sections in `config.schema.json`. Configuration changes require
`kyz daemon reload` (or a restart) — the daemon never watches the file.
