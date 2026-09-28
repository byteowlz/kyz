# Multi-machine vault synchronization (v5)

A kyz vault is a mergeable set of files: every entry write is an operation
in a per-entry log, and merging two replicas is a set union followed by a
deterministic projection. No server is involved — distribute the vault
with any file synchronizer and kyz reconciles it.

## Layout

```
vault.json              manifest: vault id, key slots, MAC
vault.entries/
  3f9c…e1.json          one file per entry: encrypted name, operation log, MAC
  a07b…42.json
```

- Each `get`/`set`/`delete` reads the manifest plus one entry file, so
  latency does not grow with vault size.
- Entry file names are keyed hashes of `service/key`; service and key
  names are stored encrypted. Field names, tags and timestamps are still
  visible in plaintext inside entry files.
- The manifest only changes when key slots change.

## Workflow

Sync the directory holding `vault.json` and `vault.entries/` with
[Syncthing](https://syncthing.net/), a private Git repo, or a shared
drive.

- **Conflict copies are handled automatically.** When two machines edit
  the same entry, the synchronizer writes a sibling copy
  (`<id>.sync-conflict-….json`). kyz reads verified copies as part of the
  entry right away, folds them into the entry file on its next write, and
  removes them. `kyz vault unlock` does the same for every entry and for
  conflict copies of the manifest. Copies that do not verify (another
  vault, corrupt, tampered) are ignored and never deleted.
- **Explicit merge** of another replica, e.g. a copy on a USB stick:

  ```bash
  kyz vault merge /mnt/usb/kyz/vault.json      # entries read from /mnt/usb/kyz/vault.entries/
  kyz vault merge old-vault.json               # a legacy single-file v4 vault
  kyz vault merge /mnt/usb/kyz/vault.json --dry-run   # report only
  kyz vault merge /mnt/usb/kyz/vault.json --json      # machine-readable report
  ```

  The merge verifies the source under the unlocked session's key (every
  MAC and every blob) before taking the target's lock, then writes only
  the entry files that changed — or nothing at all. The source is never
  modified.

Older v1–v4 vaults migrate to v5 on `kyz vault unlock`. Migration produces
identical operation ids for identical data, so replicas that migrate
independently deduplicate their shared history when merged.

**One caveat when both sides come from v3.** v3 deletions are physical
removals with no tombstone, so a secret deleted on one machine *before*
migration is indistinguishable from a secret the other fork never had.
If a merge would introduce entries that exist only in the source's pre-v4
history and are absent from your vault, `kyz vault merge` refuses and
lists them — re-run with `--yes` once you have confirmed none of them
were deleted on purpose.

## Key slots and passphrase changes

The vault's data key is wrapped once per key slot. Replicas are the same
vault when they share the `vault_id` and verify under the same data key —
their slots may differ, so changing the passphrase on one machine does not
break syncing.

```bash
kyz vault passwd     # adds a slot for the new passphrase, removes the old one
kyz vault slots      # list slots (no key material)
```

Slots merge as a union and a removal always wins, so the old passphrase
stops working on every replica once the change has synced or been merged.
**Copies of `vault.json` made before the change (backups, stale replicas)
still open with the old passphrase.** Revoking a leaked passphrase for
good requires rotating the data key, which is not implemented yet.

## Conflict semantics

For each `service/key`, the current state is derived from the operation
log's causal frontier:

- **Concurrent put + delete → delete wins.** Even if the put is newer.
  Deletions observed by a later write no longer apply — an explicit
  re-create (`kyz set ... --yes` after the merge) is causally later than
  the delete and revives the entry.
- **Concurrent put + put → deterministic winner.** The winner is chosen
  by the total order `(changed_at, id)`; every losing version is kept in
  full and reported as a conflict. Related fields (username, password,
  API key) always come from one complete snapshot — field-level splicing
  is intentionally not performed, so a merged entry is always a state
  that one machine actually wrote (the KeePass/KeePassXC model).

Inspect and recover conflicts:

```bash
kyz history svc/api-key        # roles: current / CONFLICT / ancestor / deleted
kyz rollback svc/api-key --to 1        # restore by sequence (1 = oldest)
kyz rollback svc/api-key --to 0123456789abcdef0123456789abcdef:7   # or by op id
```

Rollback is itself a new write that references the current frontier; it
never rewrites history.

## Syncthing notes

Exclude in-flight temp files and the lock file so a write in progress is
never replicated:

```
// .stignore
.vault.json.tmp-*
vault.json.lock
vault.entries/.*.tmp-*
```

The lock file must stay at its fixed path next to `vault.json`; it is not
part of the vault content.

## Retention and tombstones

- Delete operations (tombstones) are retained indefinitely. There is no
  time-based garbage collection: an old replica that comes back online
  must still see the deletion to lose to it.
- `history_retention` (config) limits how many versions `kyz history`
  displays; it does not trim stored data.
- Canonicalization prunes the *ciphertext* of snapshots a tombstone
  causally supersedes, keeping the operation headers. This does not
  delete the ciphertext from external backups or old sync copies — treat
  every historical copy of the vault as sensitive.

## Trust and integrity

- The manifest and every entry file carry an HMAC-SHA256 keyed via
  domain-separated HKDF from the vault's data key. An entry file's MAC
  also binds its file name, so files cannot be swapped between entries.
  Tampering with any metadata — tags, field names, HLCs, parents, kind,
  blobs, or key slots — fails verification.
- Merge and conflict-copy handling refuse files from an independent
  vault.
- Someone with write access to the vault directory can still delete an
  entry file or restore an older copy of one. Syncing brings the missing
  operations back from any replica that has them, but a single isolated
  copy cannot detect it.
- Workspace-vault trust (`.kyz/vault.json`) pins the manifest, so it only
  asks for re-confirmation when key slots change, not on every write.
  Migration to v5 rewrites the manifest and asks once.
