# Multi-machine vault synchronization (v4)

Vault format v4 turns `vault.json` into a mergeable artifact: every entry
write is an operation in a per-entry log, and merging two replicas is a
set union followed by a deterministic projection. This guide explains how
to distribute a vault across machines and how merging resolves conflicts.

## Workflow

Distribute the vault file with any file synchronizer — [Syncthing](https://syncthing.net/), a private Git repo, a shared drive — then merge explicitly:

```bash
# Machine A and B both edited the vault; the sync tool produced a conflict
# copy (Syncthing: vault.sync-conflict-20260923-….json) or you copied the
# remote file over manually:
kyz vault merge vault.sync-conflict-20260923-120000-ABCDEF.json
kyz vault merge /mnt/usb/vault.json          # any path works
kyz vault merge copy.json --dry-run          # report only, write nothing
kyz vault merge copy.json --json             # machine-readable report
```

The merge:

- uses the current unlocked session's data key;
- verifies the source (v4 only, same vault id / kdf / wrapped DK, valid
  MAC, every blob decrypts) **before** taking the target's lock, so
  concurrent reads are never blocked by the O(source size) verification;
- takes the target's exclusive lock, re-reads it, unions the operation
  sets, canonicalizes, and writes back atomically — or writes nothing at
  all when the merged result is byte-identical;
- never modifies the source file. Remove or archive it yourself once the
  report looks right.

An older v3/v2/v1 copy cannot be merged directly: run `kyz vault unlock`
on that copy first (on its own machine or path) — unlock migrates it to
v4, and migration produces identical operation ids for identical data, so
the shared history deduplicates when you merge.

**One caveat when both sides come from v3.** v3 deletions are physical
removals with no tombstone, so a secret deleted on one machine *before*
migration is indistinguishable from a secret the other fork never had.
If a merge would introduce entries that exist only in the source's
pre-v4 history and are absent from your vault, `kyz vault merge` refuses
and lists them — re-run with `--yes` once you have confirmed none of
them were deleted on purpose.

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

- **Exclude in-flight temp files** from synchronization so a write in
  progress is never replicated: add `.vault.json.tmp-*` (and the lock
  file `vault.json.lock`) to your `.stignore`:

  ```
  // .stignore
  .vault.json.tmp-*
  vault.json.lock
  ```

- The lock file must stay at its fixed path next to the vault; it is not
  part of the vault content.
- Syncthing conflict copies are ordinary v4 files — merge them with
  `kyz vault merge`, then delete the conflict copy.

## Retention and tombstones

- Delete operations (tombstones) are retained indefinitely. There is no
  time-based garbage collection: an old replica that comes back online
  must still see the deletion to lose to it.
- `history_retention` (config) limits how many versions `kyz history`
  displays; it no longer trims stored data. Physical compaction would
  require a documented causal-watermark protocol and is intentionally
  out of scope for v4.
- Canonicalization prunes the *ciphertext* of snapshots that a tombstone
  makes unreachable (before it, or concurrent with it), keeping the
  operation headers. This does not delete the ciphertext from external
  backups or old sync copies — treat every historical copy of the file
  as sensitive.

## Trust and integrity

- Each vault has a `vault_id`; replicas of the same vault share it (forked
  v3 copies derive it from the shared kdf + wrapped DK). Merge refuses
  files from an independent vault.
- The whole file (operation headers and ciphertext) is covered by an
  HMAC-SHA256 keyed via domain-separated HKDF from the vault DK.
  Tampering with any metadata — service/key position, tags, field names,
  HLCs, parents, kind, or blobs — fails verification.
- Migration to v4 changes the file bytes, so workspace vaults require a
  new trust confirmation (`--yes` on first unlock) via the existing
  fingerprint mechanism.
