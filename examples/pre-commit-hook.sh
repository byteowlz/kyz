#!/usr/bin/env bash
# Pre-commit hook for kyz secret scanning.
# Install: cp examples/pre-commit-hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
#
# Scans staged files for accidentally committed vault secret values.
# Requires: kyz vault to be unlocked.

set -euo pipefail

# Skip if kyz is not installed
if ! command -v kyz &>/dev/null; then
    exit 0
fi

# Skip if vault is not unlocked (don't block commits when vault is locked)
if ! kyz vault status --json 2>/dev/null | grep -q '"unlocked": true'; then
    exit 0
fi

# Scan staged files for leaked secrets
exec kyz scan --staged --hook
