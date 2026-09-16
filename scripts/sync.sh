#!/usr/bin/env bash
# Mirrors the 18 published rote Plays from ~/.rote/flows/<name>/ into
# plays/<name>/ in this repo. Development source stays under ~/.rote/flows;
# this script only reads from there and writes into the repo tree.
set -euo pipefail

SRC_ROOT="$HOME/.rote/flows"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_ROOT="$REPO_ROOT/plays"

PLAYS=(
  agent-resource-audit
  playoffs-standings
  mcp-doctor
  mcp-context-tax
  mcp-package-health
  mcp-config-secrets-audit
  session-digest
  commit-attribution-guard
  laptop-loss-drill
  agent-disk-tax
  scheduled-job-graveyard
  shell-history-leak-scan
  git-credential-exposure
  agent-plugin-inventory
  python-ssl-doctor
  command-shadow-audit
  commit-identity-check
  timemachine-exclusions-audit
)

for play in "${PLAYS[@]}"; do
  if [ ! -d "$SRC_ROOT/$play" ]; then
    echo "error: missing source directory $SRC_ROOT/$play" >&2
    exit 1
  fi
done

mkdir -p "$DEST_ROOT"

for play in "${PLAYS[@]}"; do
  src="$SRC_ROOT/$play/"
  dest="$DEST_ROOT/$play/"
  mkdir -p "$dest"
  rsync -a --delete \
    --exclude='__pycache__/' \
    --exclude='.rote-flow-lint.json' \
    --exclude='.DS_Store' \
    --exclude='*.pyc' \
    "$src" "$dest"

  version=$(grep -m1 '^ \* version:' "$dest/main.ts" | sed 's/^ \* version: *//')
  echo "$play $version"
done

# Refresh the Version column in README.md from each play's main.ts, so the
# table never drifts from what was actually synced.
python3 - "$REPO_ROOT" <<'PY'
import re, sys, os
root = sys.argv[1]
readme = os.path.join(root, "README.md")
t = open(readme).read()
def ver(name):
    m = re.search(r"^ \* version: (\S+)$", open(os.path.join(root, "plays", name, "main.ts")).read(), re.M)
    return m.group(1)
t2 = re.sub(r"^\| \[([a-z0-9-]+)\]\(([^)]+)\) \| [0-9.]+ \|", lambda m: f"| [{m.group(1)}]({m.group(2)}) | {ver(m.group(1))} |", t, flags=re.M)
if t2 != t:
    open(readme, "w").write(t2); print("README versions refreshed")
else:
    print("README versions already current")
PY
