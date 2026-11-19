#!/bin/bash
# Push this repo to GitHub — run once
# 1. Create empty repo on github.com (no README, no .gitignore)
# 2. Run: bash scripts/push.sh
# Replace URL below with your repo URL
set -e
REPO_URL=${1:-"https://github.com/piyushsinghania108/ghost-ledger.git"}
git init -b main 2>/dev/null || true
git add .
git commit -m "feat: Ghost Ledger v4.1 fixed — MCP, consent, PDF fix, full SHA-256" || echo "nothing to commit"
git remote remove origin 2>/dev/null || true
git remote add origin "$REPO_URL"
git push -u origin main
echo "Pushed to $REPO_URL"
