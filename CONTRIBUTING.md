# Contributing

1. Fork, create branch: `feat/<short-name>`
2. Never commit `.env`, `*.db`, secrets, or raw cmdlines. Scanner masks values — keep it that way.
3. Add test in `tests/` for any new scanner or PDF change.
4. Run `make test` before PR.
5. Evidence Pack changes must pass Unicode + 2-asset PDF test.

## Security
Do not open PRs with real tokens, keys, or client data. Use masked fingerprints only.
