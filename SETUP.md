# Setup — 3 Commands

```bash
git clone https://github.com/piyushsinghania108/ghost-ledger.git
cd ghost-ledger
make setup && make run
```

Then:
1. Enter client name
2. Tick consent (required)
3. Tick secret scan ONLY if authorised (opt-in, default OFF)
4. Click Run Enterprise Scan

## Env
```bash
cp .env.example .env
# Fill GITHUB_TOKEN (read-only) + AWS keys (read-only) if needed
```

## Tests
```bash
make test
```

## Push to GitHub (first time)
```bash
bash scripts/push.sh https://github.com/piyushsinghania108/ghost-ledger.git
```
