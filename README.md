# PROOF CLI Blackbox Plugin

`@proof-computer/proof-cli-blackbox` adds native oclif Blackbox logging
commands to the public `proof` CLI.

## Install

```fish
npm install --global @proof-computer/proof-cli
proof plugins install @proof-computer/proof-cli-blackbox
proof blackbox --help
```

The standalone `blackbox` binary remains supported by the Blackbox repo during
the migration and delegates through a compatibility adapter to the same
command-specific runners.

## Common Flow

```fish
set -gx BLACKBOX_BASE_URL https://proof-blackbox.fly.dev
set -gx BLACKBOX_OWNER_URI '//your-owner-uri'

proof blackbox status --base-url $BLACKBOX_BASE_URL
proof blackbox account --base-url $BLACKBOX_BASE_URL
proof blackbox sinks create --base-url $BLACKBOX_BASE_URL --name my-app --job-id acurast:mainnet:12345 --env-file .blackbox/my-app.env
proof blackbox read-token create --name my-app --scope tail
proof blackbox read --name my-app --limit 20
proof blackbox search --name my-app --label phase=boot
proof blackbox tail --name my-app --limit 10 --timeout-ms 60000
```

## Slipway Application Logging

For Slipway-backed PROOF Applications that use reusable operator-owned
Blackbox profiles, configure the shared Application id from the Blackbox topic:

```fish
set -gx BLACKBOX_OWNER_URI '//your-owner-uri'
set -gx PROOF_LOCKBOX_OPERATOR_UPLOAD_TOKEN '...'

proof blackbox configure-slipway switchboard-validator \
  --slipway-url https://slipway.fly.dev \
  --lockbox-url https://lockbox.fly.dev \
  --json
```

The command resolves the Application binding through Slipway, creates or
reuses a Blackbox sink factory, keeps the log DEK and factory token in the
local `0600` Blackbox state file, uploads the encrypted reusable profile
directly to Lockbox, and records only redacted profile metadata back to
Slipway. Slipway can then ask Lockbox to materialize per-job
`BLACKBOX_LOG_CONFIG` secrets during automated launches.

## State And Trust Boundary

State is stored in `--state-file` or `BLACKBOX_HOME/keys.json`, defaulting to
`~/.blackbox/keys.json` with file mode `0600`. Legacy cwd
`.blackbox/sinks/<name>.json` files remain readable.

Owner-signed commands read `BLACKBOX_OWNER_URI` by default. Read tokens fetch
encrypted log batches. The DEK stays local and is required to decrypt records.
`proof blackbox configure-slipway` never prints the DEK, sink factory token,
compact config, Slipway session token, or Lockbox upload token.

## Development

```fish
pnpm install
pnpm typecheck
pnpm test
pnpm build
node scripts/verify-package.mjs
pnpm pack:dry-run
```

Local root CLI smoke, from this checkout beside `../proof-cli`:

```fish
pnpm smoke:proof-plugin
```
