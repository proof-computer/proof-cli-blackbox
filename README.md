# PROOF CLI Blackbox Plugin

`@proof-computer/proof-cli-blackbox` adds native oclif Blackbox logging
commands to the public `proof` CLI.

## Install

```fish
npm install --global @proof-computer/proof-cli
proof plugins install @proof-computer/proof-cli-blackbox
proof blackbox --help
```

The standalone `blackbox` binary in the private Blackbox repo is
maintenance-only. It contains no command implementation; it imports this
package and delegates through `runBlackboxCli`. New Blackbox CLI work belongs
in this oclif plugin.

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

If the local Blackbox state file is lost after a profile has already been
created, the old DEK cannot be recovered from Blackbox. Reconfigure future
launches by rotating the sink factory token and uploading a replacement
Lockbox profile:

```fish
proof blackbox configure-slipway switchboard-validator \
  --slipway-url https://slipway.fly.dev \
  --lockbox-url https://lockbox.fly.dev \
  --rotate-factory-token \
  --json
```

With the factory-token model the runtime self-creates its job-bound sink, so
reads resolve it automatically from the saved profile: `read`/`search`/`tail`
with `--name <app>` and no `--sink-id` list the owner's sinks under the
profile's factory and pick the newest active one (or the one matching
`--job-id`/`--deployment-id`). The chosen sink is reported as `resolvedSink`.

```fish
proof blackbox sinks list --name switchboard-validator
proof blackbox read --name switchboard-validator --limit 20 --json
proof blackbox tail --name switchboard-validator --timeout-ms 60000
proof blackbox read --name switchboard-validator --deployment-id 76976 --json
```

An explicit `--sink-id` (for example from a Slipway `blackbox.configure` plan
item or execution record) still takes precedence:

```fish
proof blackbox read --name switchboard-validator --sink-id slipway-bbx-... --json
proof blackbox tail --name switchboard-validator --sink-id slipway-bbx-... --timeout-ms 60000
```

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
