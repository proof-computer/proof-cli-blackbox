import { Command, Flags } from "@oclif/core";

export default class Blackbox extends Command {
  static description = [
    "Run Blackbox logging commands.",
    "Blackbox stores encrypted logs for verified Acurast jobs. Local DEKs and read tokens remain in your Blackbox state file."
  ].join("\n");
  static examples = [
    "<%= config.bin %> blackbox status --base-url https://proof-blackbox.fly.dev",
    "<%= config.bin %> blackbox configure-slipway switchboard-validator --slipway-url https://slipway.fly.dev --lockbox-url https://lockbox.fly.dev",
    "<%= config.bin %> blackbox sinks create --base-url https://proof-blackbox.fly.dev --name my-app --job-id acurast:mainnet:12345",
    "<%= config.bin %> blackbox read --name my-app --limit 20"
  ];
  static flags = {
    help: Flags.help({ char: "h" })
  };
  static id = "blackbox";
  static summary = "Run Blackbox logging commands.";

  async run(): Promise<void> {
    this.log(`Blackbox logging commands.

USAGE
  $ ${this.config.bin} blackbox status --base-url <url>
  $ ${this.config.bin} blackbox account --base-url <url>
  $ ${this.config.bin} blackbox admin grant-credit --base-url <url> --admin-token-env <ENV> --owner <hex> --amount <atomic>
  $ ${this.config.bin} blackbox configure-slipway <APPLICATION_ID>
  $ ${this.config.bin} blackbox sinks create --base-url <url> --name <name> --job-id <id>
  $ ${this.config.bin} blackbox read-token create|list|revoke --name <name>
  $ ${this.config.bin} blackbox read|search|tail --name <name>

STATE
  State is stored in --state-file or BLACKBOX_HOME/keys.json, defaulting to ~/.blackbox/keys.json.
  Owner-signed commands read BLACKBOX_OWNER_URI by default.`);
  }
}
