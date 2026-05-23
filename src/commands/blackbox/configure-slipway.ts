import { Args, Command, Flags } from "@oclif/core";

import { jsonFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../command-helpers.js";
import { runBlackboxConfigureSlipway } from "../../runner.js";

export default class BlackboxConfigureSlipway extends Command {
  static args = {
    applicationId: Args.string({ description: "Shared PROOF Application id.", required: true })
  };
  static description = "Configure Blackbox logging for a Slipway-backed PROOF Application.";
  static examples = [
    "<%= config.bin %> blackbox configure-slipway switchboard-validator --slipway-url https://slipway.fly.dev --lockbox-url https://lockbox.fly.dev --json"
  ];
  static flags = {
    help: Flags.help({ char: "h" }),
    "slipway-url": Flags.string({ description: "Slipway API base URL." }),
    "slipway-session-token-env": Flags.string({ description: "Environment variable containing the Slipway session token." }),
    "slipway-config-file": Flags.string({ description: "Path to a Slipway ops session JSON file." }),
    "lockbox-url": Flags.string({ description: "Lockbox base URL or operator Blackbox config upload URL." }),
    "lockbox-token-env": Flags.string({ description: "Environment variable containing the Lockbox operator upload token." }),
    "owner-uri-env": ownerUriEnvFlag,
    name: nameFlag,
    "state-file": stateFileFlag,
    "reuse-dek-from": Flags.string({ description: "Saved Blackbox sink or profile name whose local DEK should be reused." }),
    "dek-env": Flags.string({ description: "Environment variable containing an existing base64url Blackbox log DEK." }),
    "rotate-dek": Flags.boolean({ description: "Generate a fresh profile DEK instead of reusing a saved profile DEK." }),
    "rotate-factory-token": Flags.boolean({ description: "Rotate the Blackbox sink factory token to recover a lost local profile state file." }),
    "dry-run": Flags.boolean({ description: "Resolve context and print planned actions without writing Blackbox, Lockbox, or Slipway state." }),
    json: jsonFlag
  };
  static id = "blackbox configure-slipway";
  static summary = "Configure Blackbox logging for a Slipway Application.";

  async run(): Promise<void> {
    const { args, flags } = await this.parse(BlackboxConfigureSlipway);
    await runBlackboxConfigureSlipway({ applicationId: args.applicationId, flags });
  }
}
