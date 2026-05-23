import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../../command-helpers.js";
import { runBlackboxReadTokenCreate } from "../../../runner.js";

export default class BlackboxReadTokenCreate extends Command {
  static description = "Create and optionally save a Blackbox read or tail token.";
  static examples = ["<%= config.bin %> blackbox read-token create --name my-app --scope tail --json"];
  static flags = {
    help: Flags.help({ char: "h" }),
    "base-url": baseUrlFlag,
    "manifest-url": manifestUrlFlag,
    "manifest-signer": manifestSignerFlag,
    name: nameFlag,
    "sink-name": nameFlag,
    "state-file": stateFileFlag,
    "owner-uri-env": ownerUriEnvFlag,
    "sink-id": Flags.string({ description: "Sink id." }),
    scope: Flags.string({ description: "Token scope: read or tail." }),
    "token-id": Flags.string({ description: "Explicit token id." }),
    "wrapped-dek": Flags.string({ description: "Optional wrapped DEK metadata." }),
    "expires-at": Flags.string({ description: "Optional token expiry timestamp." }),
    json: jsonFlag
  };
  static id = "blackbox read-token create";
  static summary = "Create a Blackbox read token.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxReadTokenCreate);
    await runBlackboxReadTokenCreate({ flags });
  }
}
