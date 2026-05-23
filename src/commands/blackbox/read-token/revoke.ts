import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../../command-helpers.js";
import { runBlackboxReadTokenRevoke } from "../../../runner.js";

export default class BlackboxReadTokenRevoke extends Command {
  static description = "Revoke a Blackbox read token for a sink.";
  static examples = ["<%= config.bin %> blackbox read-token revoke --name my-app --token-id bbx_rt_... --json"];
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
    "token-id": Flags.string({ description: "Token id to revoke." }),
    json: jsonFlag
  };
  static id = "blackbox read-token revoke";
  static summary = "Revoke a Blackbox read token.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxReadTokenRevoke);
    await runBlackboxReadTokenRevoke({ flags });
  }
}
