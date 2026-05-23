import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../../command-helpers.js";
import { runBlackboxReadTokenList } from "../../../runner.js";

export default class BlackboxReadTokenList extends Command {
  static description = "List Blackbox read tokens for a sink.";
  static examples = ["<%= config.bin %> blackbox read-token list --name my-app --json"];
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
    json: jsonFlag
  };
  static id = "blackbox read-token list";
  static summary = "List Blackbox read tokens.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxReadTokenList);
    await runBlackboxReadTokenList({ flags });
  }
}
