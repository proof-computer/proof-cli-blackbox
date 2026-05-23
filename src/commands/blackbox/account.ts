import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../command-helpers.js";
import { runBlackboxAccount } from "../../runner.js";

export default class BlackboxAccount extends Command {
  static description = "Read Blackbox account credit and optional ledger state.";
  static examples = ["<%= config.bin %> blackbox account --base-url https://proof-blackbox.fly.dev --json"];
  static flags = {
    help: Flags.help({ char: "h" }),
    "base-url": baseUrlFlag,
    "manifest-url": manifestUrlFlag,
    "manifest-signer": manifestSignerFlag,
    name: nameFlag,
    "sink-name": nameFlag,
    "state-file": stateFileFlag,
    "owner-uri-env": ownerUriEnvFlag,
    ledger: Flags.boolean({ description: "Read the account ledger instead of account summary." }),
    json: jsonFlag
  };
  static id = "blackbox account";
  static summary = "Read Blackbox account state.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxAccount);
    await runBlackboxAccount({ flags });
  }
}
