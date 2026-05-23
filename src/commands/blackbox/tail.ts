import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../command-helpers.js";
import { runBlackboxTail } from "../../runner.js";

export default class BlackboxTail extends Command {
  static description = "Tail and locally decrypt live Blackbox log batches.";
  static examples = ["<%= config.bin %> blackbox tail --name my-app --limit 10 --timeout-ms 60000 --json"];
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
    limit: Flags.string({ description: "Maximum number of batches." }),
    "timeout-ms": Flags.string({ description: "Tail timeout in milliseconds." }),
    dek: Flags.string({ description: "Base64url Blackbox log DEK." }),
    "dek-env": Flags.string({ description: "Environment variable containing the Blackbox log DEK." }),
    "read-token": Flags.string({ description: "Read token bearer value." }),
    "read-token-env": Flags.string({ description: "Environment variable containing the read token." }),
    "token-id": Flags.string({ description: "Saved read token id." }),
    json: jsonFlag
  };
  static id = "blackbox tail";
  static summary = "Tail Blackbox log batches.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxTail);
    await runBlackboxTail({ flags });
  }
}
