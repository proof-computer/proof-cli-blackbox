import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../command-helpers.js";
import { runBlackboxRead } from "../../runner.js";

export default class BlackboxRead extends Command {
  static description = "Read and locally decrypt Blackbox log batches.";
  static examples = ["<%= config.bin %> blackbox read --name my-app --limit 20 --json"];
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
    "job-id": Flags.string({ description: "Filter by Acurast job id." }),
    "after-sequence": Flags.string({ description: "Read after this sequence." }),
    limit: Flags.string({ description: "Maximum number of batches." }),
    dek: Flags.string({ description: "Base64url Blackbox log DEK." }),
    "dek-env": Flags.string({ description: "Environment variable containing the Blackbox log DEK." }),
    "read-token": Flags.string({ description: "Read token bearer value." }),
    "read-token-env": Flags.string({ description: "Environment variable containing the read token." }),
    "token-id": Flags.string({ description: "Saved read token id." }),
    json: jsonFlag
  };
  static id = "blackbox read";
  static summary = "Read Blackbox log batches.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxRead);
    await runBlackboxRead({ flags });
  }
}
