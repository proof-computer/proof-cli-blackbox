import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../command-helpers.js";
import { runBlackboxSearch } from "../../runner.js";

export default class BlackboxSearch extends Command {
  static description = "Search and locally decrypt Blackbox log batches.";
  static examples = ["<%= config.bin %> blackbox search --name my-app --label phase=boot --json"];
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
    "batch-id": Flags.string({ description: "Filter by batch id." }),
    "received-after": Flags.string({ description: "Filter by received-at lower bound." }),
    "received-before": Flags.string({ description: "Filter by received-at upper bound." }),
    "sequence-start": Flags.string({ description: "Filter by sequence lower bound." }),
    "sequence-end": Flags.string({ description: "Filter by sequence upper bound." }),
    limit: Flags.string({ description: "Maximum number of batches." }),
    label: Flags.string({ multiple: true, description: "Search label as key=value." }),
    dek: Flags.string({ description: "Base64url Blackbox log DEK." }),
    "dek-env": Flags.string({ description: "Environment variable containing the Blackbox log DEK." }),
    "read-token": Flags.string({ description: "Read token bearer value." }),
    "read-token-env": Flags.string({ description: "Environment variable containing the read token." }),
    "token-id": Flags.string({ description: "Saved read token id." }),
    json: jsonFlag
  };
  static id = "blackbox search";
  static summary = "Search Blackbox log batches.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxSearch);
    await runBlackboxSearch({ flags });
  }
}
