import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, stateFileFlag } from "../../command-helpers.js";
import { runBlackboxStatus } from "../../runner.js";

export default class BlackboxStatus extends Command {
  static description = "Read Blackbox service health and optional admin status.";
  static examples = ["<%= config.bin %> blackbox status --base-url https://proof-blackbox.fly.dev --json"];
  static flags = {
    help: Flags.help({ char: "h" }),
    "base-url": baseUrlFlag,
    "manifest-url": manifestUrlFlag,
    "manifest-signer": manifestSignerFlag,
    name: nameFlag,
    "sink-name": nameFlag,
    "state-file": stateFileFlag,
    "admin-token-env": Flags.string({ description: "Environment variable containing the admin bearer token." }),
    json: jsonFlag
  };
  static id = "blackbox status";
  static summary = "Read Blackbox service health.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxStatus);
    await runBlackboxStatus({ flags });
  }
}
