import { Command, Flags, type Interfaces } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../../command-helpers.js";
import { runBlackboxSinksList } from "../../../runner.js";

export default class BlackboxSinksList extends Command {
  static description =
    "List owner sinks, including job-bound sinks self-created by factory-token runtimes. With --name matching a configure-slipway profile, only that application's factory sinks are listed.";
  static examples = [
    "<%= config.bin %> blackbox sinks list --name switchboard-validator",
    "<%= config.bin %> blackbox sinks list --name switchboard-validator --deployment-id 76976 --json"
  ];
  static flags: Interfaces.FlagInput = {
    help: Flags.help({ char: "h" }),
    "base-url": baseUrlFlag,
    "manifest-url": manifestUrlFlag,
    "manifest-signer": manifestSignerFlag,
    name: nameFlag,
    "sink-name": nameFlag,
    "state-file": stateFileFlag,
    "owner-uri-env": ownerUriEnvFlag,
    "job-id": Flags.string({ description: "Filter by Acurast job id." }),
    "deployment-id": Flags.string({ description: "Filter by Acurast deployment id." }),
    json: jsonFlag
  };
  static id = "blackbox sinks list";
  static summary = "List Blackbox sinks.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxSinksList);
    await runBlackboxSinksList({ flags });
  }
}
