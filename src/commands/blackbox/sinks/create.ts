import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, ownerUriEnvFlag, stateFileFlag } from "../../../command-helpers.js";
import { runBlackboxSinksCreate } from "../../../runner.js";

export default class BlackboxSinksCreate extends Command {
  static description = "Create a Blackbox sink and persist local DEK state.";
  static examples = [
    "<%= config.bin %> blackbox sinks create --base-url https://proof-blackbox.fly.dev --name my-app --job-id acurast:mainnet:12345 --env-file .blackbox/my-app.env"
  ];
  static flags = {
    help: Flags.help({ char: "h" }),
    "base-url": baseUrlFlag,
    "manifest-url": manifestUrlFlag,
    "manifest-signer": manifestSignerFlag,
    name: nameFlag,
    "sink-name": nameFlag,
    "state-file": stateFileFlag,
    "owner-uri-env": ownerUriEnvFlag,
    "sink-id": Flags.string({ description: "Explicit sink id." }),
    "job-id": Flags.string({ description: "Acurast job id allowed to write this sink." }),
    "deployment-id": Flags.string({ description: "Acurast deployment id allowed to write this sink." }),
    network: Flags.string({ description: "Blackbox network label." }),
    "retention-seconds": Flags.string({ description: "Retention window in seconds." }),
    "max-retained-bytes": Flags.string({ description: "Maximum retained encrypted bytes." }),
    "max-ingest-bytes-per-minute": Flags.string({ description: "Maximum ingest bytes per minute." }),
    label: Flags.string({ multiple: true, description: "Sink label as key=value." }),
    dek: Flags.string({ description: "Existing base64url Blackbox log DEK." }),
    "env-file": Flags.string({ description: "Write runtime env file with sink id, write URL, and DEK." }),
    "spool-dir": Flags.string({ description: "Runtime spool directory to write into the env file." }),
    context: Flags.string({ description: "Runtime context label to write into the env file." }),
    json: jsonFlag
  };
  static id = "blackbox sinks create";
  static summary = "Create a Blackbox sink.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxSinksCreate);
    await runBlackboxSinksCreate({ flags });
  }
}
