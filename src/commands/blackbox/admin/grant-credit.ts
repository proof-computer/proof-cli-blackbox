import { Command, Flags } from "@oclif/core";

import { baseUrlFlag, jsonFlag, manifestSignerFlag, manifestUrlFlag, nameFlag, stateFileFlag } from "../../../command-helpers.js";
import { runBlackboxAdminGrantCredit } from "../../../runner.js";

export default class BlackboxAdminGrantCredit extends Command {
  static description = "Grant private admin credit to a Blackbox account.";
  static examples = [
    "<%= config.bin %> blackbox admin grant-credit --base-url https://proof-blackbox.fly.dev --admin-token-env BLACKBOX_ADMIN_TOKEN --owner 0x... --amount 100000 --json"
  ];
  static flags = {
    help: Flags.help({ char: "h" }),
    "base-url": baseUrlFlag,
    "manifest-url": manifestUrlFlag,
    "manifest-signer": manifestSignerFlag,
    name: nameFlag,
    "sink-name": nameFlag,
    "state-file": stateFileFlag,
    "admin-token-env": Flags.string({ description: "Environment variable containing the admin bearer token." }),
    owner: Flags.string({ description: "Owner public key hex to credit." }),
    amount: Flags.string({ description: "ACU amount in atomic units." }),
    "top-up-id": Flags.string({ description: "Idempotency key for the admin credit." }),
    source: Flags.string({ description: "Admin credit source label." }),
    json: jsonFlag
  };
  static id = "blackbox admin grant-credit";
  static summary = "Grant private admin credit.";

  async run(): Promise<void> {
    const { flags } = await this.parse(BlackboxAdminGrantCredit);
    await runBlackboxAdminGrantCredit({ flags });
  }
}
