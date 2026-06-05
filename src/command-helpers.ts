import { Flags, type Interfaces } from "@oclif/core";

export const jsonFlag: Interfaces.BooleanFlag<boolean> = Flags.boolean({
  description: "Print machine-readable output."
});

export const baseUrlFlag: Interfaces.OptionFlag<string | undefined> = Flags.string({
  description: "Blackbox service base URL."
});

export const nameFlag: Interfaces.OptionFlag<string | undefined> = Flags.string({
  description: "Saved Blackbox sink name."
});

export const stateFileFlag: Interfaces.OptionFlag<string | undefined> = Flags.string({
  description: "Path to Blackbox local key/state JSON."
});

export const ownerUriEnvFlag: Interfaces.OptionFlag<string | undefined> = Flags.string({
  description: "Environment variable containing the owner sr25519 URI."
});

export const manifestUrlFlag: Interfaces.OptionFlag<string | undefined> = Flags.string({
  description: "Signed Switchboard network manifest URL for Blackbox discovery."
});

export const manifestSignerFlag: Interfaces.OptionFlag<string | undefined> = Flags.string({
  description: "Expected signed Switchboard network manifest signer."
});
