import { Flags } from "@oclif/core";

export const jsonFlag = Flags.boolean({
  description: "Print machine-readable output."
});

export const baseUrlFlag = Flags.string({
  description: "Blackbox service base URL."
});

export const nameFlag = Flags.string({
  description: "Saved Blackbox sink name."
});

export const stateFileFlag = Flags.string({
  description: "Path to Blackbox local key/state JSON."
});

export const ownerUriEnvFlag = Flags.string({
  description: "Environment variable containing the owner sr25519 URI."
});

export const manifestUrlFlag = Flags.string({
  description: "Signed Switchboard network manifest URL for Blackbox discovery."
});

export const manifestSignerFlag = Flags.string({
  description: "Expected signed Switchboard network manifest signer."
});
