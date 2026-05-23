import { access, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(await readFile(path.join(repoRoot, "package.json"), "utf8"));

const requiredArtifacts = [
  "dist/commands/blackbox.js",
  "dist/commands/blackbox/status.js",
  "dist/commands/blackbox/account.js",
  "dist/commands/blackbox/admin/grant-credit.js",
  "dist/commands/blackbox/configure-slipway.js",
  "dist/commands/blackbox/sinks/create.js",
  "dist/commands/blackbox/read-token/create.js",
  "dist/commands/blackbox/read-token/list.js",
  "dist/commands/blackbox/read-token/revoke.js",
  "dist/commands/blackbox/read.js",
  "dist/commands/blackbox/search.js",
  "dist/commands/blackbox/tail.js",
  "dist/index.js",
  "oclif.manifest.json",
  "README.md"
];
const requiredFilesEntries = [
  "dist",
  "oclif.manifest.json",
  "README.md"
];
const forbiddenDependencies = [
  "@proof/blackbox-cli",
  "@proof/blackbox-client",
  "@proof/blackbox-service",
  "@proof-computer/proof-cli-lockbox",
  "@proof-computer/proof-cli-slipway"
];

const errors = [];

if (packageJson.name !== "@proof-computer/proof-cli-blackbox") {
  errors.push("package.json name must be @proof-computer/proof-cli-blackbox");
}

if (packageJson.private !== false) {
  errors.push("package.json private must be false");
}

if (packageJson.bin) {
  errors.push("Blackbox proof plugin must not publish a standalone bin");
}

if (packageJson.main !== "dist/index.js") {
  errors.push("package.json main must point to dist/index.js");
}

if (packageJson.types !== "dist/index.d.ts") {
  errors.push("package.json types must point to dist/index.d.ts");
}

for (const artifact of requiredArtifacts) {
  try {
    await access(path.join(repoRoot, artifact));
  } catch {
    errors.push(`Missing package artifact: ${artifact}`);
  }
}

for (const entry of requiredFilesEntries) {
  if (!packageJson.files?.includes(entry)) {
    errors.push(`package.json files must include ${entry}`);
  }
}

if (packageJson.oclif?.commands !== "./dist/commands") {
  errors.push("package.json oclif.commands must point to ./dist/commands");
}

if (packageJson.oclif?.topicSeparator !== " ") {
  errors.push("package.json oclif.topicSeparator must be a single space");
}

if (!packageJson.oclif?.topics?.blackbox) {
  errors.push("package.json oclif.topics must declare blackbox");
}

const dependencyBlocks = [
  packageJson.dependencies ?? {},
  packageJson.devDependencies ?? {},
  packageJson.optionalDependencies ?? {},
  packageJson.peerDependencies ?? {}
];
for (const forbidden of forbiddenDependencies) {
  if (dependencyBlocks.some((block) => Object.hasOwn(block, forbidden))) {
    errors.push(`Blackbox plugin must not depend on private product package ${forbidden}`);
  }
}

if (errors.length > 0) {
  throw new Error(errors.join("\n"));
}

console.log("Package artifacts verified.");
