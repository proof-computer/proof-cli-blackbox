import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const proofCliRoot = path.resolve(process.env.PROOF_CLI_ROOT ?? path.join(repoRoot, "..", "proof-cli"));
const proofDevBin = path.join(proofCliRoot, "bin", "dev.js");
const home = await mkdtemp(path.join(tmpdir(), "proof-cli-blackbox-smoke-"));

try {
  const env = {
    ...process.env,
    HOME: home,
    XDG_CACHE_HOME: path.join(home, ".cache"),
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    NODE_ENV: "test"
  };

  run(process.execPath, [proofDevBin, "plugins", "link", repoRoot], { cwd: proofCliRoot, env });

  const plugins = run(process.execPath, [proofDevBin, "plugins"], { cwd: proofCliRoot, env });
  assertIncludes(plugins.stdout, "@proof-computer/proof-cli-blackbox");

  const help = run(process.execPath, [proofDevBin, "blackbox", "--help"], { cwd: proofCliRoot, env });
  assertIncludes(help.stdout, "Run Blackbox logging commands");

  const statusHelp = run(process.execPath, [proofDevBin, "blackbox", "status", "--help"], { cwd: proofCliRoot, env });
  assertIncludes(statusHelp.stdout, "Read Blackbox service health");
  assertIncludes(statusHelp.stdout, "--base-url");

  const createHelp = run(process.execPath, [proofDevBin, "blackbox", "sinks", "create", "--help"], { cwd: proofCliRoot, env });
  assertIncludes(createHelp.stdout, "Create a Blackbox sink");
  assertIncludes(createHelp.stdout, "--job-id");

  const configureHelp = run(process.execPath, [proofDevBin, "blackbox", "configure-slipway", "--help"], { cwd: proofCliRoot, env });
  assertIncludes(configureHelp.stdout, "Configure Blackbox logging");
  assertIncludes(configureHelp.stdout, "--lockbox-url");

  const tailHelp = run(process.execPath, [proofDevBin, "blackbox", "tail", "--help"], { cwd: proofCliRoot, env });
  assertIncludes(tailHelp.stdout, "Tail Blackbox log batches");
  assertIncludes(tailHelp.stdout, "--timeout-ms");

  console.log("Root proof Blackbox plugin smoke passed.");
} finally {
  await rm(home, { recursive: true, force: true });
}

function run(command, args, options) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: options.env,
    shell: false
  });
  if (result.status !== 0) {
    throw new Error([
      `Command failed: ${command} ${args.join(" ")}`,
      `exit: ${result.status}`,
      result.stdout,
      result.stderr
    ].filter(Boolean).join("\n"));
  }
  return result;
}

function assertIncludes(value, expected) {
  if (!value.includes(expected)) {
    throw new Error(`Expected output to include ${JSON.stringify(expected)}.\nOutput:\n${value}`);
  }
}
