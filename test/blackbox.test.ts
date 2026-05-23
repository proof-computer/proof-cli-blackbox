import assert from "node:assert/strict";
import { createCipheriv } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { before, describe, it, type TestContext } from "node:test";

import { Keyring } from "@polkadot/keyring";
import { u8aToHex } from "@polkadot/util";
import { cryptoWaitReady } from "@polkadot/util-crypto";

import { runBlackboxCli } from "../src/index.js";
import type { BlackboxBatchDto } from "../src/internal/reader.js";

const OWNER_URI = "//blackbox-cli-owner";
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const commandUrl = pathToFileURL(path.join(repoRoot, "src", "commands", "blackbox.ts")).href;
const statusCommandUrl = pathToFileURL(path.join(repoRoot, "src", "commands", "blackbox", "status.ts")).href;
const createCommandUrl = pathToFileURL(path.join(repoRoot, "src", "commands", "blackbox", "sinks", "create.ts")).href;
const configureSlipwayCommandUrl = pathToFileURL(path.join(repoRoot, "src", "commands", "blackbox", "configure-slipway.ts")).href;
const readTokenCreateCommandUrl = pathToFileURL(path.join(repoRoot, "src", "commands", "blackbox", "read-token", "create.ts")).href;
const readCommandUrl = pathToFileURL(path.join(repoRoot, "src", "commands", "blackbox", "read.ts")).href;

let ownerPublicKeyHex: string;

before(async () => {
  await cryptoWaitReady();
  const keyring = new Keyring({ type: "sr25519" });
  ownerPublicKeyHex = u8aToHex(keyring.addFromUri(OWNER_URI).publicKey);
});

describe("proof-cli Blackbox runner", () => {
  it("creates a sink, persists 0600 state, writes runtime env, and reads saved status", async (t) => {
    const harness = await createHarness(t);
    const envFile = path.join(harness.dir, "blackbox.env");

    const created = await runJson(harness, [
      "sinks",
      "create",
      "--base-url",
      harness.baseUrl,
      "--name",
      "app",
      "--job-id",
      "job-1",
      "--retention-seconds",
      "60",
      "--max-retained-bytes",
      "1000000",
      "--max-ingest-bytes-per-minute",
      "1000000",
      "--env-file",
      envFile
    ]) as { state: { sinkId: string; writeUrl: string; dek: string } };

    assert.equal(created.state.sinkId, "sink-1");
    assert.match(created.state.writeUrl, /\/v1\/sinks\/sink-1\/events$/);

    const statePath = path.join(harness.dir, "home", "keys.json");
    const saved = JSON.parse(await readFile(statePath, "utf8")) as {
      defaultSink: string;
      sinks: Record<string, { sinkId: string; dek: string }>;
    };
    assert.equal(saved.defaultSink, "app");
    assert.equal(saved.sinks.app?.sinkId, "sink-1");
    assert.equal(saved.sinks.app?.dek, created.state.dek);
    assert.equal((await stat(statePath)).mode & 0o777, 0o600);

    const envText = await readFile(envFile, "utf8");
    assert.match(envText, /BLACKBOX_SINK_ID="sink-1"/);
    assert.match(envText, /BLACKBOX_JOB_ID="job-1"/);
    assert.match(envText, /BLACKBOX_WRITE_URL=/);
    assert.match(envText, /BLACKBOX_LOG_DEK=/);
    assert.equal((await stat(envFile)).mode & 0o777, 0o600);

    const status = await runJson(harness, ["status", "--name", "app"]) as { baseUrl: string; health: { ok: boolean } };
    assert.equal(status.baseUrl, harness.baseUrl);
    assert.equal(status.health.ok, true);
  });

  it("uses explicit state files and keeps legacy cwd sink state readable", async (t) => {
    const harness = await createHarness(t);
    const stateFile = path.join(harness.dir, "keys-injected.json");

    await runJson(harness, [
      "sinks",
      "create",
      "--base-url",
      harness.baseUrl,
      "--name",
      "injected",
      "--job-id",
      "job-1",
      "--state-file",
      stateFile
    ]);
    assert.equal((await stat(stateFile)).mode & 0o777, 0o600);

    const legacyDir = path.join(harness.dir, ".blackbox", "sinks");
    await mkdir(legacyDir, { recursive: true });
    await writeFile(path.join(legacyDir, "legacy.json"), JSON.stringify({
      name: "legacy",
      baseUrl: harness.baseUrl,
      sinkId: "legacy-sink",
      owner: ownerPublicKeyHex,
      writeUrl: `${harness.baseUrl}/v1/sinks/legacy-sink/events`,
      dek: fixedDek(),
      createdAt: new Date(0).toISOString()
    }));

    const status = await runJson({
      ...harness,
      env: { ...harness.env, BLACKBOX_HOME: path.join(harness.dir, "empty-home") }
    }, ["status", "--name", "legacy"]) as { baseUrl: string; health: { ok: boolean } };
    assert.equal(status.baseUrl, harness.baseUrl);
    assert.equal(status.health.ok, true);
  });

  it("reads, searches, and tails decrypted logs with saved state and read tokens", async (t) => {
    const harness = await createHarness(t);
    const dek = fixedDek();
    harness.batch = makeBatch(dek);

    await runJson(harness, [
      "sinks",
      "create",
      "--base-url",
      harness.baseUrl,
      "--name",
      "logs",
      "--job-id",
      "job-1",
      "--dek",
      dek
    ]);

    const token = await runJson(harness, ["read-token", "create", "--name", "logs", "--scope", "read"]) as {
      readToken: string;
    };
    assert.match(token.readToken, /^bbx_rt_/);

    const read = await runJson(harness, ["read", "--name", "logs"]) as { batches: Array<{ records: Array<{ event: string }> }> };
    assert.equal(read.batches[0]?.records[0]?.event, "boot");

    const search = await runJson(harness, ["search", "--name", "logs", "--label", "phase=boot"]) as {
      batches: Array<{ records: Array<{ event: string }> }>;
      scannedBytes: number;
    };
    assert.equal(search.batches[0]?.records[0]?.event, "boot");
    assert.equal(search.scannedBytes, 42);

    const tail = await runJson(harness, ["tail", "--name", "logs", "--limit", "1", "--timeout-ms", "1000"]) as {
      batches: Array<{ records: Array<{ event: string }> }>;
    };
    assert.equal(tail.batches[0]?.records[0]?.event, "boot");
  });

  it("requires an explicit admin token env for private credit grants", async (t) => {
    const harness = await createHarness(t);
    await assert.rejects(
      () =>
        runJson(harness, [
          "admin",
          "grant-credit",
          "--base-url",
          harness.baseUrl,
          "--owner",
          ownerPublicKeyHex,
          "--amount",
          "1000"
        ]),
      /requires explicit --admin-token-env/
    );
  });

  it("configures Slipway-backed Blackbox logging through Lockbox without printing the DEK", async (t) => {
    const harness = await createHarness(t);
    const sessionFile = path.join(harness.dir, "ops-session.json");
    const dek = fixedDek();
    await writeFile(sessionFile, `${JSON.stringify({
      slipwayUrl: "https://slipway.test",
      sessionToken: "slipway-session-token",
      address: "github:12345",
      seedEnv: "",
      savedAtMs: 0
    })}\n`);
    const requests: Array<{ host: string; method: string; path: string; authorization?: string; body?: Record<string, unknown> }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      const method = init?.method ?? "GET";
      const authorization = (init?.headers as Record<string, string> | undefined)?.authorization;
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body)) as Record<string, unknown>;
      requests.push({ host: url.hostname, method, path: url.pathname, authorization, body });
      if (url.hostname === "slipway.test" && method === "GET" && url.pathname === "/api/applications/validator/blackbox/configure-slipway-context") {
        return jsonResponse({
          ok: true,
          context: {
            domain: "proof.slipway.blackbox.configure-slipway-context.v1",
            applicationId: "validator",
            repository: "proof-computer/switchboard-validator",
            policyVersionId: "validator-v1",
            policyDigest: "a".repeat(64),
            manifestDigest: "b".repeat(64),
            dispatchId: "lockbox-dispatch:abc",
            planItemId: "blackbox-configure:abc",
            idempotencyKey: "slipway-plan:abc",
            job: {
              jobId: "job-1",
              deploymentId: "deployment-1"
            },
            blackbox: {
              sinkId: "slipway-bbx-validator",
              sinkName: "validator",
              baseUrl: harness.baseUrl,
              writeUrl: `${harness.baseUrl}/v1/sinks/slipway-bbx-validator/events`,
              jobId: "job-1",
              deploymentId: "deployment-1",
              envName: "BLACKBOX_LOG_CONFIG",
              spoolDir: "./blackbox-log-spool",
              context: {
                application: "validator"
              }
            },
            lockbox: {
              secretId: "blackbox-log-config",
              envName: "BLACKBOX_LOG_CONFIG",
              uploadUrl: "https://lockbox.test/api/operator/blackbox-log-config-secret-versions"
            }
          }
        });
      }
      if (url.hostname === "lockbox.test" && method === "POST" && url.pathname === "/api/operator/blackbox-log-config-secret-versions") {
        const compact = JSON.parse(String(body?.compactConfig ?? "{}")) as { dek?: string; sinkId?: string };
        assert.equal(compact.dek, dek);
        assert.equal(compact.sinkId, "slipway-bbx-validator");
        return jsonResponse({
          ok: true,
          replayed: false,
          secretVersion: {
            secretId: "blackbox-log-config",
            versionId: "lockbox-secret-version:blackbox",
            target: "env",
            name: "BLACKBOX_LOG_CONFIG",
            required: true,
            bundleId: "blackbox-log-config",
            encryptedPayloadDigest: `sha256:${"3".repeat(64)}`
          },
          configDigest: `sha256:${"1".repeat(64)}`,
          dekDigest: `sha256:${"2".repeat(64)}`
        });
      }
      if (url.hostname === "slipway.test" && method === "POST" && url.pathname === "/api/applications/validator/blackbox/configure-slipway-record") {
        return jsonResponse({ ok: true, configuration: { configurationId: "blackbox-configuration:abc" } });
      }
      return harness.fetchImpl(input, init);
    };
    const lines: string[] = [];
    await runBlackboxCli([
      "configure-slipway",
      "validator",
      "--slipway-config-file",
      sessionFile,
      "--dek-env",
      "BLACKBOX_TEST_DEK",
      "--json"
    ], {
      cwd: harness.dir,
      env: {
        ...harness.env,
        BLACKBOX_TEST_DEK: dek,
        PROOF_LOCKBOX_OPERATOR_UPLOAD_TOKEN: "lockbox-operator-token"
      },
      fetchImpl,
      stdout: (line) => lines.push(line)
    });
    const outputText = lines.join("\n");
    assert.equal(outputText.includes(dek), false);
    assert.equal(outputText.includes("lockbox-operator-token"), false);
    assert.equal(outputText.includes("slipway-session-token"), false);
    const parsed = JSON.parse(outputText) as { blackbox: { sinkId: string }; lockbox: { secretVersion: { versionId: string } } };
    assert.equal(parsed.blackbox.sinkId, "slipway-bbx-validator");
    assert.equal(parsed.lockbox.secretVersion.versionId, "lockbox-secret-version:blackbox");
    assert.equal(requests.some((request) => request.host === "lockbox.test" && request.authorization === "Bearer lockbox-operator-token"), true);
    assert.equal(requests.some((request) => request.host === "slipway.test" && request.authorization === "Bearer slipway-session-token"), true);
    const saved = JSON.parse(await readFile(path.join(harness.dir, "home", "keys.json"), "utf8")) as {
      sinks: Record<string, { sinkId: string; dek: string; slipway?: { lockboxSecretVersionId?: string } }>;
    };
    assert.equal(saved.sinks.validator?.sinkId, "slipway-bbx-validator");
    assert.equal(saved.sinks.validator?.dek, dek);
    assert.equal(saved.sinks.validator?.slipway?.lockboxSecretVersionId, "lockbox-secret-version:blackbox");
  });

  it("configures reusable Slipway Blackbox profiles without printing DEK or factory token", async (t) => {
    const harness = await createHarness(t);
    const sessionFile = path.join(harness.dir, "ops-session.json");
    const dek = fixedDek();
    await writeFile(sessionFile, `${JSON.stringify({
      slipwayUrl: "https://slipway.test",
      sessionToken: "slipway-session-token"
    })}\n`);
    const requests: Array<{ host: string; method: string; path: string; authorization?: string; body?: Record<string, unknown> }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      const method = init?.method ?? "GET";
      const authorization = (init?.headers as Record<string, string> | undefined)?.authorization;
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body)) as Record<string, unknown>;
      requests.push({ host: url.hostname, method, path: url.pathname, authorization, body });
      if (url.hostname === "slipway.test" && method === "GET" && url.pathname === "/api/applications/validator/blackbox/configure-slipway-context") {
        return jsonResponse({
          ok: true,
          context: {
            domain: "proof.slipway.blackbox.configure-slipway-context.v1",
            mode: "profile",
            applicationId: "validator",
            repository: "proof-computer/switchboard-validator",
            policyDigest: "a".repeat(64),
            blackbox: {
              profileId: "validator",
              profileName: "validator",
              sinkName: "validator",
              baseUrl: harness.baseUrl,
              network: "acurast-mainnet",
              sinkIdPrefix: "slipway-bbx-",
              factoryId: "validator",
              retentionSecondsMax: 3600,
              maxRetainedBytesMax: 1_000_000,
              maxIngestBytesPerMinuteMax: 1_000_000,
              envName: "BLACKBOX_LOG_CONFIG",
              spoolDir: "./blackbox-log-spool",
              context: { application: "validator" }
            },
            lockbox: {
              envName: "BLACKBOX_LOG_CONFIG",
              uploadUrl: "https://lockbox.test/api/operator/blackbox-profiles"
            }
          }
        });
      }
      if (url.hostname === "lockbox.test" && method === "POST" && url.pathname === "/api/operator/blackbox-profiles") {
        const blackbox = body?.blackbox as Record<string, unknown>;
        assert.equal(body?.domain, "proof.lockbox.operator-blackbox-profile.v1");
        assert.equal(blackbox.dek, dek);
        assert.match(String(blackbox.factoryToken), /^bbx_sf_validator_/);
        return jsonResponse({
          ok: true,
          replayed: false,
          profile: {
            profileId: "validator",
            revision: `sha256:${"4".repeat(64)}`,
            applicationId: "validator",
            repository: "proof-computer/switchboard-validator",
            profileName: "validator",
            blackbox: {
              baseUrl: harness.baseUrl,
              ownerPublicKey: ownerPublicKeyHex,
              network: "acurast-mainnet",
              sinkIdPrefix: "slipway-bbx-",
              factoryId: "validator",
              factoryTokenDigest: `sha256:${"5".repeat(64)}`,
              retentionSecondsMax: 3600,
              maxRetainedBytesMax: 1_000_000,
              maxIngestBytesPerMinuteMax: 1_000_000,
              envName: "BLACKBOX_LOG_CONFIG",
              spoolDir: "./blackbox-log-spool",
              contextDigest: `sha256:${"6".repeat(64)}`,
              dekDigest: `sha256:${"7".repeat(64)}`
            }
          }
        });
      }
      if (url.hostname === "slipway.test" && method === "POST" && url.pathname === "/api/applications/validator/blackbox/configure-slipway-profile-record") {
        return jsonResponse({ ok: true, profile: { profileId: "validator", revision: `sha256:${"4".repeat(64)}` } });
      }
      return harness.fetchImpl(input, init);
    };
    const lines: string[] = [];
    await runBlackboxCli([
      "configure-slipway",
      "validator",
      "--slipway-config-file",
      sessionFile,
      "--dek-env",
      "BLACKBOX_TEST_DEK",
      "--json"
    ], {
      cwd: harness.dir,
      env: {
        ...harness.env,
        BLACKBOX_TEST_DEK: dek,
        PROOF_LOCKBOX_OPERATOR_UPLOAD_TOKEN: "lockbox-operator-token"
      },
      fetchImpl,
      stdout: (line) => lines.push(line)
    });
    const outputText = lines.join("\n");
    assert.equal(outputText.includes(dek), false);
    assert.equal(outputText.includes("bbx_sf_validator_"), false);
    const parsed = JSON.parse(outputText) as { mode?: string; blackbox?: { profileId?: string } };
    assert.equal(parsed.mode, "profile");
    assert.equal(parsed.blackbox?.profileId, "validator");
    assert.equal(requests.some((request) => request.host === "lockbox.test" && request.authorization === "Bearer lockbox-operator-token"), true);
    const saved = JSON.parse(await readFile(path.join(harness.dir, "home", "keys.json"), "utf8")) as {
      profiles?: Record<string, { dek?: string; factoryToken?: string; lockboxProfileRevision?: string }>;
    };
    assert.equal(saved.profiles?.validator?.dek, dek);
    assert.match(saved.profiles?.validator?.factoryToken ?? "", /^bbx_sf_validator_/);
    assert.equal(saved.profiles?.validator?.lockboxProfileRevision, `sha256:${"4".repeat(64)}`);
  });
});

describe("proof-cli Blackbox oclif help", () => {
  it("prints top-level Blackbox help", () => {
    const result = runCommand(commandUrl, []);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Blackbox logging commands/u);
  });

  it("declares native status help metadata", async () => {
    const { default: Command } = await import(statusCommandUrl) as { default: { description?: string; flags?: Record<string, unknown> } };

    assert.match(Command.description ?? "", /Read Blackbox service health/u);
    assert.ok(Command.flags?.["base-url"]);
  });

  it("declares native sink creation help metadata", async () => {
    const { default: Command } = await import(createCommandUrl) as { default: { description?: string; flags?: Record<string, unknown> } };

    assert.match(Command.description ?? "", /Create a Blackbox sink/u);
    assert.ok(Command.flags?.["job-id"]);
  });

  it("declares native configure-slipway help metadata", async () => {
    const { default: Command } = await import(configureSlipwayCommandUrl) as { default: { description?: string; flags?: Record<string, unknown> } };

    assert.match(Command.description ?? "", /Configure Blackbox logging/u);
    assert.ok(Command.flags?.["lockbox-url"]);
  });
});

describe("proof-cli Blackbox native oclif execution", () => {
  it("runs leaf commands through oclif-parsed flags", async (t) => {
    const harness = await createHarness(t);
    const dek = fixedDek();
    harness.batch = makeBatch(dek);
    const stateFile = path.join(harness.dir, "native-keys.json");

    const status = await runCommandInProcess(statusCommandUrl, ["--base-url", harness.baseUrl, "--json"], {
      env: harness.env,
      fetchImpl: harness.fetchImpl
    });
    assert.equal((JSON.parse(status.stdout) as { health: { ok: boolean } }).health.ok, true);

    const created = await runCommandInProcess(createCommandUrl, [
      "--base-url",
      harness.baseUrl,
      "--state-file",
      stateFile,
      "--name",
      "native",
      "--job-id",
      "job-1",
      "--dek",
      dek,
      "--json"
    ], {
      env: harness.env,
      fetchImpl: harness.fetchImpl
    });
    assert.equal((JSON.parse(created.stdout) as { state: { sinkId: string } }).state.sinkId, "sink-1");

    const token = await runCommandInProcess(readTokenCreateCommandUrl, [
      "--state-file",
      stateFile,
      "--name",
      "native",
      "--scope",
      "read",
      "--json"
    ], {
      env: harness.env,
      fetchImpl: harness.fetchImpl
    });
    assert.match((JSON.parse(token.stdout) as { readToken: string }).readToken, /^bbx_rt_/);

    const read = await runCommandInProcess(readCommandUrl, [
      "--state-file",
      stateFile,
      "--name",
      "native",
      "--limit",
      "1",
      "--json"
    ], {
      env: harness.env,
      fetchImpl: harness.fetchImpl
    });
    assert.equal((JSON.parse(read.stdout) as { batches: Array<{ records: Array<{ event: string }> }> }).batches[0]?.records[0]?.event, "boot");
  });

  it("rejects unknown flags before reaching the compatibility parser", async (t) => {
    const harness = await createHarness(t);
    await assert.rejects(
      () => runCommandInProcess(statusCommandUrl, ["--base-url", harness.baseUrl, "--bogus"], {
        env: harness.env,
        fetchImpl: harness.fetchImpl
      }),
      /bogus|Nonexistent flag/u
    );
  });
});

async function createHarness(t: TestContext): Promise<{
  baseUrl: string;
  dir: string;
  env: NodeJS.ProcessEnv;
  batch?: BlackboxBatchDto;
  fetchImpl: typeof fetch;
}> {
  const dir = await mkdtemp(path.join(tmpdir(), "proof-cli-blackbox-"));
  const harness = {
    baseUrl: "https://blackbox.test",
    dir,
    env: {
      ...process.env,
      BLACKBOX_OWNER_URI: OWNER_URI,
      BLACKBOX_ADMIN_TOKEN: "admin-token",
      BLACKBOX_HOME: path.join(dir, "home")
    },
    batch: undefined as BlackboxBatchDto | undefined,
    fetchImpl: (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      const method = init?.method ?? "GET";

      if (url.pathname === "/v1/health") {
        return jsonResponse({ ok: true, service: "blackbox" });
      }
      if (url.pathname === "/v1/account") {
        return jsonResponse({ owner: ownerPublicKeyHex, availableCredit: "100000" });
      }
      if (url.pathname === "/v1/account/ledger") {
        return jsonResponse({ account: { owner: ownerPublicKeyHex, availableCredit: "100000" }, ledger: [] });
      }
      if (method === "POST" && /^\/v1\/admin\/accounts\/[^/]+\/credit-grants$/.test(url.pathname)) {
        return jsonResponse({ creditGrant: { owner: ownerPublicKeyHex, amount: "1000" } });
      }
      if (method === "POST" && url.pathname === "/v1/sinks") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { jobId?: string; deploymentId?: string; owner?: string; network?: string; sinkId?: string };
        return jsonResponse({
          sink: {
            sinkId: body.sinkId ?? "sink-1",
            owner: body.owner ?? ownerPublicKeyHex,
            network: body.network ?? "acurast-mainnet",
            jobId: body.jobId,
            deploymentId: body.deploymentId
          }
        });
      }
      if (method === "POST" && url.pathname === "/v1/sink-factories") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { factoryId?: string; owner?: string; applicationId?: string; network?: string; sinkIdPrefix?: string };
        return jsonResponse({
          factory: {
            factoryId: body.factoryId ?? "factory-1",
            owner: body.owner ?? ownerPublicKeyHex,
            applicationId: body.applicationId ?? "validator",
            network: body.network ?? "acurast-mainnet",
            sinkIdPrefix: body.sinkIdPrefix ?? "slipway-bbx-"
          },
          factoryToken: `bbx_sf_${body.factoryId ?? "factory-1"}_${"a".repeat(48)}`
        }, 201);
      }
      if (method === "POST" && /^\/v1\/sinks\/[^/]+\/read-tokens$/.test(url.pathname)) {
        return jsonResponse({
          token: {
            tokenId: "token-1",
            sinkId: "sink-1",
            scope: "read",
            createdAt: new Date(0).toISOString()
          },
          readToken: "bbx_rt_1"
        });
      }
      if (method === "GET" && /^\/v1\/sinks\/[^/]+\/read-tokens$/.test(url.pathname)) {
        return jsonResponse({ tokens: [] });
      }
      if (method === "DELETE" && /^\/v1\/sinks\/[^/]+\/read-tokens\/[^/]+$/.test(url.pathname)) {
        return jsonResponse({ revoked: true });
      }
      if (method === "GET" && /^\/v1\/sinks\/[^/]+\/events$/.test(url.pathname)) {
        return jsonResponse({ batches: harness.batch ? [harness.batch] : [] });
      }
      if (method === "GET" && /^\/v1\/sinks\/[^/]+\/search$/.test(url.pathname)) {
        return jsonResponse({ scannedBytes: 42, batches: harness.batch ? [harness.batch] : [] });
      }
      if (method === "GET" && /^\/v1\/sinks\/[^/]+\/tail$/.test(url.pathname)) {
        return sseResponse(harness.batch);
      }
      return jsonResponse({ error: `unexpected ${method} ${url.pathname}` }, 404);
    }) as typeof fetch
  };
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  return harness;
}

async function runJson(harness: { dir: string; env: NodeJS.ProcessEnv; fetchImpl: typeof fetch }, args: string[]): Promise<unknown> {
  const lines: string[] = [];
  await runBlackboxCli([...args, "--json"], {
    cwd: harness.dir,
    env: harness.env,
    fetchImpl: harness.fetchImpl,
    stdout: (line) => lines.push(line)
  });
  return JSON.parse(lines.join("\n"));
}

async function runCommandInProcess(
  commandUrlValue: string,
  args: readonly string[],
  options: { env: NodeJS.ProcessEnv; fetchImpl: typeof fetch }
): Promise<{ stdout: string }> {
  const { default: Command } = await import(commandUrlValue) as {
    default: { run(argv?: string[]): Promise<unknown> };
  };
  const previousEnv = process.env;
  const previousFetch = globalThis.fetch;
  const previousExitCode = process.exitCode;
  const previousStdoutWrite = process.stdout.write;
  let stdout = "";
  process.env = { ...previousEnv, ...options.env };
  globalThis.fetch = options.fetchImpl;
  process.stdout.write = ((chunk: string | Uint8Array, ..._args: unknown[]) => {
    stdout += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    return true;
  }) as typeof process.stdout.write;
  try {
    await Command.run([...args]);
    return { stdout };
  } finally {
    process.env = previousEnv;
    globalThis.fetch = previousFetch;
    process.exitCode = previousExitCode;
    process.stdout.write = previousStdoutWrite;
  }
}

function makeBatch(dek: string): BlackboxBatchDto {
  return {
    sinkId: "sink-1",
    jobId: "job-1",
    batchId: "batch-1",
    writerPublicKey: "writer",
    sequenceStart: 1,
    sequenceEnd: 1,
    previousHash: null,
    hash: "0x00",
    byteLength: 100,
    receivedAt: new Date(0).toISOString(),
    labels: { phase: "boot" },
    batch: {
      sinkId: "sink-1",
      jobId: "job-1",
      writerPublicKey: "writer",
      sequenceStart: 1,
      sequenceEnd: 1,
      createdAt: new Date(0).toISOString(),
      encrypted: [encryptRecord(dek, { event: "boot", ok: true })],
      labels: { phase: "boot" }
    }
  };
}

function encryptRecord(key: string, value: unknown) {
  const iv = Buffer.alloc(12, 7);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key, "base64url"), iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return {
    v: 1 as const,
    alg: "A256GCM" as const,
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url")
  };
}

function fixedDek(): string {
  return Buffer.alloc(32, 9).toString("base64url");
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}

function sseResponse(batch: BlackboxBatchDto | undefined): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream({
    start(controller) {
      if (batch) {
        controller.enqueue(encoder.encode(`event: batch\ndata: ${JSON.stringify(batch)}\n\n`));
      }
      controller.close();
    }
  });
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/event-stream"
    }
  });
}

function runCommand(
  commandUrlValue: string,
  args: readonly string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv } = {}
) {
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--eval",
      `const {default: Command} = await import(${JSON.stringify(commandUrlValue)}); await Command.run(${JSON.stringify(args)});`
    ],
    {
      cwd: options.cwd ?? repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        NODE_ENV: "test",
        ...options.env
      }
    }
  );
}
