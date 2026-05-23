import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

import { Keyring } from "@polkadot/keyring";
import { u8aToHex } from "@polkadot/util";
import { cryptoWaitReady } from "@polkadot/util-crypto";

import { generateBlackboxLogDek } from "./internal/crypto.js";
import { discoverServices, normalizeBaseUrl, resolveBlackboxBaseUrls } from "./internal/discovery.js";
import { createBlackboxReader } from "./internal/reader.js";
import { createBlackboxSignedJsonRequest, type BlackboxRequestSigner } from "./internal/signer.js";

export interface BlackboxCliOptions {
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  fetchImpl?: typeof fetch;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
  now?: () => Date;
}

export interface ParsedArgs {
  positionals: string[];
  flags: Map<string, string | boolean | string[]>;
}

export type BlackboxCliFlagValue = string | boolean | string[] | undefined;
export type BlackboxCliFlags =
  | ReadonlyMap<string, string | boolean | string[]>
  | Record<string, BlackboxCliFlagValue>;

export interface BlackboxNativeCommandInput {
  flags?: BlackboxCliFlags;
}

interface SavedBlackboxSinkState {
  name: string;
  baseUrl: string;
  sinkId: string;
  jobId?: string;
  deploymentId?: string;
  owner: string;
  writeUrl: string;
  dek: string;
  createdAt: string;
  slipway?: {
    applicationId: string;
    policyDigest: string;
    dispatchId: string;
    lockboxSecretVersionId?: string;
    configDigest?: string;
    dekDigest?: string;
    configuredAt?: string;
  };
  readTokens?: Record<string, SavedReadTokenState>;
  defaultReadTokenId?: string;
}

interface SavedBlackboxKeysFile {
  version: 1;
  defaultSink?: string;
  sinks: Record<string, SavedBlackboxSinkState>;
  profiles?: Record<string, SavedBlackboxProfileState>;
}

interface SavedBlackboxProfileState {
  name: string;
  applicationId: string;
  repository: string;
  policyDigest: string;
  profileId: string;
  revision?: string;
  baseUrl: string;
  owner: string;
  dek: string;
  factoryId: string;
  factoryToken: string;
  factoryTokenDigest?: string;
  lockboxProfileRevision?: string;
  configuredAt: string;
}

interface SavedReadTokenState {
  tokenId: string;
  readToken: string;
  scope: "read" | "tail";
  createdAt: string;
}

interface CreateSinkResponse {
  sink: {
    sinkId: string;
    owner: string;
    network: string;
    deploymentId?: string;
    jobId?: string;
  };
}

interface ReadTokenCreateResponse {
  token: {
    tokenId: string;
    sinkId: string;
    scope: "read" | "tail";
    createdAt: string;
  };
  readToken: string;
}

interface SlipwayConfigureContext {
  domain: "proof.slipway.blackbox.configure-slipway-context.v1";
  mode?: "job" | "profile";
  applicationId: string;
  repository: string;
  policyVersionId?: string;
  policyDigest: string;
  manifestDigest?: string;
  dispatchId?: string;
  planItemId?: string;
  idempotencyKey?: string;
  job?: {
    jobId: string;
    deploymentId: string;
    [key: string]: unknown;
  };
  blackbox: {
    sinkId?: string;
    sinkName: string;
    baseUrl: string;
    writeUrl?: string;
    jobId?: string;
    deploymentId?: string;
    profileId?: string;
    profileName?: string;
    network?: string;
    sinkIdPrefix?: string;
    factoryId?: string;
    retentionSecondsMax?: number;
    maxRetainedBytesMax?: number;
    maxIngestBytesPerMinuteMax?: number;
    envName: string;
    spoolDir: string;
    context?: Record<string, string | number | boolean>;
    contextDigest?: string;
  };
  lockbox?: {
    secretId?: string;
    envName?: string;
    uploadUrl?: string;
  };
}

type SlipwayJobConfigureContext = SlipwayConfigureContext & {
  mode?: "job";
  policyVersionId: string;
  manifestDigest: string;
  dispatchId: string;
  planItemId: string;
  idempotencyKey: string;
  job: {
    jobId: string;
    deploymentId: string;
    [key: string]: unknown;
  };
  blackbox: SlipwayConfigureContext["blackbox"] & {
    sinkId: string;
    writeUrl: string;
    jobId: string;
    deploymentId: string;
  };
};

type SlipwayProfileConfigureContext = SlipwayConfigureContext & {
  mode: "profile";
  blackbox: SlipwayConfigureContext["blackbox"] & {
    profileId: string;
    profileName: string;
    network: string;
    sinkIdPrefix: string;
    factoryId: string;
    retentionSecondsMax: number;
    maxRetainedBytesMax: number;
    maxIngestBytesPerMinuteMax: number;
  };
};

interface LockboxOperatorUploadResponse {
  replayed?: boolean;
  secretVersion: {
    secretId: string;
    versionId: string;
    target: "env" | "file";
    name: string;
    required: boolean;
    bundleId: string;
    encryptedPayloadDigest: string;
  };
  configDigest: string;
  dekDigest: string;
}

interface LockboxOperatorProfileUploadResponse {
  replayed?: boolean;
  profile: {
    profileId: string;
    revision: string;
    applicationId: string;
    repository: string;
    profileName: string;
    blackbox: {
      baseUrl: string;
      ownerPublicKey: string;
      network: string;
      sinkIdPrefix: string;
      factoryId: string;
      factoryTokenDigest: string;
      retentionSecondsMax: number;
      maxRetainedBytesMax: number;
      maxIngestBytesPerMinuteMax: number;
      envName: string;
      spoolDir: string;
      contextDigest: string;
      dekDigest: string;
    };
  };
}

export async function runBlackboxCli(argv = process.argv.slice(2), options: BlackboxCliOptions = {}): Promise<void> {
  const parsed = parseArgs(argv);
  const command = normalizeCommand(parsed.positionals);
  if (command === "help" || boolFlag(parsed.flags, "help") || boolFlag(parsed.flags, "h")) {
    emit(options, helpText());
    return;
  }

  switch (command) {
    case "status":
      await runBlackboxStatus({ flags: parsed.flags }, options);
      return;
    case "account":
      await runBlackboxAccount({ flags: parsed.flags }, options);
      return;
    case "admin-grant-credit":
      await runBlackboxAdminGrantCredit({ flags: parsed.flags }, options);
      return;
    case "sinks-create":
      await runBlackboxSinksCreate({ flags: parsed.flags }, options);
      return;
    case "configure-slipway":
      await runBlackboxConfigureSlipway({
        applicationId: requiredPositional(parsed, 1, "APPLICATION_ID"),
        flags: parsed.flags
      }, options);
      return;
    case "read-token-create":
      await runBlackboxReadTokenCreate({ flags: parsed.flags }, options);
      return;
    case "read-token-list":
      await runBlackboxReadTokenList({ flags: parsed.flags }, options);
      return;
    case "read-token-revoke":
      await runBlackboxReadTokenRevoke({ flags: parsed.flags }, options);
      return;
    case "read":
      await runBlackboxRead({ flags: parsed.flags }, options);
      return;
    case "search":
      await runBlackboxSearch({ flags: parsed.flags }, options);
      return;
    case "tail":
      await runBlackboxTail({ flags: parsed.flags }, options);
      return;
  }
}

export async function runBlackboxCliToExitCode(argv: readonly string[], options: BlackboxCliOptions = {}): Promise<number> {
  try {
    await runBlackboxCli([...argv], options);
    return typeof process.exitCode === "number" ? process.exitCode : 0;
  } catch (error) {
    (options.stderr ?? console.error)(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

export async function runBlackboxStatus(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await statusCommand(parsedCommandInput(["status"], input.flags), options);
}

export async function runBlackboxAccount(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await accountCommand(parsedCommandInput(["account"], input.flags), options);
}

export async function runBlackboxAdminGrantCredit(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await adminGrantCreditCommand(parsedCommandInput(["admin", "grant-credit"], input.flags), options);
}

export async function runBlackboxSinksCreate(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await sinksCreateCommand(parsedCommandInput(["sinks", "create"], input.flags), options);
}

export async function runBlackboxConfigureSlipway(
  input: BlackboxNativeCommandInput & { applicationId: string },
  options: BlackboxCliOptions = {}
): Promise<void> {
  await configureSlipwayCommand(parsedCommandInput(["configure-slipway", input.applicationId], input.flags), options);
}

export async function runBlackboxReadTokenCreate(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await readTokenCreateCommand(parsedCommandInput(["read-token", "create"], input.flags), options);
}

export async function runBlackboxReadTokenList(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await readTokenListCommand(parsedCommandInput(["read-token", "list"], input.flags), options);
}

export async function runBlackboxReadTokenRevoke(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await readTokenRevokeCommand(parsedCommandInput(["read-token", "revoke"], input.flags), options);
}

export async function runBlackboxRead(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await readCommand(parsedCommandInput(["read"], input.flags), options);
}

export async function runBlackboxSearch(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await searchCommand(parsedCommandInput(["search"], input.flags), options);
}

export async function runBlackboxTail(input: BlackboxNativeCommandInput = {}, options: BlackboxCliOptions = {}): Promise<void> {
  await tailCommand(parsedCommandInput(["tail"], input.flags), options);
}

async function statusCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const cwd = options.cwd ?? process.cwd();
  const state = await maybeLoadSinkState(cwd, stateName(parsed.flags), parsed.flags, options.env ?? process.env);
  const baseUrl = await resolveBlackboxCliBaseUrl({
    flags: parsed.flags,
    env: options.env ?? process.env,
    cwd,
    state,
    fetchImpl
  });
  const health = await fetchJson(new URL("/v1/health", baseUrl).toString(), { fetchImpl });
  const adminTokenEnv = stringFlag(parsed.flags, "admin-token-env");
  const status = adminTokenEnv
    ? await fetchJson(new URL("/v1/admin/status", baseUrl).toString(), {
        fetchImpl,
        headers: { authorization: `Bearer ${requiredEnv(options.env ?? process.env, adminTokenEnv)}` }
      })
    : undefined;
  output(parsed, options, { baseUrl, health, admin: status }, `Blackbox ${health.service ?? "service"} at ${baseUrl}`);
}

async function accountCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const context = await commandContext(parsed, options);
  const route = boolFlag(parsed.flags, "ledger") ? "/v1/account/ledger" : "/v1/account";
  const account = await signedJson({
    baseUrl: context.baseUrl,
    path: route,
    method: "GET",
    signer: context.signer,
    fetchImpl: context.fetchImpl
  });
  output(parsed, options, account, accountSummary(account));
}

async function adminGrantCreditCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const env = options.env ?? process.env;
  const adminTokenEnv = stringFlag(parsed.flags, "admin-token-env");
  if (!adminTokenEnv) {
    throw new Error("admin grant-credit requires explicit --admin-token-env");
  }
  const owner = requiredStringFlag(parsed.flags, "owner");
  const amount = requiredStringFlag(parsed.flags, "amount");
  const fetchImpl = options.fetchImpl ?? fetch;
  const cwd = options.cwd ?? process.cwd();
  const state = await maybeLoadSinkState(cwd, stateName(parsed.flags), parsed.flags, env);
  const baseUrl = await resolveBlackboxCliBaseUrl({
    flags: parsed.flags,
    env,
    cwd,
    state,
    fetchImpl
  });
  const body = {
    amount,
    topUpId: stringFlag(parsed.flags, "top-up-id") ?? `blackbox-cli-${Date.now()}-${randomBytes(6).toString("hex")}`,
    source: stringFlag(parsed.flags, "source") ?? "blackbox-cli-admin"
  };
  const response = await fetchJson(new URL(`/v1/admin/accounts/${encodeURIComponent(owner)}/credit-grants`, baseUrl).toString(), {
    fetchImpl,
    method: "POST",
    headers: {
      authorization: `Bearer ${requiredEnv(env, adminTokenEnv)}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });
  output(parsed, options, response, `Granted ${amount} ACU atomic units to ${owner}`);
}

async function sinksCreateCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const context = await commandContext(parsed, options);
  const owner = context.signer.publicKeyHex;
  const jobId = stringFlag(parsed.flags, "job-id");
  const deploymentId = stringFlag(parsed.flags, "deployment-id");
  if (!jobId && !deploymentId) {
    throw new Error("sinks create requires --job-id or --deployment-id");
  }
  const body = {
    sinkId: stringFlag(parsed.flags, "sink-id"),
    owner,
    network: stringFlag(parsed.flags, "network") ?? context.env.BLACKBOX_NETWORK ?? "acurast-mainnet",
    deploymentId,
    jobId,
    retentionSeconds: numberFlag(parsed.flags, "retention-seconds", 86_400),
    maxRetainedBytes: numberFlag(parsed.flags, "max-retained-bytes", 100_000_000),
    maxIngestBytesPerMinute: numberFlag(parsed.flags, "max-ingest-bytes-per-minute", 10_000_000),
    labels: labelFlags(parsed.flags)
  };
  const created = await signedJson<CreateSinkResponse>({
    baseUrl: context.baseUrl,
    path: "/v1/sinks",
    method: "POST",
    signer: context.signer,
    body,
    fetchImpl: context.fetchImpl
  });
  const name = stateName(parsed.flags) ?? created.sink.sinkId;
  const dek = stringFlag(parsed.flags, "dek") ?? generateBlackboxLogDek();
  const state: SavedBlackboxSinkState = {
    name,
    baseUrl: context.baseUrl,
    sinkId: created.sink.sinkId,
    jobId: created.sink.jobId,
    deploymentId: created.sink.deploymentId,
    owner,
    writeUrl: new URL(`/v1/sinks/${encodeURIComponent(created.sink.sinkId)}/events`, context.baseUrl).toString(),
    dek,
    createdAt: nowIso(options)
  };
  await saveSinkState(context.cwd, state, parsed.flags, context.env);
  const envFile = stringFlag(parsed.flags, "env-file");
  if (envFile) {
    await writeRuntimeEnvFile(path.resolve(context.cwd, envFile), state, parsed.flags);
  }
  output(parsed, options, { ...created, state }, `Created Blackbox sink ${state.sinkId} (${name})`);
}

async function configureSlipwayCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const applicationId = requiredPositional(parsed, 1, "APPLICATION_ID");
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const fetchImpl = options.fetchImpl ?? fetch;
  const session = await resolveSlipwaySession(parsed.flags, env);
  requireSecureHttpUrl(session.slipwayUrl, "Slipway URL", env);
  const contextResult = await fetchJson<{ context?: SlipwayConfigureContext }>(
    new URL(`/api/applications/${encodeURIComponent(applicationId)}/blackbox/configure-slipway-context`, session.slipwayUrl).toString(),
    {
      fetchImpl,
      headers: { authorization: `Bearer ${session.sessionToken}` }
    }
  );
  const context = contextResult.context;
  if (!context) throw new Error("Slipway configure-slipway context response did not include context");
  if (context.mode === "profile") {
    await configureSlipwayProfileCommand({
      applicationId,
      context,
      parsed,
      options,
      session,
      env,
      cwd,
      fetchImpl
    });
    return;
  }
  assertSlipwayJobContext(context);
  const name = stateName(parsed.flags) ?? context.blackbox.sinkName ?? applicationId;
  const currentState = await maybeLoadSinkState(cwd, name, parsed.flags, env);
  const lockboxUrl = resolveLockboxOperatorUploadUrl(parsed.flags, env, context);
  requireSecureHttpUrl(lockboxUrl, "Lockbox URL", env);

  if (boolFlag(parsed.flags, "dry-run")) {
    output(parsed, options, {
      dryRun: true,
      applicationId,
      blackbox: {
        sinkId: context.blackbox.sinkId,
        sinkName: context.blackbox.sinkName,
        baseUrl: context.blackbox.baseUrl,
        writeUrl: context.blackbox.writeUrl,
        jobId: context.blackbox.jobId,
        deploymentId: context.blackbox.deploymentId
      },
      lockbox: {
        uploadUrl: lockboxUrl,
        secretId: context.lockbox?.secretId ?? "blackbox-log-config",
        envName: context.lockbox?.envName ?? context.blackbox.envName
      },
      state: {
        name,
        willReuseLocalDek: Boolean(currentState?.dek && currentState.sinkId === context.blackbox.sinkId)
      }
    }, `Would configure Blackbox for ${applicationId} using sink ${context.blackbox.sinkId}`);
    return;
  }

  const signer = await ownerSigner(parsed.flags, env);
  const sink = await ensureConfigureSlipwaySink({
    context,
    signer,
    fetchImpl
  });
  const dek = await resolveConfigureSlipwayDek({
    flags: parsed.flags,
    env,
    cwd,
    currentState,
    context
  });
  const compactConfig = buildCompactBlackboxLogConfig({
    context,
    dek,
    writeUrl: sink.writeUrl
  });
  const state: SavedBlackboxSinkState = {
    ...currentState,
    name,
    baseUrl: context.blackbox.baseUrl,
    sinkId: sink.sinkId,
    jobId: sink.jobId,
    deploymentId: sink.deploymentId,
    owner: signer.publicKeyHex,
    writeUrl: sink.writeUrl,
    dek,
    createdAt: currentState?.createdAt ?? nowIso(options),
    slipway: {
      applicationId,
      policyDigest: context.policyDigest,
      dispatchId: context.dispatchId,
      configuredAt: nowIso(options)
    }
  };
  await saveSinkState(cwd, state, parsed.flags, env);

  const lockboxTokenEnv = stringFlag(parsed.flags, "lockbox-token-env") ?? "PROOF_LOCKBOX_OPERATOR_UPLOAD_TOKEN";
  const lockbox = await fetchJson<LockboxOperatorUploadResponse>(lockboxUrl, {
    fetchImpl,
    method: "POST",
    headers: {
      authorization: `Bearer ${requiredEnv(env, lockboxTokenEnv)}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      domain: "proof.lockbox.operator-blackbox-log-config-secret-version.v1",
      applicationId,
      repository: context.repository,
      policyVersionId: context.policyVersionId,
      policyDigest: context.policyDigest,
      manifestDigest: context.manifestDigest,
      dispatchId: context.dispatchId,
      planItemId: context.planItemId,
      idempotencyKey: context.idempotencyKey,
      job: {
        jobId: context.job.jobId,
        deploymentId: context.job.deploymentId
      },
      blackbox: {
        sinkId: sink.sinkId,
        sinkName: context.blackbox.sinkName,
        baseUrl: context.blackbox.baseUrl,
        writeUrl: sink.writeUrl,
        ownerPublicKey: signer.publicKeyHex,
        envName: context.blackbox.envName,
        spoolDir: context.blackbox.spoolDir,
        context: context.blackbox.context ?? {}
      },
      compactConfig
    })
  });

  const record = await fetchJson<Record<string, unknown>>(
    new URL(`/api/applications/${encodeURIComponent(applicationId)}/blackbox/configure-slipway-record`, session.slipwayUrl).toString(),
    {
      fetchImpl,
      method: "POST",
      headers: {
        authorization: `Bearer ${session.sessionToken}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        configDigest: lockbox.configDigest,
        dekDigest: lockbox.dekDigest,
        blackbox: {
          sinkId: sink.sinkId,
          baseUrl: context.blackbox.baseUrl,
          writeUrl: sink.writeUrl,
          jobId: sink.jobId,
          deploymentId: sink.deploymentId,
          ownerPublicKey: signer.publicKeyHex,
          idempotencyState: sink.idempotencyState
        },
        lockbox: lockbox.secretVersion
      })
    }
  );

  state.slipway = {
    applicationId,
    policyDigest: context.policyDigest,
    dispatchId: context.dispatchId,
    configuredAt: state.slipway?.configuredAt ?? nowIso(options),
    lockboxSecretVersionId: lockbox.secretVersion.versionId,
    configDigest: lockbox.configDigest,
    dekDigest: lockbox.dekDigest
  };
  await saveSinkState(cwd, state, parsed.flags, env);

  output(parsed, options, {
    applicationId,
    blackbox: {
      sinkId: sink.sinkId,
      sinkName: context.blackbox.sinkName,
      baseUrl: context.blackbox.baseUrl,
      writeUrl: sink.writeUrl,
      jobId: sink.jobId,
      deploymentId: sink.deploymentId,
      ownerPublicKey: normalizePublicKeyHex(signer.publicKeyHex),
      idempotencyState: sink.idempotencyState
    },
    lockbox: {
      replayed: Boolean(lockbox.replayed),
      secretVersion: lockbox.secretVersion,
      configDigest: lockbox.configDigest,
      dekDigest: lockbox.dekDigest
    },
    slipway: record
  }, `Configured Blackbox for ${applicationId}: sink ${sink.sinkId}, Lockbox ${lockbox.secretVersion.versionId}`);
}

async function configureSlipwayProfileCommand(input: {
  applicationId: string;
  context: SlipwayConfigureContext;
  parsed: ParsedArgs;
  options: BlackboxCliOptions;
  session: { slipwayUrl: string; sessionToken: string };
  env: NodeJS.ProcessEnv;
  cwd: string;
  fetchImpl: typeof fetch;
}): Promise<void> {
  assertSlipwayProfileContext(input.context);
  const context = input.context;
  const name = stateName(input.parsed.flags) ?? context.blackbox.profileId ?? input.applicationId;
  const currentProfile = await maybeLoadProfileState(name, input.parsed.flags, input.env);
  const lockboxUrl = resolveLockboxOperatorProfileUploadUrl(input.parsed.flags, input.env, context);
  requireSecureHttpUrl(lockboxUrl, "Lockbox URL", input.env);

  if (boolFlag(input.parsed.flags, "dry-run")) {
    output(input.parsed, input.options, {
      dryRun: true,
      applicationId: input.applicationId,
      mode: "profile",
      blackbox: {
        profileId: context.blackbox.profileId,
        profileName: context.blackbox.profileName,
        baseUrl: context.blackbox.baseUrl,
        factoryId: context.blackbox.factoryId,
        sinkIdPrefix: context.blackbox.sinkIdPrefix,
        envName: context.blackbox.envName,
        spoolDir: context.blackbox.spoolDir
      },
      lockbox: {
        uploadUrl: lockboxUrl,
        envName: context.lockbox?.envName ?? context.blackbox.envName
      },
      state: {
        name,
        willReuseLocalDek: Boolean(currentProfile?.dek),
        hasSavedFactoryToken: Boolean(currentProfile?.factoryToken && currentProfile.factoryId === context.blackbox.factoryId)
      }
    }, `Would configure reusable Blackbox profile ${context.blackbox.profileId} for ${input.applicationId}`);
    return;
  }

  const signer = await ownerSigner(input.parsed.flags, input.env);
  const dek = await resolveConfigureSlipwayProfileDek({
    flags: input.parsed.flags,
    env: input.env,
    cwd: input.cwd,
    currentProfile
  });
  await ensureKeysFileWritable(input.parsed.flags, input.env);
  const factory = await ensureConfigureSlipwaySinkFactory({
    context,
    signer,
    currentProfile,
    rotateFactoryToken: boolFlag(input.parsed.flags, "rotate-factory-token"),
    fetchImpl: input.fetchImpl
  });
  const configuredAt = nowIso(input.options);
  const pendingProfileState: SavedBlackboxProfileState = {
    ...currentProfile,
    name,
    applicationId: input.applicationId,
    repository: context.repository,
    policyDigest: context.policyDigest,
    profileId: context.blackbox.profileId,
    baseUrl: context.blackbox.baseUrl,
    owner: signer.publicKeyHex,
    dek,
    factoryId: context.blackbox.factoryId,
    factoryToken: factory.factoryToken,
    configuredAt
  };
  await saveProfileState({
    name,
    state: pendingProfileState,
    flags: input.parsed.flags,
    env: input.env
  });
  const lockboxTokenEnv = stringFlag(input.parsed.flags, "lockbox-token-env") ?? "PROOF_LOCKBOX_OPERATOR_UPLOAD_TOKEN";
  const lockbox = await fetchJson<LockboxOperatorProfileUploadResponse>(lockboxUrl, {
    fetchImpl: input.fetchImpl,
    method: "POST",
    headers: {
      authorization: `Bearer ${requiredEnv(input.env, lockboxTokenEnv)}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      domain: "proof.lockbox.operator-blackbox-profile.v1",
      applicationId: input.applicationId,
      repository: context.repository,
      profileId: context.blackbox.profileId,
      profileName: context.blackbox.profileName,
      blackbox: {
        baseUrl: context.blackbox.baseUrl,
        ownerPublicKey: signer.publicKeyHex,
        network: context.blackbox.network,
        sinkIdPrefix: context.blackbox.sinkIdPrefix,
        factoryId: context.blackbox.factoryId,
        factoryToken: factory.factoryToken,
        retentionSecondsMax: context.blackbox.retentionSecondsMax,
        maxRetainedBytesMax: context.blackbox.maxRetainedBytesMax,
        maxIngestBytesPerMinuteMax: context.blackbox.maxIngestBytesPerMinuteMax,
        envName: context.blackbox.envName,
        spoolDir: context.blackbox.spoolDir,
        context: context.blackbox.context ?? {},
        dek
      }
    })
  });

  const record = await fetchJson<Record<string, unknown>>(
    new URL(`/api/applications/${encodeURIComponent(input.applicationId)}/blackbox/configure-slipway-profile-record`, input.session.slipwayUrl).toString(),
    {
      fetchImpl: input.fetchImpl,
      method: "POST",
      headers: {
        authorization: `Bearer ${input.session.sessionToken}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        profile: lockbox.profile
      })
    }
  );

  await saveProfileState({
    name,
    state: {
      ...pendingProfileState,
      revision: lockbox.profile.revision,
      factoryTokenDigest: lockbox.profile.blackbox.factoryTokenDigest,
      lockboxProfileRevision: lockbox.profile.revision
    },
    flags: input.parsed.flags,
    env: input.env
  });

  output(input.parsed, input.options, {
    applicationId: input.applicationId,
    mode: "profile",
    blackbox: {
      profileId: lockbox.profile.profileId,
      revision: lockbox.profile.revision,
      profileName: lockbox.profile.profileName,
      baseUrl: lockbox.profile.blackbox.baseUrl,
      ownerPublicKey: normalizePublicKeyHex(lockbox.profile.blackbox.ownerPublicKey),
      network: lockbox.profile.blackbox.network,
      sinkIdPrefix: lockbox.profile.blackbox.sinkIdPrefix,
      factoryId: lockbox.profile.blackbox.factoryId,
      envName: lockbox.profile.blackbox.envName,
      spoolDir: lockbox.profile.blackbox.spoolDir,
      contextDigest: lockbox.profile.blackbox.contextDigest,
      dekDigest: lockbox.profile.blackbox.dekDigest
    },
    lockbox: {
      replayed: Boolean(lockbox.replayed),
      profileRevision: lockbox.profile.revision
    },
    localState: {
      name,
      factoryTokenSource: factory.tokenSource,
      factoryTokenRotated: factory.tokenSource === "rotated"
    },
    slipway: record
  }, `Configured reusable Blackbox profile ${lockbox.profile.profileId} for ${input.applicationId}`);
}

async function readTokenCreateCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const context = await commandContext(parsed, options);
  const sinkId = resolveSinkId(parsed.flags, context.state);
  const scope = stringFlag(parsed.flags, "scope") ?? "read";
  if (scope !== "read" && scope !== "tail") {
    throw new Error("--scope must be read or tail");
  }
  const created = await signedJson<ReadTokenCreateResponse>({
    baseUrl: context.baseUrl,
    path: `/v1/sinks/${encodeURIComponent(sinkId)}/read-tokens`,
    method: "POST",
    signer: context.signer,
    body: {
      tokenId: stringFlag(parsed.flags, "token-id"),
      scope,
      wrappedDek: stringFlag(parsed.flags, "wrapped-dek"),
      expiresAt: stringFlag(parsed.flags, "expires-at")
    },
    fetchImpl: context.fetchImpl
  });
  if (context.state) {
    context.state.readTokens = context.state.readTokens ?? {};
    context.state.readTokens[created.token.tokenId] = {
      tokenId: created.token.tokenId,
      readToken: created.readToken,
      scope,
      createdAt: created.token.createdAt
    };
    context.state.defaultReadTokenId = created.token.tokenId;
    await saveSinkState(context.cwd, context.state, parsed.flags, context.env);
  }
  output(parsed, options, created, `Created ${scope} token ${created.token.tokenId}`);
}

async function readTokenListCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const context = await commandContext(parsed, options);
  const sinkId = resolveSinkId(parsed.flags, context.state);
  const result = await signedJson({
    baseUrl: context.baseUrl,
    path: `/v1/sinks/${encodeURIComponent(sinkId)}/read-tokens`,
    method: "GET",
    signer: context.signer,
    fetchImpl: context.fetchImpl
  });
  output(parsed, options, result, `Read tokens for ${sinkId}`);
}

async function readTokenRevokeCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const context = await commandContext(parsed, options);
  const sinkId = resolveSinkId(parsed.flags, context.state);
  const tokenId = requiredStringFlag(parsed.flags, "token-id");
  const result = await signedJson({
    baseUrl: context.baseUrl,
    path: `/v1/sinks/${encodeURIComponent(sinkId)}/read-tokens/${encodeURIComponent(tokenId)}`,
    method: "DELETE",
    signer: context.signer,
    fetchImpl: context.fetchImpl
  });
  if (context.state?.readTokens?.[tokenId]) {
    delete context.state.readTokens[tokenId];
    if (context.state.defaultReadTokenId === tokenId) {
      context.state.defaultReadTokenId = undefined;
    }
    await saveSinkState(context.cwd, context.state, parsed.flags, context.env);
  }
  output(parsed, options, result, `Revoked token ${tokenId}`);
}

async function readCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const reader = await readerContext(parsed, options);
  const result = await reader.reader.readBatches({
    jobId: stringFlag(parsed.flags, "job-id"),
    afterSequence: optionalNumberFlag(parsed.flags, "after-sequence"),
    limit: optionalNumberFlag(parsed.flags, "limit")
  });
  output(parsed, options, result, `${result.batches.length} batch(es)`);
}

async function searchCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const reader = await readerContext(parsed, options);
  const result = await reader.reader.searchBatches({
    jobId: stringFlag(parsed.flags, "job-id"),
    batchId: stringFlag(parsed.flags, "batch-id"),
    receivedAfter: stringFlag(parsed.flags, "received-after"),
    receivedBefore: stringFlag(parsed.flags, "received-before"),
    sequenceStart: optionalNumberFlag(parsed.flags, "sequence-start"),
    sequenceEnd: optionalNumberFlag(parsed.flags, "sequence-end"),
    limit: optionalNumberFlag(parsed.flags, "limit"),
    labels: labelFlags(parsed.flags)
  });
  output(parsed, options, result, `${result.batches.length} batch(es), scanned ${result.scannedBytes} bytes`);
}

async function tailCommand(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<void> {
  const reader = await readerContext(parsed, options);
  const limit = numberFlag(parsed.flags, "limit", 1);
  const timeoutMs = numberFlag(parsed.flags, "timeout-ms", 15_000);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const batches = [];
  try {
    for await (const batch of reader.reader.tailBatches({ signal: controller.signal })) {
      batches.push(batch);
      if (batches.length >= limit) {
        controller.abort();
        break;
      }
    }
  } catch (error) {
    if (!controller.signal.aborted) {
      throw error;
    }
  } finally {
    clearTimeout(timeout);
  }
  output(parsed, options, { batches }, `${batches.length} tail batch(es)`);
}

interface CommandContext {
  env: NodeJS.ProcessEnv;
  cwd: string;
  fetchImpl: typeof fetch;
  baseUrl: string;
  state?: SavedBlackboxSinkState;
  signer: BlackboxRequestSigner;
}

async function commandContext(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<CommandContext> {
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const fetchImpl = options.fetchImpl ?? fetch;
  const state = await maybeLoadSinkState(cwd, stateName(parsed.flags), parsed.flags, env);
  const baseUrl = await resolveBlackboxCliBaseUrl({ flags: parsed.flags, env, cwd, state, fetchImpl });
  const signer = await ownerSigner(parsed.flags, env);
  return { env, cwd, fetchImpl, baseUrl, state, signer };
}

async function readerContext(parsed: ParsedArgs, options: BlackboxCliOptions): Promise<{
  reader: ReturnType<typeof createBlackboxReader>;
}> {
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const fetchImpl = options.fetchImpl ?? fetch;
  const name = stateName(parsed.flags);
  const state = await maybeLoadSinkState(cwd, name, parsed.flags, env);
  const profile = state ? undefined : await maybeLoadProfileState(name, parsed.flags, env);
  const baseUrl = await resolveBlackboxCliBaseUrl({ flags: parsed.flags, env, cwd, state: state ?? profile, fetchImpl });
  const sinkId = resolveSinkId(parsed.flags, state);
  const dek = resolveDek(parsed.flags, env, state ?? profile);
  const readToken = resolveReadToken(parsed.flags, env, state);
  const signer = readToken ? undefined : await ownerSigner(parsed.flags, env);
  return {
    reader: createBlackboxReader({
      baseUrl,
      sinkId,
      dek,
      readToken,
      signer,
      fetch: fetchImpl
    })
  };
}

export async function resolveBlackboxCliBaseUrl(input: {
  flags: Map<string, string | boolean | string[]>;
  env: NodeJS.ProcessEnv;
  cwd: string;
  state?: { baseUrl?: string };
  fetchImpl?: typeof fetch;
}): Promise<string> {
  const explicit = stringFlag(input.flags, "base-url") ?? input.env.BLACKBOX_BASE_URL ?? input.state?.baseUrl;
  if (explicit) {
    return normalizeBaseUrl(explicit);
  }
  const manifestUrl = stringFlag(input.flags, "manifest-url");
  const manifestSigner = stringFlag(input.flags, "manifest-signer");
  if (manifestUrl && manifestSigner) {
    const discovery = await discoverServices({
      manifestUrlCandidates: [manifestUrl],
      expectedManifestSigner: manifestSigner,
      requiredCatalogs: ["blackbox"],
      fetchImpl: input.fetchImpl ?? fetch
    });
    const [baseUrl] = resolveBlackboxBaseUrls(discovery);
    if (baseUrl) {
      return baseUrl;
    }
  }
  throw new Error("Blackbox base URL is required via --base-url, BLACKBOX_BASE_URL, saved state, or signed discovery flags");
}

async function ownerSigner(flags: Map<string, string | boolean | string[]>, env: NodeJS.ProcessEnv): Promise<BlackboxRequestSigner> {
  const envName = stringFlag(flags, "owner-uri-env") ?? "BLACKBOX_OWNER_URI";
  const uri = env[envName];
  if (!uri) {
    throw new Error(`${envName} is required for owner-signed Blackbox commands`);
  }
  await cryptoWaitReady();
  const keyring = new Keyring({ type: "sr25519" });
  const pair = keyring.addFromUri(uri);
  return {
    scheme: "Sr25519",
    publicKeyHex: u8aToHex(pair.publicKey),
    sign(message: Uint8Array): Uint8Array {
      return pair.sign(message);
    }
  };
}

async function signedJson<T = unknown>(input: {
  baseUrl: string;
  path: string;
  method: string;
  signer: BlackboxRequestSigner;
  body?: unknown;
  fetchImpl: typeof fetch;
}): Promise<T> {
  const url = new URL(input.path, input.baseUrl).toString();
  const request = await createBlackboxSignedJsonRequest({
    signer: input.signer,
    method: input.method,
    path: pathWithQuery(url),
    body: input.body
  });
  return fetchJson<T>(url, {
    fetchImpl: input.fetchImpl,
    method: input.method,
    headers: request.headers,
    body: request.body
  });
}

async function signedJsonRaw(input: {
  baseUrl: string;
  path: string;
  method: string;
  signer: BlackboxRequestSigner;
  body?: unknown;
  fetchImpl: typeof fetch;
}): Promise<{ response: Response; body: unknown }> {
  const url = new URL(input.path, input.baseUrl).toString();
  const request = await createBlackboxSignedJsonRequest({
    signer: input.signer,
    method: input.method,
    path: pathWithQuery(url),
    body: input.body
  });
  const response = await input.fetchImpl(url, {
    method: input.method,
    headers: request.headers,
    body: request.body
  });
  const text = await response.text();
  let body: unknown;
  try {
    body = text.length === 0 ? {} : JSON.parse(text);
  } catch {
    body = { body: text };
  }
  return { response, body };
}

async function ensureConfigureSlipwaySink(input: {
  context: SlipwayJobConfigureContext;
  signer: BlackboxRequestSigner;
  fetchImpl: typeof fetch;
}): Promise<{
  sinkId: string;
  owner: string;
  jobId: string;
  deploymentId: string;
  writeUrl: string;
  idempotencyState: "created" | "reused";
}> {
  const existing = await signedJsonRaw({
    baseUrl: input.context.blackbox.baseUrl,
    path: `/v1/sinks/${encodeURIComponent(input.context.blackbox.sinkId)}`,
    method: "GET",
    signer: input.signer,
    fetchImpl: input.fetchImpl
  });
  if (existing.response.ok) {
    const sink = (existing.body as { sink?: Record<string, unknown> }).sink;
    if (!sink) throw new Error("Blackbox sink lookup returned no sink");
    return validateConfigureSlipwaySink(input.context, input.signer.publicKeyHex, sink, "reused");
  }
  if (existing.response.status !== 404) {
    throw new Error(`GET Blackbox sink failed (${existing.response.status}): ${JSON.stringify(existing.body).slice(0, 500)}`);
  }

  const created = await signedJson<CreateSinkResponse>({
    baseUrl: input.context.blackbox.baseUrl,
    path: "/v1/sinks",
    method: "POST",
    signer: input.signer,
    body: {
      sinkId: input.context.blackbox.sinkId,
      owner: input.signer.publicKeyHex,
      network: "acurast-mainnet",
      deploymentId: input.context.blackbox.deploymentId,
      jobId: input.context.blackbox.jobId,
      retentionSeconds: 7 * 24 * 60 * 60,
      maxRetainedBytes: 256 * 1024 * 1024,
      maxIngestBytesPerMinute: 8 * 1024 * 1024,
      labels: {
        applicationId: input.context.applicationId,
        policyDigest: input.context.policyDigest,
        sinkName: input.context.blackbox.sinkName
      }
    },
    fetchImpl: input.fetchImpl
  });
  return validateConfigureSlipwaySink(input.context, input.signer.publicKeyHex, created.sink as unknown as Record<string, unknown>, "created");
}

async function ensureConfigureSlipwaySinkFactory(input: {
  context: SlipwayProfileConfigureContext;
  signer: BlackboxRequestSigner;
  currentProfile?: SavedBlackboxProfileState;
  rotateFactoryToken: boolean;
  fetchImpl: typeof fetch;
}): Promise<{ factoryToken: string; tokenSource: "created" | "local-state" | "rotated" }> {
  const response = await signedJson<{
    replayed?: boolean;
    factory?: {
      factoryId?: string;
      owner?: string;
      applicationId?: string;
      network?: string;
      sinkIdPrefix?: string;
    };
    factoryToken?: string;
  }>({
    baseUrl: input.context.blackbox.baseUrl,
    path: "/v1/sink-factories",
    method: "POST",
    signer: input.signer,
    body: {
      factoryId: input.context.blackbox.factoryId,
      owner: input.signer.publicKeyHex,
      applicationId: input.context.applicationId,
      network: input.context.blackbox.network,
      sinkIdPrefix: input.context.blackbox.sinkIdPrefix,
      retentionSecondsMax: input.context.blackbox.retentionSecondsMax,
      maxRetainedBytesMax: input.context.blackbox.maxRetainedBytesMax,
      maxIngestBytesPerMinuteMax: input.context.blackbox.maxIngestBytesPerMinuteMax
    },
    fetchImpl: input.fetchImpl
  });
  if (
    response.factory?.factoryId !== input.context.blackbox.factoryId ||
    response.factory.applicationId !== input.context.applicationId ||
    normalizePublicKeyHex(String(response.factory.owner ?? "")) !== normalizePublicKeyHex(input.signer.publicKeyHex)
  ) {
    throw new Error("Blackbox sink factory response does not match the Slipway profile binding");
  }
  const token = response.factoryToken ?? (
    input.currentProfile?.factoryId === input.context.blackbox.factoryId &&
    normalizePublicKeyHex(input.currentProfile.owner) === normalizePublicKeyHex(input.signer.publicKeyHex)
      ? input.currentProfile.factoryToken
      : undefined
  );
  if (!token) {
    if (input.rotateFactoryToken) {
      const rotated = await signedJson<{
        factory?: {
          factoryId?: string;
          owner?: string;
          applicationId?: string;
        };
        factoryToken?: string;
        rotated?: boolean;
      }>({
        baseUrl: input.context.blackbox.baseUrl,
        path: `/v1/sink-factories/${encodeURIComponent(input.context.blackbox.factoryId)}/token-rotations`,
        method: "POST",
        signer: input.signer,
        fetchImpl: input.fetchImpl
      });
      if (
        rotated.factory?.factoryId !== input.context.blackbox.factoryId ||
        rotated.factory.applicationId !== input.context.applicationId ||
        normalizePublicKeyHex(String(rotated.factory.owner ?? "")) !== normalizePublicKeyHex(input.signer.publicKeyHex) ||
        typeof rotated.factoryToken !== "string" ||
        rotated.factoryToken.length === 0
      ) {
        throw new Error("Blackbox sink factory token rotation response does not match the Slipway profile binding");
      }
      return { factoryToken: rotated.factoryToken, tokenSource: "rotated" };
    }
    throw new Error("Blackbox sink factory already exists but no local factory token is saved. Rerun from the original BLACKBOX_HOME/state-file, or rerun with --rotate-factory-token to recover future Slipway launches by rotating the factory token and uploading a replacement Lockbox profile. Existing logs remain readable only with the original DEK.");
  }
  return { factoryToken: token, tokenSource: response.factoryToken ? "created" : "local-state" };
}

function validateConfigureSlipwaySink(
  context: SlipwayJobConfigureContext,
  ownerPublicKey: string,
  sink: Record<string, unknown>,
  idempotencyState: "created" | "reused"
): {
  sinkId: string;
  owner: string;
  jobId: string;
  deploymentId: string;
  writeUrl: string;
  idempotencyState: "created" | "reused";
} {
  const sinkId = requiredStringValue(sink.sinkId, "sink.sinkId");
  const owner = requiredStringValue(sink.owner, "sink.owner");
  const jobId = requiredStringValue(sink.jobId, "sink.jobId");
  const deploymentId = requiredStringValue(sink.deploymentId, "sink.deploymentId");
  if (
    sinkId !== context.blackbox.sinkId ||
    normalizePublicKeyHex(owner) !== normalizePublicKeyHex(ownerPublicKey) ||
    jobId !== context.blackbox.jobId ||
    deploymentId !== context.blackbox.deploymentId
  ) {
    throw new Error("Existing Blackbox sink does not match the Slipway Application binding");
  }
  return {
    sinkId,
    owner,
    jobId,
    deploymentId,
    writeUrl: new URL(`/v1/sinks/${encodeURIComponent(sinkId)}/events`, context.blackbox.baseUrl).toString(),
    idempotencyState
  };
}

async function resolveConfigureSlipwayDek(input: {
  flags: Map<string, string | boolean | string[]>;
  env: NodeJS.ProcessEnv;
  cwd: string;
  currentState?: SavedBlackboxSinkState;
  context: SlipwayJobConfigureContext;
}): Promise<string> {
  const envName = stringFlag(input.flags, "dek-env");
  if (envName) return validateBlackboxDek(requiredEnv(input.env, envName));
  const reuseName = stringFlag(input.flags, "reuse-dek-from");
  if (reuseName) {
    const reused = await maybeLoadSinkState(input.cwd, reuseName, input.flags, input.env);
    if (!reused?.dek) throw new Error(`No saved Blackbox DEK found for --reuse-dek-from ${reuseName}`);
    return validateBlackboxDek(reused.dek);
  }
  if (
    input.currentState?.dek &&
    input.currentState.sinkId === input.context.blackbox.sinkId &&
    input.currentState.jobId === input.context.blackbox.jobId &&
    input.currentState.deploymentId === input.context.blackbox.deploymentId
  ) {
    return validateBlackboxDek(input.currentState.dek);
  }
  return generateBlackboxLogDek();
}

function buildCompactBlackboxLogConfig(input: {
  context: SlipwayJobConfigureContext;
  dek: string;
  writeUrl: string;
}): string {
  const context = input.context.blackbox.context ?? {};
  return canonicalJson({
    sinkId: input.context.blackbox.sinkId,
    jobId: input.context.blackbox.jobId,
    writeUrl: input.writeUrl,
    dek: input.dek,
    spoolDir: input.context.blackbox.spoolDir,
    ...(Object.keys(context).length === 0 ? {} : { context: canonicalJson(context) })
  });
}

async function resolveConfigureSlipwayProfileDek(input: {
  flags: Map<string, string | boolean | string[]>;
  env: NodeJS.ProcessEnv;
  cwd: string;
  currentProfile?: SavedBlackboxProfileState;
}): Promise<string> {
  const envName = stringFlag(input.flags, "dek-env");
  if (envName) return validateBlackboxDek(requiredEnv(input.env, envName));
  const reuseName = stringFlag(input.flags, "reuse-dek-from");
  if (reuseName) {
    const reused = await maybeLoadProfileState(reuseName, input.flags, input.env) ??
      await maybeLoadSinkState(input.cwd, reuseName, input.flags, input.env);
    if (!reused?.dek) throw new Error(`No saved Blackbox DEK found for --reuse-dek-from ${reuseName}`);
    return validateBlackboxDek(reused.dek);
  }
  if (!boolFlag(input.flags, "rotate-dek") && input.currentProfile?.dek) {
    return validateBlackboxDek(input.currentProfile.dek);
  }
  return generateBlackboxLogDek();
}

function validateBlackboxDek(value: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || Buffer.from(value, "base64url").length !== 32) {
    throw new Error("Blackbox log DEK must be base64url and decode to 32 bytes");
  }
  return value;
}

function resolveLockboxOperatorUploadUrl(
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv,
  context: SlipwayConfigureContext
): string {
  const explicit = stringFlag(flags, "lockbox-url") ?? env.PROOF_LOCKBOX_OPERATOR_UPLOAD_URL ?? context.lockbox?.uploadUrl;
  if (!explicit) throw new Error("Lockbox operator upload URL is required via --lockbox-url, PROOF_LOCKBOX_OPERATOR_UPLOAD_URL, or Slipway context");
  const url = new URL(explicit);
  if (url.pathname === "/" || url.pathname.length === 0) {
    url.pathname = "/api/operator/blackbox-log-config-secret-versions";
  }
  return url.toString();
}

function resolveLockboxOperatorProfileUploadUrl(
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv,
  context: SlipwayProfileConfigureContext
): string {
  const explicit = stringFlag(flags, "lockbox-url") ?? env.PROOF_LOCKBOX_OPERATOR_UPLOAD_URL ?? context.lockbox?.uploadUrl;
  if (!explicit) throw new Error("Lockbox operator upload URL is required via --lockbox-url, PROOF_LOCKBOX_OPERATOR_UPLOAD_URL, or Slipway context");
  const url = new URL(explicit);
  if (url.pathname === "/" || url.pathname.length === 0) {
    url.pathname = "/api/operator/blackbox-profiles";
  }
  return url.toString();
}

function assertSlipwayJobContext(context: SlipwayConfigureContext): asserts context is SlipwayJobConfigureContext {
  if (!context.policyVersionId || !context.manifestDigest || !context.dispatchId || !context.planItemId || !context.idempotencyKey || !context.job) {
    throw new Error("Slipway configure-slipway job context is missing required Lockbox dispatch/job fields");
  }
  if (!context.blackbox.sinkId || !context.blackbox.writeUrl || !context.blackbox.jobId || !context.blackbox.deploymentId) {
    throw new Error("Slipway configure-slipway job context is missing required Blackbox sink fields");
  }
}

function assertSlipwayProfileContext(context: SlipwayConfigureContext): asserts context is SlipwayProfileConfigureContext {
  if (context.mode !== "profile") throw new Error("Slipway configure-slipway context is not profile mode");
  const blackbox = context.blackbox;
  if (
    !blackbox.profileId ||
    !blackbox.profileName ||
    !blackbox.network ||
    !blackbox.sinkIdPrefix ||
    !blackbox.factoryId ||
    typeof blackbox.retentionSecondsMax !== "number" ||
    typeof blackbox.maxRetainedBytesMax !== "number" ||
    typeof blackbox.maxIngestBytesPerMinuteMax !== "number"
  ) {
    throw new Error("Slipway profile context is missing required Blackbox profile fields");
  }
}

async function resolveSlipwaySession(
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv
): Promise<{ slipwayUrl: string; sessionToken: string }> {
  const configFile = stringFlag(flags, "slipway-config-file") ?? env.SLIPWAY_OPS_CONFIG_FILE;
  let fileSession: { slipwayUrl?: string; sessionToken?: string } | undefined;
  if (configFile) {
    fileSession = JSON.parse(await readFile(configFile, "utf8")) as { slipwayUrl?: string; sessionToken?: string };
  } else {
    try {
      fileSession = JSON.parse(await readFile(path.join(homedir(), ".config", "slipway", "ops-session.json"), "utf8")) as { slipwayUrl?: string; sessionToken?: string };
    } catch {
      fileSession = undefined;
    }
  }
  const tokenEnv = stringFlag(flags, "slipway-session-token-env");
  const sessionToken = tokenEnv
    ? requiredEnv(env, tokenEnv)
    : env.SLIPWAY_OPS_SESSION_TOKEN ?? fileSession?.sessionToken;
  const slipwayUrl = stringFlag(flags, "slipway-url") ?? env.SLIPWAY_OPS_SLIPWAY_URL ?? env.SLIPWAY_URL ?? fileSession?.slipwayUrl;
  if (!slipwayUrl) throw new Error("Slipway URL is required via --slipway-url, SLIPWAY_OPS_SLIPWAY_URL, SLIPWAY_URL, or SLIPWAY_OPS_CONFIG_FILE");
  if (!sessionToken) throw new Error("Slipway session token is required via --slipway-session-token-env, SLIPWAY_OPS_SESSION_TOKEN, or SLIPWAY_OPS_CONFIG_FILE");
  return { slipwayUrl: normalizeBaseUrl(slipwayUrl), sessionToken };
}

function requireSecureHttpUrl(raw: string, label: string, env: NodeJS.ProcessEnv): void {
  const url = new URL(raw);
  if (url.protocol === "https:") return;
  const local = url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1");
  if (local || env.NODE_ENV === "test") return;
  throw new Error(`${label} must use https, except for localhost/test`);
}

async function fetchJson<T = Record<string, unknown>>(url: string, input: {
  fetchImpl: typeof fetch;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<T> {
  const response = await input.fetchImpl(url, {
    method: input.method ?? "GET",
    headers: {
      accept: "application/json",
      ...input.headers
    },
    body: input.body
  });
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = text.length === 0 ? {} : JSON.parse(text);
  } catch {
    parsed = { body: text };
  }
  if (!response.ok) {
    throw new Error(`${input.method ?? "GET"} ${url} failed (${response.status}): ${JSON.stringify(parsed).slice(0, 500)}`);
  }
  return parsed as T;
}

function output(parsed: ParsedArgs, options: BlackboxCliOptions, value: unknown, summary: string): void {
  if (boolFlag(parsed.flags, "json")) {
    emit(options, JSON.stringify(value, null, 2));
  } else {
    emit(options, summary);
  }
}

function emit(options: BlackboxCliOptions, line: string): void {
  (options.stdout ?? console.log)(line);
}

function accountSummary(value: unknown): string {
  const input = value as { account?: { owner?: string; availableCredit?: string }; owner?: string; availableCredit?: string };
  const account = input.account ?? input;
  return `Account ${account.owner ?? "<unknown>"} available=${account.availableCredit ?? "0"}`;
}

function resolveSinkId(flags: Map<string, string | boolean | string[]>, state: SavedBlackboxSinkState | undefined): string {
  return stringFlag(flags, "sink-id") ?? state?.sinkId ?? requiredStringFlag(flags, "sink-id");
}

function resolveDek(
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv,
  state: { dek?: string } | undefined
): string {
  const envName = stringFlag(flags, "dek-env");
  if (envName) return requiredEnv(env, envName);
  return stringFlag(flags, "dek") ?? env.BLACKBOX_LOG_DEK ?? state?.dek ?? requiredStringFlag(flags, "dek");
}

function resolveReadToken(
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv,
  state: SavedBlackboxSinkState | undefined
): string | undefined {
  const envName = stringFlag(flags, "read-token-env");
  if (envName) return requiredEnv(env, envName);
  const tokenId = stringFlag(flags, "token-id") ?? state?.defaultReadTokenId;
  return stringFlag(flags, "read-token") ?? env.BLACKBOX_READ_TOKEN ?? (tokenId ? state?.readTokens?.[tokenId]?.readToken : undefined);
}

function stateName(flags: Map<string, string | boolean | string[]>): string | undefined {
  return stringFlag(flags, "name") ?? stringFlag(flags, "sink-name");
}

async function maybeLoadSinkState(
  cwd: string,
  name: string | undefined,
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv
): Promise<SavedBlackboxSinkState | undefined> {
  const keys = await maybeLoadKeysFile(flags, env);
  const selectedName = name ?? keys?.defaultSink;
  if (selectedName && keys?.sinks[selectedName]) {
    return keys.sinks[selectedName];
  }
  if (!selectedName) return undefined;
  try {
    return JSON.parse(await readFile(legacySinkStatePath(cwd, selectedName), "utf8")) as SavedBlackboxSinkState;
  } catch {
    return undefined;
  }
}

async function saveSinkState(
  _cwd: string,
  state: SavedBlackboxSinkState,
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv
): Promise<void> {
  const file = stateFilePath(flags, env);
  const existing = await maybeLoadKeysFile(flags, env) ?? { version: 1, sinks: {} };
  existing.version = 1;
  existing.defaultSink = state.name;
  existing.sinks[state.name] = state;
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(existing, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await chmod(file, 0o600);
}

async function maybeLoadProfileState(
  name: string | undefined,
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv
): Promise<SavedBlackboxProfileState | undefined> {
  const keys = await maybeLoadKeysFile(flags, env);
  if (!name) return undefined;
  return keys?.profiles?.[name];
}

async function saveProfileState(input: {
  name: string;
  state: SavedBlackboxProfileState;
  flags: Map<string, string | boolean | string[]>;
  env: NodeJS.ProcessEnv;
}): Promise<void> {
  const file = stateFilePath(input.flags, input.env);
  const existing = await maybeLoadKeysFile(input.flags, input.env) ?? { version: 1, sinks: {}, profiles: {} };
  existing.version = 1;
  existing.profiles = existing.profiles ?? {};
  existing.profiles[input.name] = input.state;
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(existing, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await chmod(file, 0o600);
}

async function ensureKeysFileWritable(
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv
): Promise<void> {
  const file = stateFilePath(flags, env);
  const existing = await maybeLoadKeysFile(flags, env) ?? { version: 1, sinks: {}, profiles: {} };
  existing.version = 1;
  existing.profiles = existing.profiles ?? {};
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(existing, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await chmod(file, 0o600);
}

async function maybeLoadKeysFile(
  flags: Map<string, string | boolean | string[]>,
  env: NodeJS.ProcessEnv
): Promise<SavedBlackboxKeysFile | undefined> {
  try {
    const parsed = JSON.parse(await readFile(stateFilePath(flags, env), "utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    const file = parsed as Partial<SavedBlackboxKeysFile>;
    if (file.version !== 1 || !file.sinks || typeof file.sinks !== "object" || Array.isArray(file.sinks)) {
      return undefined;
    }
    return { version: 1, defaultSink: file.defaultSink, sinks: file.sinks, profiles: file.profiles };
  } catch {
    return undefined;
  }
}

function stateFilePath(flags: Map<string, string | boolean | string[]>, env: NodeJS.ProcessEnv): string {
  const explicit = stringFlag(flags, "state-file");
  if (explicit) return path.resolve(explicit);
  const home = env.BLACKBOX_HOME ? path.resolve(env.BLACKBOX_HOME) : path.join(homedir(), ".blackbox");
  return path.join(home, "keys.json");
}

function legacySinkStatePath(cwd: string, name: string): string {
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    throw new Error(`invalid Blackbox sink state name ${JSON.stringify(name)}`);
  }
  return path.join(cwd, ".blackbox", "sinks", `${name}.json`);
}

async function writeRuntimeEnvFile(file: string, state: SavedBlackboxSinkState, flags: Map<string, string | boolean | string[]>): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const spoolDir = stringFlag(flags, "spool-dir") ?? `.blackbox/spool/${state.name}`;
  const context = stringFlag(flags, "context") ?? state.name;
  const lines = [
    ["BLACKBOX_SINK_ID", state.sinkId],
    ["BLACKBOX_JOB_ID", state.jobId],
    ["BLACKBOX_WRITE_URL", state.writeUrl],
    ["BLACKBOX_LOG_DEK", state.dek],
    ["BLACKBOX_SPOOL_DIR", spoolDir],
    ["BLACKBOX_CONTEXT", context]
  ]
    .filter((entry): entry is [string, string] => typeof entry[1] === "string" && entry[1].length > 0)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`);
  await writeFile(file, `${lines.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
  await chmod(file, 0o600);
}

function labelFlags(flags: Map<string, string | boolean | string[]>): Record<string, string> | undefined {
  const labels: Record<string, string> = {};
  for (const raw of stringFlags(flags, "label")) {
    const eq = raw.indexOf("=");
    if (eq <= 0) {
      throw new Error("--label must be key=value");
    }
    labels[raw.slice(0, eq)] = raw.slice(eq + 1);
  }
  return Object.keys(labels).length > 0 ? labels : undefined;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string | boolean | string[]>();
  const positionals: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--") {
      positionals.push(...argv.slice(index + 1));
      break;
    }
    if (!arg.startsWith("--")) {
      positionals.push(arg);
      continue;
    }
    const eq = arg.indexOf("=");
    if (eq > 2) {
      setFlag(flags, arg.slice(2, eq), arg.slice(eq + 1));
      continue;
    }
    const name = arg.slice(2);
    const next = argv[index + 1];
    if (next && !next.startsWith("--")) {
      setFlag(flags, name, next);
      index += 1;
    } else {
      setFlag(flags, name, true);
    }
  }
  return { positionals, flags };
}

function setFlag(flags: Map<string, string | boolean | string[]>, name: string, value: string | boolean): void {
  const existing = flags.get(name);
  if (existing === undefined) {
    flags.set(name, value);
  } else if (Array.isArray(existing)) {
    existing.push(String(value));
  } else {
    flags.set(name, [String(existing), String(value)]);
  }
}

function parsedCommandInput(positionals: readonly string[], flags: BlackboxCliFlags | undefined): ParsedArgs {
  return {
    positionals: [...positionals],
    flags: flagMap(flags)
  };
}

function flagMap(flags: BlackboxCliFlags | undefined): Map<string, string | boolean | string[]> {
  if (!flags) return new Map();
  if (flags instanceof Map) return new Map(flags);
  const mapped = new Map<string, string | boolean | string[]>();
  for (const [name, value] of Object.entries(flags)) {
    if (value === undefined || value === false) continue;
    if (Array.isArray(value)) {
      if (value.length > 0) mapped.set(name, value);
      continue;
    }
    mapped.set(name, value);
  }
  return mapped;
}

function normalizeCommand(positionals: string[]): string {
  if (positionals.length === 0) return "help";
  if (positionals[0] === "admin" && positionals[1] === "grant-credit") return "admin-grant-credit";
  if (positionals[0] === "sinks" && positionals[1] === "create") return "sinks-create";
  if (positionals[0] === "configure-slipway") return "configure-slipway";
  if (positionals[0] === "read-token" && positionals[1] === "create") return "read-token-create";
  if (positionals[0] === "read-token" && positionals[1] === "list") return "read-token-list";
  if (positionals[0] === "read-token" && positionals[1] === "revoke") return "read-token-revoke";
  if (["status", "account", "read", "search", "tail", "help"].includes(positionals[0])) return positionals[0];
  throw new Error(`Unknown blackbox command: ${positionals.join(" ")}`);
}

function requiredPositional(parsed: ParsedArgs, index: number, name: string): string {
  const value = parsed.positionals[index];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function stringFlag(flags: Map<string, string | boolean | string[]>, name: string): string | undefined {
  const value = flags.get(name);
  if (Array.isArray(value)) return value[value.length - 1];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function stringFlags(flags: Map<string, string | boolean | string[]>, name: string): string[] {
  const value = flags.get(name);
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return [value];
  return [];
}

function requiredStringFlag(flags: Map<string, string | boolean | string[]>, name: string): string {
  const value = stringFlag(flags, name);
  if (!value) {
    throw new Error(`--${name} is required`);
  }
  return value;
}

function boolFlag(flags: Map<string, string | boolean | string[]>, name: string): boolean {
  return flags.get(name) === true || flags.get(name) === "true";
}

function numberFlag(flags: Map<string, string | boolean | string[]>, name: string, fallback: number): number {
  const value = stringFlag(flags, name);
  if (!value) return fallback;
  return parseIntegerFlag(value, name);
}

function optionalNumberFlag(flags: Map<string, string | boolean | string[]>, name: string): number | undefined {
  const value = stringFlag(flags, name);
  return value ? parseIntegerFlag(value, name) : undefined;
}

function parseIntegerFlag(value: string, name: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`--${name} must be a non-negative integer`);
  }
  return Number(value);
}

function requiredEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function requiredStringValue(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function normalizePublicKeyHex(value: string): string {
  const hex = value.replace(/^0x/u, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error("public key must be a 32-byte hex string");
  }
  return hex;
}

function pathWithQuery(rawUrl: string): string {
  const url = new URL(rawUrl);
  return `${url.pathname}${url.search}`;
}

function nowIso(options: Pick<BlackboxCliOptions, "now">): string {
  return (options.now?.() ?? new Date()).toISOString();
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (value === undefined) return null;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, canonicalize(item)]));
  }
  return String(value);
}

function helpText(): string {
  return `Usage:
  blackbox status --base-url <url> [--admin-token-env <ENV>]
  blackbox account --base-url <url> [--ledger]
  blackbox admin grant-credit --base-url <url> --admin-token-env <ENV> --owner <hex> --amount <atomic>
  blackbox configure-slipway <APPLICATION_ID>
  blackbox sinks create --base-url <url> --name <name> --job-id <id> [--env-file <path>]
  blackbox read-token create|list|revoke --name <name>
  blackbox read|search|tail --name <name>

State is stored in --state-file or BLACKBOX_HOME/keys.json, defaulting to ~/.blackbox/keys.json.
Legacy cwd .blackbox/sinks/<name>.json files remain readable.
Owner-signed commands read BLACKBOX_OWNER_URI by default. Blackbox is optional and standalone; this CLI does not alter switchboard deploy defaults.`;
}
