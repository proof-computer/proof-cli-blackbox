import { createHash } from "node:crypto";

import { verifyReportSignature, type ReportSignature } from "./report-signing.js";

export type ServiceRole =
  | "control-api"
  | "control-mutator"
  | "relay"
  | "quote-signer"
  | "manifest-builder"
  | "gateway"
  | "validator"
  | "explorer"
  | "operator-intake"
  | "job-manager"
  | "blackbox"
  | "other";

export type ServiceState = "candidate" | "active" | "degraded" | "draining" | "disabled";

export interface NetworkManifestCatalogRef {
  url: string;
  signer?: string;
  required?: boolean;
  maxStaleSeconds?: number;
  digest?: string;
  metadata?: Record<string, unknown>;
}

export interface NetworkManifest {
  version: 1;
  sequence: number;
  issuedAt: string;
  effectiveAt?: string;
  expiresAt?: string;
  chain: {
    name?: string;
    chainId: string | number | bigint;
  };
  catalogs?: Record<string, NetworkManifestCatalogRef>;
}

export interface ServiceCatalogMember {
  serviceId: string;
  role?: ServiceRole;
  state?: ServiceState;
  apiBaseUrl?: string;
  statusUrl?: string;
  validationReportUrl?: string;
  controlPlaneUrl?: string;
  serviceSigner?: string;
  acurastDeploymentId?: string;
  acurastJobId?: string;
  scriptHash?: string;
  capabilities?: string[];
  weight?: number;
  effectiveAt?: string;
  expiresAt?: string;
  metadata?: Record<string, unknown>;
}

export interface ServiceCatalog {
  version: 1;
  role: ServiceRole;
  sequence: number;
  issuedAt: string;
  effectiveAt?: string;
  expiresAt?: string;
  members: ServiceCatalogMember[];
  metadata?: Record<string, unknown>;
}

export interface ServiceDiscoveryConfig {
  manifestUrlCandidates: string[];
  expectedManifestSigner?: string;
  requiredCatalogs?: Array<ServiceRole | string>;
  fetchImpl?: typeof fetch;
  now?: Date;
  allowExpiredManifest?: boolean;
  allowExpiredCatalogs?: boolean;
}

export interface ResolvedServiceCatalog {
  key: string;
  ref: NetworkManifestCatalogRef;
  catalog: ServiceCatalog;
  signer: string;
}

export interface ResolvedServiceDiscovery {
  manifestUrl: string;
  manifest: NetworkManifest;
  manifestSigner: string;
  catalogs: Record<string, ResolvedServiceCatalog>;
  membersByRole: Partial<Record<ServiceRole, ServiceCatalogMember[]>>;
}

const NETWORK_MANIFEST_DOMAINS = new Set(["switchboard.network-manifest.v1", "proof-ingress.network-manifest.v1"]);
const SERVICE_CATALOG_DOMAINS = new Set(["switchboard.service-catalog.v1", "proof-ingress.service-catalog.v1"]);

export async function discoverServices(config: ServiceDiscoveryConfig): Promise<ResolvedServiceDiscovery> {
  if (!config.expectedManifestSigner) {
    throw new Error("expectedManifestSigner is required for service discovery");
  }
  const fetchImpl = config.fetchImpl ?? fetch;
  const manifest = await fetchVerifiedManifest(config, fetchImpl);
  const now = config.now ?? new Date();
  const catalogs: Record<string, ResolvedServiceCatalog> = {};
  const membersByRole: Partial<Record<ServiceRole, ServiceCatalogMember[]>> = {};

  for (const [key, ref] of Object.entries(manifest.manifest.catalogs ?? {})) {
    try {
      const catalog = await fetchVerifiedCatalog(ref, { ...config, now }, fetchImpl);
      catalogs[key] = {
        key,
        ref,
        catalog: catalog.catalog,
        signer: catalog.signer
      };
      const activeMembers = activeServiceCatalogMembers(catalog.catalog, {
        now,
        includeDegraded: true
      });
      membersByRole[catalog.catalog.role] = [...(membersByRole[catalog.catalog.role] ?? []), ...activeMembers];
    } catch (error) {
      if (ref.required || config.requiredCatalogs?.includes(key) || config.requiredCatalogs?.includes(catalogKeyToRole(key))) {
        throw error;
      }
    }
  }

  for (const required of config.requiredCatalogs ?? []) {
    if (!catalogs[required] && !membersByRole[catalogKeyToRole(required)]) {
      throw new Error(`Required service catalog ${required} was not resolved`);
    }
  }

  return {
    manifestUrl: manifest.url,
    manifest: manifest.manifest,
    manifestSigner: manifest.signer,
    catalogs,
    membersByRole
  };
}

export function resolveBlackboxBaseUrls(discovery: ResolvedServiceDiscovery): string[] {
  return uniqueStrings(
    (discovery.membersByRole.blackbox ?? [])
      .map((member) => member.apiBaseUrl)
      .filter((url): url is string => Boolean(url))
      .map((url) => normalizeBaseUrl(url))
  );
}

export function normalizeBaseUrl(value: string): string {
  const url = new URL(value);
  url.hash = "";
  url.search = "";
  return url.toString().replace(/\/+$/, "");
}

function catalogKeyToRole(key: string): ServiceRole {
  const normalized = key.replace(/([a-z])([A-Z])/g, "$1-$2").replace(/_/g, "-").toLowerCase();
  if (normalized === "control-apis") return "control-api";
  if (normalized === "controlapi") return "control-api";
  if (normalized === "relays") return "relay";
  if (normalized === "gateways") return "gateway";
  if (normalized === "validators") return "validator";
  if (normalized === "explorers") return "explorer";
  if (normalized === "operator-intakes") return "operator-intake";
  if (normalized === "job-managers") return "job-manager";
  if (["blackboxes", "logging", "logs"].includes(normalized)) return "blackbox";
  return normalized as ServiceRole;
}

async function fetchVerifiedManifest(
  config: ServiceDiscoveryConfig,
  fetchImpl: typeof fetch
): Promise<{ url: string; manifest: NetworkManifest; signer: string }> {
  const failures = [];
  for (const url of config.manifestUrlCandidates.filter((candidate) => candidate.length > 0)) {
    try {
      const response = await fetchImpl(url, {
        headers: {
          accept: "application/json"
        }
      });
      const body = await response.text();
      if (!response.ok) {
        throw new Error(`${response.status} ${body.slice(0, 500)}`);
      }
      const verified = await verifySignedNetworkManifest(JSON.parse(body), {
        expectedSigner: config.expectedManifestSigner,
        now: config.now,
        allowExpired: config.allowExpiredManifest
      });
      return {
        url,
        manifest: verified.manifest,
        signer: verified.signer
      };
    } catch (error) {
      failures.push(`${url}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw new Error(`Service discovery manifest fetch failed: ${failures.join("; ")}`);
}

async function fetchVerifiedCatalog(
  ref: NetworkManifestCatalogRef,
  config: ServiceDiscoveryConfig & { now: Date },
  fetchImpl: typeof fetch
): Promise<{ catalog: ServiceCatalog; signer: string }> {
  const response = await fetchImpl(ref.url, {
    headers: {
      accept: "application/json"
    }
  });
  const bodyBytes = Buffer.from(await response.arrayBuffer());
  const body = bodyBytes.toString("utf8");
  if (!response.ok) {
    throw new Error(`service catalog fetch failed for ${ref.url}: ${response.status} ${body.slice(0, 500)}`);
  }
  if (!ref.signer && !ref.digest) {
    throw new Error(`service catalog ${ref.url} must declare signer or digest`);
  }
  if (ref.digest) {
    const actualDigest = `0x${createHash("sha256").update(bodyBytes).digest("hex")}`;
    if (actualDigest.toLowerCase() !== ref.digest.toLowerCase()) {
      throw new Error(`service catalog ${ref.url} digest mismatch`);
    }
  }
  const verified = await verifySignedServiceCatalog(JSON.parse(body), {
    expectedSigner: ref.signer,
    now: config.now,
    allowExpired: config.allowExpiredCatalogs
  });
  if (ref.maxStaleSeconds !== undefined) {
    const issuedAtMs = Date.parse(verified.catalog.issuedAt);
    if (!Number.isFinite(issuedAtMs)) {
      throw new Error(`service catalog ${ref.url} has invalid issuedAt`);
    }
    if (config.now.getTime() - issuedAtMs > ref.maxStaleSeconds * 1000) {
      throw new Error(`service catalog ${ref.url} is older than maxStaleSeconds=${ref.maxStaleSeconds}`);
    }
  }
  return verified;
}

async function verifySignedNetworkManifest(
  input: unknown,
  options: { expectedSigner?: string; now?: Date; allowExpired?: boolean } = {}
): Promise<{ manifest: NetworkManifest; signer: string; signature: ReportSignature }> {
  const signed = parseSignedEnvelope<NetworkManifest>(input);
  if (!NETWORK_MANIFEST_DOMAINS.has(signed.signature.domain)) {
    throw new Error(`Unexpected network manifest signature domain ${signed.signature.domain}`);
  }
  if (!options.allowExpired && expired(signed.payload, options.now)) {
    throw new Error("Network manifest is expired");
  }
  const signer = await verifyReportSignature(signed.payload, signed.signature);
  if (options.expectedSigner && !sameSigner(signer, options.expectedSigner)) {
    throw new Error(`Network manifest signer ${signer} does not match expected signer ${options.expectedSigner}`);
  }
  return {
    manifest: normalizeManifest(signed.payload),
    signer,
    signature: signed.signature
  };
}

async function verifySignedServiceCatalog(
  input: unknown,
  options: { expectedSigner?: string; now?: Date; allowExpired?: boolean } = {}
): Promise<{ catalog: ServiceCatalog; signer: string; signature: ReportSignature }> {
  const signed = parseSignedEnvelope<ServiceCatalog>(input, "catalog");
  if (!SERVICE_CATALOG_DOMAINS.has(signed.signature.domain)) {
    throw new Error(`Unexpected service catalog signature domain ${signed.signature.domain}`);
  }
  const catalog = normalizeServiceCatalog(signed.payload);
  if (!options.allowExpired && expired(catalog, options.now)) {
    throw new Error("Service catalog is expired");
  }
  const signer = await verifyReportSignature(catalog, signed.signature);
  if (options.expectedSigner && !sameSigner(signer, options.expectedSigner)) {
    throw new Error(`Service catalog signer ${signer} does not match expected signer ${options.expectedSigner}`);
  }
  return {
    catalog,
    signer,
    signature: signed.signature
  };
}

function parseSignedEnvelope<T>(input: unknown, payloadKey = "manifest"): { payload: T; signature: ReportSignature } {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Expected signed JSON object");
  }
  const record = input as Record<string, unknown>;
  const payload = record[payloadKey];
  const signature = record.signature;
  if (!payload || !signature || typeof signature !== "object" || Array.isArray(signature)) {
    throw new Error(`Expected signed ${payloadKey} envelope`);
  }
  return {
    payload: payload as T,
    signature: signature as ReportSignature
  };
}

function normalizeManifest(manifest: NetworkManifest): NetworkManifest {
  return {
    ...manifest,
    chain: {
      ...manifest.chain,
      chainId: manifest.chain.chainId.toString()
    },
    catalogs: manifest.catalogs
      ? Object.fromEntries(
          Object.entries(manifest.catalogs).map(([key, ref]) => [
            key,
            {
              ...ref,
              url: normalizeUrl(ref.url)
            }
          ])
        )
      : undefined
  };
}

function normalizeServiceCatalog(catalog: ServiceCatalog): ServiceCatalog {
  return {
    ...catalog,
    members: (catalog.members ?? []).map((member) => ({
      ...member,
      role: member.role ?? catalog.role,
      state: member.state ?? "active",
      apiBaseUrl: member.apiBaseUrl ? normalizeBaseUrl(member.apiBaseUrl) : undefined,
      statusUrl: member.statusUrl ? normalizeUrl(member.statusUrl) : undefined,
      validationReportUrl: member.validationReportUrl ? normalizeUrl(member.validationReportUrl) : undefined,
      controlPlaneUrl: member.controlPlaneUrl ? normalizeUrl(member.controlPlaneUrl) : undefined
    }))
  };
}

function activeServiceCatalogMembers(
  catalog: ServiceCatalog,
  options: { now?: Date; includeDegraded?: boolean; includeDraining?: boolean } = {}
): ServiceCatalogMember[] {
  const now = options.now ?? new Date();
  return normalizeServiceCatalog(catalog).members.filter((member) => {
    if (member.state === "disabled" || member.state === "candidate") return false;
    if (member.state === "degraded" && !options.includeDegraded) return false;
    if (member.state === "draining" && !options.includeDraining) return false;
    if (member.effectiveAt && Date.parse(member.effectiveAt) > now.getTime()) return false;
    if (member.expiresAt && Date.parse(member.expiresAt) <= now.getTime()) return false;
    return true;
  });
}

function normalizeUrl(value: string): string {
  const url = new URL(value);
  url.hash = "";
  return url.toString();
}

function expired(value: { expiresAt?: string }, now = new Date()): boolean {
  return Boolean(value.expiresAt && Date.parse(value.expiresAt) <= now.getTime());
}

function sameSigner(left: string, right: string): boolean {
  if (/^0x[0-9a-fA-F]+$/.test(left) && /^0x[0-9a-fA-F]+$/.test(right)) {
    return left.toLowerCase() === right.toLowerCase();
  }
  return left === right;
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)];
}
