import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";

import { canonicalJson, sha256Hex } from "./hash.js";

export type BlackboxAuthScheme = "Sr25519" | "Ed25519";

export interface BlackboxRequestSigner {
  scheme: BlackboxAuthScheme;
  publicKeyHex: string;
  sign(message: Uint8Array): Uint8Array | string | Promise<Uint8Array | string>;
}

export interface BlackboxSignedJsonRequestInput {
  signer: BlackboxRequestSigner;
  method: string;
  path: string;
  body?: unknown;
  signedAt?: string;
  nonce?: string;
}

export interface BlackboxSignedJsonRequest {
  headers: Record<string, string>;
  body?: string;
  signedAt: string;
  nonce: string;
}

export function blackboxRequestBodyHash(body: Uint8Array | string): string {
  return sha256Hex(typeof body === "string" ? Buffer.from(body, "utf8") : body);
}

export function buildBlackboxSigningMessage(input: {
  method: string;
  path: string;
  body: Uint8Array | string;
  signedAt: string;
  nonce: string;
}): Buffer {
  return Buffer.from(
    [
      input.method.toUpperCase(),
      input.path,
      blackboxRequestBodyHash(input.body),
      input.signedAt,
      input.nonce
    ].join("\n"),
    "utf8"
  );
}

export async function createBlackboxSignedJsonRequest(
  input: BlackboxSignedJsonRequestInput
): Promise<BlackboxSignedJsonRequest> {
  const body = input.body === undefined ? undefined : canonicalJson(input.body);
  const bodyBytes = body === undefined ? Buffer.alloc(0) : Buffer.from(body, "utf8");
  const signedAt = input.signedAt ?? new Date().toISOString();
  const nonce = input.nonce ?? randomBytes(16).toString("base64url");
  const message = buildBlackboxSigningMessage({
    method: input.method,
    path: input.path,
    body: bodyBytes,
    signedAt,
    nonce
  });
  const signature = await input.signer.sign(message);
  const signatureBytes =
    typeof signature === "string" ? Buffer.from(stripHexPrefix(signature), "hex") : Buffer.from(signature);

  const headers: Record<string, string> = {
    accept: "application/json",
    authorization: `${input.signer.scheme} ${normalizePublicKeyHex(input.signer.publicKeyHex)}:${signatureBytes.toString("base64")}`,
    "x-signed-at": signedAt,
    "x-nonce": nonce
  };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
  }

  return {
    headers,
    body,
    signedAt,
    nonce
  };
}

export function normalizePublicKeyHex(value: string): string {
  const hex = stripHexPrefix(value).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error("Blackbox signer public key must be a 32-byte hex string");
  }
  return hex;
}

function stripHexPrefix(value: string): string {
  return value.startsWith("0x") ? value.slice(2) : value;
}
