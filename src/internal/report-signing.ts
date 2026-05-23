import { stringToU8a } from "@polkadot/util";
import { cryptoWaitReady, encodeAddress, signatureVerify } from "@polkadot/util-crypto";
import { ethers } from "ethers";

import { canonicalJson } from "./hash.js";

export type ReportSignatureScheme = "substrate-sr25519" | "eip191-secp256k1";

export interface ReportSignature {
  scheme: ReportSignatureScheme;
  domain: string;
  signer: string;
  signature: string;
  signedAt: string;
  publicKey?: string;
  ss58Format?: number;
}

export async function verifyReportSignature(payload: unknown, signature: ReportSignature): Promise<string> {
  const message = reportSigningMessage(signature.domain, payload);
  if (signature.scheme === "eip191-secp256k1") {
    return ethers.verifyMessage(message, signature.signature);
  }

  await cryptoWaitReady();
  const result = signatureVerify(stringToU8a(message), signature.signature, signature.publicKey ?? signature.signer);
  if (!result.isValid) {
    throw new Error(`Invalid ${signature.scheme} report signature for ${signature.signer}`);
  }
  if (signature.publicKey) {
    const signer = encodeAddress(result.publicKey, signature.ss58Format);
    if (signer !== signature.signer) {
      throw new Error(`Report signature public key does not match signer ${signature.signer}`);
    }
  }
  return signature.signer;
}

export function reportSigningMessage(domain: string, payload: unknown): string {
  return canonicalJson({
    domain,
    payload
  });
}
