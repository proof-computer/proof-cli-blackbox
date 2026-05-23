import { createHash } from "node:crypto";

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function canonicalBodyHash(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

export function sha256Hex(value: string | Uint8Array): string {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (value === undefined) {
    return null;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));
    return Object.fromEntries(entries.map(([key, item]) => [key, canonicalize(item)]));
  }
  return String(value);
}
