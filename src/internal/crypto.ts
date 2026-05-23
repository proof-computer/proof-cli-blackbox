import { createDecipheriv, randomBytes } from "node:crypto";

export interface BlackboxEncryptedRecord {
  v: 1;
  alg: "A256GCM";
  iv: string;
  ciphertext: string;
  tag: string;
}

export function generateBlackboxLogDek(): string {
  return Buffer.from(randomBytes(32)).toString("base64url");
}

export function decryptBlackboxRecord<T = unknown>(key: string, encrypted: BlackboxEncryptedRecord): T {
  if (encrypted.v !== 1 || encrypted.alg !== "A256GCM") {
    throw new Error(`Unsupported Blackbox encrypted record format: v=${encrypted.v} alg=${encrypted.alg}`);
  }

  const decipher = createDecipheriv("aes-256-gcm", decodeBlackboxLogDek(key), base64UrlDecode(encrypted.iv));
  decipher.setAuthTag(base64UrlDecode(encrypted.tag));
  const plaintext = Buffer.concat([
    decipher.update(base64UrlDecode(encrypted.ciphertext)),
    decipher.final()
  ]).toString("utf8");

  return JSON.parse(plaintext) as T;
}

function decodeBlackboxLogDek(key: string): Buffer {
  const decoded = base64UrlDecode(key);
  if (decoded.length !== 32) {
    throw new Error("Blackbox log DEK must decode to 32 bytes");
  }
  return decoded;
}

function base64UrlDecode(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Expected base64url value");
  }
  return Buffer.from(value, "base64url");
}
