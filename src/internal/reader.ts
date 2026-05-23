import { decryptBlackboxRecord, type BlackboxEncryptedRecord } from "./crypto.js";
import { createBlackboxSignedJsonRequest, type BlackboxRequestSigner } from "./signer.js";

export interface BlackboxLogBatch {
  sinkId: string;
  jobId: string;
  batchId?: string;
  writerPublicKey: string;
  sequenceStart: number;
  sequenceEnd: number;
  previousHash?: string | null;
  createdAt: string;
  encrypted: BlackboxEncryptedRecord[];
  labels?: Record<string, string>;
}

export interface BlackboxBatchDto {
  sinkId: string;
  jobId: string;
  batchId: string;
  writerPublicKey: string;
  sequenceStart: number;
  sequenceEnd: number;
  previousHash: string | null;
  hash: string;
  byteLength: number;
  receivedAt: string;
  labels: Record<string, string>;
  batch: BlackboxLogBatch;
}

export interface BlackboxDecryptedBatch<T = unknown> extends BlackboxBatchDto {
  records: T[];
}

export interface BlackboxReadQuery {
  jobId?: string;
  afterSequence?: number;
  limit?: number;
}

export interface BlackboxSearchQuery extends BlackboxReadQuery {
  batchId?: string;
  receivedAfter?: string;
  receivedBefore?: string;
  sequenceStart?: number;
  sequenceEnd?: number;
  labels?: Record<string, string>;
}

export interface BlackboxReadResult<T = unknown> {
  batches: Array<BlackboxDecryptedBatch<T>>;
}

export interface BlackboxSearchResult<T = unknown> extends BlackboxReadResult<T> {
  scannedBytes: number;
  usage?: {
    idempotencyKey: string;
    owner: string;
    sinkId: string;
    kind: string;
    quantity: string;
    acuAmount: string;
    createdAtMs: number;
  };
}

export interface BlackboxTailOptions {
  signal?: AbortSignal;
}

export interface BlackboxReaderOptions {
  baseUrl?: string;
  sinkId?: string;
  eventsUrl?: string;
  searchUrl?: string;
  tailUrl?: string;
  dek: string;
  signer?: BlackboxRequestSigner;
  readToken?: string;
  fetch?: typeof fetch;
}

export interface BlackboxReader {
  readBatches<T = unknown>(query?: BlackboxReadQuery): Promise<BlackboxReadResult<T>>;
  searchBatches<T = unknown>(query?: BlackboxSearchQuery): Promise<BlackboxSearchResult<T>>;
  tailBatches<T = unknown>(options?: BlackboxTailOptions): AsyncIterable<BlackboxDecryptedBatch<T>>;
}

export function createBlackboxReader(options: BlackboxReaderOptions): BlackboxReader {
  return new SignedBlackboxReader(options);
}

class SignedBlackboxReader implements BlackboxReader {
  private readonly fetchFn: typeof fetch;

  constructor(private readonly options: BlackboxReaderOptions) {
    this.fetchFn = options.fetch ?? fetch;
  }

  async readBatches<T = unknown>(query: BlackboxReadQuery = {}): Promise<BlackboxReadResult<T>> {
    const response = await this.signedGet(this.url("events", readQueryParams(query)));
    const body = (await response.json()) as { batches?: BlackboxBatchDto[] };
    if (!response.ok) {
      throw new Error(`Blackbox read failed: ${response.status} ${JSON.stringify(body)}`);
    }
    return {
      batches: (body.batches ?? []).map((batch) => decryptBatch<T>(this.options.dek, batch))
    };
  }

  async searchBatches<T = unknown>(query: BlackboxSearchQuery = {}): Promise<BlackboxSearchResult<T>> {
    const response = await this.signedGet(this.url("search", flattenSearchQuery(query)));
    const body = (await response.json()) as {
      scannedBytes?: number;
      batches?: BlackboxBatchDto[];
      usage?: BlackboxSearchResult["usage"];
    };
    if (!response.ok) {
      throw new Error(`Blackbox search failed: ${response.status} ${JSON.stringify(body)}`);
    }
    return {
      scannedBytes: body.scannedBytes ?? 0,
      usage: body.usage,
      batches: (body.batches ?? []).map((batch) => decryptBatch<T>(this.options.dek, batch))
    };
  }

  async *tailBatches<T = unknown>(options: BlackboxTailOptions = {}): AsyncIterable<BlackboxDecryptedBatch<T>> {
    const url = this.url("tail", {});
    const response = await this.fetchFn(url, {
      method: "GET",
      headers: await this.authHeaders("GET", url),
      signal: options.signal
    });
    if (!response.ok) {
      throw new Error(`Blackbox tail failed: ${response.status} ${(await response.text()).slice(0, 500)}`);
    }
    if (!response.body) {
      throw new Error("Blackbox tail response did not include a body");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) {
          return;
        }
        buffer += decoder.decode(chunk.value, { stream: true });
        for (;;) {
          const boundary = buffer.indexOf("\n\n");
          if (boundary === -1) {
            break;
          }
          const rawEvent = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const batch = parseSseBatch(rawEvent);
          if (batch) {
            yield decryptBatch<T>(this.options.dek, batch);
          }
        }
      }
    } finally {
      await reader.cancel().catch(() => undefined);
    }
  }

  private async signedGet(url: string): Promise<Response> {
    return this.fetchFn(url, {
      method: "GET",
      headers: await this.authHeaders("GET", url)
    });
  }

  private async authHeaders(method: string, url: string): Promise<Record<string, string>> {
    if (this.options.readToken) {
      return {
        accept: "application/json",
        authorization: `Bearer ${this.options.readToken}`
      };
    }
    if (!this.options.signer) {
      throw new Error("Blackbox reader requires signer or readToken");
    }
    const request = await createBlackboxSignedJsonRequest({
      signer: this.options.signer,
      method,
      path: pathWithQuery(url)
    });
    return request.headers;
  }

  private url(kind: "events" | "search" | "tail", query: Record<string, string | number | undefined>): string {
    const configured = kind === "events" ? this.options.eventsUrl : kind === "search" ? this.options.searchUrl : this.options.tailUrl;
    const base =
      configured ??
      (() => {
        if (!this.options.baseUrl || !this.options.sinkId) {
          throw new Error("Blackbox reader requires either explicit URLs or baseUrl plus sinkId");
        }
        const suffix = kind === "events" ? "events" : kind;
        return new URL(`/v1/sinks/${encodeURIComponent(this.options.sinkId)}/${suffix}`, this.options.baseUrl).toString();
      })();
    const url = new URL(base);
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined) {
        url.searchParams.set(key, String(value));
      }
    }
    return url.toString();
  }
}

export function decryptBatch<T = unknown>(dek: string, batch: BlackboxBatchDto): BlackboxDecryptedBatch<T> {
  return {
    ...batch,
    records: batch.batch.encrypted.map((record) => decryptBlackboxRecord<T>(dek, record))
  };
}

function flattenSearchQuery(query: BlackboxSearchQuery): Record<string, string | number | undefined> {
  const flattened: Record<string, string | number | undefined> = {
    batchId: query.batchId,
    jobId: query.jobId,
    afterSequence: query.afterSequence,
    limit: query.limit,
    receivedAfter: query.receivedAfter,
    receivedBefore: query.receivedBefore,
    sequenceStart: query.sequenceStart,
    sequenceEnd: query.sequenceEnd
  };
  for (const [key, value] of Object.entries(query.labels ?? {})) {
    flattened[`label.${key}`] = value;
  }
  return flattened;
}

function readQueryParams(query: BlackboxReadQuery): Record<string, string | number | undefined> {
  return {
    jobId: query.jobId,
    afterSequence: query.afterSequence,
    limit: query.limit
  };
}

function parseSseBatch(rawEvent: string): BlackboxBatchDto | undefined {
  let eventName = "message";
  const data: string[] = [];
  for (const line of rawEvent.split(/\r?\n/)) {
    if (line.startsWith(":")) {
      continue;
    }
    if (line.startsWith("event:")) {
      eventName = line.slice("event:".length).trim();
    }
    if (line.startsWith("data:")) {
      data.push(line.slice("data:".length).trimStart());
    }
  }
  if (eventName !== "batch" || data.length === 0) {
    return undefined;
  }
  return JSON.parse(data.join("\n")) as BlackboxBatchDto;
}

function pathWithQuery(rawUrl: string): string {
  const url = new URL(rawUrl);
  return `${url.pathname}${url.search}`;
}
