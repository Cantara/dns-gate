import type { DnsRecord, Forward, RecordFields } from "../model.ts";

/**
 * One DNS provider account. Every method talks to the live provider; nothing is cached across
 * calls except what a provider needs to translate names to its own ids.
 */
export interface Provider {
  /** The name this provider has in the config, e.g. "porkbun". */
  readonly name: string;
  listDomains(): Promise<string[]>;
  listRecords(domain: string): Promise<DnsRecord[]>;
  listForwards(domain: string): Promise<Forward[]>;
  /** Refuses fields this provider cannot store (a TTL below its minimum, a type it lacks). */
  validate(fields: RecordFields): string[];
  createRecord(domain: string, fields: RecordFields): Promise<void>;
  updateRecord(domain: string, id: string, fields: RecordFields): Promise<void>;
  deleteRecord(domain: string, id: string): Promise<void>;
}

export class ProviderError extends Error {
  readonly status: number | undefined;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "ProviderError";
    this.status = status;
  }
}

export type Fetch = typeof fetch;
