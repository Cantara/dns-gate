// An in-memory provider for tests and for trying dns-gate without a real account. It behaves like
// the real ones where it matters: every write changes what the next read returns, ids are its own.

import type { DnsRecord, Forward, RecordFields } from "../model.ts";
import { ProviderError, type Provider } from "./provider.ts";

export class MemoryProvider implements Provider {
  readonly name: string;
  readonly zones = new Map<string, DnsRecord[]>();
  readonly forwards = new Map<string, Forward[]>();
  #next = 1;
  /** Set to make the next write throw, to test a failure part-way through applying a proposal. */
  failNextWrite: string | undefined;

  constructor(name: string, zones: Record<string, RecordFields[]> = {}) {
    this.name = name;
    for (const [domain, records] of Object.entries(zones)) {
      this.zones.set(domain, records.map((r) => ({ id: String(this.#next++), ...r })));
    }
  }

  #zone(domain: string): DnsRecord[] {
    const z = this.zones.get(domain);
    if (!z) throw new ProviderError(`memory: no domain ${domain}`, 404);
    return z;
  }

  #maybeFail(): void {
    if (this.failNextWrite !== undefined) {
      const msg = this.failNextWrite;
      this.failNextWrite = undefined;
      throw new ProviderError(msg, 500);
    }
  }

  async listDomains(): Promise<string[]> {
    return [...this.zones.keys()];
  }

  async listRecords(domain: string): Promise<DnsRecord[]> {
    return this.#zone(domain).map((r) => ({ ...r }));
  }

  async listForwards(domain: string): Promise<Forward[]> {
    this.#zone(domain);
    return (this.forwards.get(domain) ?? []).map((f) => ({ ...f }));
  }

  validate(f: RecordFields): string[] {
    return f.ttl < 60 ? [`memory: ttl must be at least 60 (got ${f.ttl})`] : [];
  }

  async createRecord(domain: string, f: RecordFields): Promise<void> {
    this.#maybeFail();
    this.#zone(domain).push({ id: String(this.#next++), ...f });
  }

  async updateRecord(domain: string, id: string, f: RecordFields): Promise<void> {
    this.#maybeFail();
    const zone = this.#zone(domain);
    const i = zone.findIndex((r) => r.id === id);
    if (i < 0) throw new ProviderError(`memory: no record ${id}`, 404);
    zone[i] = { id, ...f };
  }

  async deleteRecord(domain: string, id: string): Promise<void> {
    this.#maybeFail();
    const zone = this.#zone(domain);
    const i = zone.findIndex((r) => r.id === id);
    if (i < 0) throw new ProviderError(`memory: no record ${id}`, 404);
    zone.splice(i, 1);
  }
}
