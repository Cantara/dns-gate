// Domeneshop (https://api.domeneshop.no/docs/), API v0. HTTP Basic auth: token as user, secret as password.
// Documented: records are addressed by a numeric id under a numeric domain id; the apex host is "@".
// Undocumented but relied on (as the vendor's own clients do): MX/SRV numbers come back as strings.

import type { DnsRecord, Forward, RecordFields } from "../model.ts";
import { ProviderError, type Fetch, type Provider } from "./provider.ts";

const BASE = "https://api.domeneshop.no/v0";

export interface DomeneshopCredentials {
  token: string;
  secret: string;
}

interface DsDomain {
  id: number;
  domain: string;
}

interface DsRecord {
  id: number;
  host: string;
  ttl: number;
  type: string;
  data: string;
  priority?: number | string;
  weight?: number | string;
  port?: number | string;
}

interface DsForward {
  host: string;
  frame: boolean;
  url: string;
}

const num = (v: number | string | undefined): number | undefined =>
  v === undefined || v === null || v === "" ? undefined : Number(v);

export class DomeneshopProvider implements Provider {
  readonly name: string;
  readonly #auth: string;
  readonly #fetch: Fetch;
  #domainIds = new Map<string, number>();

  constructor(name: string, creds: DomeneshopCredentials, fetchImpl: Fetch = fetch) {
    this.name = name;
    this.#auth = "Basic " + Buffer.from(`${creds.token}:${creds.secret}`).toString("base64");
    this.#fetch = fetchImpl;
  }

  async #call(method: string, path: string, body?: unknown): Promise<Response> {
    const res = await this.#fetch(BASE + path, {
      method,
      headers: {
        Authorization: this.#auth,
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new ProviderError(`domeneshop ${method} ${path}: HTTP ${res.status} ${text.slice(0, 300)}`.trim(), res.status);
    }
    return res;
  }

  async listDomains(): Promise<string[]> {
    const domains = (await (await this.#call("GET", "/domains")).json()) as DsDomain[];
    this.#domainIds = new Map(domains.map((d) => [d.domain, d.id]));
    return domains.map((d) => d.domain);
  }

  async #domainId(domain: string): Promise<number> {
    if (!this.#domainIds.has(domain)) await this.listDomains();
    const id = this.#domainIds.get(domain);
    if (id === undefined) throw new ProviderError(`domeneshop: no domain ${domain} on this account`, 404);
    return id;
  }

  async listRecords(domain: string): Promise<DnsRecord[]> {
    const id = await this.#domainId(domain);
    const rows = (await (await this.#call("GET", `/domains/${id}/dns`)).json()) as DsRecord[];
    return rows.map((r) => {
      const rec: DnsRecord = { id: String(r.id), name: r.host, type: r.type, content: r.data, ttl: Number(r.ttl) };
      const priority = num(r.priority), weight = num(r.weight), port = num(r.port);
      if (priority !== undefined) rec.priority = priority;
      if (weight !== undefined) rec.weight = weight;
      if (port !== undefined) rec.port = port;
      return rec;
    });
  }

  async listForwards(domain: string): Promise<Forward[]> {
    const id = await this.#domainId(domain);
    const rows = (await (await this.#call("GET", `/domains/${id}/forwards/`)).json()) as DsForward[];
    return rows.map((f) => ({ id: f.host, name: f.host, url: f.url, kind: f.frame ? "frame" : "redirect" }));
  }

  validate(f: RecordFields): string[] {
    const problems: string[] = [];
    if (f.ttl < 60 || f.ttl > 604800 || f.ttl % 60 !== 0) {
      problems.push(`domeneshop needs a ttl between 60 and 604800 that is a multiple of 60 (got ${f.ttl})`);
    }
    return problems;
  }

  #body(f: RecordFields): Record<string, unknown> {
    const body: Record<string, unknown> = { host: f.name, ttl: f.ttl, type: f.type, data: f.content };
    if (f.priority !== undefined) body.priority = f.priority;
    if (f.weight !== undefined) body.weight = f.weight;
    if (f.port !== undefined) body.port = f.port;
    return body;
  }

  async createRecord(domain: string, f: RecordFields): Promise<void> {
    await this.#call("POST", `/domains/${await this.#domainId(domain)}/dns`, this.#body(f));
  }

  async updateRecord(domain: string, id: string, f: RecordFields): Promise<void> {
    await this.#call("PUT", `/domains/${await this.#domainId(domain)}/dns/${encodeURIComponent(id)}`, this.#body(f));
  }

  async deleteRecord(domain: string, id: string): Promise<void> {
    await this.#call("DELETE", `/domains/${await this.#domainId(domain)}/dns/${encodeURIComponent(id)}`);
  }
}
