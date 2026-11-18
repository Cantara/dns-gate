// Porkbun API v3 (https://api.porkbun.com/api/json/v3). Every call is a POST with the key pair in the
// JSON body. Shapes confirmed against the live API by homelab's porkbun-ddns (27 Jul 2026) and the
// acme.sh dns_porkbun plugin; Porkbun's own docs refuse scripted fetches.
// Porkbun API access must also be switched ON per domain in its control panel, or every call fails.
//
// Translation notes:
// - Porkbun returns `name` as the full name ("home.steinar.rocks") and takes the subdomain on write
//   ("home", "" for the apex). dns-gate's names are relative, with "@" for the apex.
// - ttl and prio come back as strings.
// - An SRV record's content is "weight port target"; dns-gate keeps weight and port as fields.

import type { DnsRecord, Forward, RecordFields } from "../model.ts";
import { ProviderError, type Fetch, type Provider } from "./provider.ts";

const BASE = "https://api.porkbun.com/api/json/v3";
const MIN_TTL = 600;

export interface PorkbunCredentials {
  apiKey: string;
  secretApiKey: string;
}

interface PbRecord {
  id: string;
  name: string;
  type: string;
  content: string;
  ttl: string;
  prio?: string | null;
}

interface PbForward {
  id: string;
  subdomain: string;
  location: string;
  type: string;
}

export function relativeName(fqdn: string, domain: string): string {
  if (fqdn === domain) return "@";
  const suffix = "." + domain;
  return fqdn.endsWith(suffix) ? fqdn.slice(0, -suffix.length) : fqdn;
}

export class PorkbunProvider implements Provider {
  readonly name: string;
  readonly #creds: PorkbunCredentials;
  readonly #fetch: Fetch;

  constructor(name: string, creds: PorkbunCredentials, fetchImpl: Fetch = fetch) {
    this.name = name;
    this.#creds = creds;
    this.#fetch = fetchImpl;
  }

  async #call<T>(path: string, extra: Record<string, unknown> = {}): Promise<T> {
    const res = await this.#fetch(BASE + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ apikey: this.#creds.apiKey, secretapikey: this.#creds.secretApiKey, ...extra }),
      signal: AbortSignal.timeout(30_000),
    });
    const text = await res.text();
    let json: { status?: string; message?: string } & Record<string, unknown>;
    try {
      json = JSON.parse(text);
    } catch {
      throw new ProviderError(`porkbun ${path}: HTTP ${res.status}, not JSON: ${text.slice(0, 200)}`, res.status);
    }
    if (!res.ok || json.status !== "SUCCESS") {
      throw new ProviderError(`porkbun ${path}: HTTP ${res.status} ${json.message ?? json.status ?? ""}`.trim(), res.status);
    }
    return json as T;
  }

  async listDomains(): Promise<string[]> {
    const out: string[] = [];
    // listAll pages by 1000.
    for (let start = 0; ; start += 1000) {
      const page = await this.#call<{ domains?: { domain: string }[] }>("/domain/listAll", { start: String(start) });
      const domains = page.domains ?? [];
      out.push(...domains.map((d) => d.domain));
      if (domains.length < 1000) return out;
    }
  }

  async listRecords(domain: string): Promise<DnsRecord[]> {
    const { records } = await this.#call<{ records: PbRecord[] }>(`/dns/retrieve/${encodeURIComponent(domain)}`);
    return records.map((r) => {
      const rec: DnsRecord = {
        id: String(r.id),
        name: relativeName(r.name, domain),
        type: r.type,
        content: r.content,
        ttl: Number(r.ttl),
      };
      const prio = r.prio === undefined || r.prio === null || r.prio === "" ? undefined : Number(r.prio);
      if (r.type === "SRV") {
        const [weight, port, ...target] = r.content.split(/\s+/);
        if (weight !== undefined && port !== undefined && target.length > 0) {
          rec.weight = Number(weight);
          rec.port = Number(port);
          rec.content = target.join(" ");
        }
        if (prio !== undefined) rec.priority = prio;
      } else if (r.type === "MX" && prio !== undefined) {
        rec.priority = prio;
      }
      return rec;
    });
  }

  async listForwards(domain: string): Promise<Forward[]> {
    const { forwards } = await this.#call<{ forwards?: PbForward[] }>(`/domain/getUrlForwarding/${encodeURIComponent(domain)}`);
    return (forwards ?? []).map((f) => ({
      id: String(f.id),
      name: f.subdomain === "" ? "@" : f.subdomain,
      url: f.location,
      kind: f.type,
    }));
  }

  validate(f: RecordFields): string[] {
    const problems: string[] = [];
    if (f.ttl < MIN_TTL) problems.push(`porkbun's smallest ttl is ${MIN_TTL} (got ${f.ttl})`);
    if (f.type === "SRV" && (f.weight === undefined || f.port === undefined)) {
      problems.push("an SRV record needs weight and port");
    }
    return problems;
  }

  #body(f: RecordFields): Record<string, unknown> {
    const body: Record<string, unknown> = {
      name: f.name === "@" ? "" : f.name,
      type: f.type,
      content: f.type === "SRV" ? `${f.weight} ${f.port} ${f.content}` : f.content,
      ttl: String(f.ttl),
    };
    if (f.priority !== undefined) body.prio = String(f.priority);
    return body;
  }

  async createRecord(domain: string, f: RecordFields): Promise<void> {
    await this.#call(`/dns/create/${encodeURIComponent(domain)}`, this.#body(f));
  }

  async updateRecord(domain: string, id: string, f: RecordFields): Promise<void> {
    await this.#call(`/dns/edit/${encodeURIComponent(domain)}/${encodeURIComponent(id)}`, this.#body(f));
  }

  async deleteRecord(domain: string, id: string): Promise<void> {
    await this.#call(`/dns/delete/${encodeURIComponent(domain)}/${encodeURIComponent(id)}`);
  }
}
