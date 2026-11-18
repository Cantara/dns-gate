// The config file: which providers, which domains each holds, the domain groups, and who is granted
// which groups. It holds no secrets: credentials are read from the files it names, and agents are
// listed by the SHA-256 of their token. The file is meant to be reviewable and kept in a repo.
//
// A domain is managed only if it is listed under "domains". A domain the provider holds but this file
// does not list is invisible to everyone.

import { readFileSync } from "node:fs";
import type { RecordFields } from "./model.ts";

export interface ProviderConfig {
  type: "porkbun" | "domeneshop" | "memory";
  /** JSON file with the provider's credentials. Required for porkbun and domeneshop. */
  credentialsFile?: string;
  /** For type "memory": the starting zones. */
  zones?: Record<string, RecordFields[]>;
}

export interface AgentConfig {
  id: string;
  tokenSha256: string;
  groups: string[];
}

export interface PersonConfig {
  /** The Google account's email address; it is also the person's principal id. */
  email: string;
  groups: string[];
}

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecretFile: string;
}

export interface Config {
  listen: { host: string; port: number };
  /** The URL people open, e.g. https://dns-gate.example.com. Sign-in redirects come back to it. */
  publicUrl: string;
  database: string;
  providers: Record<string, ProviderConfig>;
  /** domain → provider name */
  domains: Record<string, string>;
  /** group name → domains */
  groups: Record<string, string[]>;
  agents: AgentConfig[];
  people: PersonConfig[];
  oidc?: OidcConfig;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStrArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

function onlyKeys(where: string, obj: Record<string, unknown>, allowed: string[]): string[] {
  return Object.keys(obj)
    .filter((k) => !allowed.includes(k))
    .map((k) => `${where}: unknown key "${k}"`);
}

/** Every problem at once, so a broken config is fixed in one pass. */
export function validateConfig(raw: unknown): { config?: Config; problems: string[] } {
  const p: string[] = [];
  if (!isObj(raw)) return { problems: ["the config is not a JSON object"] };
  p.push(...onlyKeys("config", raw, ["listen", "publicUrl", "database", "providers", "domains", "groups", "agents", "people", "oidc"]));

  const listen = raw.listen;
  if (!isObj(listen) || typeof listen.host !== "string" || !Number.isInteger(listen.port)) {
    p.push('listen must be {"host": string, "port": integer}');
  }
  if (typeof raw.publicUrl !== "string" || !/^https?:\/\//.test(raw.publicUrl)) p.push("publicUrl must be an http(s) URL");
  if (typeof raw.database !== "string" || raw.database === "") p.push("database must be a file path");

  const providers = isObj(raw.providers) ? raw.providers : (p.push("providers must be an object"), {});
  for (const [name, pc] of Object.entries(providers)) {
    if (!isObj(pc)) {
      p.push(`providers.${name} must be an object`);
      continue;
    }
    p.push(...onlyKeys(`providers.${name}`, pc, ["type", "credentialsFile", "zones"]));
    if (pc.type !== "porkbun" && pc.type !== "domeneshop" && pc.type !== "memory") {
      p.push(`providers.${name}.type must be porkbun, domeneshop or memory`);
    } else if (pc.type !== "memory" && typeof pc.credentialsFile !== "string") {
      p.push(`providers.${name}.credentialsFile is required for ${pc.type}`);
    }
  }

  const domains = isObj(raw.domains) ? raw.domains : (p.push("domains must be an object"), {});
  for (const [domain, prov] of Object.entries(domains)) {
    if (typeof prov !== "string" || !(prov in providers)) p.push(`domains.${domain} names no configured provider`);
  }

  const groups = isObj(raw.groups) ? raw.groups : (p.push("groups must be an object"), {});
  for (const [g, list] of Object.entries(groups)) {
    if (!isStrArray(list)) {
      p.push(`groups.${g} must be a list of domains`);
      continue;
    }
    for (const d of list) if (!(d in domains)) p.push(`groups.${g} names ${d}, which is not under domains`);
  }

  const checkGroups = (where: string, gs: unknown) => {
    if (!isStrArray(gs)) return p.push(`${where}.groups must be a list of group names`);
    for (const g of gs) if (!(g in groups)) p.push(`${where} is granted group ${g}, which is not defined`);
  };

  const agents = Array.isArray(raw.agents) ? raw.agents : (p.push("agents must be a list"), []);
  const ids = new Set<string>();
  agents.forEach((a, i) => {
    if (!isObj(a)) return p.push(`agents[${i}] must be an object`);
    p.push(...onlyKeys(`agents[${i}]`, a, ["id", "tokenSha256", "groups"]));
    if (typeof a.id !== "string" || a.id === "") p.push(`agents[${i}].id is required`);
    else if (ids.has(a.id)) p.push(`agents[${i}].id ${a.id} is used twice`);
    else ids.add(a.id);
    if (typeof a.tokenSha256 !== "string" || !/^[0-9a-f]{64}$/.test(a.tokenSha256)) {
      p.push(`agents[${i}].tokenSha256 must be 64 lowercase hex characters (dns-gate new-token makes one)`);
    }
    checkGroups(`agents[${i}]`, a.groups);
  });

  const people = Array.isArray(raw.people) ? raw.people : (p.push("people must be a list"), []);
  people.forEach((person, i) => {
    if (!isObj(person)) return p.push(`people[${i}] must be an object`);
    p.push(...onlyKeys(`people[${i}]`, person, ["email", "groups"]));
    if (typeof person.email !== "string" || !person.email.includes("@")) p.push(`people[${i}].email is required`);
    else if (ids.has(person.email.toLowerCase())) p.push(`people[${i}].email is also used as an agent id`);
    checkGroups(`people[${i}]`, person.groups);
  });

  if (raw.oidc !== undefined) {
    const o = raw.oidc;
    if (!isObj(o) || typeof o.issuer !== "string" || typeof o.clientId !== "string" || typeof o.clientSecretFile !== "string") {
      p.push('oidc must be {"issuer", "clientId", "clientSecretFile"}');
    } else {
      p.push(...onlyKeys("oidc", o, ["issuer", "clientId", "clientSecretFile"]));
    }
  }

  if (p.length > 0) return { problems: p };
  const config = raw as unknown as Config;
  config.people = config.people.map((x) => ({ ...x, email: x.email.toLowerCase() }));
  return { config, problems: [] };
}

export function loadConfig(path: string): Config {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new ConfigError(`cannot read ${path}: ${(e as Error).message}`);
  }
  const { config, problems } = validateConfig(raw);
  if (!config) throw new ConfigError(`${path}:\n  ${problems.join("\n  ")}`);
  return config;
}

export function readJsonFile<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}
