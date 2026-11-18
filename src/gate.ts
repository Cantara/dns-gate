// The gate: who may see which domain, what a proposal may contain, and the one path by which a
// change reaches a provider. Nothing in dns-gate writes to a provider except accept() below, and
// accept() refuses anyone who is not a person.

import { randomBytes } from "node:crypto";
import { isIP } from "node:net";
import {
  describeChange,
  fieldsOf,
  isProposableType,
  PROPOSABLE_TYPES,
  sameFields,
  type Change,
  type DnsRecord,
  type Forward,
  type Principal,
  type Proposal,
  type ProposalStatus,
  type RecordFields,
} from "./model.ts";
import type { Provider } from "./providers/provider.ts";
import type { Store } from "./store.ts";

/** A refusal the caller should see as is: no access, bad input, wrong state. Never a provider fault. */
export class GateError extends Error {
  readonly code: "forbidden" | "not_found" | "invalid" | "conflict";
  constructor(code: GateError["code"], message: string) {
    super(message);
    this.name = "GateError";
    this.code = code;
  }
}

/** What an agent sends: records by their fields, existing records by the id it read from list_records. */
export type ChangeInput =
  | { op: "create"; record: RecordFields }
  | { op: "update"; id: string; record: RecordFields }
  | { op: "delete"; id: string };

export interface GateOptions {
  providers: Map<string, Provider>;
  /** domain → provider name */
  domains: Record<string, string>;
  /** group → domains */
  groups: Record<string, string[]>;
  store: Store;
  now?: () => Date;
}

export interface AcceptResult {
  proposal: Proposal;
  applied: string[];
}

const MAX_CHANGES = 50;
const LABEL = /^(\*|[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)$/;
const HOST = /^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$/;

export class Gate {
  readonly #o: GateOptions;
  readonly #now: () => Date;

  constructor(o: GateOptions) {
    this.#o = o;
    this.#now = o.now ?? (() => new Date());
  }

  // ---- access -------------------------------------------------------------------------------

  /** The domains a principal's groups reach, sorted. */
  domainsFor(p: Principal): string[] {
    const out = new Set<string>();
    for (const g of p.groups) for (const d of this.#o.groups[g] ?? []) out.add(d);
    return [...out].sort();
  }

  #mayUse(p: Principal, domain: string): void {
    // A domain outside the principal's groups answers exactly as one that does not exist, so a
    // principal cannot learn which domains are managed here by probing.
    if (!this.domainsFor(p).includes(domain)) throw new GateError("not_found", `no domain ${domain} for you`);
  }

  #provider(domain: string): Provider {
    const name = this.#o.domains[domain];
    const provider = name === undefined ? undefined : this.#o.providers.get(name);
    if (!provider) throw new GateError("not_found", `no provider is configured for ${domain}`);
    return provider;
  }

  #audit(p: Principal, action: string, proposal: Proposal | null, domain: string | null, detail: unknown): void {
    this.#o.store.audit({
      at: this.#now().toISOString(),
      principal: `${p.kind}:${p.id}`,
      action,
      proposalId: proposal?.id ?? null,
      domain,
      detail: typeof detail === "string" ? detail : JSON.stringify(detail),
    });
  }

  // ---- reading ------------------------------------------------------------------------------

  listDomains(p: Principal): { domain: string; provider: string }[] {
    return this.domainsFor(p).map((domain) => ({ domain, provider: this.#o.domains[domain] ?? "?" }));
  }

  async listRecords(p: Principal, domain: string): Promise<DnsRecord[]> {
    this.#mayUse(p, domain);
    return this.#provider(domain).listRecords(domain);
  }

  async listForwards(p: Principal, domain: string): Promise<Forward[]> {
    this.#mayUse(p, domain);
    return this.#provider(domain).listForwards(domain);
  }

  listProposals(p: Principal, status?: ProposalStatus): Proposal[] {
    return this.#o.store.listProposals({ domains: this.domainsFor(p), ...(status ? { status } : {}) });
  }

  getProposal(p: Principal, id: string): Proposal {
    const proposal = this.#o.store.getProposal(id);
    if (!proposal || !this.domainsFor(p).includes(proposal.domain)) throw new GateError("not_found", `no proposal ${id}`);
    return proposal;
  }

  // ---- proposing ----------------------------------------------------------------------------

  #checkFields(domain: string, f: RecordFields, provider: Provider): string[] {
    const problems: string[] = [];
    if (typeof f !== "object" || f === null) return ["record must be an object"];
    const name = f.name;
    if (typeof name !== "string" || name === "") problems.push("name is required: a name relative to the domain, or @ for the apex");
    else if (name !== "@") {
      if (name === domain || name.endsWith("." + domain)) problems.push(`name must be relative to the domain: "${name}" should not end in ${domain}`);
      else if (!name.split(".").every((l) => LABEL.test(l))) problems.push(`name "${name}" is not a valid relative name (lowercase labels)`);
    }
    if (!isProposableType(f.type)) problems.push(`type must be one of ${PROPOSABLE_TYPES.join(", ")}`);
    if (typeof f.content !== "string" || f.content === "") problems.push("content is required");
    if (!Number.isInteger(f.ttl)) problems.push("ttl must be a whole number of seconds");
    for (const k of ["priority", "weight", "port"] as const) {
      const v = f[k];
      if (v !== undefined && (!Number.isInteger(v) || v < 0 || v > 65535)) problems.push(`${k} must be a whole number from 0 to 65535`);
    }
    if (problems.length > 0) return problems;

    switch (f.type) {
      case "A":
        if (isIP(f.content) !== 4) problems.push(`an A record's content must be an IPv4 address (got "${f.content}")`);
        break;
      case "AAAA":
        if (isIP(f.content) !== 6) problems.push(`an AAAA record's content must be an IPv6 address (got "${f.content}")`);
        break;
      case "CNAME":
        if (name === "@") problems.push("a CNAME cannot be at the apex (@)");
        if (!HOST.test(f.content)) problems.push(`a CNAME's content must be a host name (got "${f.content}")`);
        break;
      case "MX":
        if (f.priority === undefined) problems.push("an MX record needs a priority");
        if (!HOST.test(f.content)) problems.push(`an MX record's content must be a host name (got "${f.content}")`);
        break;
      case "SRV":
        if (f.priority === undefined || f.weight === undefined || f.port === undefined) problems.push("an SRV record needs priority, weight and port");
        if (!HOST.test(f.content)) problems.push(`an SRV record's content must be the target host name (got "${f.content}")`);
        break;
      case "NS":
        if (!HOST.test(f.content)) problems.push(`an NS record's content must be a host name (got "${f.content}")`);
        break;
      case "TXT":
        if (f.content.length > 4000) problems.push("a TXT record's content is limited to 4000 characters here");
        break;
    }
    if (f.type !== "MX" && f.type !== "SRV" && f.priority !== undefined) problems.push(`priority applies only to MX and SRV, not ${f.type}`);
    if (f.type !== "SRV" && (f.weight !== undefined || f.port !== undefined)) problems.push("weight and port apply only to SRV");
    problems.push(...provider.validate(f));
    return problems;
  }

  /** Copy only the known fields, so nothing an agent adds rides along into storage. */
  static #clean(r: RecordFields): RecordFields {
    const out: RecordFields = { name: r.name, type: r.type, content: r.content, ttl: r.ttl };
    if (r.priority !== undefined) out.priority = r.priority;
    if (r.weight !== undefined) out.weight = r.weight;
    if (r.port !== undefined) out.port = r.port;
    return out;
  }

  async propose(p: Principal, domain: string, inputs: ChangeInput[], reason: string): Promise<Proposal> {
    if (p.kind !== "agent") throw new GateError("forbidden", "only agents propose changes; people accept or reject them");
    this.#mayUse(p, domain);
    if (typeof reason !== "string" || reason.trim() === "") throw new GateError("invalid", "say why: reason is required, and the person deciding will read it");
    if (!Array.isArray(inputs) || inputs.length === 0) throw new GateError("invalid", "a proposal needs at least one change");
    if (inputs.length > MAX_CHANGES) throw new GateError("invalid", `at most ${MAX_CHANGES} changes in one proposal`);

    const provider = this.#provider(domain);
    const live = await provider.listRecords(domain);
    const byId = new Map(live.map((r) => [r.id, r]));
    const touched = new Set<string>();
    const changes: Change[] = [];
    const problems: string[] = [];

    inputs.forEach((c, i) => {
      const at = `change ${i + 1}`;
      if (typeof c !== "object" || c === null) return problems.push(`${at}: must be an object`);
      if (c.op === "update" || c.op === "delete") {
        const before = byId.get(String(c.id));
        if (!before) return problems.push(`${at}: no record with id ${c.id} in ${domain}; list_records shows the ids`);
        if (touched.has(before.id)) return problems.push(`${at}: record ${before.id} is changed twice in one proposal`);
        touched.add(before.id);
        if (!isProposableType(before.type)) return problems.push(`${at}: ${before.type} records cannot be changed through dns-gate yet`);
        if (c.op === "delete") return changes.push({ op: "delete", before });
        const fp = this.#checkFields(domain, c.record, provider);
        if (fp.length > 0) return problems.push(...fp.map((x) => `${at}: ${x}`));
        const after = Gate.#clean(c.record);
        if (sameFields(after, fieldsOf(before))) return problems.push(`${at}: the update changes nothing`);
        return changes.push({ op: "update", before, after });
      }
      if (c.op === "create") {
        const fp = this.#checkFields(domain, c.record, provider);
        if (fp.length > 0) return problems.push(...fp.map((x) => `${at}: ${x}`));
        const after = Gate.#clean(c.record);
        if (live.some((r) => sameFields(fieldsOf(r), after))) return problems.push(`${at}: that record already exists`);
        if (after.type === "CNAME" && live.some((r) => r.name === after.name)) {
          return problems.push(`${at}: ${after.name} already has records, and a CNAME must stand alone`);
        }
        return changes.push({ op: "create", after });
      }
      return problems.push(`${at}: op must be create, update or delete`);
    });
    if (problems.length > 0) throw new GateError("invalid", problems.join("\n"));

    const proposal: Proposal = {
      id: "p_" + randomBytes(6).toString("hex"),
      domain,
      changes,
      reason: reason.trim(),
      proposedBy: p.id,
      proposedAt: this.#now().toISOString(),
      status: "pending",
    };
    this.#o.store.insertProposal(proposal);
    this.#audit(p, "propose", proposal, domain, { changes: changes.map(describeChange), reason: proposal.reason });
    return proposal;
  }

  withdraw(p: Principal, id: string): Proposal {
    const proposal = this.getProposal(p, id);
    if (proposal.proposedBy !== p.id || p.kind !== "agent") throw new GateError("forbidden", "only the agent that proposed it can withdraw it");
    if (!this.#o.store.decide(id, "withdrawn", p.id, this.#now().toISOString())) {
      throw new GateError("conflict", `proposal ${id} is no longer pending`);
    }
    this.#audit(p, "withdraw", proposal, proposal.domain, "");
    return this.getProposal(p, id);
  }

  // ---- deciding (people only) ---------------------------------------------------------------

  #mustBePerson(p: Principal): void {
    if (p.kind !== "person") throw new GateError("forbidden", "only a person signed in on the web page can accept or reject a proposal");
  }

  reject(p: Principal, id: string, note: string): Proposal {
    this.#mustBePerson(p);
    const proposal = this.getProposal(p, id);
    if (!this.#o.store.decide(id, "rejected", p.id, this.#now().toISOString(), note || undefined)) {
      throw new GateError("conflict", `proposal ${id} is no longer pending`);
    }
    this.#audit(p, "reject", proposal, proposal.domain, note);
    return this.getProposal(p, id);
  }

  /** Why each change can no longer be applied as proposed; empty when all still can. */
  static staleness(changes: Change[], live: DnsRecord[]): string[] {
    const out: string[] = [];
    for (const c of changes) {
      if (c.op === "create") {
        if (live.some((r) => sameFields(fieldsOf(r), c.after))) out.push(`${describeChange(c)}: that record now exists already`);
      } else {
        const now = live.find((r) => r.id === c.before.id);
        if (!now) out.push(`${describeChange(c)}: the record is gone`);
        else if (!sameFields(fieldsOf(now), fieldsOf(c.before))) out.push(`${describeChange(c)}: the record changed since the proposal`);
      }
    }
    return out;
  }

  /** What is wrong with the live records after applying; empty when they match. */
  static readBack(changes: Change[], live: DnsRecord[]): string[] {
    const out: string[] = [];
    for (const c of changes) {
      if (c.op === "create" || c.op === "update") {
        if (!live.some((r) => sameFields(fieldsOf(r), c.after))) out.push(`${describeChange(c)}: not found after applying`);
      }
      if (c.op === "delete" && live.some((r) => r.id === c.before.id)) out.push(`${describeChange(c)}: still there after applying`);
    }
    return out;
  }

  async accept(p: Principal, id: string): Promise<AcceptResult> {
    this.#mustBePerson(p);
    const proposal = this.getProposal(p, id);
    if (proposal.status !== "pending") throw new GateError("conflict", `proposal ${id} is ${proposal.status}, not pending`);
    const provider = this.#provider(proposal.domain);
    const at = () => this.#now().toISOString();

    // 1. Refuse rather than overwrite: every record the proposal touches must still be as it saw it.
    const stale = Gate.staleness(proposal.changes, await provider.listRecords(proposal.domain));
    if (stale.length > 0) {
      const note = "the live records changed after the proposal was made:\n" + stale.join("\n");
      if (this.#o.store.decide(id, "stale", p.id, at(), note)) this.#audit(p, "stale", proposal, proposal.domain, stale);
      throw new GateError("conflict", note);
    }

    // 2. Claim it. Only one decision can move it out of pending.
    if (!this.#o.store.decide(id, "accepted", p.id, at())) throw new GateError("conflict", `proposal ${id} is no longer pending`);
    this.#audit(p, "accept", proposal, proposal.domain, proposal.changes.map(describeChange));

    // 3. Apply, in order; stop at the first failure and say exactly what was done.
    const applied: string[] = [];
    for (const c of proposal.changes) {
      try {
        if (c.op === "create") await provider.createRecord(proposal.domain, c.after);
        else if (c.op === "update") await provider.updateRecord(proposal.domain, c.before.id, c.after);
        else await provider.deleteRecord(proposal.domain, c.before.id);
        applied.push(describeChange(c));
      } catch (e) {
        const note = `failed at: ${describeChange(c)}\nerror: ${(e as Error).message}\napplied before it: ${applied.length === 0 ? "nothing" : "\n" + applied.join("\n")}`;
        this.#o.store.setOutcome(id, "failed", note);
        this.#audit(p, "apply-failed", proposal, proposal.domain, note);
        return { proposal: this.getProposal(p, id), applied };
      }
    }

    // 4. Read back: the provider's word that a write succeeded is not the same as the record being there.
    const wrong = Gate.readBack(proposal.changes, await provider.listRecords(proposal.domain));
    if (wrong.length > 0) {
      const note = "applied, but reading back does not match:\n" + wrong.join("\n");
      this.#o.store.setOutcome(id, "failed", note);
      this.#audit(p, "readback-failed", proposal, proposal.domain, wrong);
    } else {
      this.#audit(p, "applied", proposal, proposal.domain, applied);
    }
    return { proposal: this.getProposal(p, id), applied };
  }
}
