// The provider-neutral shapes everything else speaks. A provider translates its own API to these and back.

/**
 * The types an agent may propose changes to. Both providers store these as plain content plus the
 * optional priority/weight/port, so nothing is lost in translation. Other types (CAA, DS, ALIAS,
 * TLSA, …) are listed as they are live but cannot be changed through dns-gate yet.
 */
export const PROPOSABLE_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS"] as const;
export type ProposableType = (typeof PROPOSABLE_TYPES)[number];

export function isProposableType(t: string): t is ProposableType {
  return (PROPOSABLE_TYPES as readonly string[]).includes(t);
}

/** A DNS record as it is live at a provider. `name` is relative to the domain: "@" is the apex. */
export interface DnsRecord {
  id: string;
  name: string;
  type: string;
  content: string;
  ttl: number;
  priority?: number;
  weight?: number;
  port?: number;
}

/** A record's fields without the provider's id: what an agent proposes. */
export type RecordFields = Omit<DnsRecord, "id">;

/** An HTTP forward (redirect) as it is live at a provider. Read-only in this version. */
export interface Forward {
  id: string;
  name: string;
  url: string;
  kind: string;
}

export type Change =
  | { op: "create"; after: RecordFields }
  | { op: "update"; before: DnsRecord; after: RecordFields }
  | { op: "delete"; before: DnsRecord };

export type ProposalStatus = "pending" | "accepted" | "rejected" | "withdrawn" | "stale" | "failed";

export interface Proposal {
  id: string;
  domain: string;
  changes: Change[];
  reason: string;
  proposedBy: string;
  proposedAt: string;
  status: ProposalStatus;
  decidedBy?: string;
  decidedAt?: string;
  /** Why it was rejected, why it went stale, or what failed. */
  note?: string;
}

export type PrincipalKind = "agent" | "person";

export interface Principal {
  id: string;
  kind: PrincipalKind;
  /** Domain groups this principal is granted. */
  groups: string[];
}

/** One line per change, the same text on the page, in MCP results and in the audit log. */
export function describeRecord(r: RecordFields): string {
  const extra: string[] = [];
  if (r.priority !== undefined) extra.push(`priority ${r.priority}`);
  if (r.weight !== undefined) extra.push(`weight ${r.weight}`);
  if (r.port !== undefined) extra.push(`port ${r.port}`);
  extra.push(`ttl ${r.ttl}`);
  return `${r.name} ${r.type} ${r.content} (${extra.join(", ")})`;
}

export function describeChange(c: Change): string {
  switch (c.op) {
    case "create":
      return `+ ${describeRecord(c.after)}`;
    case "delete":
      return `- ${describeRecord(c.before)}`;
    case "update":
      return `~ ${describeRecord(c.before)}\n  → ${describeRecord(c.after)}`;
  }
}

/** True when a live record has exactly the proposed fields (the id is not compared). */
export function sameFields(a: RecordFields, b: RecordFields): boolean {
  return (
    a.name === b.name &&
    a.type === b.type &&
    a.content === b.content &&
    a.ttl === b.ttl &&
    a.priority === b.priority &&
    a.weight === b.weight &&
    a.port === b.port
  );
}

export function fieldsOf(r: DnsRecord): RecordFields {
  const { id: _id, ...fields } = r;
  return fields;
}
