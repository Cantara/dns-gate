// The MCP endpoint for agents: JSON-RPC 2.0 over Streamable HTTP, stateless, answering every POST
// with application/json (no server-sent events). Hand-written rather than built on the SDK so the
// service that holds DNS credentials carries as few dependencies as possible.
//
// There is deliberately no tool that accepts or rejects a proposal. An agent cannot reach accept()
// through this file at all, and Gate.accept() refuses an agent besides.

import { GateError, type ChangeInput, type Gate } from "./gate.ts";
import { describeChange, describeRecord, PROPOSABLE_TYPES, type Principal, type Proposal, type ProposalStatus } from "./model.ts";
import { ProviderError } from "./providers/provider.ts";

export const SERVER_INFO = { name: "dns-gate", version: "0.1.0" };
const PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS = `dns-gate manages DNS records at several providers. You can read domains, records and forwards, and propose changes. You cannot apply a change: a person reads your proposal on the dns-gate web page and accepts or rejects it. Read the records first (list_records), then propose with the record ids you read. Give a reason a person can judge. Tell your human the proposal's page link so they can decide.`;

const RECORD_SCHEMA = {
  type: "object",
  properties: {
    name: { type: "string", description: 'Name relative to the domain: "www", "_dmarc", or "@" for the apex' },
    type: { type: "string", enum: [...PROPOSABLE_TYPES] },
    content: { type: "string", description: "IP address, target host name or text" },
    ttl: { type: "integer", description: "Seconds. Porkbun's minimum is 600; Domeneshop needs a multiple of 60" },
    priority: { type: "integer", description: "MX and SRV only" },
    weight: { type: "integer", description: "SRV only" },
    port: { type: "integer", description: "SRV only" },
  },
  required: ["name", "type", "content", "ttl"],
  additionalProperties: false,
};

const READ = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

export const TOOLS = [
  {
    name: "list_domains",
    description: "The domains you may read and propose changes for, with the provider that holds each.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: READ,
  },
  {
    name: "list_records",
    description: "The DNS records of one domain as they are live at its provider now, with the ids a proposal needs.",
    inputSchema: { type: "object", properties: { domain: { type: "string" } }, required: ["domain"], additionalProperties: false },
    annotations: READ,
  },
  {
    name: "list_forwards",
    description: "The HTTP forwards (redirects) of one domain, as they are live. Read-only: forwards cannot be proposed yet.",
    inputSchema: { type: "object", properties: { domain: { type: "string" } }, required: ["domain"], additionalProperties: false },
    annotations: READ,
  },
  {
    name: "propose_change",
    description:
      "Propose changes to one domain's records. Nothing changes live: a person must accept the proposal on the web page. If the records you touch change before then, accepting is refused and you propose again.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string" },
        reason: { type: "string", description: "Why, in a sentence or two the person deciding can judge" },
        changes: {
          type: "array",
          minItems: 1,
          items: {
            oneOf: [
              { type: "object", properties: { op: { const: "create" }, record: RECORD_SCHEMA }, required: ["op", "record"], additionalProperties: false },
              {
                type: "object",
                properties: { op: { const: "update" }, id: { type: "string", description: "The record's id from list_records" }, record: RECORD_SCHEMA },
                required: ["op", "id", "record"],
                additionalProperties: false,
              },
              { type: "object", properties: { op: { const: "delete" }, id: { type: "string" } }, required: ["op", "id"], additionalProperties: false },
            ],
          },
        },
      },
      required: ["domain", "reason", "changes"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "list_proposals",
    description: "Proposals on your domains, newest first, optionally only those with one status.",
    inputSchema: {
      type: "object",
      properties: { status: { type: "string", enum: ["pending", "accepted", "rejected", "withdrawn", "stale", "failed"] } },
      additionalProperties: false,
    },
    annotations: READ,
  },
  {
    name: "get_proposal",
    description: "One proposal: its changes, its status and, once decided, who decided and why.",
    inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"], additionalProperties: false },
    annotations: READ,
  },
  {
    name: "withdraw_proposal",
    description: "Withdraw a pending proposal you made.",
    inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
] as const;

interface RpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

export interface RpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string };
}

const ok = (id: RpcRequest["id"], result: unknown): RpcResponse => ({ jsonrpc: "2.0", id: id ?? null, result });
const fail = (id: RpcRequest["id"], code: number, message: string): RpcResponse => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

export function proposalText(p: Proposal, pageUrl: string): string {
  const lines = [
    `Proposal ${p.id} on ${p.domain}: ${p.status}`,
    `Proposed by ${p.proposedBy} at ${p.proposedAt}`,
    `Reason: ${p.reason}`,
    ...p.changes.map(describeChange),
  ];
  if (p.decidedBy) lines.push(`Decided by ${p.decidedBy} at ${p.decidedAt}`);
  if (p.note) lines.push(`Note: ${p.note}`);
  lines.push(`Page: ${pageUrl}`);
  return lines.join("\n");
}

export class McpHandler {
  readonly #gate: Gate;
  readonly #publicUrl: string;

  constructor(gate: Gate, publicUrl: string) {
    this.#gate = gate;
    this.#publicUrl = publicUrl.replace(/\/$/, "");
  }

  #page(id: string): string {
    return `${this.#publicUrl}/proposals/${encodeURIComponent(id)}`;
  }

  /** One JSON-RPC message in, one response out (undefined for a notification). */
  async handle(agent: Principal, msg: unknown): Promise<RpcResponse | undefined> {
    if (typeof msg !== "object" || msg === null || Array.isArray(msg)) return fail(null, -32600, "expected one JSON-RPC request object");
    const req = msg as RpcRequest;
    if (req.jsonrpc !== "2.0" || typeof req.method !== "string") return fail(req.id, -32600, "not a JSON-RPC 2.0 request");
    const isNotification = req.id === undefined;
    if (isNotification) return undefined;

    switch (req.method) {
      case "initialize": {
        const asked = typeof req.params?.protocolVersion === "string" ? req.params.protocolVersion : "";
        return ok(req.id, {
          protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions: INSTRUCTIONS,
        });
      }
      case "ping":
        return ok(req.id, {});
      case "tools/list":
        return ok(req.id, { tools: TOOLS });
      case "tools/call": {
        const name = req.params?.name;
        const args = (req.params?.arguments ?? {}) as Record<string, unknown>;
        if (typeof name !== "string" || !TOOLS.some((t) => t.name === name)) return fail(req.id, -32602, `unknown tool ${String(name)}`);
        try {
          return ok(req.id, await this.#call(agent, name, args));
        } catch (e) {
          if (e instanceof GateError) return ok(req.id, { isError: true, content: [{ type: "text", text: `${e.code}: ${e.message}` }] });
          if (e instanceof ProviderError) return ok(req.id, { isError: true, content: [{ type: "text", text: `provider error: ${e.message}` }] });
          throw e;
        }
      }
      default:
        return fail(req.id, -32601, `method ${req.method} not found`);
    }
  }

  async #call(agent: Principal, name: string, a: Record<string, unknown>): Promise<unknown> {
    const str = (k: string): string => {
      if (typeof a[k] !== "string") throw new GateError("invalid", `${k} is required`);
      return a[k] as string;
    };
    const result = (text: string, structured: Record<string, unknown>) => ({ content: [{ type: "text", text }], structuredContent: structured });

    switch (name) {
      case "list_domains": {
        const domains = this.#gate.listDomains(agent);
        return result(domains.length === 0 ? "No domains are granted to you." : domains.map((d) => `${d.domain} (${d.provider})`).join("\n"), { domains });
      }
      case "list_records": {
        const records = await this.#gate.listRecords(agent, str("domain"));
        return result(records.map((r) => `[${r.id}] ${describeRecord(r)}`).join("\n") || "No records.", { records });
      }
      case "list_forwards": {
        const forwards = await this.#gate.listForwards(agent, str("domain"));
        return result(forwards.map((f) => `${f.name} → ${f.url} (${f.kind})`).join("\n") || "No forwards.", { forwards });
      }
      case "propose_change": {
        const p = await this.#gate.propose(agent, str("domain"), a.changes as ChangeInput[], str("reason"));
        return result(proposalText(p, this.#page(p.id)) + "\nWaiting for a person to accept it.", { proposal: p, page: this.#page(p.id) });
      }
      case "list_proposals": {
        const status = typeof a.status === "string" ? (a.status as ProposalStatus) : undefined;
        const list = this.#gate.listProposals(agent, status);
        return result(
          list.map((p) => `${p.id} ${p.status} ${p.domain}: ${p.reason} (${p.changes.length} change${p.changes.length === 1 ? "" : "s"})`).join("\n") || "No proposals.",
          { proposals: list },
        );
      }
      case "get_proposal": {
        const p = this.#gate.getProposal(agent, str("id"));
        return result(proposalText(p, this.#page(p.id)), { proposal: p, page: this.#page(p.id) });
      }
      case "withdraw_proposal": {
        const p = this.#gate.withdraw(agent, str("id"));
        return result(proposalText(p, this.#page(p.id)), { proposal: p });
      }
    }
    throw new GateError("invalid", `unknown tool ${name}`);
  }
}
