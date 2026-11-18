// Proposals and the audit log, in SQLite (node:sqlite, built into Node). The audit log is
// append-only: this module has no way to change or remove an event once written.

import { DatabaseSync } from "node:sqlite";
import type { Change, Proposal, ProposalStatus } from "./model.ts";

export interface AuditEvent {
  seq: number;
  at: string;
  principal: string;
  action: string;
  proposalId: string | null;
  domain: string | null;
  detail: string;
}

interface ProposalRow {
  id: string;
  domain: string;
  changes: string;
  reason: string;
  proposed_by: string;
  proposed_at: string;
  status: string;
  decided_by: string | null;
  decided_at: string | null;
  note: string | null;
}

function toProposal(r: ProposalRow): Proposal {
  const p: Proposal = {
    id: r.id,
    domain: r.domain,
    changes: JSON.parse(r.changes) as Change[],
    reason: r.reason,
    proposedBy: r.proposed_by,
    proposedAt: r.proposed_at,
    status: r.status as ProposalStatus,
  };
  if (r.decided_by !== null) p.decidedBy = r.decided_by;
  if (r.decided_at !== null) p.decidedAt = r.decided_at;
  if (r.note !== null) p.note = r.note;
  return p;
}

export class Store {
  readonly #db: DatabaseSync;

  constructor(path: string) {
    this.#db = new DatabaseSync(path);
    this.#db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS proposals (
        id TEXT PRIMARY KEY,
        domain TEXT NOT NULL,
        changes TEXT NOT NULL,
        reason TEXT NOT NULL,
        proposed_by TEXT NOT NULL,
        proposed_at TEXT NOT NULL,
        status TEXT NOT NULL,
        decided_by TEXT,
        decided_at TEXT,
        note TEXT
      );
      CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        at TEXT NOT NULL,
        principal TEXT NOT NULL,
        action TEXT NOT NULL,
        proposal_id TEXT,
        domain TEXT,
        detail TEXT NOT NULL
      );
    `);
  }

  close(): void {
    this.#db.close();
  }

  insertProposal(p: Proposal): void {
    this.#db
      .prepare(
        `INSERT INTO proposals (id, domain, changes, reason, proposed_by, proposed_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(p.id, p.domain, JSON.stringify(p.changes), p.reason, p.proposedBy, p.proposedAt, p.status);
  }

  getProposal(id: string): Proposal | undefined {
    const row = this.#db.prepare(`SELECT * FROM proposals WHERE id = ?`).get(id) as ProposalRow | undefined;
    return row ? toProposal(row) : undefined;
  }

  /** Newest first. */
  listProposals(filter: { status?: ProposalStatus; domains: string[] }): Proposal[] {
    if (filter.domains.length === 0) return [];
    const marks = filter.domains.map(() => "?").join(", ");
    const args: string[] = [...filter.domains];
    let sql = `SELECT * FROM proposals WHERE domain IN (${marks})`;
    if (filter.status) {
      sql += ` AND status = ?`;
      args.push(filter.status);
    }
    sql += ` ORDER BY proposed_at DESC, id DESC`;
    return (this.#db.prepare(sql).all(...args) as unknown as ProposalRow[]).map(toProposal);
  }

  /**
   * Move a proposal out of "pending". Returns false when it was no longer pending, so two people
   * deciding at once cannot both win: only one UPDATE matches.
   */
  decide(id: string, status: ProposalStatus, by: string, at: string, note?: string): boolean {
    const res = this.#db
      .prepare(`UPDATE proposals SET status = ?, decided_by = ?, decided_at = ?, note = ? WHERE id = ? AND status = 'pending'`)
      .run(status, by, at, note ?? null, id);
    return Number(res.changes) === 1;
  }

  /** Record the outcome of an apply on a proposal already moved out of pending. */
  setOutcome(id: string, status: ProposalStatus, note?: string): void {
    this.#db.prepare(`UPDATE proposals SET status = ?, note = ? WHERE id = ?`).run(status, note ?? null, id);
  }

  audit(e: Omit<AuditEvent, "seq">): void {
    this.#db
      .prepare(`INSERT INTO events (at, principal, action, proposal_id, domain, detail) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(e.at, e.principal, e.action, e.proposalId, e.domain, e.detail);
  }

  events(filter: { proposalId?: string } = {}): AuditEvent[] {
    const rows = filter.proposalId
      ? this.#db.prepare(`SELECT * FROM events WHERE proposal_id = ? ORDER BY seq`).all(filter.proposalId)
      : this.#db.prepare(`SELECT * FROM events ORDER BY seq`).all();
    return (rows as unknown as { seq: number; at: string; principal: string; action: string; proposal_id: string | null; domain: string | null; detail: string }[]).map(
      (r) => ({ seq: r.seq, at: r.at, principal: r.principal, action: r.action, proposalId: r.proposal_id, domain: r.domain, detail: r.detail }),
    );
  }
}
