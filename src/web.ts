// The pages people see. Plain HTML, no scripts: the content-security policy allows none.

import { describeRecord, type Change, type Principal, type Proposal } from "./model.ts";

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}
const e = escapeHtml;

const STYLE = `
:root{--bg:#fbfbf9;--fg:#1d1d1b;--muted:#6b6b66;--line:#ddddd6;--add:#e3f4e1;--del:#fbe4e1;--chg:#fdf3d7;--btn:#1d1d1b;--btnfg:#fff}
@media (prefers-color-scheme: dark){:root{--bg:#161615;--fg:#ecece8;--muted:#9a9a93;--line:#33332f;--add:#1f3a1d;--del:#43221e;--chg:#3d3418;--btn:#ecece8;--btnfg:#161615}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 16px}h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 8px}
a{color:inherit}.muted{color:var(--muted)}header{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:16px}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
code,.rec{font-family:ui-monospace,monospace;font-size:.92em;overflow-wrap:anywhere}
.chg{padding:8px 10px;border-radius:6px;margin:6px 0}.create{background:var(--add)}.delete{background:var(--del)}.update{background:var(--chg)}
.op{font-weight:600;margin-right:6px}button{font:inherit;padding:8px 16px;border-radius:6px;border:1px solid var(--btn);background:var(--btn);color:var(--btnfg);cursor:pointer}
button.secondary{background:transparent;color:var(--fg)}form.inline{display:inline}textarea{width:100%;font:inherit;padding:6px;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px}
.status{display:inline-block;padding:1px 8px;border-radius:999px;border:1px solid var(--line);font-size:.85em}.note{white-space:pre-wrap;border-left:3px solid var(--line);padding-left:10px}
.actions{display:flex;gap:16px;flex-wrap:wrap;align-items:flex-start;margin-top:20px}.actions form{flex:1 1 260px}
`;

export function layout(title: string, body: string, who?: Principal, csrf?: string): string {
  const signout =
    who && csrf
      ? `<form class="inline" method="post" action="/logout"><span class="muted">${e(who.id)}</span> <button class="secondary" type="submit">Sign out</button></form>`
      : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${e(title)} · dns-gate</title><style>${STYLE}</style></head><body><main>
<header><div><a href="/" style="text-decoration:none"><strong>dns-gate</strong></a></div>${signout}</header>
<h1>${e(title)}</h1>${body}</main></body></html>`;
}

function changeHtml(c: Change): string {
  if (c.op === "create") return `<div class="chg create"><span class="op">Add</span><span class="rec">${e(describeRecord(c.after))}</span></div>`;
  if (c.op === "delete") return `<div class="chg delete"><span class="op">Remove</span><span class="rec">${e(describeRecord(c.before))}</span></div>`;
  return `<div class="chg update"><span class="op">Change</span><span class="rec">${e(describeRecord(c.before))}</span><br><span class="op">to</span><span class="rec">${e(describeRecord(c.after))}</span></div>`;
}

const when = (iso: string) => e(iso.replace("T", " ").replace(/\.\d+Z$/, " UTC"));

function row(p: Proposal): string {
  return `<tr><td><a href="/proposals/${e(p.id)}">${e(p.domain)}</a><br><span class="muted">${e(p.reason)}</span></td>
<td>${p.changes.length}</td><td>${e(p.proposedBy)}</td><td><span class="status">${e(p.status)}</span></td><td class="muted">${when(p.proposedAt)}</td></tr>`;
}

function table(list: Proposal[]): string {
  return `<table><thead><tr><th>Domain and reason</th><th>Changes</th><th>Proposed by</th><th>Status</th><th>When</th></tr></thead><tbody>${list.map(row).join("")}</tbody></table>`;
}

export function proposalsPage(who: Principal, pending: Proposal[], decided: Proposal[], csrf: string): string {
  const body =
    (pending.length === 0 ? '<p class="muted">Nothing is waiting for you.</p>' : `<p>${pending.length} waiting for you to accept or reject.</p>${table(pending)}`) +
    (decided.length > 0 ? `<h2>Recently decided</h2>${table(decided)}` : "");
  return layout("Proposals", body, who, csrf);
}

export function proposalPage(who: Principal, p: Proposal, csrf: string): string {
  let body = `<p><span class="status">${e(p.status)}</span> <strong>${e(p.domain)}</strong>, proposed by <strong>${e(p.proposedBy)}</strong> at ${when(p.proposedAt)}</p>
<p><strong>Reason:</strong> ${e(p.reason)}</p>
<h2>Changes</h2>${p.changes.map(changeHtml).join("")}`;
  if (p.decidedBy) body += `<p class="muted">Decided by ${e(p.decidedBy)} at ${when(p.decidedAt ?? "")}</p>`;
  if (p.note) body += `<p class="note">${e(p.note)}</p>`;
  if (p.status === "pending") {
    body += `<div class="actions">
<form method="post" action="/proposals/${e(p.id)}/accept"><input type="hidden" name="csrf" value="${e(csrf)}">
<p>Accepting applies these changes to live DNS at once. If the records changed since the proposal was made, nothing is applied.</p>
<button type="submit">Accept and apply</button></form>
<form method="post" action="/proposals/${e(p.id)}/reject"><input type="hidden" name="csrf" value="${e(csrf)}">
<p><label for="note">Why not (the agent reads this)</label></p><textarea id="note" name="note" rows="3"></textarea>
<p><button class="secondary" type="submit">Reject</button></p></form></div>`;
  }
  return layout(`Proposal ${p.id}`, body, who, csrf);
}

export function signedOutPage(canSignIn: boolean): string {
  return layout(
    "Sign in",
    canSignIn
      ? '<p>Agents propose DNS changes here; people accept or reject them.</p><p><a href="/login">Sign in with Google</a></p>'
      : "<p>This dns-gate has no sign-in configured, so nobody can accept proposals here.</p>",
  );
}

export function page403(email: string): string {
  return layout("Not granted", `<p>${e(email)} is not a person in this dns-gate's config, so it cannot see or decide anything here.</p>`);
}
