// End to end over HTTP: the MCP endpoint as an agent sees it, and the web page as a person sees it.
// Google is replaced by a stand-in SignIn; everything else is the real server.

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { Sessions, type SignIn } from "../src/auth.ts";
import { createDnsGateServer } from "../src/server.ts";
import { setup } from "./helpers.ts";
import { sha256Hex } from "../src/auth.ts";

const AGENT_TOKEN = "dg_test_agent_token";
const OUTSIDE_AGENT_TOKEN = "dg_test_outside_token";

async function start(opts: { email?: string } = {}) {
  const { gate, homelab, store } = setup();
  const signIn: SignIn = {
    async start() {
      return { url: "https://accounts.example/auth?state=s1", pending: { state: "s1", codeVerifier: "v", nonce: "n", expires: Date.now() + 60_000 } };
    },
    async finish() {
      return opts.email ?? "steinar@example.com";
    },
  };
  let base = "";
  const server = createDnsGateServer({
    gate,
    agents: [
      { id: "steinar-agent", tokenSha256: sha256Hex(AGENT_TOKEN), groups: ["homelab"] },
      { id: "outside-agent", tokenSha256: sha256Hex(OUTSIDE_AGENT_TOKEN), groups: ["xor"] },
    ],
    people: [
      { email: "steinar@example.com", groups: ["homelab"] },
      { email: "totto@example.com", groups: ["xor"] },
    ],
    publicUrl: "http://127.0.0.1",
    sessions: new Sessions(),
    signIn,
    log: () => {},
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { base, server, gate, homelab, store };
}

let rpcId = 0;
async function rpc(base: string, token: string | undefined, method: string, params: unknown = {}) {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
  return { status: res.status, body: res.status === 200 ? ((await res.json()) as { result?: any; error?: any }) : undefined };
}
const call = (base: string, token: string, name: string, args: unknown = {}) => rpc(base, token, "tools/call", { name, arguments: args });

async function signInAs(base: string): Promise<{ cookie: string; csrf: string }> {
  await fetch(`${base}/login`, { redirect: "manual" });
  const cb = await fetch(`${base}/auth/callback?state=s1&code=c`, { redirect: "manual" });
  const setCookie = cb.headers.get("set-cookie") ?? "";
  const cookie = setCookie.split(";")[0] as string;
  const page = await (await fetch(`${base}/`, { headers: { Cookie: cookie } })).text();
  const csrf = /name="csrf" value="([^"]+)"/.exec(page)?.[1] ?? (/name="csrf"/.test(page) ? "" : "");
  return { cookie, csrf };
}

async function csrfFor(base: string, cookie: string, id: string): Promise<string> {
  const page = await (await fetch(`${base}/proposals/${id}`, { headers: { Cookie: cookie } })).text();
  return /name="csrf" value="([^"]+)"/.exec(page)?.[1] ?? "";
}

test("mcp: no token or a wrong token is refused", async () => {
  const { base, server } = await start();
  try {
    assert.equal((await rpc(base, undefined, "tools/list")).status, 401);
    assert.equal((await rpc(base, "dg_wrong", "tools/list")).status, 401);
  } finally {
    server.close();
  }
});

test("mcp: initialize, and the tool list has no way to accept or reject", async () => {
  const { base, server } = await start();
  try {
    const init = await rpc(base, AGENT_TOKEN, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
    assert.equal(init.body?.result.protocolVersion, "2025-06-18");
    assert.equal(init.body?.result.serverInfo.name, "dns-gate");
    const names = (await rpc(base, AGENT_TOKEN, "tools/list")).body?.result.tools.map((t: { name: string }) => t.name);
    assert.deepEqual(names, ["list_domains", "list_records", "list_forwards", "propose_change", "list_proposals", "get_proposal", "withdraw_proposal"]);
    assert.ok(!names.some((n: string) => /accept|reject|apply/.test(n)));
    const unknown = await call(base, AGENT_TOKEN, "accept_proposal", { id: "x" });
    assert.equal(unknown.body?.error.code, -32602);
  } finally {
    server.close();
  }
});

test("mcp: a notification gets 202 and no body", async () => {
  const { base, server } = await start();
  try {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${AGENT_TOKEN}` },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    });
    assert.equal(res.status, 202);
  } finally {
    server.close();
  }
});

test("mcp: a browser page on another origin cannot use an agent's token", async () => {
  const { base, server } = await start();
  try {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${AGENT_TOKEN}`, Origin: "https://evil.example" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test("mcp: an agent reads its domains and records, and not another group's", async () => {
  const { base, server } = await start();
  try {
    const domains = await call(base, AGENT_TOKEN, "list_domains");
    assert.deepEqual(domains.body?.result.structuredContent.domains, [{ domain: "example.rocks", provider: "homelab-dns" }]);
    const recs = await call(base, AGENT_TOKEN, "list_records", { domain: "example.rocks" });
    assert.equal(recs.body?.result.structuredContent.records.length, 4);
    const other = await call(base, AGENT_TOKEN, "list_records", { domain: "example.no" });
    assert.equal(other.body?.result.isError, true);
    assert.match(other.body?.result.content[0].text, /^not_found/);
  } finally {
    server.close();
  }
});

test("end to end: an agent proposes, the agent cannot accept, a person accepts on the page, live DNS changes", async () => {
  const { base, server, homelab } = await start();
  try {
    const prop = await call(base, AGENT_TOKEN, "propose_change", {
      domain: "example.rocks",
      reason: "point api at the new host",
      changes: [{ op: "create", record: { name: "api", type: "A", content: "203.0.113.20", ttl: 600 } }],
    });
    const id = prop.body?.result.structuredContent.proposal.id as string;
    assert.match(prop.body?.result.structuredContent.page, new RegExp(`/proposals/${id}$`));
    assert.ok(!(await homelab.listRecords("example.rocks")).some((r) => r.name === "api"));

    // The agent's token gets it nowhere on the web side: it has no session.
    const asAgent = await fetch(`${base}/proposals/${id}/accept`, {
      method: "POST",
      headers: { Authorization: `Bearer ${AGENT_TOKEN}`, "Content-Type": "application/x-www-form-urlencoded" },
      body: "csrf=x",
      redirect: "manual",
    });
    assert.equal(asAgent.status, 200); // the signed-out page, nothing applied
    assert.match(await asAgent.text(), /Sign in/);
    assert.ok(!(await homelab.listRecords("example.rocks")).some((r) => r.name === "api"));

    const { cookie } = await signInAs(base);
    const page = await (await fetch(`${base}/proposals/${id}`, { headers: { Cookie: cookie } })).text();
    assert.match(page, /point api at the new host/);
    assert.match(page, /api A 203\.0\.113\.20/);

    // Without the form's csrf value the accept is refused.
    const noCsrf = await fetch(`${base}/proposals/${id}/accept`, { method: "POST", headers: { Cookie: cookie, "Content-Type": "application/x-www-form-urlencoded" }, body: "csrf=wrong", redirect: "manual" });
    assert.equal(noCsrf.status, 403);

    const csrf = await csrfFor(base, cookie, id);
    const accept = await fetch(`${base}/proposals/${id}/accept`, {
      method: "POST",
      headers: { Cookie: cookie, "Content-Type": "application/x-www-form-urlencoded" },
      body: `csrf=${encodeURIComponent(csrf)}`,
      redirect: "manual",
    });
    assert.equal(accept.status, 303);
    assert.ok((await homelab.listRecords("example.rocks")).some((r) => r.name === "api" && r.content === "203.0.113.20"));

    const after = await call(base, AGENT_TOKEN, "get_proposal", { id });
    assert.equal(after.body?.result.structuredContent.proposal.status, "accepted");
    assert.equal(after.body?.result.structuredContent.proposal.decidedBy, "steinar@example.com");
  } finally {
    server.close();
  }
});

test("web: a Google account not in the config is refused", async () => {
  const { base, server } = await start({ email: "stranger@example.com" });
  try {
    await fetch(`${base}/login`, { redirect: "manual" });
    const cb = await fetch(`${base}/auth/callback?state=s1&code=c`, { redirect: "manual" });
    assert.equal(cb.status, 403);
    assert.equal(cb.headers.get("set-cookie"), null);
  } finally {
    server.close();
  }
});

test("web: a callback with an unknown state is refused", async () => {
  const { base, server } = await start();
  try {
    const cb = await fetch(`${base}/auth/callback?state=forged&code=c`, { redirect: "manual" });
    assert.equal(cb.status, 400);
  } finally {
    server.close();
  }
});

test("web: a person sees only proposals for their groups' domains", async () => {
  const { base, server } = await start({ email: "totto@example.com" });
  try {
    const prop = await call(base, AGENT_TOKEN, "propose_change", { domain: "example.rocks", reason: "r", changes: [{ op: "delete", id: "2" }] });
    const id = prop.body?.result.structuredContent.proposal.id as string;
    const { cookie } = await signInAs(base);
    const list = await (await fetch(`${base}/`, { headers: { Cookie: cookie } })).text();
    assert.ok(!list.includes(id));
    const one = await fetch(`${base}/proposals/${id}`, { headers: { Cookie: cookie } });
    assert.equal(one.status, 404);
  } finally {
    server.close();
  }
});

test("web: pages are served with a strict content-security policy", async () => {
  const { base, server } = await start();
  try {
    const res = await fetch(`${base}/`);
    assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/);
    assert.equal(res.headers.get("x-frame-options"), "DENY");
  } finally {
    server.close();
  }
});
