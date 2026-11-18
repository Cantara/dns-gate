// The HTTP server: /mcp for agents (bearer token), and the web page for people (Google sign-in).

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { agentForToken, personForEmail, type PendingLogin, type Sessions, type SignIn } from "./auth.ts";
import type { AgentConfig, PersonConfig } from "./config.ts";
import { GateError, type Gate } from "./gate.ts";
import { McpHandler } from "./mcp.ts";
import { ProviderError } from "./providers/provider.ts";
import { escapeHtml, layout, page403, proposalPage, proposalsPage, signedOutPage } from "./web.ts";

export interface ServerOptions {
  gate: Gate;
  agents: AgentConfig[];
  people: PersonConfig[];
  publicUrl: string;
  sessions: Sessions;
  /** Absent when no sign-in is configured: the page then explains that, and nobody can accept. */
  signIn?: SignIn;
  log?: (line: string) => void;
}

const COOKIE = "dns_gate_session";
const MAX_MCP_BODY = 1_000_000;
const MAX_FORM_BODY = 16_000;

function readBody(req: IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > limit) {
        reject(new HttpError(413, "request body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function cookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

export function createDnsGateServer(o: ServerOptions): Server {
  const publicUrl = o.publicUrl.replace(/\/$/, "");
  const publicOrigin = new URL(publicUrl).origin;
  const secure = publicUrl.startsWith("https://");
  const mcp = new McpHandler(o.gate, publicUrl);
  const pending = new Map<string, PendingLogin>();
  const log = o.log ?? ((line: string) => console.log(line));
  const redirectUri = `${publicUrl}/auth/callback`;

  const send = (res: ServerResponse, status: number, body: string, type = "text/html; charset=utf-8", extra: Record<string, string | string[]> = {}) => {
    res.writeHead(status, { "Content-Type": type, ...SECURITY_HEADERS, ...extra });
    res.end(body);
  };
  const redirect = (res: ServerResponse, to: string, extra: Record<string, string | string[]> = {}) => {
    res.writeHead(303, { Location: to, ...SECURITY_HEADERS, ...extra });
    res.end();
  };
  const sessionCookie = (value: string, maxAge: number) =>
    `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;

  async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") return send(res, 405, "", "text/plain", { Allow: "POST" });
    // Browsers send Origin; agents usually do not. A foreign Origin is a web page trying to use a
    // local agent's network position, which the MCP spec says to refuse.
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== publicOrigin) return send(res, 403, "foreign origin", "text/plain");
    const auth = req.headers.authorization ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    const agent = token ? agentForToken(o.agents, token) : undefined;
    if (!agent) return send(res, 401, JSON.stringify({ error: "a valid agent bearer token is required" }), "application/json", { "WWW-Authenticate": 'Bearer realm="dns-gate"' });

    let msg: unknown;
    try {
      msg = JSON.parse(await readBody(req, MAX_MCP_BODY));
    } catch (e) {
      if (e instanceof HttpError) throw e;
      return send(res, 400, JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }), "application/json");
    }
    const reply = await mcp.handle(agent, msg);
    if (reply === undefined) return send(res, 202, "", "text/plain");
    send(res, 200, JSON.stringify(reply), "application/json");
  }

  async function handleWeb(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const sid = cookies(req)[COOKIE];
    const session = o.sessions.get(sid);
    const person = session ? personForEmail(o.people, session.email) : undefined;

    if (url.pathname === "/healthz") return send(res, 200, "ok\n", "text/plain");

    if (url.pathname === "/login" && req.method === "GET") {
      if (!o.signIn) return send(res, 503, layout("Sign-in is not set up", "<p>This dns-gate has no sign-in configured, so nobody can accept proposals here.</p>"));
      const { url: to, pending: p } = await o.signIn.start(redirectUri);
      pending.set(p.state, p);
      for (const [k, v] of pending) if (v.expires < Date.now()) pending.delete(k);
      return redirect(res, to);
    }

    if (url.pathname === "/auth/callback" && req.method === "GET") {
      if (!o.signIn) return send(res, 503, "sign-in is not configured", "text/plain");
      const state = url.searchParams.get("state") ?? "";
      const p = pending.get(state);
      pending.delete(state);
      if (!p || p.expires < Date.now()) return send(res, 400, layout("Sign-in expired", '<p>That sign-in link is old or was already used. <a href="/login">Sign in again</a>.</p>'));
      let email: string;
      try {
        // The redirect URI sent to the token endpoint must be the public one, not what a proxy forwarded.
        email = await o.signIn.finish(new URL(`${redirectUri}${url.search}`), p, redirectUri);
      } catch (e) {
        log(`sign-in failed: ${(e as Error).message}`);
        return send(res, 400, layout("Sign-in failed", '<p>The sign-in could not be completed. <a href="/login">Try again</a>.</p>'));
      }
      if (!personForEmail(o.people, email)) {
        log(`sign-in refused for ${email}: not a person in the config`);
        return send(res, 403, page403(email));
      }
      o.sessions.delete(sid);
      const { id } = o.sessions.create(email);
      log(`signed in: ${email}`);
      return redirect(res, "/", { "Set-Cookie": sessionCookie(id, 8 * 3600) });
    }

    if (url.pathname === "/logout" && req.method === "POST") {
      o.sessions.delete(sid);
      return redirect(res, "/", { "Set-Cookie": sessionCookie("", 0) });
    }

    if (!session || !person) return send(res, 200, signedOutPage(Boolean(o.signIn)));

    if (url.pathname === "/" && req.method === "GET") {
      return send(res, 200, proposalsPage(person, o.gate.listProposals(person, "pending"), o.gate.listProposals(person).filter((p) => p.status !== "pending").slice(0, 30), session.csrf));
    }

    const m = /^\/proposals\/([A-Za-z0-9_]+)(\/(accept|reject))?$/.exec(url.pathname);
    if (m) {
      const id = m[1] as string;
      const action = m[3];
      if (!action && req.method === "GET") {
        return send(res, 200, proposalPage(person, o.gate.getProposal(person, id), session.csrf));
      }
      if (action && req.method === "POST") {
        const origin = req.headers.origin;
        if (origin !== undefined && origin !== publicOrigin) return send(res, 403, "foreign origin", "text/plain");
        const form = new URLSearchParams(await readBody(req, MAX_FORM_BODY));
        if (form.get("csrf") !== session.csrf) return send(res, 403, layout("Refused", "<p>The form was stale. Reload the page and try again.</p>"));
        const outcome =
          action === "accept"
            ? (await o.gate.accept(person, id)).proposal.status
            : o.gate.reject(person, id, (form.get("note") ?? "").slice(0, 2000)).status;
        log(`${person.id} ${action} ${id}: ${outcome}`);
        return redirect(res, `/proposals/${encodeURIComponent(id)}`);
      }
    }
    return send(res, 404, layout("Not found", "<p>No such page.</p>"));
  }

  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", publicUrl);
    try {
      if (url.pathname === "/mcp") await handleMcp(req, res);
      else await handleWeb(req, res, url);
    } catch (e) {
      if (res.headersSent) return res.destroy();
      if (e instanceof HttpError) return send(res, e.status, e.message, "text/plain");
      if (e instanceof GateError) {
        const status = { forbidden: 403, not_found: 404, invalid: 400, conflict: 409 }[e.code];
        return send(res, status, layout("Not done", `<p>${escapeHtml(e.message).replace(/\n/g, "<br>")}</p><p><a href="/">Back</a></p>`));
      }
      if (e instanceof ProviderError) return send(res, 502, layout("Provider error", `<p>${escapeHtml(e.message)}</p><p><a href="/">Back</a></p>`));
      const ref = randomBytes(4).toString("hex");
      log(`error ${ref}: ${(e as Error).stack ?? String(e)}`);
      send(res, 500, `internal error (ref ${ref})`, "text/plain");
    }
  });
}
