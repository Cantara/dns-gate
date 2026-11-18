// Who is calling. Agents present a bearer token; the config holds only its SHA-256. People sign in
// with Google (OpenID Connect) and get a session cookie; the config lists which emails are people.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { AgentConfig, PersonConfig } from "./config.ts";
import type { Principal } from "./model.ts";

export function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/** A new agent token, with the hash that goes in the config. The token itself is shown once. */
export function newToken(): { token: string; sha256: string } {
  const token = "dg_" + randomBytes(32).toString("base64url");
  return { token, sha256: sha256Hex(token) };
}

export function agentForToken(agents: AgentConfig[], token: string): Principal | undefined {
  const got = Buffer.from(sha256Hex(token), "hex");
  let found: AgentConfig | undefined;
  for (const a of agents) {
    // Compare against every agent, so the time taken says nothing about which one matched.
    const want = Buffer.from(a.tokenSha256, "hex");
    if (want.length === got.length && timingSafeEqual(want, got)) found = a;
  }
  return found ? { id: found.id, kind: "agent", groups: [...found.groups] } : undefined;
}

export function personForEmail(people: PersonConfig[], email: string): Principal | undefined {
  const p = people.find((x) => x.email === email.toLowerCase());
  return p ? { id: p.email, kind: "person", groups: [...p.groups] } : undefined;
}

export interface Session {
  email: string;
  csrf: string;
  expires: number;
}

/** In memory: a restart signs everyone out, which is acceptable for a page used to approve changes. */
export class Sessions {
  readonly #byId = new Map<string, Session>();
  readonly #ttlMs: number;
  readonly #now: () => number;

  constructor(ttlMs = 8 * 3600_000, now: () => number = Date.now) {
    this.#ttlMs = ttlMs;
    this.#now = now;
  }

  create(email: string): { id: string; session: Session } {
    const id = randomBytes(32).toString("base64url");
    const session = { email: email.toLowerCase(), csrf: randomBytes(24).toString("base64url"), expires: this.#now() + this.#ttlMs };
    this.#byId.set(id, session);
    return { id, session };
  }

  get(id: string | undefined): Session | undefined {
    if (!id) return undefined;
    const s = this.#byId.get(id);
    if (!s) return undefined;
    if (s.expires < this.#now()) {
      this.#byId.delete(id);
      return undefined;
    }
    return s;
  }

  delete(id: string | undefined): void {
    if (id) this.#byId.delete(id);
  }
}

/** Sign-in with an OpenID Connect provider. Split out so tests can stand in for Google. */
export interface SignIn {
  /** Where to send the browser, and what to remember until it comes back. */
  start(redirectUri: string): Promise<{ url: string; pending: PendingLogin }>;
  /** The verified email address, or an error. */
  finish(callbackUrl: URL, pending: PendingLogin, redirectUri: string): Promise<string>;
}

export interface PendingLogin {
  state: string;
  codeVerifier: string;
  nonce: string;
  expires: number;
}

export async function googleSignIn(issuer: string, clientId: string, clientSecret: string): Promise<SignIn> {
  const client = await import("openid-client");
  const config = await client.discovery(new URL(issuer), clientId, clientSecret);
  return {
    async start(redirectUri) {
      const codeVerifier = client.randomPKCECodeVerifier();
      const pending: PendingLogin = {
        state: client.randomState(),
        nonce: client.randomNonce(),
        codeVerifier,
        expires: Date.now() + 10 * 60_000,
      };
      const url = client.buildAuthorizationUrl(config, {
        redirect_uri: redirectUri,
        scope: "openid email",
        code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: "S256",
        state: pending.state,
        nonce: pending.nonce,
        prompt: "select_account",
      });
      return { url: url.href, pending };
    },
    async finish(callbackUrl, pending) {
      const tokens = await client.authorizationCodeGrant(config, callbackUrl, {
        pkceCodeVerifier: pending.codeVerifier,
        expectedState: pending.state,
        expectedNonce: pending.nonce,
        idTokenExpected: true,
      });
      const claims = tokens.claims();
      if (!claims || typeof claims.email !== "string") throw new Error("the sign-in returned no email address");
      if (claims.email_verified !== true) throw new Error("the email address is not verified with the sign-in provider");
      return claims.email;
    },
  };
}
