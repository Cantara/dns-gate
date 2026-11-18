import { test } from "node:test";
import assert from "node:assert/strict";
import { validateConfig } from "../src/config.ts";
import { agentForToken, newToken } from "../src/auth.ts";

const GOOD = {
  listen: { host: "127.0.0.1", port: 8787 },
  publicUrl: "https://dns-gate.example.com",
  database: "/var/lib/dns-gate/dns-gate.db",
  providers: { porkbun: { type: "porkbun", credentialsFile: "/etc/dns-gate/porkbun.json" } },
  domains: { "steinar.rocks": "porkbun" },
  groups: { homelab: ["steinar.rocks"] },
  agents: [{ id: "steinar-agent", tokenSha256: "a".repeat(64), groups: ["homelab"] }],
  people: [{ email: "Steinar@Example.com", groups: ["homelab"] }],
};

test("a good config passes, and emails are lower-cased", () => {
  const { config, problems } = validateConfig(GOOD);
  assert.deepEqual(problems, []);
  assert.equal(config?.people[0]?.email, "steinar@example.com");
});

test("every problem is reported at once", () => {
  const { problems } = validateConfig({
    ...GOOD,
    extra: 1,
    domains: { "steinar.rocks": "nope" },
    groups: { homelab: ["steinar.rocks", "missing.no"] },
    agents: [{ id: "a", tokenSha256: "short", groups: ["undefined-group"] }],
  });
  assert.ok(problems.some((p) => /unknown key "extra"/.test(p)));
  assert.ok(problems.some((p) => /names no configured provider/.test(p)));
  assert.ok(problems.some((p) => /missing\.no, which is not under domains/.test(p)));
  assert.ok(problems.some((p) => /tokenSha256 must be 64/.test(p)));
  assert.ok(problems.some((p) => /group undefined-group, which is not defined/.test(p)));
});

test("a provider other than memory needs a credentials file", () => {
  const { problems } = validateConfig({ ...GOOD, providers: { porkbun: { type: "porkbun" } } });
  assert.ok(problems.some((p) => /credentialsFile is required/.test(p)));
});

test("a new token matches its own hash and nothing else", () => {
  const t = newToken();
  assert.match(t.token, /^dg_/);
  const agents = [{ id: "x", tokenSha256: t.sha256, groups: [] }];
  assert.equal(agentForToken(agents, t.token)?.id, "x");
  assert.equal(agentForToken(agents, t.token + "x"), undefined);
  assert.equal(agentForToken(agents, newToken().token), undefined);
});
