// The providers' translation to and from their APIs, against a recorded fake of each API.
// These prove the shapes we send and parse; they do not prove the live API still has them.
// `dns-gate check-config` against a real account is that check.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DomeneshopProvider } from "../src/providers/domeneshop.ts";
import { PorkbunProvider, relativeName } from "../src/providers/porkbun.ts";
import { ProviderError } from "../src/providers/provider.ts";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function fakeFetch(route: (c: Call) => { status?: number; body?: unknown }) {
  const calls: Call[] = [];
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const c: Call = {
      url: String(input),
      method: init?.method ?? "GET",
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    };
    calls.push(c);
    const r = route(c);
    const status = r.status ?? 200;
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return { f, calls };
}

// ---- Porkbun ------------------------------------------------------------------------------

test("porkbun: relative names", () => {
  assert.equal(relativeName("steinar.rocks", "steinar.rocks"), "@");
  assert.equal(relativeName("home.steinar.rocks", "steinar.rocks"), "home");
  assert.equal(relativeName("*.steinar.rocks", "steinar.rocks"), "*");
  assert.equal(relativeName("a.b.steinar.rocks", "steinar.rocks"), "a.b");
});

test("porkbun: credentials go in the body, never in the URL", async () => {
  const { f, calls } = fakeFetch(() => ({ body: { status: "SUCCESS", records: [] } }));
  await new PorkbunProvider("pb", { apiKey: "pk1_k", secretApiKey: "sk1_s" }, f).listRecords("steinar.rocks");
  assert.equal(calls[0]?.url, "https://api.porkbun.com/api/json/v3/dns/retrieve/steinar.rocks");
  assert.equal(calls[0]?.method, "POST");
  assert.deepEqual(calls[0]?.body, { apikey: "pk1_k", secretapikey: "sk1_s" });
  assert.ok(!calls[0]?.url.includes("sk1_s"));
});

test("porkbun: records are translated: full names, string numbers, SRV content", async () => {
  const { f } = fakeFetch(() => ({
    body: {
      status: "SUCCESS",
      records: [
        { id: "101", name: "steinar.rocks", type: "ALIAS", content: "pixie.porkbun.com", ttl: "600", prio: "0", notes: "" },
        { id: "102", name: "home.steinar.rocks", type: "A", content: "203.0.113.5", ttl: "600", prio: null, notes: "" },
        { id: "103", name: "steinar.rocks", type: "MX", content: "mx.example.net", ttl: "3600", prio: "10", notes: "" },
        { id: "104", name: "_sip._tcp.steinar.rocks", type: "SRV", content: "5 5060 sip.example.net", ttl: "600", prio: "20", notes: "" },
      ],
    },
  }));
  const records = await new PorkbunProvider("pb", { apiKey: "k", secretApiKey: "s" }, f).listRecords("steinar.rocks");
  assert.deepEqual(records, [
    { id: "101", name: "@", type: "ALIAS", content: "pixie.porkbun.com", ttl: 600 },
    { id: "102", name: "home", type: "A", content: "203.0.113.5", ttl: 600 },
    { id: "103", name: "@", type: "MX", content: "mx.example.net", ttl: 3600, priority: 10 },
    { id: "104", name: "_sip._tcp", type: "SRV", content: "sip.example.net", ttl: 600, priority: 20, weight: 5, port: 5060 },
  ]);
});

test("porkbun: writes send the subdomain, string ttl and prio, and SRV content back in Porkbun's form", async () => {
  const { f, calls } = fakeFetch(() => ({ body: { status: "SUCCESS", id: 1 } }));
  const pb = new PorkbunProvider("pb", { apiKey: "k", secretApiKey: "s" }, f);
  await pb.createRecord("steinar.rocks", { name: "@", type: "A", content: "203.0.113.5", ttl: 600 });
  await pb.updateRecord("steinar.rocks", "104", { name: "_sip._tcp", type: "SRV", content: "sip.example.net", ttl: 600, priority: 20, weight: 5, port: 5060 });
  await pb.deleteRecord("steinar.rocks", "102");
  assert.equal(calls[0]?.url, "https://api.porkbun.com/api/json/v3/dns/create/steinar.rocks");
  assert.deepEqual(calls[0]?.body, { apikey: "k", secretapikey: "s", name: "", type: "A", content: "203.0.113.5", ttl: "600" });
  assert.equal(calls[1]?.url, "https://api.porkbun.com/api/json/v3/dns/edit/steinar.rocks/104");
  assert.deepEqual(calls[1]?.body, { apikey: "k", secretapikey: "s", name: "_sip._tcp", type: "SRV", content: "5 5060 sip.example.net", ttl: "600", prio: "20" });
  assert.equal(calls[2]?.url, "https://api.porkbun.com/api/json/v3/dns/delete/steinar.rocks/102");
});

test("porkbun: an ERROR status is a failure even with HTTP 200", async () => {
  const { f } = fakeFetch(() => ({ body: { status: "ERROR", message: "API access is not enabled for this domain" } }));
  await assert.rejects(new PorkbunProvider("pb", { apiKey: "k", secretApiKey: "s" }, f).listRecords("steinar.rocks"), (e: unknown) => {
    assert.ok(e instanceof ProviderError);
    assert.match(e.message, /API access is not enabled/);
    return true;
  });
});

test("porkbun: refuses a ttl below its minimum before any call", () => {
  const pb = new PorkbunProvider("pb", { apiKey: "k", secretApiKey: "s" }, fakeFetch(() => ({})).f);
  assert.deepEqual(pb.validate({ name: "x", type: "A", content: "203.0.113.1", ttl: 300 }), ["porkbun's smallest ttl is 600 (got 300)"]);
});

test("porkbun: forwards", async () => {
  const { f } = fakeFetch(() => ({
    body: { status: "SUCCESS", forwards: [{ id: "9", subdomain: "", location: "https://example.com", type: "temporary", includePath: "no", wildcard: "yes" }] },
  }));
  const fw = await new PorkbunProvider("pb", { apiKey: "k", secretApiKey: "s" }, f).listForwards("steinar.rocks");
  assert.deepEqual(fw, [{ id: "9", name: "@", url: "https://example.com", kind: "temporary" }]);
});

// ---- Domeneshop ---------------------------------------------------------------------------

const DOMAINS = [{ id: 7, domain: "example.no", nameservers: [], services: {} }];

test("domeneshop: basic auth, domain looked up by name, records translated", async () => {
  const { f, calls } = fakeFetch((c) => {
    if (c.url.endsWith("/domains")) return { body: DOMAINS };
    return {
      body: [
        { id: 1, host: "@", ttl: 3600, type: "A", data: "198.51.100.1" },
        { id: 2, host: "@", ttl: 3600, type: "MX", data: "mx.example.net", priority: "10" },
        { id: 3, host: "_sip._tcp", ttl: 3600, type: "SRV", data: "sip.example.net", priority: "20", weight: "5", port: "5060" },
      ],
    };
  });
  const ds = new DomeneshopProvider("ds", { token: "tok", secret: "sec" }, f);
  const records = await ds.listRecords("example.no");
  assert.equal(calls[0]?.headers.Authorization, "Basic " + Buffer.from("tok:sec").toString("base64"));
  assert.equal(calls[1]?.url, "https://api.domeneshop.no/v0/domains/7/dns");
  assert.deepEqual(records, [
    { id: "1", name: "@", type: "A", content: "198.51.100.1", ttl: 3600 },
    { id: "2", name: "@", type: "MX", content: "mx.example.net", ttl: 3600, priority: 10 },
    { id: "3", name: "_sip._tcp", type: "SRV", content: "sip.example.net", ttl: 3600, priority: 20, weight: 5, port: 5060 },
  ]);
});

test("domeneshop: writes use POST/PUT/DELETE on the record's id", async () => {
  const { f, calls } = fakeFetch((c) => (c.url.endsWith("/domains") ? { body: DOMAINS } : c.method === "POST" ? { status: 201, body: { id: 9 } } : { status: 204 }));
  const ds = new DomeneshopProvider("ds", { token: "t", secret: "s" }, f);
  await ds.createRecord("example.no", { name: "www", type: "CNAME", content: "example.no", ttl: 3600 });
  await ds.updateRecord("example.no", "2", { name: "@", type: "MX", content: "mx2.example.net", ttl: 3600, priority: 20 });
  await ds.deleteRecord("example.no", "3");
  const writes = calls.filter((c) => !c.url.endsWith("/domains"));
  assert.deepEqual(writes.map((c) => `${c.method} ${c.url}`), [
    "POST https://api.domeneshop.no/v0/domains/7/dns",
    "PUT https://api.domeneshop.no/v0/domains/7/dns/2",
    "DELETE https://api.domeneshop.no/v0/domains/7/dns/3",
  ]);
  assert.deepEqual(writes[0]?.body, { host: "www", ttl: 3600, type: "CNAME", data: "example.no" });
  assert.deepEqual(writes[1]?.body, { host: "@", ttl: 3600, type: "MX", data: "mx2.example.net", priority: 20 });
});

test("domeneshop: a domain not on the account is a clear error", async () => {
  const { f } = fakeFetch(() => ({ body: DOMAINS }));
  await assert.rejects(new DomeneshopProvider("ds", { token: "t", secret: "s" }, f).listRecords("other.no"), /no domain other.no on this account/);
});

test("domeneshop: HTTP errors carry the status", async () => {
  const { f } = fakeFetch(() => ({ status: 401, body: { error: "unauthorized" } }));
  await assert.rejects(new DomeneshopProvider("ds", { token: "t", secret: "s" }, f).listDomains(), (e: unknown) => {
    assert.ok(e instanceof ProviderError);
    assert.equal(e.status, 401);
    return true;
  });
});

test("domeneshop: ttl must be a multiple of 60 between 60 and 604800", () => {
  const ds = new DomeneshopProvider("ds", { token: "t", secret: "s" }, fakeFetch(() => ({})).f);
  assert.equal(ds.validate({ name: "x", type: "A", content: "203.0.113.1", ttl: 3600 }).length, 0);
  assert.equal(ds.validate({ name: "x", type: "A", content: "203.0.113.1", ttl: 90 }).length, 1);
  assert.equal(ds.validate({ name: "x", type: "A", content: "203.0.113.1", ttl: 30 }).length, 1);
});

test("domeneshop: forwards", async () => {
  const { f } = fakeFetch((c) => (c.url.endsWith("/domains") ? { body: DOMAINS } : { body: [{ host: "@", frame: false, url: "https://example.com" }] }));
  const fw = await new DomeneshopProvider("ds", { token: "t", secret: "s" }, f).listForwards("example.no");
  assert.deepEqual(fw, [{ id: "@", name: "@", url: "https://example.com", kind: "redirect" }]);
});
