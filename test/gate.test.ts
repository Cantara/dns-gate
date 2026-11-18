import { test } from "node:test";
import assert from "node:assert/strict";
import { GateError } from "../src/gate.ts";
import { agent, otherAgent, outsider, person, setup } from "./helpers.ts";

const rejectsWith = (code: GateError["code"], pattern?: RegExp) => (e: unknown) => {
  assert.ok(e instanceof GateError, `expected a GateError, got ${String(e)}`);
  assert.equal(e.code, code);
  if (pattern) assert.match(e.message, pattern);
  return true;
};

test("a principal sees only the domains in its groups", async () => {
  const { gate } = setup();
  assert.deepEqual(gate.listDomains(agent).map((d) => d.domain), ["example.rocks"]);
  assert.deepEqual(gate.listDomains(outsider).map((d) => d.domain), ["example.no"]);
  // Outside its groups, a domain answers as if it did not exist.
  await assert.rejects(gate.listRecords(agent, "example.no"), rejectsWith("not_found"));
  await assert.rejects(gate.listRecords(agent, "nonexistent.com"), rejectsWith("not_found"));
});

test("a proposal changes nothing live", async () => {
  const { gate, homelab } = setup();
  const before = await homelab.listRecords("example.rocks");
  const p = await gate.propose(agent, "example.rocks", [{ op: "create", record: { name: "api", type: "A", content: "203.0.113.20", ttl: 600 } }], "new API host");
  assert.equal(p.status, "pending");
  assert.deepEqual(await homelab.listRecords("example.rocks"), before);
});

test("people cannot propose and agents cannot accept or reject", async () => {
  const { gate } = setup();
  await assert.rejects(
    gate.propose(person, "example.rocks", [{ op: "delete", id: "1" }], "x"),
    rejectsWith("forbidden"),
  );
  const p = await gate.propose(agent, "example.rocks", [{ op: "delete", id: "1" }], "retire the apex A");
  await assert.rejects(gate.accept(agent, p.id), rejectsWith("forbidden", /only a person/));
  assert.throws(() => gate.reject(agent, p.id, "no"), rejectsWith("forbidden"));
  assert.equal(gate.getProposal(person, p.id).status, "pending");
});

test("a person outside the domain's groups cannot see or accept its proposals", async () => {
  const { gate } = setup();
  const p = await gate.propose(agent, "example.rocks", [{ op: "delete", id: "1" }], "retire the apex A");
  assert.throws(() => gate.getProposal(outsider, p.id), rejectsWith("not_found"));
  await assert.rejects(gate.accept(outsider, p.id), rejectsWith("not_found"));
  assert.deepEqual(gate.listProposals(outsider), []);
});

test("accepting applies create, update and delete, and reads them back", async () => {
  const { gate, homelab, store } = setup();
  const p = await gate.propose(
    agent,
    "example.rocks",
    [
      { op: "create", record: { name: "api", type: "A", content: "203.0.113.20", ttl: 600 } },
      { op: "update", id: "1", record: { name: "@", type: "A", content: "203.0.113.11", ttl: 600 } },
      { op: "delete", id: "2" },
    ],
    "move the apex, add api, drop www",
  );
  const r = await gate.accept(person, p.id);
  assert.equal(r.proposal.status, "accepted");
  assert.equal(r.proposal.decidedBy, person.id);
  assert.equal(r.applied.length, 3);
  const live = await homelab.listRecords("example.rocks");
  assert.ok(live.some((x) => x.name === "api" && x.content === "203.0.113.20"));
  assert.equal(live.find((x) => x.id === "1")?.content, "203.0.113.11");
  assert.ok(!live.some((x) => x.id === "2"));
  const actions = store.events({ proposalId: p.id }).map((e) => e.action);
  assert.deepEqual(actions, ["propose", "accept", "applied"]);
  assert.equal(store.events({ proposalId: p.id })[1]?.principal, `person:${person.id}`);
});

test("accepting refuses, instead of overwriting, when a touched record changed after the proposal", async () => {
  const { gate, homelab } = setup();
  const p = await gate.propose(agent, "example.rocks", [{ op: "update", id: "1", record: { name: "@", type: "A", content: "203.0.113.11", ttl: 600 } }], "move");
  // Someone changes the record by hand at the provider.
  await homelab.updateRecord("example.rocks", "1", { name: "@", type: "A", content: "203.0.113.99", ttl: 600 });
  await assert.rejects(gate.accept(person, p.id), rejectsWith("conflict", /changed since the proposal/));
  assert.equal(gate.getProposal(person, p.id).status, "stale");
  assert.equal((await homelab.listRecords("example.rocks")).find((x) => x.id === "1")?.content, "203.0.113.99");
});

test("accepting refuses when a deleted record is already gone, or a created one already exists", async () => {
  const { gate, homelab } = setup();
  const del = await gate.propose(agent, "example.rocks", [{ op: "delete", id: "2" }], "drop www");
  const add = await gate.propose(agent, "example.rocks", [{ op: "create", record: { name: "api", type: "A", content: "203.0.113.20", ttl: 600 } }], "api");
  await homelab.deleteRecord("example.rocks", "2");
  await homelab.createRecord("example.rocks", { name: "api", type: "A", content: "203.0.113.20", ttl: 600 });
  await assert.rejects(gate.accept(person, del.id), rejectsWith("conflict", /gone/));
  await assert.rejects(gate.accept(person, add.id), rejectsWith("conflict", /exists already/));
});

test("a proposal is decided once: a second accept or a reject after it is refused", async () => {
  const { gate } = setup();
  const p = await gate.propose(agent, "example.rocks", [{ op: "delete", id: "2" }], "drop www");
  await gate.accept(person, p.id);
  await assert.rejects(gate.accept(person, p.id), rejectsWith("conflict"));
  assert.throws(() => gate.reject(person, p.id, "too late"), rejectsWith("conflict"));
});

test("a failure part-way through stops, and the proposal says what was applied", async () => {
  const { gate, homelab } = setup();
  const p = await gate.propose(
    agent,
    "example.rocks",
    [
      { op: "create", record: { name: "a1", type: "A", content: "203.0.113.21", ttl: 600 } },
      { op: "create", record: { name: "a2", type: "A", content: "203.0.113.22", ttl: 600 } },
    ],
    "two hosts",
  );
  const origCreate = homelab.createRecord.bind(homelab);
  let calls = 0;
  homelab.createRecord = async (d, f) => {
    if (++calls === 2) throw new Error("provider said no");
    return origCreate(d, f);
  };
  const r = await gate.accept(person, p.id);
  assert.equal(r.proposal.status, "failed");
  assert.equal(r.applied.length, 1);
  assert.match(r.proposal.note ?? "", /failed at: \+ a2 A/);
  assert.match(r.proposal.note ?? "", /applied before it: \n\+ a1 A/);
});

test("a write the provider reports as done but that is not there is caught by the read-back", async () => {
  const { gate, homelab } = setup();
  const p = await gate.propose(agent, "example.rocks", [{ op: "create", record: { name: "ghost", type: "A", content: "203.0.113.30", ttl: 600 } }], "ghost");
  homelab.createRecord = async () => {}; // claims success, writes nothing
  const r = await gate.accept(person, p.id);
  assert.equal(r.proposal.status, "failed");
  assert.match(r.proposal.note ?? "", /not found after applying/);
});

test("rejecting records who and why, and changes nothing", async () => {
  const { gate, homelab } = setup();
  const before = await homelab.listRecords("example.rocks");
  const p = await gate.propose(agent, "example.rocks", [{ op: "delete", id: "1" }], "retire");
  const r = gate.reject(person, p.id, "the apex is still in use");
  assert.equal(r.status, "rejected");
  assert.equal(r.note, "the apex is still in use");
  assert.deepEqual(await homelab.listRecords("example.rocks"), before);
});

test("only the proposing agent can withdraw, and only while pending", async () => {
  const { gate } = setup();
  const p = await gate.propose(agent, "example.rocks", [{ op: "delete", id: "1" }], "retire");
  assert.throws(() => gate.withdraw(otherAgent, p.id), rejectsWith("forbidden"));
  assert.equal(gate.withdraw(agent, p.id).status, "withdrawn");
  assert.throws(() => gate.withdraw(agent, p.id), rejectsWith("conflict"));
  await assert.rejects(gate.accept(person, p.id), rejectsWith("conflict"));
});

test("bad proposals are refused with every problem named", async () => {
  const { gate } = setup();
  const bad = async (changes: unknown[], pattern: RegExp, reason = "r") =>
    assert.rejects(gate.propose(agent, "example.rocks", changes as never, reason), rejectsWith("invalid", pattern));
  await bad([], /at least one change/);
  await bad([{ op: "delete", id: "1" }], /reason is required/, " ");
  await bad([{ op: "delete", id: "999" }], /no record with id 999/);
  await bad([{ op: "delete", id: "4" }], /CAA records cannot be changed/);
  await bad([{ op: "delete", id: "1" }, { op: "delete", id: "1" }], /changed twice/);
  await bad([{ op: "create", record: { name: "x", type: "A", content: "not-an-ip", ttl: 600 } }], /IPv4/);
  await bad([{ op: "create", record: { name: "x", type: "AAAA", content: "203.0.113.1", ttl: 600 } }], /IPv6/);
  await bad([{ op: "create", record: { name: "x.example.rocks", type: "A", content: "203.0.113.1", ttl: 600 } }], /relative/);
  await bad([{ op: "create", record: { name: "@", type: "CNAME", content: "elsewhere.com", ttl: 600 } }], /apex/);
  await bad([{ op: "create", record: { name: "www", type: "A", content: "203.0.113.1", ttl: 600 } }, { op: "create", record: { name: "www", type: "CNAME", content: "x.com", ttl: 600 } }], /must stand alone/);
  await bad([{ op: "create", record: { name: "@", type: "MX", content: "mx2.example.net", ttl: 600 } }], /needs a priority/);
  await bad([{ op: "create", record: { name: "x", type: "A", content: "203.0.113.1", ttl: 600, priority: 5 } }], /priority applies only/);
  await bad([{ op: "create", record: { name: "x", type: "A", content: "203.0.113.1", ttl: 30 } }], /ttl must be at least 60/);
  await bad([{ op: "create", record: { name: "@", type: "A", content: "203.0.113.10", ttl: 600 } }], /already exists/);
  await bad([{ op: "update", id: "1", record: { name: "@", type: "A", content: "203.0.113.10", ttl: 600 } }], /changes nothing/);
  await bad([{ op: "rename", id: "1" }], /op must be/);
});

test("fields an agent adds beyond the record's own are not stored", async () => {
  const { gate } = setup();
  const p = await gate.propose(
    agent,
    "example.rocks",
    [{ op: "create", record: { name: "x", type: "A", content: "203.0.113.5", ttl: 600, sneaky: "yes" } as never }],
    "x",
  );
  const c = p.changes[0];
  assert.ok(c && c.op === "create");
  assert.deepEqual(Object.keys(c.after).sort(), ["content", "name", "ttl", "type"]);
});
