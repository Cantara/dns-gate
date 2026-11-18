import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Gate } from "../src/gate.ts";
import type { Principal, RecordFields } from "../src/model.ts";
import { MemoryProvider } from "../src/providers/memory.ts";
import { Store } from "../src/store.ts";

export const agent: Principal = { id: "steinar-agent", kind: "agent", groups: ["homelab"] };
export const otherAgent: Principal = { id: "other-agent", kind: "agent", groups: ["homelab"] };
export const person: Principal = { id: "steinar@example.com", kind: "person", groups: ["homelab"] };
export const outsider: Principal = { id: "totto@example.com", kind: "person", groups: ["xor"] };

export const ZONE: RecordFields[] = [
  { name: "@", type: "A", content: "203.0.113.10", ttl: 600 },
  { name: "www", type: "CNAME", content: "example.rocks", ttl: 600 },
  { name: "@", type: "MX", content: "mx.example.net", ttl: 600, priority: 10 },
  { name: "@", type: "CAA", content: '0 issue "letsencrypt.org"', ttl: 600 },
];

export function setup() {
  const dir = mkdtempSync(join(tmpdir(), "dns-gate-test-"));
  const store = new Store(join(dir, "test.db"));
  const homelab = new MemoryProvider("homelab-dns", { "example.rocks": ZONE });
  const xor = new MemoryProvider("xor-dns", { "example.no": [{ name: "@", type: "A", content: "198.51.100.1", ttl: 3600 }] });
  const gate = new Gate({
    providers: new Map([
      ["homelab-dns", homelab],
      ["xor-dns", xor],
    ]),
    domains: { "example.rocks": "homelab-dns", "example.no": "xor-dns" },
    groups: { homelab: ["example.rocks"], xor: ["example.no"] },
    store,
  });
  return { dir, store, homelab, xor, gate };
}
