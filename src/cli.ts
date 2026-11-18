#!/usr/bin/env node
// dns-gate command line. Run `dns-gate --help`.

import { ConfigError, loadConfig, readJsonFile, type Config } from "./config.ts";
import { googleSignIn, newToken, Sessions, type SignIn } from "./auth.ts";
import { Gate } from "./gate.ts";
import { DomeneshopProvider, type DomeneshopCredentials } from "./providers/domeneshop.ts";
import { MemoryProvider } from "./providers/memory.ts";
import { PorkbunProvider, type PorkbunCredentials } from "./providers/porkbun.ts";
import type { Provider } from "./providers/provider.ts";
import { createDnsGateServer } from "./server.ts";
import { Store } from "./store.ts";
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const USAGE = `dns-gate: agents read DNS and propose changes; a person accepts them before they go live.

Usage:
  dns-gate serve --config <file>         Run the server (MCP at /mcp, web page at /).
  dns-gate check-config --config <file>  Validate the config and the credential files it names,
                                         and list what each provider holds. Reads only.
  dns-gate new-token                     Print a new agent token and the SHA-256 for the config.
                                         Changes nothing; the token is shown only this once.
  dns-gate --help                        This text.

The config format is in README.md.`;

function usage(code: number): never {
  (code === 0 ? console.log : console.error)(USAGE);
  process.exit(code);
}

export function buildProviders(config: Config): Map<string, Provider> {
  const out = new Map<string, Provider>();
  for (const [name, pc] of Object.entries(config.providers)) {
    if (pc.type === "porkbun") {
      const c = readJsonFile<PorkbunCredentials>(pc.credentialsFile as string);
      if (!c.apiKey || !c.secretApiKey) throw new ConfigError(`${pc.credentialsFile}: needs apiKey and secretApiKey`);
      out.set(name, new PorkbunProvider(name, c));
    } else if (pc.type === "domeneshop") {
      const c = readJsonFile<DomeneshopCredentials>(pc.credentialsFile as string);
      if (!c.token || !c.secret) throw new ConfigError(`${pc.credentialsFile}: needs token and secret`);
      out.set(name, new DomeneshopProvider(name, c));
    } else {
      out.set(name, new MemoryProvider(name, pc.zones ?? {}));
    }
  }
  return out;
}

async function checkConfig(path: string): Promise<number> {
  const config = loadConfig(path);
  const providers = buildProviders(config);
  let bad = 0;
  for (const [name, provider] of providers) {
    try {
      const held = await provider.listDomains();
      const mine = Object.entries(config.domains).filter(([, p]) => p === name).map(([d]) => d);
      const missing = mine.filter((d) => !held.includes(d));
      console.log(`${name}: reachable, holds ${held.length} domain(s); config manages ${mine.length}${missing.length ? `; NOT held: ${missing.join(", ")}` : ""}`);
      if (missing.length) bad++;
    } catch (e) {
      console.log(`${name}: FAILED: ${(e as Error).message}`);
      bad++;
    }
  }
  console.log(`${config.agents.length} agent(s), ${config.people.length} person(s), ${Object.keys(config.groups).length} group(s); sign-in ${config.oidc ? "configured" : "NOT configured"}`);
  return bad === 0 ? 0 : 1;
}

async function serve(path: string): Promise<void> {
  const config = loadConfig(path);
  const store = new Store(config.database);
  const gate = new Gate({ providers: buildProviders(config), domains: config.domains, groups: config.groups, store });
  let signIn: SignIn | undefined;
  if (config.oidc) {
    const secret = readFileSync(config.oidc.clientSecretFile, "utf8").trim();
    signIn = await googleSignIn(config.oidc.issuer, config.oidc.clientId, secret);
  } else {
    console.log("warning: no oidc in the config, so nobody can sign in and accept proposals");
  }
  const server = createDnsGateServer({
    gate,
    agents: config.agents,
    people: config.people,
    publicUrl: config.publicUrl,
    sessions: new Sessions(),
    ...(signIn ? { signIn } : {}),
  });
  server.listen(config.listen.port, config.listen.host, () => {
    console.log(`dns-gate listening on ${config.listen.host}:${config.listen.port}, public URL ${config.publicUrl}`);
  });
  const stop = () => server.close(() => (store.close(), process.exit(0)));
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

async function main(argv: string[]): Promise<void> {
  if (argv.includes("--help") || argv.includes("-h")) usage(0);
  const [cmd, ...rest] = argv;
  if (cmd === "new-token") {
    if (rest.length > 0) usage(2);
    const t = newToken();
    console.log(`token (give it to the agent; it is not stored anywhere): ${t.token}`);
    console.log(`tokenSha256 (put this in the config):                  ${t.sha256}`);
    return;
  }
  if (cmd === "serve" || cmd === "check-config") {
    if (rest.length !== 2 || rest[0] !== "--config" || !rest[1]) usage(2);
    if (cmd === "serve") return serve(rest[1]);
    process.exit(await checkConfig(rest[1]));
  }
  usage(2);
}

const invokedDirectly = (() => {
  try {
    return realpathSync(process.argv[1] ?? "") === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main(process.argv.slice(2)).catch((e) => {
    console.error(e instanceof ConfigError ? `config error: ${e.message}` : e);
    process.exit(1);
  });
}
