# dns-gate

**Agents read DNS and propose changes. A person accepts them before they go live.**

Most DNS providers hand out API tokens that can do everything on the account, so an AI agent cannot
safely hold one. dns-gate holds the provider credentials itself and gives each agent its own,
much weaker identity: it can read the records of the domains it is granted and propose changes, and
that is all. A proposal changes nothing. A person signs in to dns-gate's web page with Google, reads
the proposal and accepts or rejects it; only an accept writes to the provider.

- **Several providers:** Porkbun and Domeneshop today; the provider layer is small to extend.
- **Domain groups:** domains are put in groups, and each agent and each person is granted groups.
  Outside its groups a domain does not exist for that principal.
- **No silent overwrites:** accepting re-reads the live records first. If any record the proposal
  touches changed after the proposal was made, nothing is applied and the proposal is marked stale.
- **Read back:** after applying, dns-gate reads the records again and marks the proposal failed if
  they do not match, so a provider's "OK" is not taken on trust.
- **Audit log:** every proposal, decision and outcome is recorded with who and when.

Status: first version. Records of type A, AAAA, CNAME, MX, TXT, SRV and NS can be changed; other types
and HTTP forwards are shown but read-only.

## How it fits together

```
agent ──MCP (bearer token)──▶ dns-gate ──provider API──▶ Porkbun / Domeneshop
person ──web page (Google sign-in)──▶ dns-gate
```

dns-gate must run where agents cannot read its config directory or credential files. An agent that
can read the provider credentials can bypass dns-gate entirely, so running it as a local MCP server
next to the agent would defeat the point. Run it as a service on a separate machine or container.

## Running it

Requires Node.js 22.18 or newer (it runs the TypeScript sources directly) and no build step.

```sh
npm ci
node src/cli.ts new-token                       # an agent token, plus the hash for the config
node src/cli.ts check-config --config cfg.json  # validate, and test each provider's credentials (reads only)
node src/cli.ts serve --config cfg.json
```

Put dns-gate behind a TLS-terminating reverse proxy, and set `publicUrl` to the URL people open.

## Config

```json
{
  "listen": { "host": "127.0.0.1", "port": 8787 },
  "publicUrl": "https://dns-gate.example.com",
  "database": "/var/lib/dns-gate/dns-gate.db",
  "providers": {
    "porkbun": { "type": "porkbun", "credentialsFile": "/etc/dns-gate/porkbun.json" },
    "domeneshop": { "type": "domeneshop", "credentialsFile": "/etc/dns-gate/domeneshop.json" }
  },
  "domains": { "example.rocks": "porkbun", "example.no": "domeneshop" },
  "groups": { "homelab": ["example.rocks"], "company": ["example.no"] },
  "agents": [{ "id": "my-agent", "tokenSha256": "<from new-token>", "groups": ["homelab"] }],
  "people": [{ "email": "me@example.com", "groups": ["homelab", "company"] }],
  "oidc": {
    "issuer": "https://accounts.google.com",
    "clientId": "<Google OAuth client id>",
    "clientSecretFile": "/etc/dns-gate/google-client-secret"
  }
}
```

- The config holds no secrets. Agents are listed by the SHA-256 of their token; credentials are in
  the files it names, which should be readable only by the dns-gate service user.
- A domain is managed only if it is listed under `domains`. Others on the same account are invisible.
- Unknown keys are refused, and `check-config` reports every problem at once.

Credential files:

| Provider | File contents | Where to get it |
|---|---|---|
| Porkbun | `{"apiKey": "pk1_…", "secretApiKey": "sk1_…"}` | Account → API Access. Also switch **API access on for each domain**. |
| Domeneshop | `{"token": "…", "secret": "…"}` | domeneshop.no/admin?view=api |

Google sign-in: create an OAuth client of type *Web application* in a Google Cloud project, with the
redirect URI `<publicUrl>/auth/callback`. dns-gate asks only for `openid email` and refuses an
address Google has not verified, or one not listed under `people`.

## Connecting an agent

Claude Code:

```sh
claude mcp add --transport http dns-gate https://dns-gate.example.com/mcp \
  --header "Authorization: Bearer <agent token>"
```

Tools: `list_domains`, `list_records`, `list_forwards`, `propose_change`, `list_proposals`,
`get_proposal`, `withdraw_proposal`. There is no tool to accept or reject.

## Development

```sh
npm test          # unit and HTTP tests, no network
npm run typecheck
```

Runtime dependency: `openid-client` (for Google sign-in) only. The MCP endpoint is a small
hand-written JSON-RPC handler rather than the MCP SDK, to keep the dependency tree of a service that
holds DNS credentials short. SQLite comes from Node itself (`node:sqlite`).

## License

Apache License 2.0. See [LICENSE](LICENSE).
