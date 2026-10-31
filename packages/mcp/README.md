# @lumoauth/mcp

LumoAuth sign-in and authorization for MCP servers built with the official
TypeScript SDK: `@modelcontextprotocol/sdk` (v1) and
`@modelcontextprotocol/server` (v2).

```ts
import { lumoAuth } from '@lumoauth/mcp';

const auth = lumoAuth();                    // LUMOAUTH_ORG_ID + LUMOAUTH_MCP_SERVER_ID
app.use(auth.router());                     // OAuth discovery for MCP clients
app.post('/mcp', auth.protect(), mcp);      // 401 challenge, token check, req.auth
```

Claude, ChatGPT, VS Code, Cursor and every other MCP client that follows
the MCP authorization specification can then sign users in through
LumoAuth and call the server with a token issued for it.

## What it does

LumoAuth is the authorization server: it registers MCP clients, shows the
consent screen and issues tokens whose audience is your server's Resource
URI. Your server stays a resource server, and this package gives it what
the MCP specification asks of one:

- `router()` serves the protected resource metadata (RFC 9728) at
  `/.well-known/oauth-protected-resource/...`, naming your LumoAuth
  organization as the authorization server. For older clients it also
  mirrors LumoAuth's metadata at `/.well-known/oauth-authorization-server`.
- `protect()` answers `401` with a `WWW-Authenticate` challenge that points
  at that document, or verifies the token: signature against the
  organization's keys, issuer, audience, expiry, `at+jwt` type, and no
  portal test tokens. A DPoP-bound token must come with the `DPoP` scheme
  and a fresh proof. A refusal states its real reason.
- The verified caller lands on `req.auth`, which the SDK passes to tools.

On the first request, the package reads the server's registration from
LumoAuth: the Resource URI, the advertised scopes and the **Require DPoP**
switch. Call `await auth.ready()` at start-up to read it sooner and to fail
fast on a wrong server id. Restart the server after you change the
registration.

## Setup

1. Register the server in the LumoAuth portal under **AI Agents → MCP
   servers**. The **Resource URI** is the URL that clients connect to. For
   local development, register a second server with
   `http://localhost:3000/mcp`.
2. `npm install @lumoauth/mcp`
3. Set `LUMOAUTH_ORG_ID` and `LUMOAUTH_MCP_SERVER_ID` (the `mcp_…` id on the
   server's page). For the EU region, set
   `LUMOAUTH_URL=https://eu.app.lumoauth.dev`.

### SDK v1 with Express

```ts
import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { getCaller, lumoAuth } from '@lumoauth/mcp';

const auth = lumoAuth();
await auth.ready();

function buildServer() {
    const server = new McpServer({ name: 'invoices', version: '1.0.0' });
    server.registerTool('whoami', { description: 'Who is calling' }, async (extra) => {
        const caller = getCaller(extra)!;   // set, because auth.protect() ran first
        return { content: [{ type: 'text', text: caller.isAgent ? `agent ${caller.agentId}` : `user ${caller.sub}` }] };
    });
    return server;
}

const app = express();
app.use(express.json());
app.use(auth.router());
app.post('/mcp', auth.protect(), async (req, res) => {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
});
app.listen(3000);
```

### SDK v2

With a `fetch` handler (Cloudflare-style, Hono, Bun, Deno):

```ts
import { McpServer, createMcpHandler } from '@modelcontextprotocol/server';
import { getCaller, lumoAuth } from '@lumoauth/mcp';

const auth = lumoAuth();
const handler = createMcpHandler(() => buildServer());

export async function fetchHandler(request: Request): Promise<Response> {
    const discovery = await auth.discovery(request);
    if (discovery) return discovery;
    const authInfo = await auth.gate(request);
    if (authInfo instanceof Response) return authInfo;
    return handler.fetch(request, { authInfo });
}
```

With Express, `toNodeHandler` from `@modelcontextprotocol/node` forwards
`req.auth` to the handler:

```ts
app.use(auth.router());
app.post('/mcp', auth.protect(), toNodeHandler(handler));
```

`toNodeHandler` reads the request body itself, so a route behind
`express.json()` answers `400 Parse error`. If the app needs that parser,
pass the parsed body on:

```ts
const mcp = toNodeHandler(handler);
app.post('/mcp', auth.protect(), (req, res) => mcp(req, res, req.body));
```

The token check uses `node:crypto` (through `@lumoauth/agent`), so it runs
on Node 20+, Bun and Deno.

## Who is calling

`getCaller(extra)` (v1) or `getCaller(ctx)` (v2) returns the verified caller,
or `undefined` for a request without auth info, as on stdio:

| Field | Meaning |
| --- | --- |
| `sub` | The user id, or `agent_agt_…` for an agent |
| `isAgent`, `agentId` | An AI agent and its `agt_…` id |
| `isDelegated`, `actor`, `actChain` | An agent acting for the user `sub` |
| `scopes`, `capabilities` | Granted scopes; the agent's capabilities |
| `clientId` | The OAuth client (RFC 9068 `client_id`) |
| `dpopJkt` | The key thumbprint of a DPoP-bound token |
| `claims` | All verified claims |

## Per-tool authorization

`auth.secureTools(server, options)` guards every tool that is registered
after the call; `scopes` maps tool names to the scopes they need:

```ts
const server = new McpServer({ name: 'invoices', version: '1.0.0' });
auth.secureTools(server, { scopes: { refund: ['invoices:refund'] } });
server.registerTool('refund', { inputSchema: { invoiceId: z.string() } }, async ({ invoiceId }) => ...);
```

`auth.guard(name, handler, options)` guards one handler:

```ts
server.registerTool('change_bank_details', { inputSchema: { iban: z.string() } },
    auth.guard('change_bank_details', changeBankDetails, { users: true }));   // people only
```

The options:

- `scopes`: the scopes the tool needs. As in LumoAuth, a granted scope that
  ends in `:*` (such as `invoices:*`) covers the scopes under it, and every
  other scope compares exactly. Prefer narrow scopes: the MCP security best
  practices list wildcard scopes as a common mistake.
- `agents: true` or `agents: ['billing.reminders']`: AI agents only, with
  these capabilities.
- `users: true`: people only. `users: 'delegated'` also admits an agent
  that acts for a person.
- `policy`: ask LumoAuth's per-tool policy (on by default when the server's
  client credentials are set, see below).
- `allowUnauthenticated: true`: run the tool on a request without auth info,
  as on stdio. By default, such a call is refused.

A refused call becomes an error result that the model can read. With SDK
v2, `scopeChallenge: auth.scopeChallenge('invoices:refund')` on
`registerTool` turns a missing scope into a `403 insufficient_scope`
step-up instead, so the client can ask the user for the scope.

### LumoAuth's per-tool policy

Whether a user or agent may run a tool can be a policy that you manage in
LumoAuth: roles, relationships, ABAC rules, agent capabilities. The server
asks LumoAuth as itself and never forwards the caller's token, which the
MCP specification forbids. Set it up once:

1. Create an OAuth client for the MCP server with the `client_credentials`
   grant and the `mcp:authorize` scope.
2. Edit the server in the portal. In the step **Who may connect and how**,
   select that client under **Per-tool authorization**.
3. Set `LUMOAUTH_MCP_CLIENT_ID` and `LUMOAUTH_MCP_CLIENT_SECRET`.

Decisions are cached for 30 seconds (`toolDecisionTtl`). When LumoAuth
cannot be reached, the tool is refused.

## Configuration

| Option | Environment variable | Default |
| --- | --- | --- |
| `orgId` | `LUMOAUTH_ORG_ID` | required unless `issuer` is set |
| `serverId` | `LUMOAUTH_MCP_SERVER_ID` | none; without it pass `resource` |
| `resource` | `LUMOAUTH_MCP_RESOURCE` | from the registration |
| `lumoauthUrl` | `LUMOAUTH_URL` | `https://app.lumoauth.dev` |
| `issuer` | `LUMOAUTH_ISSUER` | `{lumoauthUrl}/orgs/{orgId}/api/v1` (set it for a custom domain) |
| `clientId`, `clientSecret` | `LUMOAUTH_MCP_CLIENT_ID`, `LUMOAUTH_MCP_CLIENT_SECRET` | only for the per-tool policy |
| `requiredScopes` | | none |
| `scopesSupported` | | the registration's basic scopes |
| `requireDpop` | | the registration's **Require DPoP** switch |
| `publicUrl` | | the origin of the Resource URI; the DPoP `htu` check uses it |
| `requestUrl` | | for a proxy that rewrites paths: builds the public request URL |
| `replayCache` | | in memory; share one between replicas (`add(key, ttl)` returns `false` for a replay) |
| `authorizationServerMetadata` | | `true` |

## Requirements

Node 20 or later. The package installs `@lumoauth/agent` and
`@lumoauth/shared` 1.2 or later, the releases with access-token and DPoP
verification. Install the MCP SDK yourself: the tests run against
`@modelcontextprotocol/sdk` 1.32 and `@modelcontextprotocol/server` 2.4.
