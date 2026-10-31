<div align="center">

<a href="https://lumoauth.dev">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://docs.lumoauth.dev/img/lumoauth-logo-horizontal-reversed.svg">
    <img src="https://docs.lumoauth.dev/img/lumoauth-logo-horizontal.svg" alt="LumoAuth" height="36">
  </picture>
</a>

# @lumoauth/mcp

**Add sign-in and per-tool access control to an MCP server built with the official TypeScript SDK.**

[![@lumoauth/mcp on npm](https://img.shields.io/badge/npm-%40lumoauth%2Fmcp-111)](https://www.npmjs.com/package/@lumoauth/mcp)
[![Node 20+](https://img.shields.io/badge/node-20%2B-111)](#requirements)
[![MCP SDK v1 and v2](https://img.shields.io/badge/mcp%20sdk-v1%20%C2%B7%20v2-111)](#other-setups)
[![License: MIT](https://img.shields.io/badge/license-MIT-111)](#license)

[Quick start](#quick-start) · [Other setups](#other-setups) · [Who is calling](#who-is-calling) · [Per-tool authorization](#per-tool-authorization) · [Troubleshooting](#troubleshooting) · [Docs](https://docs.lumoauth.dev/mcp/)

</div>

---

```ts
import { lumoAuth } from '@lumoauth/mcp';

const auth = lumoAuth();                    // reads LUMOAUTH_ORG_ID and LUMOAUTH_MCP_SERVER_ID
app.use(auth.router());                     // discovery for MCP clients
app.post('/mcp', auth.protect(), mcp);      // 401 challenge, token check, req.auth
```

[LumoAuth](https://lumoauth.dev) signs users in and issues the tokens. Your server checks each token and runs the tool. It works with `@modelcontextprotocol/sdk` (v1) and `@modelcontextprotocol/server` (v2).

No access to the server's code, or not a TypeScript server? [`npx lumoauth secure`](https://www.npmjs.com/package/lumoauth) puts the same checks in front of any MCP server.

## Quick start

You need Node 20 or later and a LumoAuth organization. [Create an organization](https://app.lumoauth.dev/register) if you do not have one yet.

### 1. Register your server

In the LumoAuth portal:

1. Open **AI Agents → MCP servers** and click **Register MCP server**.
2. Set **Server name** to `Invoices` and **Resource URI** to `http://localhost:3000/mcp`.
3. Click **Next** twice, then click **Register MCP server**.
4. On the server's page, click **Edit**, then **Next**. Make two changes:
   - Under **Scopes**, click **Use defaults**.
   - Switch off **Require DPoP sender-constrained tokens**. Claude Code does not send DPoP proofs, so it cannot connect while this switch is on.
5. Click **Next**, then **Save changes**. Copy the **Server id** (`mcp_…`) from the top of the page.

The **Resource URI** is the exact URL that clients connect to. A token for one Resource URI does not work at another.

### 2. Run the server

```bash
npm install @lumoauth/mcp @modelcontextprotocol/sdk express
```

Save this as `server.mjs`. It is plain JavaScript, so it runs without a build step. In TypeScript, write `getCaller(extra)!`.

```js
import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { getCaller, lumoAuth } from '@lumoauth/mcp';

const auth = lumoAuth();
await auth.ready();

function buildServer() {
    const server = new McpServer({ name: 'invoices', version: '1.0.0' });
    server.registerTool('whoami', { description: 'Show who is calling' }, async (extra) => ({
        content: [{ type: 'text', text: getCaller(extra).sub }],
    }));
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

Start it with your organization's slug and the server id from step 1. The slug is the part after `/orgs/` in the portal's URL.

```bash
export LUMOAUTH_ORG_ID=acme
export LUMOAUTH_MCP_SERVER_ID=mcp_0123456789abcdef01234567
node server.mjs
```

For the EU region, also set `LUMOAUTH_URL=https://eu.app.lumoauth.dev`.

### 3. Call it without a token

```console
$ curl -i -X POST http://localhost:3000/mcp
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer scope="mcp:read", resource_metadata="http://localhost:3000/.well-known/oauth-protected-resource/mcp"
```

Your server now rejects calls without a token. The `401` tells MCP clients where to find LumoAuth.

### 4. Sign in from a client

First, create an application for the client in the portal:

1. Open **Applications**, click **New application** and choose **Single-page or mobile app**.
2. Set **Application name** to `Local MCP client` and **Redirect URI** to `http://localhost:8765/callback`.
3. Click **Create application** and copy the **Client ID**.
4. On the **Configuration** tab, set **Scopes** to `openid profile email offline_access mcp:read`. Click **Save configuration**.

Then connect Claude Code, with your client ID:

```bash
claude mcp add --transport http \
  --client-id client_0123456789abcdef0123456789abcdef \
  --callback-port 8765 \
  invoices http://localhost:3000/mcp

claude mcp login invoices
```

Your browser opens on the LumoAuth sign-in page. After you sign in and approve, `claude mcp list` shows the connection:

```console
invoices: http://localhost:3000/mcp (HTTP) - ✔ Connected
```

Ask Claude Code to call `whoami`, and the tool returns your LumoAuth user id from the verified token.

Other MCP clients connect the same way if they let you set a client ID and a callback port. [Troubleshooting](#troubleshooting) explains the errors that you may see.

### Before you go to production

- Register a separate server with your public `https://` address. LumoAuth accepts plain `http://` only for `localhost`, `127.0.0.1` and `[::1]`.
- Under **Allowed clients**, choose **Only the clients I pick**.
- Switch on **Require DPoP sender-constrained tokens** if all your clients can send proofs. Agents built on the LumoAuth JavaScript, Python and Go SDKs can do so.

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/LumoAuth/mcp-typescript/main/assets/how-it-works-dark.svg">
    <img src="https://raw.githubusercontent.com/LumoAuth/mcp-typescript/main/assets/how-it-works.svg" alt="An MCP client calls your server without a token and gets a 401 that says where to sign in. The user signs in through LumoAuth, which issues a token for this server only. The client calls the tool with the token. Your server checks the token and runs the tool." width="720">
  </picture>
</p>

LumoAuth is the authorization server. It shows the consent screen and issues tokens whose audience is your server's Resource URI. Your server stays a resource server, and this package gives it what the MCP specification asks of one:

- `router()` serves the protected resource metadata at `/.well-known/oauth-protected-resource/...`. This document names your LumoAuth organization as the authorization server. For older clients, `router()` also serves LumoAuth's metadata at `/.well-known/oauth-authorization-server`.
- `protect()` answers `401` with a `WWW-Authenticate` challenge that points to that document, or it verifies the token. It checks the signature against the organization's keys, issuer, audience, expiry and `at+jwt` type, and it rejects portal test tokens. A DPoP-bound token must come with the `DPoP` scheme and a fresh proof. A rejection states its real reason.
- `protect()` puts the verified caller on `req.auth`, which the SDK passes to tools.

On the first request, the package reads the server's registration from LumoAuth: the Resource URI, the advertised scopes and the **Require DPoP** switch. Call `await auth.ready()` at start-up to read it sooner and to report a wrong server id at once. Restart the server after you change the registration.

## Other setups

The quick start uses SDK v1 with Express. SDK v2 works with a `fetch` handler or with Express.

### SDK v2 with a `fetch` handler

For Cloudflare-style handlers, Hono, Bun and Deno:

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

The token check uses `node:crypto` (through `@lumoauth/agent`), so it runs on Node 20+, Bun and Deno.

### SDK v2 with Express

`toNodeHandler` from `@modelcontextprotocol/node` forwards `req.auth` to the handler:

```ts
app.use(auth.router());
app.post('/mcp', auth.protect(), toNodeHandler(handler));
```

`toNodeHandler` reads the request body itself, so a route behind `express.json()` answers `400 Parse error`. If the app needs that parser, pass the parsed body on:

```ts
const mcp = toNodeHandler(handler);
app.post('/mcp', auth.protect(), (req, res) => mcp(req, res, req.body));
```

## Who is calling

`getCaller(extra)` (v1) or `getCaller(ctx)` (v2) returns the verified caller, or `undefined` for a request without auth info, as on stdio:

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

`auth.secureTools(server, options)` guards every tool that is registered after the call. `scopes` maps tool names to the scopes that they need:

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

- `scopes`: the scopes that the tool needs. As in LumoAuth, a granted scope that ends in `:*` (such as `invoices:*`) covers the scopes under it, and every other scope compares exactly. Prefer narrow scopes, because the MCP security best practices list wildcard scopes as a common mistake.
- `agents: true` or `agents: ['billing.reminders']`: AI agents only, with these capabilities.
- `users: true`: people only. `users: 'delegated'` also admits an agent that acts for a person.
- `policy`: ask LumoAuth's per-tool policy. This is on by default when the server's client credentials are set, as described below.
- `allowUnauthenticated: true`: run the tool on a request without auth info, as on stdio. By default, such a call is rejected.

A rejected call becomes an error result that the model can read. With SDK v2, `scopeChallenge: auth.scopeChallenge('invoices:refund')` on `registerTool` turns a missing scope into a `403 insufficient_scope` step-up instead. The client can then ask the user for the scope.

Add a new scope in two places: the server's **Scopes**, and the **Scopes** of each application that may ask for it.

### LumoAuth's per-tool policy

With the policy on, the server asks LumoAuth about each tool. The server asks as itself and never forwards the caller's token, which the MCP specification forbids.

**Every tool is denied until you grant it.** Set it up once:

1. **Create the server's own application.** Open **Applications**, click **New application** and choose **Machine to machine**. Copy the **Client ID** and the **Client secret**, which is shown only once.
2. **Allow the scope.** On the application's **Configuration** tab, set **Scopes** to `mcp:authorize`. The form also asks for a redirect URI, which this application does not use, so enter any `https://` URL. Click **Save configuration**.
3. **Connect it to the MCP server.** Edit the server. In the step **Who may connect and how**, select the application under **Per-tool authorization**.
4. **Give the server its credentials.** Set `LUMOAUTH_MCP_CLIENT_ID` and `LUMOAUTH_MCP_CLIENT_SECRET`, then restart it.
5. **Grant access.** Open **Relationships**. Under **Namespaces**, create the namespace that you need, with the relation `invoke`. Then, under **Tuples**, add one relationship for each grant:

   | To grant | Object namespace | Object ID | Relation | Subject |
   | --- | --- | --- | --- | --- |
   | Every tool on the server | `mcp_server` | `mcp_0123456789abcdef01234567` | `invoke` | `user` and the user's id |
   | One tool | `mcp_tool` | `mcp_0123456789abcdef01234567/refund` | `invoke` | `agent` and the agent's id |

Relationships are part of the Fine-grained authorization add-on. Without it, every tool is denied.

Decisions are cached for 30 seconds (`toolDecisionTtl`). When LumoAuth cannot be reached, the tool is rejected.

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

## Troubleshooting

`npx lumoauth check` prints what the registration says, the discovery document and the `401` challenge.

| What you see | Why | What to do |
| --- | --- | --- |
| `LumoAuth has no active MCP server` at start-up | The server id or the organization slug is wrong. | Copy both again from the portal. |
| `404` from `curl` | The quick start's route accepts only `POST`. | Use `curl -i -X POST`. |
| `Protected resource … does not match expected …` | The client connects to a URL that differs from the Resource URI. `localhost` and `127.0.0.1` count as different. | Use the Resource URI exactly. |
| `invalid_dpop_proof` or `DPoP proof required` | **Require DPoP** is on and the client sends no proof. | Switch it off, then restart the server. |
| `invalid_scope` … `not allowed for this client` | The application does not allow a scope that the client asks for. | Add the scope to the application's **Scopes**. Many clients add `offline_access` on their own. |
| `Invalid Redirect URL` on a LumoAuth page | The client's redirect URI is not registered. LumoAuth accepts a changing port only on `127.0.0.1` and `[::1]`, not on `localhost`. | Create an application with the exact URI, and give the client a fixed callback port. |
| `Dynamic client registration is not enabled` | The client tried to register itself, which is off by default. | Give the client a client ID, as in [step 4](#4-sign-in-from-a-client). |
| The list of tools is empty | The per-tool policy is on and the caller has no grant. | See [LumoAuth's per-tool policy](#lumoauths-per-tool-policy). |
| A registration change has no effect | The package reads the registration once. | Restart the server. |

## Requirements

Node 20 or later. The package installs `@lumoauth/agent` and `@lumoauth/shared` 1.2 or later, the releases with access-token and DPoP verification. Install the MCP SDK yourself: the tests run against `@modelcontextprotocol/sdk` 1.32 and `@modelcontextprotocol/server` 2.4.

## License

MIT
