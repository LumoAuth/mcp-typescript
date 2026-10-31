<div align="center">

<a href="https://lumoauth.dev">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://docs.lumoauth.dev/img/lumoauth-logo-horizontal-reversed.svg">
    <img src="https://docs.lumoauth.dev/img/lumoauth-logo-horizontal.svg" alt="LumoAuth" height="36">
  </picture>
</a>

# npx lumoauth secure

**Put sign-in and per-tool access control in front of any MCP server, without changing its code.**

[![lumoauth on npm](https://img.shields.io/badge/npm-lumoauth-111)](https://www.npmjs.com/package/lumoauth)
[![Node 20+](https://img.shields.io/badge/node-20%2B-111)](https://nodejs.org)
[![HTTP and stdio](https://img.shields.io/badge/servers-HTTP%20%C2%B7%20stdio-111)](#what-it-does)
[![License: MIT](https://img.shields.io/badge/license-MIT-111)](#license)

[Quick start](#quick-start) · [What it does](#what-it-does) · [Per-tool policy](#per-tool-policy) · [Options](#options) · [Troubleshooting](#troubleshooting) · [Docs](https://docs.lumoauth.dev/mcp/)

</div>

---

```bash
# An HTTP MCP server that you already run on port 8000
npx lumoauth secure --upstream http://127.0.0.1:8000/mcp

# Start the server too, and wait until it listens
npx lumoauth secure --upstream http://127.0.0.1:8000/mcp -- python server.py

# A stdio MCP server, served over HTTP behind LumoAuth
npx lumoauth secure --stdio -- npx -y @modelcontextprotocol/server-everything
```

[LumoAuth](https://lumoauth.dev) signs users in and issues the tokens. `lumoauth` checks each token before anything reaches your server. It works with a server in any language. Building with the official TypeScript SDK? [`@lumoauth/mcp`](https://www.npmjs.com/package/@lumoauth/mcp) does the same inside your code.

## Quick start

You need Node 20 or later and a LumoAuth organization. [Create an organization](https://app.lumoauth.dev/register) if you do not have one yet.

### 1. Register your server

In the LumoAuth portal:

1. Open **AI Agents → MCP servers** and click **Register MCP server**.
2. Set **Server name** to `Invoices` and **Resource URI** to `http://localhost:8080/mcp`. This is the address of `lumoauth`, not of your server. Keep the **Streamable HTTP** transport, also for a stdio server.
3. Click **Next** twice, then click **Register MCP server**.
4. On the server's page, click **Edit**, then **Next**. Make two changes:
   - Under **Scopes**, click **Use defaults**.
   - Switch off **Require DPoP sender-constrained tokens**. Claude Code does not send DPoP proofs, so it cannot connect while this switch is on.
5. Click **Next**, then **Save changes**. Copy the **Server id** (`mcp_…`) from the top of the page.

### 2. Put it in front of your server

Use your organization's slug and the server id from step 1. The slug is the part after `/orgs/` in the portal's URL.

```bash
export LUMOAUTH_ORG_ID=acme
export LUMOAUTH_MCP_SERVER_ID=mcp_0123456789abcdef01234567

npx lumoauth secure --upstream http://127.0.0.1:8000/mcp
```

`lumoauth` prints what it protects and where it runs:

```console
lumoauth: http://127.0.0.1:8000/mcp is protected by LumoAuth
  listening      http://0.0.0.0:8080/mcp
  resource       http://localhost:8080/mcp
  issuer         https://app.lumoauth.dev/orgs/acme/api/v1
  discovery      http://localhost:8080/.well-known/oauth-protected-resource/mcp
  tool policy    off
```

No MCP server yet? Use `--stdio -- npx -y @modelcontextprotocol/server-everything` in place of `--upstream` and its URL.

For the EU region, also set `LUMOAUTH_URL=https://eu.app.lumoauth.dev`.

### 3. Call it without a token

```console
$ curl -i http://localhost:8080/mcp
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer scope="mcp:read", resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp"
```

Calls without a token no longer reach your server. The `401` tells MCP clients where to find LumoAuth.

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
  invoices http://localhost:8080/mcp

claude mcp login invoices
```

Your browser opens on the LumoAuth sign-in page. After you sign in and approve, `claude mcp list` shows the connection:

```console
invoices: http://localhost:8080/mcp (HTTP) - ✔ Connected
```

Other MCP clients connect the same way if they let you set a client ID and a callback port. [Troubleshooting](#troubleshooting) explains the errors that you may see.

### Before you go to production

- Register a separate server with your public `https://` address. LumoAuth accepts plain `http://` only for `localhost`, `127.0.0.1` and `[::1]`.
- Put `lumoauth` behind your TLS terminator or tunnel at that address. Clients reach the server at its Resource URI.
- Keep the upstream on `127.0.0.1`, so that callers can reach it only through `lumoauth`.
- Under **Allowed clients**, choose **Only the clients I pick**.
- Switch on **Require DPoP sender-constrained tokens** if all your clients can send proofs. Agents built on the LumoAuth JavaScript, Python and Go SDKs can do so.

## What it does

`secure` runs on port 8080 (or `--port`, or `PORT`). In front of your server, it does the following:

- **Discovery.** It serves the protected resource metadata that sends MCP clients to your LumoAuth organization, and it answers `401` with the challenge that points to it.
- **Token checks.** It verifies each request's LumoAuth token (Bearer or DPoP) before anything reaches your server. It never passes the token on.
- **Identity.** It sends the caller's identity to your server in the headers below. Headers with these names from the client are removed.
- **Sessions.** It binds each MCP session to the caller that opened it.
- **Tool policy.** With LumoAuth's per-tool policy on, it removes from `tools/list` the tools that the caller may not run. It rejects those calls without reaching your server.

| Header | Value |
| --- | --- |
| `X-LumoAuth-Subject` | The user id, or `agent_agt_…` for an agent |
| `X-LumoAuth-Subject-Type` | `user` or `agent` |
| `X-LumoAuth-Agent-Id` | The agent's `agt_…` id |
| `X-LumoAuth-Actor` | The agent acting for the user |
| `X-LumoAuth-Client-Id` | The OAuth client |
| `X-LumoAuth-Scopes` | The granted scopes |

**HTTP mode** works with any MCP server and any protocol revision. It reads JSON-RPC only to apply the tool policy, and it streams everything else.

**Stdio mode** gives every MCP session its own server process, so two callers never share one. The HTTP side is the MCP SDK's Streamable HTTP transport, which serves protocol revisions up to 2025-11-25.

## Per-tool policy

With the policy on, `lumoauth` asks LumoAuth about each tool and hides the tools that a caller may not run.

**Every tool is denied until you grant it.** Set it up once:

1. **Create the server's own application.** Open **Applications**, click **New application** and choose **Machine to machine**. Copy the **Client ID** and the **Client secret**, which is shown only once.
2. **Allow the scope.** On the application's **Configuration** tab, set **Scopes** to `mcp:authorize`. The form also asks for a redirect URI, which this application does not use, so enter any `https://` URL. Click **Save configuration**.
3. **Connect it to the MCP server.** Edit the server. In the step **Who may connect and how**, select the application under **Per-tool authorization**.
4. **Give `lumoauth` the credentials.** Set `LUMOAUTH_MCP_CLIENT_ID` and `LUMOAUTH_MCP_CLIENT_SECRET`, then restart it. The policy is now on; `--no-tool-policy` turns it off.
5. **Grant access.** Open **Relationships**. Under **Namespaces**, create the namespace that you need, with the relation `invoke`. Then, under **Tuples**, add one relationship for each grant:

   | To grant | Object namespace | Object ID | Relation | Subject |
   | --- | --- | --- | --- | --- |
   | Every tool on the server | `mcp_server` | `mcp_0123456789abcdef01234567` | `invoke` | `user` and the user's id |
   | One tool | `mcp_tool` | `mcp_0123456789abcdef01234567/refund` | `invoke` | `agent` and the agent's id |

Relationships are part of the Fine-grained authorization add-on. Without it, every tool is denied.

## Check the setup

`npx lumoauth check` prints what the registration says, the discovery document and the `401` challenge. It also prints what the authorization server advertises: PKCE, client metadata documents and dynamic registration.

```console
$ npx lumoauth check
LumoAuth
  issuer         https://app.lumoauth.dev/orgs/acme/api/v1
  MCP server     mcp_0123456789abcdef01234567
  resource       http://localhost:8080/mcp
  scopes         mcp:read
  DPoP           accepted, not required
  tool policy    not configured
```

## Options

Run `npx lumoauth --help` for all of them. The common ones:

| Option | Environment variable | Meaning |
| --- | --- | --- |
| `--org` | `LUMOAUTH_ORG_ID` | Organization |
| `--server` | `LUMOAUTH_MCP_SERVER_ID` | Registered MCP server id |
| `--lumoauth-url` | `LUMOAUTH_URL` | `https://eu.app.lumoauth.dev` for the EU region |
| `--upstream` | | The MCP endpoint to protect |
| `--stdio` | | The command after `--` is a stdio server |
| `--port`, `--host` | `PORT` | Where to listen (default `0.0.0.0:8080`) |
| `--path` | | Public path of the MCP endpoint (default: the Resource URI's path) |
| `--scope` | | A scope that every request needs (repeatable) |
| `--public` | | A path that needs no token, such as `/health` (repeatable) |

## Troubleshooting

| What you see | Why | What to do |
| --- | --- | --- |
| `LumoAuth has no active MCP server` at start-up | The server id or the organization slug is wrong. | Copy both again from the portal. |
| `MCP server … is registered as Public` at start-up | LumoAuth issues no tokens for a server with this mode or with the stdio transport. | Choose **OAuth 2.1 protected** and the **Streamable HTTP** transport. |
| `Protected resource … does not match expected …` | The client connects to a URL that differs from the Resource URI. `localhost` and `127.0.0.1` count as different. | Use the Resource URI exactly. |
| `invalid_dpop_proof` or `DPoP proof required` | **Require DPoP** is on and the client sends no proof. | Switch it off, then restart `lumoauth`. |
| `invalid_scope` … `not allowed for this client` | The application does not allow a scope that the client asks for. | Add the scope to the application's **Scopes**. Many clients add `offline_access` on their own. |
| `Invalid Redirect URL` on a LumoAuth page | The client's redirect URI is not registered. LumoAuth accepts a changing port only on `127.0.0.1` and `[::1]`, not on `localhost`. | Create an application with the exact URI, and give the client a fixed callback port. |
| `Dynamic client registration is not enabled` | The client tried to register itself, which is off by default. | Give the client a client ID, as in [step 4](#4-sign-in-from-a-client). |
| The list of tools is empty | The per-tool policy is on and the caller has no grant. | See [Per-tool policy](#per-tool-policy). |
| A registration change has no effect | `lumoauth` reads the registration at start-up. | Restart `lumoauth`. |

## License

MIT
