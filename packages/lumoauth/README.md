# lumoauth

`npx lumoauth secure` puts LumoAuth in front of an MCP server that has no
authentication, without changing the server's code.

```bash
# An HTTP MCP server you already run on port 8000
npx lumoauth secure --upstream http://127.0.0.1:8000/mcp

# Start it too, and wait until it listens
npx lumoauth secure --upstream http://127.0.0.1:8000/mcp -- python server.py

# A stdio MCP server, served over HTTP behind LumoAuth
npx lumoauth secure --stdio -- npx -y @modelcontextprotocol/server-everything
```

with the organization and the registered server in the environment:

```bash
export LUMOAUTH_ORG_ID=acme
export LUMOAUTH_MCP_SERVER_ID=mcp_0123456789abcdef01234567
```

Register the server first, in the LumoAuth portal under **AI Agents → MCP
servers**. The **Resource URI** is the public URL that clients connect to.
Choose the **Streamable HTTP** transport, also for a stdio server: clients
reach `lumoauth` over HTTP, and `lumoauth` cannot start with a registration
on the stdio transport, which has no OAuth settings. `lumoauth` needs Node 20
or later.

## What it does

`secure` listens on port 8080 (or `--port`, or `PORT`) and, in front of the
server:

- serves the OAuth discovery document (RFC 9728) that sends MCP clients to
  your LumoAuth organization, and answers `401` with the challenge that
  points at it;
- verifies every request's LumoAuth token (Bearer or DPoP) before anything
  reaches the server, and never passes the token on;
- tells the server who is calling in `X-LumoAuth-Subject`,
  `X-LumoAuth-Subject-Type` (`user` or `agent`), `X-LumoAuth-Agent-Id`,
  `X-LumoAuth-Actor`, `X-LumoAuth-Client-Id` and `X-LumoAuth-Scopes`
  headers. Headers with these names from the client are removed;
- binds each MCP session to the caller that opened it;
- with LumoAuth's per-tool policy on, removes from `tools/list` the tools
  that the caller may not run, and refuses those calls without reaching the
  server.

The HTTP mode is protocol-agnostic: it reads JSON-RPC only to apply the
tool policy and streams everything else, so it works with any MCP server
and any protocol revision. Keep the upstream on `127.0.0.1`, so that
callers can reach it only through `lumoauth`.

In stdio mode, every MCP session gets its own server process, so two
callers never share one. The HTTP side is the MCP SDK's Streamable HTTP
transport, which serves protocol revisions up to 2025-11-25.

## Per-tool policy

Create an OAuth client for the server with the `client_credentials` grant
and the `mcp:authorize` scope. Edit the server in the portal and, in the step
**Who may connect and how**, select that client under **Per-tool
authorization**. Set `LUMOAUTH_MCP_CLIENT_ID` and
`LUMOAUTH_MCP_CLIENT_SECRET`, and the policy is on; `--no-tool-policy` turns
it off.

## Check the setup

```bash
npx lumoauth check
```

prints what the registration says, the discovery document, the `401`
challenge, and whether the authorization server offers what MCP clients
need (PKCE, client metadata documents, dynamic registration).

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
| `--scope` | | A scope every request needs (repeatable) |
| `--public` | | A path that needs no token, such as `/health` (repeatable) |

Clients reach the server at its Resource URI, so put the proxy behind your
TLS terminator or tunnel at that address.
