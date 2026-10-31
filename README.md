# LumoAuth for the TypeScript MCP SDK

Two packages that add LumoAuth sign-in and authorization to MCP servers:

| Package | For |
| --- | --- |
| [`@lumoauth/mcp`](packages/mcp) | Servers built with the official TypeScript SDK, v1 (`@modelcontextprotocol/sdk`) or v2 (`@modelcontextprotocol/server`). Three lines with Express, or a `fetch` gate for web-standard handlers. |
| [`lumoauth`](packages/lumoauth) | `npx lumoauth secure`: any existing MCP server, in any language, over HTTP or stdio, without code changes. |

```ts
const auth = lumoAuth();                    // LUMOAUTH_ORG_ID + LUMOAUTH_MCP_SERVER_ID
app.use(auth.router());
app.post('/mcp', auth.protect(), mcp);
```

```bash
npx lumoauth secure --upstream http://127.0.0.1:8000/mcp
```

The FastMCP (Python) counterpart lives in [`../mcp-fastmcp`](../mcp-fastmcp).

## Approach

LumoAuth is the authorization server; the MCP server is a resource server.
LumoAuth already does the authorization-server half of the MCP
specification: client registration through Client ID Metadata Documents
(on by default) or dynamic registration, consent, RFC 8707 audience
binding, DPoP, per-server scopes and a per-tool policy endpoint. So these
packages do not proxy OAuth flows or mint tokens. They give the server the
resource-server half, and they read everything they can from the server's
registration in LumoAuth, so that the code needs only the organization and
the server id:

1. **Discovery.** Serve RFC 9728 protected resource metadata at the
   server's own origin. It names the organization's issuer (not a metadata
   URL), so clients find LumoAuth through `{issuer}/.well-known/openid-configuration`.
2. **Challenge.** Answer `401` with `WWW-Authenticate` pointing at that
   document, with the registration's basic scopes, in the `DPoP` scheme
   when the registration requires DPoP, and with the real reason when a
   token is refused.
3. **Verification.** Verify LumoAuth's `at+jwt` tokens locally with the
   LumoAuth SDK's verifier (`@lumoauth/agent`), including the DPoP binding.
   Audiences compare the way LumoAuth compares resource URIs, so
   `https://x.example.com` and `https://x.example.com/` both match.
4. **Identity.** Hand tools the verified caller: user or agent, the
   delegation chain, scopes and capabilities.
5. **Authorization.** Scope checks with LumoAuth's wildcard rule, caller
   checks (people only, agents with capabilities), and LumoAuth's per-tool
   policy, asked by the server with its own client-credentials token. The
   caller's token is never forwarded.

`lumoauth secure` packages the same steps as an authenticating reverse
proxy, for servers whose code you do not want to change.

## Development

`overrides` in this workspace's `package.json` link `@lumoauth/agent` and
`@lumoauth/shared` to the sibling `../sdk-js` checkout, so build those two
packages first. Without the checkout or its `dist` folders, `npm install`
still succeeds, and `npm run build` then fails with
`Cannot find module '@lumoauth/agent'`.

```bash
(cd ../sdk-js && npm ci && npm run build -w packages/shared -w packages/agent)
npm install
npm run build
npm test
```

The end-to-end tests run real MCP servers built with SDK v1 and v2, a
stdio server, and the `lumoauth` binary against a fake LumoAuth
organization.
