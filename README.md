<div align="center">

<a href="https://lumoauth.dev">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://docs.lumoauth.dev/img/lumoauth-logo-horizontal-reversed.svg">
    <img src="https://docs.lumoauth.dev/img/lumoauth-logo-horizontal.svg" alt="LumoAuth" height="36">
  </picture>
</a>

# LumoAuth for MCP servers

**Add sign-in and per-tool access control to any MCP server.**<br>
Three lines for the official TypeScript SDK. One command for everything else.

[![@lumoauth/mcp on npm](https://img.shields.io/badge/npm-%40lumoauth%2Fmcp-111)](https://www.npmjs.com/package/@lumoauth/mcp)
[![lumoauth on npm](https://img.shields.io/badge/npm-lumoauth-111)](https://www.npmjs.com/package/lumoauth)
[![Node 20+](https://img.shields.io/badge/node-20%2B-111)](#development)
[![License: MIT](https://img.shields.io/badge/license-MIT-111)](#license)

[Which package?](#which-package-do-i-need) · [`@lumoauth/mcp`](packages/mcp) · [`lumoauth`](packages/lumoauth) · [How it works](#how-it-works) · [Docs](https://docs.lumoauth.dev/mcp/)

</div>

---

## Which package do I need?

| You have… | Use | Start here |
| --- | --- | --- |
| A server built with the official TypeScript SDK, v1 or v2 | [`@lumoauth/mcp`](packages/mcp) | [Quick start](packages/mcp#quick-start) |
| Any other MCP server, in any language, over HTTP or stdio | [`npx lumoauth secure`](packages/lumoauth) | [Quick start](packages/lumoauth#quick-start) |
| A FastMCP server in Python | [`lumoauth-fastmcp`](https://github.com/LumoAuth/mcp-fastmcp) | [Quick start](https://github.com/LumoAuth/mcp-fastmcp#quick-start) |

**Inside your server**, three lines with Express:

```ts
const auth = lumoAuth();                    // reads LUMOAUTH_ORG_ID and LUMOAUTH_MCP_SERVER_ID
app.use(auth.router());                     // discovery for MCP clients
app.post('/mcp', auth.protect(), mcp);      // 401 challenge, token check, req.auth
```

**In front of your server**, without changing its code:

```bash
npx lumoauth secure --upstream http://127.0.0.1:8000/mcp
```

<table>
<tr>
<td width="33%" valign="top">

**Standard discovery**<br>
MCP clients read one well-known address on your server to find LumoAuth. No custom handshakes.

</td>
<td width="33%" valign="top">

**Sign-in and consent**<br>
LumoAuth shows the sign-in and consent screens. Your server never handles a password.

</td>
<td width="33%" valign="top">

**Token checks on your server**<br>
Each request is checked locally: signature, issuer, audience, expiry and DPoP binding.

</td>
</tr>
<tr>
<td valign="top">

**The verified caller**<br>
Your code gets a person, an AI agent, or an agent that acts for a person.

</td>
<td valign="top">

**Rules per tool**<br>
Require a scope, a person or an agent capability for each tool.

</td>
<td valign="top">

**Policy in LumoAuth**<br>
Grant each tool to a person or an agent in LumoAuth. A change applies within 30 seconds, without a restart.

</td>
</tr>
</table>

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/LumoAuth/mcp-typescript/main/assets/how-it-works-dark.svg">
    <img src="https://raw.githubusercontent.com/LumoAuth/mcp-typescript/main/assets/how-it-works.svg" alt="An MCP client calls your server without a token and gets a 401 that says where to sign in. The user signs in through LumoAuth, which issues a token for this server only. The client calls the tool with the token. Your server checks the token and runs the tool." width="720">
  </picture>
</p>

LumoAuth is the authorization server, and your MCP server is a resource server. LumoAuth already does the authorization-server half of the MCP specification: client registration, consent, tokens bound to one server, DPoP, per-server scopes and an endpoint for per-tool policy.

These packages do not proxy OAuth flows or issue tokens. They give your server the resource-server half. They read as much as possible from the server's registration in LumoAuth, so your code needs only the organization and the server id.

1. **Discovery.** Serve protected resource metadata at the server's own origin. It names the organization's issuer, so clients find LumoAuth through `{issuer}/.well-known/openid-configuration`.
2. **Challenge.** Answer `401` with `WWW-Authenticate` pointing to that document. The challenge carries the registration's basic scopes, uses the `DPoP` scheme when the registration requires DPoP, and states the real reason when a token is rejected.
3. **Verification.** Verify LumoAuth's `at+jwt` tokens locally with the LumoAuth SDK's verifier (`@lumoauth/agent`), including the DPoP binding. LumoAuth's rule for comparing resource URIs applies to audiences too, so `https://x.example.com` and `https://x.example.com/` both match.
4. **Identity.** Give tools the verified caller: user or agent, the delegation chain, scopes and capabilities.
5. **Authorization.** Check scopes with LumoAuth's wildcard rule, check the caller (people only, or agents with capabilities), and ask LumoAuth's per-tool policy. The server asks with its own client-credentials token and never forwards the caller's token.

`lumoauth secure` does the same steps as a reverse proxy, for servers whose code you do not want to change.

### Standards

| Plain name | Standard |
| --- | --- |
| Protected resource metadata | RFC 9728 |
| Resource indicators | RFC 8707 |
| DPoP | RFC 9449 |
| JWT access tokens (`at+jwt`) | RFC 9068 |
| Model Context Protocol authorization | MCP Authorization specification |

## Development

```bash
npm install
npm run build
npm test
```

The end-to-end tests run real MCP servers built with SDK v1 and v2, a stdio server, and the `lumoauth` binary against a fake LumoAuth organization.

## License

MIT
