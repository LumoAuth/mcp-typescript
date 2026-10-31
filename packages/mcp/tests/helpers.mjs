// A fake LumoAuth organization for the tests: signing key, JWKS, discovery,
// the hosted MCP registration, the token endpoint and the tool-authorize API.
import { generateKeyPairSync, sign } from 'node:crypto';

export const ISSUER = 'https://app.lumoauth.dev/orgs/acme/api/v1';
export const ORIGIN = 'https://mcp.example.com';
export const RESOURCE = `${ORIGIN}/mcp`;
export const SERVER_ID = 'mcp_0123456789abcdef01234567';
export const METADATA_URL = `${ORIGIN}/.well-known/oauth-protected-resource/mcp`;

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
export const JWKS = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' }] };

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

let counter = 0;
export function makeToken(claims = {}, header = {}) {
    const now = Math.floor(Date.now() / 1000);
    const head = b64({ typ: 'at+jwt', alg: 'RS256', kid: 'k1', ...header });
    const body = b64({
        iss: ISSUER,
        sub: 'user-123',
        aud: RESOURCE,
        client_id: 'https://client.example.com/metadata.json',
        exp: now + 600,
        iat: now - 5,
        jti: `jti-${now}-${counter++}`,
        scope: 'mcp:read',
        ...claims,
    });
    const signature = sign('sha256', Buffer.from(`${head}.${body}`), privateKey).toString('base64url');
    return `${head}.${body}.${signature}`;
}

export function registrationDocument({ requireDpop = false, scopes = ['mcp:read'] } = {}) {
    const document = {
        resource: RESOURCE,
        // Never copied: the package publishes its configured issuer
        // (older LumoAuth releases put the metadata URL here).
        authorization_servers: [ISSUER],
        bearer_methods_supported: ['header'],
        scopes_supported: scopes,
    };
    if (requireDpop) {
        document.dpop_bound_access_tokens_required = true;
        document.dpop_signing_alg_values_supported = ['ES256', 'RS256'];
    }
    return document;
}

/**
 * `fakeLumoAuth({ allowedTools })` -> { fetch, calls }. `calls` records the
 * tool-authorize requests; `allowedTools` decides them.
 */
export function fakeLumoAuth({ allowedTools = new Set(), registration = registrationDocument(), failPolicy = false } = {}) {
    const calls = { authorize: [], token: 0 };
    const json = (body, status = 200) =>
        new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
    const fetch = async (input, init = {}) => {
        const url = typeof input === 'string' ? input : input.url;
        if (url === `${ISSUER}/.well-known/openid-configuration`) {
            return json({ issuer: ISSUER, jwks_uri: `${ISSUER}/.well-known/jwks.json` });
        }
        if (url === `${ISSUER}/.well-known/jwks.json`) return json(JWKS);
        if (url === `${ISSUER}/.well-known/oauth-authorization-server`) {
            return json({ issuer: ISSUER, authorization_endpoint: `${ISSUER}/oauth/authorize`, token_endpoint: `${ISSUER}/oauth/token` });
        }
        if (url === `${ISSUER}/.well-known/oauth-protected-resource/mcp/${SERVER_ID}`) return json(registration);
        if (url === `${ISSUER}/oauth/token`) {
            calls.token += 1;
            const form = new URLSearchParams(String(init.body));
            if (form.get('client_id') !== 'srv' || form.get('client_secret') !== 'shh' || form.get('scope') !== 'mcp:authorize') {
                return json({ error: 'invalid_client' }, 401);
            }
            return json({ access_token: 'server-token', token_type: 'Bearer', expires_in: 3600 });
        }
        if (url === `${ISSUER}/mcp/servers/${SERVER_ID}/tools/authorize`) {
            const headers = new Headers(init.headers);
            if (headers.get('authorization') !== 'Bearer server-token') return json({ error: 'invalid_token' }, 401);
            if (failPolicy) return json({ error: 'server_error' }, 500);
            const body = JSON.parse(String(init.body));
            calls.authorize.push(body);
            const allowed = allowedTools.has(body.tool);
            return json(
                { allowed, subject: body.subject, resource: { type: 'mcp_tool', id: `${SERVER_ID}/${body.tool}` } },
                allowed ? 200 : 403,
            );
        }
        throw new Error(`unexpected fetch of ${url}`);
    };
    return { fetch, calls };
}

export const initialize = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'node-test', version: '1.0' } },
};
