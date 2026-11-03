// `lumoauth secure` end to end: a real MCP server without authentication
// behind the proxy, and a stdio server behind the bridge.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { after, before, describe, test } from 'node:test';
import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { DpopProofSigner } from '@lumoauth/agent';
import { lumoAuth } from '@lumoauth/mcp';
import { StdioBridge, allowedToolNames, createExtAuthzServer, createSecureProxy } from '../dist/index.mjs';
import { ISSUER, METADATA_URL, RESOURCE, SERVER_ID, fakeLumoAuth, initialize, makeToken } from '../../mcp/tests/helpers.mjs';

const HEADERS = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
const listTools = { jsonrpc: '2.0', id: 3, method: 'tools/list' };
const callTool = (name) => ({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name, arguments: {} } });
const initialized = { jsonrpc: '2.0', method: 'notifications/initialized' };

async function rpcBody(response) {
    const text = await response.text();
    if ((response.headers.get('content-type') ?? '').includes('text/event-stream')) {
        return text
            .split('\n')
            .filter((line) => line.startsWith('data:'))
            .map((line) => JSON.parse(line.slice(5).trim()))
            .find((message) => 'result' in message || 'error' in message);
    }
    return JSON.parse(text);
}

const toolNames = (body) => body.result.tools.map((tool) => tool.name).sort();
const textOf = (body) => body.result?.content?.[0]?.text;

function upstreamServer() {
    const server = new McpServer({ name: 'upstream', version: '1.0.0' });
    server.registerTool('whoami', { description: 'Echo the identity headers' }, async (extra) => ({
        content: [{ type: 'text', text: String(extra.requestInfo?.headers?.['x-lumoauth-subject'] ?? '') }],
    }));
    server.registerTool('export', { description: 'Export everything' }, async () => ({
        content: [{ type: 'text', text: 'exported' }],
    }));
    return server;
}

/** An MCP server with no authentication: stateful + SSE, or stateless + JSON. */
async function startUpstream({ json }) {
    const seen = [];
    const sessions = new Map();
    const app = express();
    app.use(express.json());
    app.get('/health', (req, res) => res.json({ ok: true }));
    app.all('/mcp', async (req, res) => {
        seen.push({ method: req.method, headers: { ...req.headers }, body: req.body });
        if (json) {
            const server = upstreamServer();
            const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
            res.on('close', () => {
                transport.close();
                server.close();
            });
            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
            return;
        }
        let transport = sessions.get(req.headers['mcp-session-id']);
        if (!transport) {
            transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => randomUUID(),
                onsessioninitialized: (id) => sessions.set(id, transport),
            });
            await upstreamServer().connect(transport);
        }
        await transport.handleRequest(req, res, req.body);
    });
    const listener = await new Promise((resolve) => {
        const l = app.listen(0, '127.0.0.1', () => resolve(l));
    });
    return { url: `http://127.0.0.1:${listener.address().port}/mcp`, seen, close: () => listener.close() };
}

function makeAuth(fake) {
    return lumoAuth({ issuer: ISSUER, orgId: 'acme', serverId: SERVER_ID, fetch: fake.fetch, clientId: 'srv', clientSecret: 'shh', env: {} });
}

async function listen(server) {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${server.address().port}`;
}

describe('secure --upstream (stateful, Server-Sent Events)', () => {
    const fake = fakeLumoAuth({ allowedTools: new Set(['whoami']) });
    const alice = `Bearer ${makeToken({ sub: 'alice' })}`;
    let upstream;
    let proxy;
    let base;
    let sessionId;

    before(async () => {
        upstream = await startUpstream({ json: false });
        proxy = createSecureProxy({
            auth: makeAuth(fake),
            upstream: upstream.url,
            path: '/mcp',
            toolPolicy: true,
            identityHeaders: true,
            publicPaths: ['/health'],
            log: () => {},
        });
        base = await listen(proxy);
    });
    after(() => {
        proxy.close();
        upstream.close();
    });

    const post = (body, headers = {}) =>
        fetch(`${base}/mcp`, { method: 'POST', headers: { ...HEADERS, ...headers }, body: JSON.stringify(body) });
    const session = () => ({ 'mcp-session-id': sessionId, 'mcp-protocol-version': '2025-11-25' });

    test('discovery and the 401 challenge', async () => {
        assert.equal((await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json()).resource, RESOURCE);
        const response = await post(initialize);
        assert.equal(response.status, 401);
        assert.equal(response.headers.get('www-authenticate'), `Bearer scope="mcp:read", resource_metadata="${METADATA_URL}"`);
        assert.equal(upstream.seen.length, 0, 'nothing reached the upstream');
    });

    test('initialize: the token stays at the proxy, the identity goes upstream', async () => {
        const response = await post(initialize, { authorization: alice, 'x-lumoauth-subject': 'mallory' });
        assert.equal(response.status, 200);
        sessionId = response.headers.get('mcp-session-id');
        assert.ok(sessionId);
        assert.equal((await rpcBody(response)).result.serverInfo.name, 'upstream');
        const headers = upstream.seen.at(-1).headers;
        assert.equal(headers.authorization, undefined);
        assert.equal(headers['x-lumoauth-subject'], 'alice');
        assert.equal(headers['x-lumoauth-subject-type'], 'user');
        assert.equal((await post(initialized, { authorization: alice, ...session() })).status, 202);
    });

    test('tools/list is filtered by LumoAuth policy (SSE answer)', async () => {
        const response = await post(listTools, { authorization: alice, ...session() });
        assert.match(response.headers.get('content-type'), /text\/event-stream/);
        assert.deepEqual(toolNames(await rpcBody(response)), ['whoami']);
    });

    test('a refused tools/call never reaches the upstream', async () => {
        const before = upstream.seen.length;
        const body = await rpcBody(await post(callTool('export'), { authorization: alice, ...session() }));
        assert.equal(body.result.isError, true);
        assert.match(textOf(body), /LumoAuth policy/);
        assert.equal(upstream.seen.length, before);
        const allowed = await rpcBody(await post(callTool('whoami'), { authorization: alice, ...session() }));
        assert.equal(textOf(allowed), 'alice');
    });

    test('another caller cannot use the session', async () => {
        const response = await post(listTools, { authorization: `Bearer ${makeToken({ sub: 'bob' })}`, ...session() });
        assert.equal(response.status, 404);
    });

    test('public paths skip authentication', async () => {
        const response = await fetch(`${base}/health`);
        assert.deepEqual(await response.json(), { ok: true });
    });

    test('DPoP-bound tokens: the proof is checked against the public URL', async () => {
        const signer = DpopProofSigner.generate();
        const token = makeToken({ sub: 'alice', cnf: { jkt: signer.thumbprint } });
        const response = await post(initialize, {
            authorization: `DPoP ${token}`,
            dpop: signer.createProof({ method: 'POST', url: RESOURCE, accessToken: token }),
        });
        assert.equal(response.status, 200);
        assert.equal(upstream.seen.at(-1).headers.dpop, undefined);
    });
});

describe('secure --upstream (stateless, JSON)', () => {
    const fake = fakeLumoAuth({ allowedTools: new Set(['whoami']) });
    let upstream;
    let proxy;
    let base;

    before(async () => {
        upstream = await startUpstream({ json: true });
        proxy = createSecureProxy({
            auth: makeAuth(fake),
            upstream: upstream.url,
            path: '/mcp',
            toolPolicy: true,
            identityHeaders: false,
            publicPaths: [],
            log: () => {},
        });
        base = await listen(proxy);
    });
    after(() => {
        proxy.close();
        upstream.close();
    });

    test('tools/list is filtered (JSON answer) and identity headers can be off', async () => {
        const response = await fetch(`${base}/mcp`, {
            method: 'POST',
            headers: { ...HEADERS, 'mcp-protocol-version': '2025-11-25', authorization: `Bearer ${makeToken()}` },
            body: JSON.stringify(listTools),
        });
        assert.match(response.headers.get('content-type'), /application\/json/);
        assert.deepEqual(toolNames(await rpcBody(response)), ['whoami']);
        assert.equal(upstream.seen.at(-1).headers['x-lumoauth-subject'], undefined);
    });
});

describe('secure --stdio', () => {
    const fake = fakeLumoAuth({ allowedTools: new Set(['whoami']) });
    const auth = makeAuth(fake);
    const alice = `Bearer ${makeToken({ sub: 'alice' })}`;
    const fixture = fileURLToPath(new URL('./fixtures/stdio-server.mjs', import.meta.url));
    let bridge;
    let proxy;
    let base;

    before(async () => {
        bridge = new StdioBridge({
            command: [process.execPath, fixture],
            filterTools: (caller, names) => allowedToolNames(auth, caller, names),
            log: () => {},
        });
        proxy = createSecureProxy({ auth, bridge, path: '/mcp', toolPolicy: true, identityHeaders: true, publicPaths: [], log: () => {} });
        base = await listen(proxy);
    });
    after(async () => {
        await bridge.close();
        proxy.close();
    });

    const post = (body, headers = {}) =>
        fetch(`${base}/mcp`, { method: 'POST', headers: { ...HEADERS, ...headers }, body: JSON.stringify(body) });

    async function open(authorization, protocolVersion = '2025-11-25') {
        const response = await post({ ...initialize, params: { ...initialize.params, protocolVersion } }, { authorization });
        assert.equal(response.status, 200);
        const body = await rpcBody(response);
        const id = response.headers.get('mcp-session-id');
        const headers = { authorization, 'mcp-session-id': id, 'mcp-protocol-version': body.result.protocolVersion };
        assert.equal((await post(initialized, headers)).status, 202);
        return { body, headers };
    }

    test('a stdio server behind LumoAuth: list, call, refuse', async () => {
        const { body, headers } = await open(alice);
        assert.equal(body.result.serverInfo.name, 'stdio-fixture');
        assert.deepEqual(toolNames(await rpcBody(await post(listTools, headers))), ['whoami']);
        assert.match(textOf(await rpcBody(await post(callTool('whoami'), headers))), /^pid \d+$/);
        const refused = await rpcBody(await post(callTool('export'), headers));
        assert.equal(refused.result.isError, true);
    });

    test('a client asking for a newer revision gets one the bridge serves', async () => {
        const { body } = await open(alice, '2099-01-01');
        assert.notEqual(body.result.protocolVersion, '2099-01-01');
    });

    test('each session has its own process and belongs to its caller', async () => {
        const first = await open(alice);
        const second = await open(alice);
        const pid = async (headers) => textOf(await rpcBody(await post(callTool('whoami'), headers)));
        assert.notEqual(await pid(first.headers), await pid(second.headers));
        const bob = { ...first.headers, authorization: `Bearer ${makeToken({ sub: 'bob' })}` };
        assert.equal((await post(listTools, bob)).status, 404);
    });

    test('requests without a session must initialize first', async () => {
        const response = await post(listTools, { authorization: alice });
        assert.equal(response.status, 400);
    });
});

describe('JIT, Vault header injection, traceparent & Envoy ext_authz mode', () => {
    const fake = fakeLumoAuth({ allowedTools: new Set(['whoami']) });
    let upstream;
    let proxy;
    let proxyBase;
    let extAuthz;
    let extBase;

    before(async () => {
        upstream = await startUpstream({ json: true });
        const auth = makeAuth(fake);
        proxy = createSecureProxy({
            auth,
            upstream: upstream.url,
            path: '/mcp',
            toolPolicy: true,
            identityHeaders: true,
            publicPaths: ['/health'],
            jit: { whoami: { type: 'identity_inspection', actions: ['read'] } },
            vaultConnections: { github: 'conn_gh_prod' },
            log: () => {},
        });
        proxyBase = await listen(proxy);

        extAuthz = createExtAuthzServer({
            auth,
            toolPolicy: true,
            identityHeaders: true,
            publicPaths: ['/healthz'],
            jit: { whoami: { type: 'identity_inspection', actions: ['read'] } },
            vaultConnections: { github: 'conn_gh_prod' },
            log: () => {},
        });
        extBase = await listen(extAuthz);
    });

    after(() => {
        proxy.close();
        extAuthz.close();
        upstream.close();
    });

    test('proxy enforces JIT on tools/call and injects Vault token + trace headers upstream when granted', async () => {
        const tp = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
        const plainToken = makeToken({ sub: 'alice' });

        // 1. Denied without JIT details
        const deniedRes = await fetch(`${proxyBase}/mcp`, {
            method: 'POST',
            headers: { ...HEADERS, 'mcp-protocol-version': '2025-11-25', authorization: `Bearer ${plainToken}` },
            body: JSON.stringify(callTool('whoami')),
        });
        assert.equal(deniedRes.status, 200);
        assert.ok(deniedRes.headers.get('insufficient-authorization-details'));
        const deniedBody = await rpcBody(deniedRes);
        assert.equal(deniedBody.result.isError, true);
        assert.equal(deniedBody.result._meta.error, 'insufficient_authorization_details');

        // 2. Allowed with JIT details: injects X-LumoAuth-Vault-Github-Token, X-LumoAuth-Trace-Id, X-LumoAuth-Is-Jit
        const jitToken = makeToken({
            sub: 'alice',
            jit: true,
            authorization_details: [{ type: 'identity_inspection', actions: ['read'] }],
        });
        const okRes = await fetch(`${proxyBase}/mcp`, {
            method: 'POST',
            headers: {
                ...HEADERS,
                'mcp-protocol-version': '2025-11-25',
                authorization: `Bearer ${jitToken}`,
                traceparent: tp,
            },
            body: JSON.stringify(callTool('whoami')),
        });
        assert.equal(okRes.status, 200);
        const lastUpstream = upstream.seen.at(-1).headers;
        assert.equal(lastUpstream['x-lumoauth-subject'], 'alice');
        assert.equal(lastUpstream['x-lumoauth-trace-id'], '4bf92f3577b34da6a3ce929d0e0e4736');
        assert.equal(lastUpstream['x-lumoauth-is-jit'], 'true');
        assert.match(lastUpstream['x-lumoauth-vault-github-token'], /^vault_tok_conn_gh_prod_/);
        assert.equal(lastUpstream.traceparent, tp);
    });

    test('Envoy ext_authz server handles health, discovery, 401 challenge, toolPolicy, JIT, and upstream headers', async () => {
        // 1. Public health check
        assert.equal((await fetch(`${extBase}/healthz`)).status, 200);

        // 2. Discovery document
        const disc = await fetch(`${extBase}/.well-known/oauth-protected-resource/mcp`);
        assert.equal(disc.status, 200);
        assert.equal((await disc.json()).resource, RESOURCE);

        // 3. Unauthenticated -> 401 challenge
        const unauth = await fetch(`${extBase}/mcp`, { method: 'POST' });
        assert.equal(unauth.status, 401);
        assert.match(unauth.headers.get('www-authenticate'), /resource_metadata=/);

        // 4. Denied by ToolPolicy -> 403 with X-LumoAuth-Denied-Tool
        const plainToken = makeToken({ sub: 'alice' });
        const deniedPolicy = await fetch(`${extBase}/mcp`, {
            method: 'POST',
            headers: { ...HEADERS, authorization: `Bearer ${plainToken}` },
            body: JSON.stringify(callTool('export')),
        });
        assert.equal(deniedPolicy.status, 403);
        assert.equal(deniedPolicy.headers.get('x-lumoauth-denied-tool'), 'export');

        // 5. Denied by JIT -> 403 with Insufficient-Authorization-Details
        const deniedJit = await fetch(`${extBase}/mcp`, {
            method: 'POST',
            headers: { ...HEADERS, authorization: `Bearer ${plainToken}` },
            body: JSON.stringify(callTool('whoami')),
        });
        assert.equal(deniedJit.status, 403);
        assert.ok(deniedJit.headers.get('insufficient-authorization-details'));
        assert.match(deniedJit.headers.get('www-authenticate'), /insufficient_authorization_details/);

        // 6. Allowed -> 200 OK with X-LumoAuth-* and Vault headers for Envoy upstream injection
        const tp = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
        const jitToken = makeToken({
            sub: 'alice',
            jit: true,
            authorization_details: [{ type: 'identity_inspection', actions: ['read'] }],
        });
        const allowed = await fetch(`${extBase}/mcp`, {
            method: 'POST',
            headers: {
                ...HEADERS,
                authorization: `Bearer ${jitToken}`,
                traceparent: tp,
                'x-envoy-original-path': '/mcp',
            },
            body: JSON.stringify(callTool('whoami')),
        });
        assert.equal(allowed.status, 200);
        assert.equal(allowed.headers.get('x-lumoauth-subject'), 'alice');
        assert.equal(allowed.headers.get('x-lumoauth-trace-id'), '4bf92f3577b34da6a3ce929d0e0e4736');
        assert.equal(allowed.headers.get('x-lumoauth-is-jit'), 'true');
        assert.match(allowed.headers.get('x-lumoauth-vault-github-token'), /^vault_tok_conn_gh_prod_/);
        assert.equal(allowed.headers.get('traceparent'), tp);
    });
});
