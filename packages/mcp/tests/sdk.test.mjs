// End to end with the real MCP TypeScript SDKs: v1 (Express + Streamable
// HTTP transport) and v2 (createMcpHandler fetch handler).
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import express from 'express';
import { McpServer as McpServerV1 } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { McpServer as McpServerV2, createMcpHandler } from '@modelcontextprotocol/server';
import { DpopProofSigner } from '@lumoauth/agent';
import * as z from 'zod';
import { getCaller, lumoAuth, parseTraceparent } from '../dist/index.mjs';
import { ISSUER, METADATA_URL, RESOURCE, SERVER_ID, fakeLumoAuth, initialize, makeToken, registrationDocument } from './helpers.mjs';

const HEADERS = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': '2025-11-25',
};

async function rpcBody(response) {
    const text = await response.text();
    if ((response.headers.get('content-type') ?? '').includes('text/event-stream')) {
        const messages = text
            .split('\n')
            .filter((line) => line.startsWith('data:'))
            .map((line) => JSON.parse(line.slice(5).trim()));
        return messages.find((m) => 'result' in m || 'error' in m);
    }
    return JSON.parse(text);
}

const listTools = { jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} };
const callTool = (name, args = {}) => ({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: args } });
const textOf = (body) => body.result?.content?.[0]?.text;
const toolNames = (body) => body.result.tools.map((t) => t.name).sort();

function makeAuth(fake, extra = {}) {
    return lumoAuth({ issuer: ISSUER, serverId: SERVER_ID, orgId: 'acme', lumoauthUrl: 'https://app.lumoauth.dev', fetch: fake.fetch, clientId: 'srv', clientSecret: 'shh', env: {}, ...extra });
}

// ── SDK v1: Express + StreamableHTTPServerTransport ─────────────────

describe('MCP SDK v1 (Express)', () => {
    const fake = fakeLumoAuth({ allowedTools: new Set(['whoami', 'refund', 'wireTransfer', 'githubIssue']) });
    const auth = makeAuth(fake);
    let base;
    let listener;

    function buildServer() {
        const server = new McpServerV1({ name: 'invoices', version: '1.0.0' });
        auth.secureTools(server, {
            scopes: { refund: ['invoices:refund'] },
            jit: { wireTransfer: { type: 'payment_initiation', actions: ['wire'] } },
        });
        server.registerTool('whoami', { description: 'Who is calling' }, async (extra) => ({
            content: [{ type: 'text', text: JSON.stringify(getCaller(extra)) }],
        }));
        server.registerTool(
            'refund',
            { description: 'Refund an invoice', inputSchema: { invoiceId: z.string() } },
            async ({ invoiceId }) => ({ content: [{ type: 'text', text: `refunded ${invoiceId}` }] }),
        );
        server.registerTool(
            'wireTransfer',
            { description: 'High-risk wire transfer', inputSchema: { amount: z.number() } },
            async ({ amount }) => ({ content: [{ type: 'text', text: `wired ${amount}` }] }),
        );
        server.registerTool('githubIssue', { description: 'Fetch GitHub token from Vault' }, async (extra) => {
            const tok = await auth.vaultToken('conn_github', extra);
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify({
                            accessToken: tok.accessToken,
                            userId: tok.userId ?? null,
                            headers: tok.headers(),
                        }),
                    },
                ],
            };
        });
        server.registerTool('export', { description: 'Export everything' }, async () => ({
            content: [{ type: 'text', text: 'exported' }],
        }));
        return server;
    }

    before(async () => {
        const app = express();
        app.use(express.json());
        app.use(auth.router());
        app.post('/mcp', auth.protect(), async (req, res) => {
            const server = buildServer();
            const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
            res.on('close', () => {
                transport.close();
                server.close();
            });
            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
        });
        await new Promise((resolve) => {
            listener = app.listen(0, '127.0.0.1', resolve);
        });
        base = `http://127.0.0.1:${listener.address().port}`;
    });
    after(() => listener.close());

    const post = (body, headers = {}) =>
        fetch(`${base}/mcp`, { method: 'POST', headers: { ...HEADERS, ...headers }, body: JSON.stringify(body) });

    test('discovery document at the root', async () => {
        const response = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
        assert.equal(response.status, 200);
        assert.deepEqual((await response.json()).authorization_servers, [ISSUER]);
    });

    test('401 challenge points at the discovery document', async () => {
        const response = await post(initialize);
        assert.equal(response.status, 401);
        assert.equal(response.headers.get('www-authenticate'), `Bearer scope="mcp:read", resource_metadata="${METADATA_URL}"`);
        assert.equal(response.headers.get('access-control-expose-headers'), 'WWW-Authenticate');
    });

    test('initialize and a tool call with the verified caller', async () => {
        const authorization = `Bearer ${makeToken({ sub: 'agent_agt_42', is_agent: true })}`;
        const init = await post(initialize, { authorization });
        assert.equal(init.status, 200);
        assert.equal((await rpcBody(init)).result.serverInfo.name, 'invoices');
        const body = await rpcBody(await post(callTool('whoami'), { authorization }));
        const caller = JSON.parse(textOf(body));
        assert.equal(caller.agentId, 'agt_42');
        assert.equal(caller.isAgent, true);
    });

    test('a guarded tool refuses a missing scope, then allows it', async () => {
        const denied = await rpcBody(await post(callTool('refund', { invoiceId: 'inv_1' }), { authorization: `Bearer ${makeToken()}` }));
        assert.equal(denied.result.isError, true);
        assert.match(textOf(denied), /invoices:refund/);
        const token = makeToken({ scope: 'mcp:read invoices:*' });
        const allowed = await rpcBody(await post(callTool('refund', { invoiceId: 'inv_1' }), { authorization: `Bearer ${token}` }));
        assert.equal(textOf(allowed), 'refunded inv_1');
    });

    test('LumoAuth policy refuses a tool it does not allow', async () => {
        const body = await rpcBody(await post(callTool('export'), { authorization: `Bearer ${makeToken()}` }));
        assert.equal(body.result.isError, true);
        assert.match(textOf(body), /LumoAuth policy/);
        const asked = fake.calls.authorize.find((call) => call.tool === 'export');
        assert.deepEqual(asked.subject, { type: 'user', id: 'user-123' });
        assert.equal(fake.calls.token, 1, 'the server token is fetched once and cached');
    });

    test('DPoP-bound tokens through Express', async () => {
        const signer = DpopProofSigner.generate();
        const token = makeToken({ cnf: { jkt: signer.thumbprint } });
        const response = await post(initialize, {
            authorization: `DPoP ${token}`,
            dpop: signer.createProof({ method: 'POST', url: RESOURCE, accessToken: token }),
        });
        assert.equal(response.status, 200);
    });

    test('secureTools filters tools/list by both local scopes and LumoAuth ToolPolicy (SDK v1)', async () => {
        // Without invoices:refund scope: refund (missing scope) and export (denied by policy) are hidden
        const basicList = await rpcBody(await post(listTools, { authorization: `Bearer ${makeToken()}` }));
        assert.deepEqual(toolNames(basicList), ['githubIssue', 'whoami', 'wireTransfer']);

        // With invoices:* scope: refund is now included, export is still hidden by LumoAuth policy
        const fullList = await rpcBody(
            await post(listTools, { authorization: `Bearer ${makeToken({ scope: 'mcp:read invoices:*' })}` }),
        );
        assert.deepEqual(toolNames(fullList), ['githubIssue', 'refund', 'whoami', 'wireTransfer']);
    });

    test('JIT / RAR guard enforces authorization_details and accepts X-LumoAuth-Jit-Token', async () => {
        // 1. Denied without JIT details, returning authorization_details_hint
        const denied = await rpcBody(
            await post(callTool('wireTransfer', { amount: 5000 }), { authorization: `Bearer ${makeToken()}` }),
        );
        assert.equal(denied.result.isError, true);
        assert.match(textOf(denied), /payment_initiation/);
        assert.match(textOf(denied), /authorization_details_hint/);

        // 2. Allowed when X-LumoAuth-Jit-Token carries matching permissions.authorization_details
        const jitToken = makeToken({
            sub: 'user-123',
            aud: ISSUER,
            jit: true,
            permissions: {
                jit_request_id: 'jit_req_99',
                authorization_details: [{ type: 'payment_initiation', actions: ['wire'] }],
            },
        });
        const allowed = await rpcBody(
            await post(callTool('wireTransfer', { amount: 5000 }), {
                authorization: `Bearer ${makeToken({ sub: 'user-123' })}`,
                'x-lumoauth-jit-token': jitToken,
            }),
        );
        assert.equal(textOf(allowed), 'wired 5000');
    });

    test('Token Vault helper resolves user_id for delegated callers and propagates W3C traceparent', async () => {
        const tp = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
        assert.deepEqual(parseTraceparent(tp), {
            traceparent: tp,
            traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        });
        assert.equal(parseTraceparent('invalid'), undefined);

        const delegatedToken = makeToken({
            sub: 'user-delegator-7',
            act: { sub: 'agent_agt_42', sub_profile: 'ai_agent' },
        });
        const resp = await rpcBody(
            await post(callTool('githubIssue'), {
                authorization: `Bearer ${delegatedToken}`,
                traceparent: tp,
            }),
        );
        const data = JSON.parse(textOf(resp));
        assert.equal(data.accessToken, 'vault_tok_conn_github_1');
        assert.equal(data.userId, 'user-delegator-7');
        assert.deepEqual(data.headers, { Authorization: 'Bearer vault_tok_conn_github_1' });

        // Verify traceparent was forwarded to both /tools/authorize and /agents/me/connections/conn_github/token
        const authCall = fake.calls.authorize.find(
            (c) => c.tool === 'githubIssue' && c.subject.id === 'user-delegator-7',
        );
        assert.equal(authCall.traceparent, tp);
        assert.equal(fake.calls.vault.length, 1);
        assert.equal(fake.calls.vault[0].traceparent, tp);
        assert.deepEqual(fake.calls.vault[0].body, { user_id: 'user-delegator-7' });
    });
});

// ── SDK v2: createMcpHandler (web-standard fetch) ───────────────────

describe('MCP SDK v2 (createMcpHandler)', () => {
    const fake = fakeLumoAuth({ allowedTools: new Set(['whoami', 'refund']), registration: registrationDocument({ requireDpop: false }) });
    const auth = makeAuth(fake);
    const handler = createMcpHandler(() => {
        const server = new McpServerV2({ name: 'invoices-v2', version: '1.0.0' });
        auth.secureTools(server);
        server.registerTool('whoami', { description: 'Who is calling' }, async (ctx) => ({
            content: [{ type: 'text', text: JSON.stringify(getCaller(ctx)) }],
        }));
        server.registerTool(
            'refund',
            {
                description: 'Refund an invoice',
                inputSchema: z.object({ invoiceId: z.string() }),
                scopeChallenge: auth.scopeChallenge('invoices:refund'),
            },
            async ({ invoiceId }) => ({ content: [{ type: 'text', text: `refunded ${invoiceId}` }] }),
        );
        server.registerTool('export', { description: 'Export everything' }, async () => ({
            content: [{ type: 'text', text: 'exported' }],
        }));
        return server;
    });

    async function serve(request) {
        const discovery = await auth.discovery(request);
        if (discovery) return discovery;
        const authInfo = await auth.gate(request);
        if (authInfo instanceof Response) return authInfo;
        return handler.fetch(request, { authInfo });
    }

    const post = (body, headers = {}) =>
        serve(new Request(RESOURCE, { method: 'POST', headers: { ...HEADERS, ...headers }, body: JSON.stringify(body) }));

    test('discovery and challenge from a fetch handler', async () => {
        const metadata = await serve(new Request(METADATA_URL));
        assert.equal((await metadata.json()).resource, RESOURCE);
        const challenge = await post(initialize);
        assert.equal(challenge.status, 401);
        assert.match(challenge.headers.get('www-authenticate'), /resource_metadata=/);
    });

    test('2025-era client: initialize and tools with the caller', async () => {
        const authorization = `Bearer ${makeToken({ sub: 'user-9', act: { sub: 'agent_agt_1' } })}`;
        const init = await post(initialize, { authorization });
        assert.equal(init.status, 200);
        const caller = JSON.parse(textOf(await rpcBody(await post(callTool('whoami'), { authorization }))));
        assert.equal(caller.sub, 'user-9');
        assert.equal(caller.actor, 'agent_agt_1');
    });

    test('scopeChallenge steps up with the resource metadata URL', async () => {
        const response = await post(callTool('refund', { invoiceId: 'inv_2' }), { authorization: `Bearer ${makeToken()}` });
        assert.equal(response.status, 403);
        const challenge = response.headers.get('www-authenticate');
        assert.match(challenge, /insufficient_scope/);
        assert.match(challenge, /scope="invoices:refund"/);
        assert.match(challenge, new RegExp(`resource_metadata="${METADATA_URL}"`));
        const allowed = await post(callTool('refund', { invoiceId: 'inv_2' }), { authorization: `Bearer ${makeToken({ scope: 'invoices:*' })}` });
        assert.equal(textOf(await rpcBody(allowed)), 'refunded inv_2');
    });

    test('secureTools filters tools/list on SDK v2 McpServer', async () => {
        const response = await post(listTools, { authorization: `Bearer ${makeToken()}` });
        assert.equal(response.status, 200);
        assert.deepEqual(toolNames(await rpcBody(response)), ['refund', 'whoami']);
    });
});
