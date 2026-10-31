import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DpopProofSigner } from '@lumoauth/agent';
import {
    LumoAuthChallenge,
    capabilityCovered,
    lumoAuth,
    normalizeResource,
    protectedResourceMetadataUrl,
    scopeCovered,
} from '../dist/index.mjs';
import { ISSUER, METADATA_URL, RESOURCE, SERVER_ID, fakeLumoAuth, makeToken, registrationDocument } from './helpers.mjs';

const env = {};

function makeAuth(options = {}) {
    const { fetch } = fakeLumoAuth(options.fake);
    return lumoAuth({ issuer: ISSUER, serverId: SERVER_ID, fetch, env, ...options.auth });
}

function request(headers = {}, url = '/mcp') {
    return { method: 'POST', url, headers };
}

async function refusal(promise) {
    try {
        await promise;
    } catch (error) {
        assert.ok(error instanceof LumoAuthChallenge, `expected a challenge, got ${error}`);
        return error;
    }
    assert.fail('expected the request to be refused');
}

// ── Configuration and discovery ─────────────────────────────────────

test('registration drives the resource, scopes and DPoP switch', async () => {
    const config = await makeAuth().ready();
    assert.equal(config.resource, RESOURCE);
    assert.deepEqual(config.scopesSupported, ['mcp:read']);
    assert.equal(config.requireDpop, false);
    assert.equal(config.resourceMetadataUrl, METADATA_URL);
});

test('environment configuration', async () => {
    const { fetch } = fakeLumoAuth();
    const auth = lumoAuth({ fetch, env: { LUMOAUTH_ORG_ID: 'acme', LUMOAUTH_MCP_SERVER_ID: SERVER_ID } });
    assert.equal(auth.issuer, ISSUER);
    assert.equal((await auth.ready()).resource, RESOURCE);
});

test('configuration errors are actionable', async () => {
    assert.throws(() => lumoAuth({ env, resource: RESOURCE }), /LUMOAUTH_ORG_ID/);
    assert.throws(() => lumoAuth({ env, issuer: ISSUER }), /Resource URI/);
    await assert.rejects(makeAuth({ auth: { resource: 'https://elsewhere.example.com/mcp' } }).ready(), /registered/);
});

test('protected resource metadata names the issuer', async () => {
    const response = await makeAuth().discoveryResponse('GET', '/.well-known/oauth-protected-resource/mcp');
    assert.equal(response.status, 200);
    assert.equal(response.headers['Access-Control-Allow-Origin'], '*');
    assert.deepEqual(JSON.parse(response.body), {
        resource: RESOURCE,
        authorization_servers: [ISSUER],
        bearer_methods_supported: ['header'],
        scopes_supported: ['mcp:read'],
    });
});

test('metadata announces DPoP when the registration requires it', async () => {
    const auth = makeAuth({ fake: { registration: registrationDocument({ requireDpop: true }) } });
    const document = JSON.parse((await auth.discoveryResponse('GET', '/.well-known/oauth-protected-resource/mcp')).body);
    assert.equal(document.dpop_bound_access_tokens_required, true);
    assert.deepEqual(document.dpop_signing_alg_values_supported, ['ES256', 'RS256']);
});

test('authorization server metadata is mirrored, other paths fall through', async () => {
    const auth = makeAuth();
    const response = await auth.discoveryResponse('GET', '/.well-known/oauth-authorization-server');
    assert.equal(JSON.parse(response.body).issuer, ISSUER);
    assert.equal((await auth.discoveryResponse('OPTIONS', '/.well-known/oauth-authorization-server')).status, 204);
    assert.equal(await auth.discoveryResponse('GET', '/mcp'), undefined);
});

// ── Challenges and Bearer tokens ────────────────────────────────────

test('missing token: challenge without error', async () => {
    const challenge = await refusal(makeAuth().authenticate(request()));
    assert.equal(challenge.status, 401);
    assert.equal(challenge.wwwAuthenticate, `Bearer scope="mcp:read", resource_metadata="${METADATA_URL}"`);
});

test('DPoP server challenges with the DPoP scheme and algs', async () => {
    const auth = makeAuth({ fake: { registration: registrationDocument({ requireDpop: true }) } });
    const challenge = await refusal(auth.authenticate(request()));
    assert.equal(challenge.wwwAuthenticate, `DPoP scope="mcp:read", resource_metadata="${METADATA_URL}", algs="ES256 RS256"`);
});

test('a valid token gives the caller', async () => {
    const token = makeToken({ sub: 'user-123', act: { sub: 'agent_agt_42', act: { sub: 'agent_agt_7' } } });
    const info = await makeAuth().authenticate(request({ authorization: `Bearer ${token}` }));
    assert.equal(info.token, token);
    assert.equal(info.resource.href, RESOURCE);
    assert.equal(info.resourceMetadataUrl, METADATA_URL);
    const caller = info.extra.caller;
    assert.equal(caller.sub, 'user-123');
    assert.equal(caller.isDelegated, true);
    assert.equal(caller.actor, 'agent_agt_42');
    assert.deepEqual(caller.actChain.map((a) => a.sub), ['agent_agt_42', 'agent_agt_7']);
});

test('agent tokens', async () => {
    const token = makeToken({ sub: 'agent_agt_42', is_agent: true, client_id: 'agt_42', capabilities: ['billing.*'] });
    const { caller } = (await makeAuth().authenticate(request({ authorization: `Bearer ${token}` }))).extra;
    assert.equal(caller.isAgent, true);
    assert.equal(caller.agentId, 'agt_42');
    assert.deepEqual(caller.capabilities, ['billing.*']);
});

for (const [name, claims, reason] of [
    ['wrong audience', { aud: 'https://other.example.com/mcp' }, /audience/i],
    ['wrong issuer', { iss: 'https://app.lumoauth.dev/orgs/other/api/v1' }, /issuer/i],
    ['expired', { exp: Math.floor(Date.now() / 1000) - 3600 }, /expired/i],
    ['portal test token', { token_use: 'test' }, /test tokens/i],
]) {
    test(`refused: ${name}`, async () => {
        const challenge = await refusal(makeAuth().authenticate(request({ authorization: `Bearer ${makeToken(claims)}` })));
        assert.equal(challenge.status, 401);
        assert.match(challenge.wwwAuthenticate, /^Bearer error="invalid_token", error_description="/);
        assert.match(challenge.wwwAuthenticate, reason);
        assert.match(challenge.wwwAuthenticate, new RegExp(`resource_metadata="${METADATA_URL}"`));
    });
}

test('an opaque token gets an explanation', async () => {
    const challenge = await refusal(makeAuth().authenticate(request({ authorization: 'Bearer 0123abcd' })));
    assert.match(challenge.wwwAuthenticate, /not a JWT/);
});

test('audiences compare the way LumoAuth compares resources', async () => {
    const token = makeToken({ aud: 'HTTPS://MCP.example.com:443/mcp/' });
    await makeAuth().authenticate(request({ authorization: `Bearer ${token}` }));
});

test('required scopes honour wildcards and step up otherwise', async () => {
    const auth = makeAuth({ auth: { requiredScopes: ['mcp:tools:call'] } });
    const info = await auth.authenticate(request({ authorization: `Bearer ${makeToken({ scope: 'mcp:tools:*' })}` }));
    assert.ok(info.scopes.includes('mcp:tools:call'));
    const challenge = await refusal(auth.authenticate(request({ authorization: `Bearer ${makeToken()}` })));
    assert.equal(challenge.status, 403);
    assert.match(challenge.wwwAuthenticate, /error="insufficient_scope"/);
    assert.match(challenge.wwwAuthenticate, /scope="mcp:tools:call"/);
});

// ── DPoP ────────────────────────────────────────────────────────────

function dpopRequest(signer, token, { url = RESOURCE, scheme = 'DPoP' } = {}) {
    return request({
        authorization: `${scheme} ${token}`,
        dpop: signer.createProof({ method: 'POST', url, accessToken: token }),
    });
}

test('DPoP-bound token with a valid proof', async () => {
    const auth = makeAuth({ fake: { registration: registrationDocument({ requireDpop: true }) } });
    const signer = DpopProofSigner.generate();
    const token = makeToken({ cnf: { jkt: signer.thumbprint } });
    const info = await auth.authenticate(dpopRequest(signer, token));
    assert.equal(info.extra.caller.dpopJkt, signer.thumbprint);
});

test('replayed proof is refused with invalid_dpop_proof', async () => {
    const auth = makeAuth({ fake: { registration: registrationDocument({ requireDpop: true }) } });
    const signer = DpopProofSigner.generate();
    const token = makeToken({ cnf: { jkt: signer.thumbprint } });
    const replayed = dpopRequest(signer, token);
    await auth.authenticate(replayed);
    const challenge = await refusal(auth.authenticate(replayed));
    assert.match(challenge.wwwAuthenticate, /^DPoP error="invalid_dpop_proof"/);
});

test('proof for another URL, bound token as Bearer, unbound token on a DPoP server', async () => {
    const auth = makeAuth({ fake: { registration: registrationDocument({ requireDpop: true }) } });
    const signer = DpopProofSigner.generate();
    const token = makeToken({ cnf: { jkt: signer.thumbprint } });
    await refusal(auth.authenticate(dpopRequest(signer, token, { url: 'https://mcp.example.com/other' })));
    const asBearer = await refusal(auth.authenticate(dpopRequest(signer, token, { scheme: 'Bearer' })));
    assert.match(asBearer.wwwAuthenticate, /^DPoP /);
    const unbound = await refusal(auth.authenticate(request({ authorization: `Bearer ${makeToken()}` })));
    assert.match(unbound.wwwAuthenticate, /^DPoP error="invalid_token"/);
});

test('bound tokens also work where DPoP is optional; the htu uses the public origin', async () => {
    const signer = DpopProofSigner.generate();
    const token = makeToken({ cnf: { jkt: signer.thumbprint } });
    // The app sees a path; the client signed the public URL.
    await makeAuth().authenticate(dpopRequest(signer, token));
});

// ── Helpers ─────────────────────────────────────────────────────────

test('scope, capability and resource helpers', () => {
    assert.equal(scopeCovered('files:read:own', ['files:*']), true);
    assert.equal(scopeCovered('files', ['files:*']), false);
    // Only ':*' is a wildcard, as in LumoAuth; everything else is exact.
    assert.equal(scopeCovered('invoices.refund', ['invoices.*']), false);
    assert.equal(scopeCovered('invoices.*', ['invoices.*']), true);
    assert.equal(scopeCovered('files:read', [':*']), false);
    assert.equal(capabilityCovered('users:delete', ['Users-*']), true);
    assert.equal(capabilityCovered('users', ['users.*']), false);
    assert.equal(normalizeResource('HTTPS://MCP.Example.com:443/mcp/'), 'https://mcp.example.com/mcp');
    assert.equal(protectedResourceMetadataUrl('https://x.example.com'), 'https://x.example.com/.well-known/oauth-protected-resource');
});
