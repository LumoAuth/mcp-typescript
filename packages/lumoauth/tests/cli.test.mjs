// The real `lumoauth` binary against a fake LumoAuth served over HTTP.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { after, before, describe, test } from 'node:test';
import { JWKS } from '../../mcp/tests/helpers.mjs';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const FIXTURE = fileURLToPath(new URL('./fixtures/stdio-server.mjs', import.meta.url));
const SERVER_ID = 'mcp_0123456789abcdef01234567';
const run = promisify(execFile);

describe('lumoauth binary', () => {
    let lumo;
    let issuer;
    const resource = 'http://127.0.0.1:18765/mcp';

    before(async () => {
        lumo = createServer((req, res) => {
            const documents = {
                [`/orgs/acme/api/v1/.well-known/oauth-protected-resource/mcp/${SERVER_ID}`]: {
                    resource,
                    authorization_servers: ['ignored'],
                    scopes_supported: ['mcp:read'],
                },
                '/orgs/acme/api/v1/.well-known/openid-configuration': {
                    issuer,
                    jwks_uri: `${issuer}/.well-known/jwks.json`,
                    code_challenge_methods_supported: ['S256'],
                    client_id_metadata_document_supported: true,
                },
                '/orgs/acme/api/v1/.well-known/jwks.json': JWKS,
            };
            const document = documents[req.url];
            res.statusCode = document ? 200 : 404;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(document ?? { error: 'not_found' }));
        });
        await new Promise((resolve) => lumo.listen(0, '127.0.0.1', resolve));
        issuer = `http://127.0.0.1:${lumo.address().port}/orgs/acme/api/v1`;
    });
    after(() => lumo.close());

    test('check prints the registration, the discovery document and the challenge', async () => {
        const { stdout } = await run(process.execPath, [CLI, 'check', '--issuer', issuer, '--server', SERVER_ID]);
        assert.match(stdout, new RegExp(`resource\\s+${resource}`));
        assert.match(stdout, /"authorization_servers": \[\s+"http:\/\/127\.0\.0\.1:\d+\/orgs\/acme\/api\/v1"/);
        assert.match(stdout, /WWW-Authenticate: Bearer scope="mcp:read", resource_metadata="http:\/\/127\.0\.0\.1:18765\/\.well-known\/oauth-protected-resource\/mcp"/);
        assert.match(stdout, /PKCE S256\s+yes/);
    });

    test('a wrong server id is reported plainly', async () => {
        await assert.rejects(run(process.execPath, [CLI, 'check', '--issuer', issuer, '--server', 'mcp_nope']), (error) => {
            assert.match(error.stderr, /no active MCP server 'mcp_nope'/);
            return true;
        });
    });

    test('secure --stdio serves the discovery document and challenges', async () => {
        const child = spawn(
            process.execPath,
            [CLI, 'secure', '--issuer', issuer, '--server', SERVER_ID, '--port', '18765', '--host', '127.0.0.1', '--stdio', '--', process.execPath, FIXTURE],
            { stdio: ['ignore', 'ignore', 'pipe'] },
        );
        try {
            let stderr = '';
            await new Promise((resolve, reject) => {
                child.stderr.on('data', (chunk) => {
                    stderr += chunk;
                    if (stderr.includes('tool policy')) resolve();
                });
                child.once('exit', (code) => reject(new Error(`exited ${code}: ${stderr}`)));
            });
            assert.match(stderr, /is protected by LumoAuth/);
            const metadata = await (await fetch('http://127.0.0.1:18765/.well-known/oauth-protected-resource/mcp')).json();
            assert.equal(metadata.resource, resource);
            const response = await fetch('http://127.0.0.1:18765/mcp', { method: 'POST', body: '{}' });
            assert.equal(response.status, 401);
        } finally {
            child.kill('SIGTERM');
        }
    });

    test('usage errors', async () => {
        await assert.rejects(run(process.execPath, [CLI, 'secure', '--issuer', issuer, '--server', SERVER_ID]), /say which server to protect/);
        await assert.rejects(run(process.execPath, [CLI, 'frobnicate']), /unknown command/);
    });
});
