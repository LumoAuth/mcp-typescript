import { parseArgs } from 'node:util';
import { lumoAuth, type LumoMcpAuth } from '@lumoauth/mcp';
import { allowedToolNames, createSecureProxy } from './proxy';
import { StdioBridge } from './stdio';
import { startUpstream, waitForUpstream } from './supervise';

const VERSION = '0.1.0';

const HELP = `lumoauth: put LumoAuth in front of an MCP server

Usage:
  npx lumoauth secure --upstream <url> [options] [-- <command that starts it>]
  npx lumoauth secure --stdio [options] -- <stdio server command>
  npx lumoauth check [options]

Commands:
  secure   Serve the MCP server over HTTP behind LumoAuth: OAuth discovery,
           token checks (Bearer and DPoP) and LumoAuth's per-tool policy.
           The server's own code does not change.
  check    Show what LumoAuth's registration says, the discovery document
           and the 401 challenge, then exit.

Options:
  --org <slug>           Organization (LUMOAUTH_ORG_ID)
  --server <id>          Registered MCP server id, mcp_... (LUMOAUTH_MCP_SERVER_ID)
  --resource <uri>       Resource URI, when there is no server id (LUMOAUTH_MCP_RESOURCE)
  --lumoauth-url <url>   LumoAuth instance (LUMOAUTH_URL, default https://app.lumoauth.dev)
  --issuer <url>         Organization issuer, for a custom domain (LUMOAUTH_ISSUER)
  --upstream <url>       The MCP endpoint to protect, e.g. http://127.0.0.1:8000/mcp
  --stdio                The command after -- is a stdio MCP server
  --port <n>             Port to listen on (PORT, default 8080)
  --host <address>       Address to listen on (default 0.0.0.0)
  --path <path>          Public path of the MCP endpoint (default: the Resource URI's path, or /mcp)
  --scope <scope>        A scope every request needs; repeat for more
  --public <path>        Forward this path without a token (health checks); repeatable
  --tool-policy          Require LumoAuth's per-tool policy (LUMOAUTH_MCP_CLIENT_ID and _SECRET)
  --no-tool-policy       Do not ask LumoAuth about tools
  --no-identity-headers  Do not send X-LumoAuth-* identity headers upstream
  -h, --help             Show this help
  -v, --version          Show the version
`;

const LUMOAUTH_OPTIONS = {
    org: { type: 'string' },
    server: { type: 'string' },
    resource: { type: 'string' },
    'lumoauth-url': { type: 'string' },
    issuer: { type: 'string' },
    scope: { type: 'string', multiple: true },
} as const;

type LumoAuthValues = {
    org?: string;
    server?: string;
    resource?: string;
    'lumoauth-url'?: string;
    issuer?: string;
    scope?: string[];
};

class UsageError extends Error {}

function makeAuth(values: LumoAuthValues): LumoMcpAuth {
    return lumoAuth({
        orgId: values.org,
        serverId: values.server,
        resource: values.resource,
        lumoauthUrl: values['lumoauth-url'],
        issuer: values.issuer,
        requiredScopes: values.scope,
    });
}

const log = (line: string) => console.error(line);

async function secure(args: string[], command: string[]): Promise<void> {
    const { values } = parseArgs({
        args,
        strict: true,
        options: {
            ...LUMOAUTH_OPTIONS,
            upstream: { type: 'string' },
            stdio: { type: 'boolean' },
            port: { type: 'string' },
            host: { type: 'string' },
            path: { type: 'string' },
            public: { type: 'string', multiple: true },
            'tool-policy': { type: 'boolean' },
            'no-tool-policy': { type: 'boolean' },
            'no-identity-headers': { type: 'boolean' },
        },
    });
    if (values.stdio && values.upstream) throw new UsageError('use --upstream or --stdio, not both');
    if (values.stdio && command.length === 0) {
        throw new UsageError('--stdio needs the server command after --, for example: lumoauth secure --stdio -- node server.js');
    }
    if (!values.stdio && !values.upstream) {
        throw new UsageError('say which server to protect: --upstream <url> for an HTTP server, or --stdio -- <command>');
    }
    if (values.upstream && !/^https?:\/\//.test(values.upstream)) {
        throw new UsageError(`--upstream must be an http(s) URL, got '${values.upstream}'`);
    }

    const auth = makeAuth(values);
    const config = await auth.ready();
    let toolPolicy = auth.hasToolPolicy && !values['no-tool-policy'];
    if (values['tool-policy']) {
        if (!auth.hasToolPolicy) {
            throw new UsageError(
                "--tool-policy needs LUMOAUTH_MCP_CLIENT_ID and LUMOAUTH_MCP_CLIENT_SECRET: the MCP server's own " +
                    'OAuth client, with the client_credentials grant and the mcp:authorize scope',
            );
        }
        toolPolicy = true;
    }
    const resourcePath = new URL(config.resource).pathname.replace(/\/+$/, '');
    const path = values.path ?? (resourcePath || '/mcp');
    const port = Number(values.port ?? process.env.PORT ?? 8080);
    const host = values.host ?? '0.0.0.0';
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new UsageError(`--port must be a port number, got '${values.port}'`);

    let child: ReturnType<typeof startUpstream> | undefined;
    if (values.upstream && command.length > 0) {
        child = startUpstream(command);
        child.on('exit', (code, signal) => {
            log(`lumoauth: the upstream command stopped (${signal ?? `exit code ${code}`})`);
            process.exit(code ?? 1);
        });
        await waitForUpstream(values.upstream, child);
    }

    const bridge = values.stdio
        ? new StdioBridge({
              command,
              filterTools: toolPolicy ? (caller, names) => allowedToolNames(auth, caller, names) : undefined,
              log,
          })
        : undefined;
    const server = createSecureProxy({
        auth,
        upstream: values.upstream,
        bridge,
        path,
        toolPolicy,
        identityHeaders: !values['no-identity-headers'],
        publicPaths: values.public ?? [],
        log,
    });
    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, resolve);
    });

    const address = server.address();
    const listening = typeof address === 'object' && address ? `${host}:${address.port}` : `${host}:${port}`;
    log(`lumoauth: ${values.stdio ? `stdio server '${command.join(' ')}'` : values.upstream} is protected by LumoAuth`);
    log(`  listening      http://${listening}${path}`);
    log(`  resource       ${config.resource}${config.requireDpop ? '  (DPoP required)' : ''}`);
    log(`  issuer         ${config.issuer}`);
    log(`  discovery      ${config.resourceMetadataUrl}`);
    log(`  tool policy    ${toolPolicy ? `on (server ${config.serverId})` : 'off'}`);
    if (config.resource.startsWith('https://')) {
        log('  Clients must reach this proxy at the Resource URI, through your TLS proxy or tunnel.');
    }

    const stop = () => {
        log('lumoauth: stopping');
        server.close();
        void bridge?.close();
        child?.removeAllListeners('exit');
        child?.kill('SIGTERM');
        setTimeout(() => process.exit(0), 200).unref();
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
}

async function check(args: string[]): Promise<void> {
    const { values } = parseArgs({ args, strict: true, options: LUMOAUTH_OPTIONS });
    const auth = makeAuth(values);
    const config = await auth.ready();
    const out = (line = '') => console.log(line);
    out('LumoAuth');
    out(`  issuer         ${config.issuer}`);
    out(`  MCP server     ${config.serverId ?? '(none: resource given directly)'}`);
    out(`  resource       ${config.resource}`);
    out(`  scopes         ${config.scopesSupported.join(' ') || '(none advertised)'}`);
    out(`  DPoP           ${config.requireDpop ? 'required' : 'accepted, not required'}`);
    out(`  tool policy    ${auth.hasToolPolicy ? `configured (client ${auth.clientId})` : 'not configured'}`);
    out();
    out(`Discovery document, served at ${config.resourceMetadataUrl}:`);
    out(JSON.stringify(await auth.protectedResourceMetadata(), null, 2));
    out();
    out('401 challenge:');
    out(`  WWW-Authenticate: ${auth.challenge(config, 401, { scope: config.requiredScopes }).wwwAuthenticate}`);
    out();

    const discoveryUrl = `${config.issuer}/.well-known/openid-configuration`;
    try {
        const response = await fetch(discoveryUrl, { headers: { Accept: 'application/json' } });
        const metadata = (await response.json()) as Record<string, unknown>;
        const pkce = Array.isArray(metadata.code_challenge_methods_supported) && metadata.code_challenge_methods_supported.includes('S256');
        out(`Authorization server (${discoveryUrl}):`);
        out(`  issuer matches        ${metadata.issuer === config.issuer ? 'yes' : `NO (${String(metadata.issuer)})`}`);
        out(`  PKCE S256             ${pkce ? 'yes' : 'NO: MCP clients refuse authorization servers without it'}`);
        out(`  client metadata docs  ${metadata.client_id_metadata_document_supported === true ? 'yes' : 'no'}`);
        out(`  dynamic registration  ${typeof metadata.registration_endpoint === 'string' ? 'yes' : 'no'}`);
    } catch (error) {
        out(`Authorization server: cannot read ${discoveryUrl}: ${(error as Error).message}`);
        process.exitCode = 1;
    }
    if (auth.hasToolPolicy) {
        try {
            auth.toolPolicy();
            out('  per-tool policy       client configured; decisions are asked on first use');
        } catch (error) {
            out(`  per-tool policy       ${(error as Error).message}`);
            process.exitCode = 1;
        }
    }
}

export async function main(argv: string[]): Promise<void> {
    const separator = argv.indexOf('--');
    const own = separator >= 0 ? argv.slice(0, separator) : argv;
    const command = separator >= 0 ? argv.slice(separator + 1) : [];
    const [name, ...args] = own;
    switch (name) {
        case 'secure':
            return secure(args, command);
        case 'check':
            return check(args);
        case '-v':
        case '--version':
        case 'version':
            console.log(VERSION);
            return;
        case undefined:
        case '-h':
        case '--help':
        case 'help':
            console.log(HELP);
            return;
        default:
            throw new UsageError(`unknown command '${name}'. Run 'lumoauth --help'.`);
    }
}

/** Run the CLI and turn failures into a message and exit code 1. */
export function run(argv: string[]): void {
    main(argv).catch((error: unknown) => {
        console.error(`lumoauth: ${(error as Error).message}`);
        if (error instanceof UsageError) console.error("Run 'lumoauth --help' for the options.");
        process.exit(1);
    });
}
