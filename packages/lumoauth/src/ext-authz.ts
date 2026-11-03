import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import {
    LumoAuthChallenge,
    missingAuthorizationDetails,
    normalizeAuthorizationDetails,
    parseTraceparent,
    writeChallenge,
    type AuthorizationDetail,
    type LumoAuthInfo,
    type LumoMcpAuth,
} from '@lumoauth/mcp';
import { inspect, refusedJitToolResult, refusedToolResult } from './jsonrpc';

/**
 * Envoy HTTP `ext_authz` server (`envoy.filters.http.ext_authz`).
 *
 * Deployed as a Kubernetes sidecar or shared cluster service, Envoy forwards
 * incoming MCP requests (and optionally buffered JSON-RPC request bodies via
 * `with_request_body`) to this server:
 *
 * - Returns `401` / `403` with RFC 9728 `WWW-Authenticate` challenges when
 *   the Bearer or DPoP token is missing or invalid.
 * - Evaluates per-tool Zanzibar policies (`toolPolicy`) and RFC 9396 JIT
 *   `authorization_details` (`jit`) when a JSON-RPC `tools/call` body is present.
 * - Returns `200 OK` with verified `X-LumoAuth-*` identity headers (and
 *   optional `X-LumoAuth-Vault-<Slug>-Token` headers) for Envoy to inject
 *   into the upstream MCP server request.
 */

export interface ExtAuthzOptions {
    auth: LumoMcpAuth;
    /** Ask LumoAuth's per-tool policy on `tools/call` bodies. */
    toolPolicy?: boolean;
    /** Emit `X-LumoAuth-*` headers on `200 OK` responses (default `true`). */
    identityHeaders?: boolean;
    /** Paths allowed without authentication (e.g. `/healthz`, `/readyz`). */
    publicPaths?: string[];
    /** Per-tool JIT / RAR `authorization_details` requirements. */
    jit?: Record<string, string | AuthorizationDetail | AuthorizationDetail[]>;
    /** Token Vault connections (`{ slug: connectionId }`) injected as `X-LumoAuth-Vault-<Slug>-Token`. */
    vaultConnections?: Record<string, string>;
    /** Maximum buffered body size in bytes (default 1 MiB). */
    maxBodyBytes?: number;
    log?: (line: string) => void;
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
    const value = req.headers[name];
    return Array.isArray(value) ? value[0] : value;
}

async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
        size += (chunk as Buffer).length;
        if (size > limit) break;
        chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks);
}

function writeJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
    const text = JSON.stringify(body);
    res.statusCode = status;
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Length', Buffer.byteLength(text));
    res.end(text);
}

export function createExtAuthzServer(options: ExtAuthzOptions): Server {
    const { auth } = options;
    const log = options.log ?? ((line: string) => console.error(line));
    const identityHeaders = options.identityHeaders ?? true;
    const publicPaths = options.publicPaths ?? ['/healthz', '/readyz'];
    const maxBody = options.maxBodyBytes ?? 1024 * 1024;

    async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
        const method = headerOf(req, 'x-envoy-original-method') ?? req.method ?? 'GET';
        const rawPath =
            headerOf(req, 'x-envoy-original-path') ??
            headerOf(req, 'x-forwarded-uri') ??
            req.url ??
            '/';
        const url = new URL(rawPath, 'http://ext-authz.invalid');

        // Health checks for the ext_authz container itself or public upstream paths
        if (publicPaths.includes(url.pathname)) {
            res.statusCode = 200;
            res.end();
            return;
        }

        // OAuth discovery documents: returning 200 OK with the metadata JSON body
        // both allows the request through Envoy ext_authz AND serves the document
        // directly when Envoy routes /.well-known/* to this cluster.
        const discovery = await auth.discoveryResponse(method, url.pathname);
        if (discovery) {
            res.statusCode = discovery.status;
            for (const [k, v] of Object.entries(discovery.headers)) res.setHeader(k, v);
            res.end(discovery.body);
            return;
        }

        let info: LumoAuthInfo;
        try {
            info = await auth.authenticate({ method, url: rawPath, headers: req.headers });
        } catch (error) {
            if (error instanceof LumoAuthChallenge) {
                writeChallenge(res, error);
                return;
            }
            throw error;
        }
        const caller = info.extra.caller;

        const body = method === 'POST' ? await readBody(req, maxBody) : undefined;
        if (body && body.length > 0 && (options.toolPolicy || options.jit)) {
            const inspection = inspect(body.toString('utf8'));
            if (!caller.traceparent && inspection.traceparent) {
                const parsedTp = parseTraceparent(inspection.traceparent);
                if (parsedTp) {
                    caller.traceparent = parsedTp.traceparent;
                    caller.traceId ??= parsedTp.traceId;
                }
            }
            if (options.toolPolicy) {
                for (const call of inspection.toolCalls) {
                    if (!(await auth.toolPolicy().isAllowed(caller, call.name))) {
                        log(`lumoauth ext-authz: refused tool '${call.name}' for ${caller.sub}`);
                        writeJson(
                            res,
                            403,
                            refusedToolResult(call.id, `LumoAuth policy does not allow this caller to run '${call.name}'.`),
                            { 'X-LumoAuth-Denied-Tool': call.name },
                        );
                        return;
                    }
                }
            }
            if (options.jit) {
                for (const call of inspection.toolCalls) {
                    const jitSpec = options.jit[call.name];
                    if (!jitSpec) continue;
                    const required = normalizeAuthorizationDetails(jitSpec);
                    const missing = missingAuthorizationDetails(required, caller.authorizationDetails);
                    if (missing.length > 0) {
                        const jitRefusal = refusedJitToolResult(call.id, call.name, missing);
                        writeJson(res, 403, jitRefusal.body, {
                            'Insufficient-Authorization-Details': jitRefusal.headerValue,
                            'WWW-Authenticate': `Bearer error="insufficient_authorization_details", error_description="JIT step-up required for tool '${call.name}'"`,
                        });
                        return;
                    }
                }
            }
        }

        res.statusCode = 200;
        if (identityHeaders) {
            res.setHeader('x-lumoauth-subject', caller.sub);
            res.setHeader('x-lumoauth-subject-type', caller.isAgent ? 'agent' : 'user');
            if (caller.agentId) res.setHeader('x-lumoauth-agent-id', caller.agentId);
            if (caller.actor) res.setHeader('x-lumoauth-actor', caller.actor);
            if (caller.clientId) res.setHeader('x-lumoauth-client-id', caller.clientId);
            res.setHeader('x-lumoauth-scopes', caller.scopes.join(' '));
            if (caller.traceId) res.setHeader('x-lumoauth-trace-id', caller.traceId);
            if (caller.isJit) res.setHeader('x-lumoauth-is-jit', 'true');
        }
        if (caller.traceparent) {
            res.setHeader('traceparent', caller.traceparent);
        }
        if (options.vaultConnections) {
            for (const [slug, connectionId] of Object.entries(options.vaultConnections)) {
                const cleanSlug = slug.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
                if (!cleanSlug || !connectionId) continue;
                const vaultToken = await auth.vaultToken(connectionId, caller);
                res.setHeader(`x-lumoauth-vault-${cleanSlug}-token`, vaultToken.accessToken);
            }
        }
        res.end();
    }

    return createServer((req, res) => {
        handle(req, res).catch((error: unknown) => {
            log(`lumoauth ext-authz: ${(error as Error).stack ?? error}`);
            if (!res.headersSent) writeJson(res, 500, { error: 'server_error' });
            else res.destroy();
        });
    });
}
