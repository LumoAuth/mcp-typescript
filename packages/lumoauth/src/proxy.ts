import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as NodeReadableStream } from 'node:stream/web';
import {
    LumoAuthChallenge,
    writeChallenge,
    type LumoAuthInfo,
    type LumoCaller,
    type LumoMcpAuth,
    type SimpleResponse,
} from '@lumoauth/mcp';
import { filterJsonBody, filterSseEvent, inspect, refusedToolResult, type Inspection } from './jsonrpc';
import type { StdioBridge } from './stdio';

/**
 * An authenticating reverse proxy for an MCP server that has no
 * authentication of its own.
 *
 * Protocol-agnostic on purpose: it reads JSON-RPC only to apply the
 * per-tool policy, and streams everything else, so it works with any MCP
 * revision and any server implementation.
 *
 * - Serves the RFC 9728 discovery document and answers `401` challenges.
 * - Verifies LumoAuth tokens (Bearer and DPoP) before anything reaches the
 *   upstream, and never forwards them: the upstream gets the verified
 *   identity in `X-LumoAuth-*` headers instead (token passthrough is
 *   forbidden by the MCP specification).
 * - Binds each `Mcp-Session-Id` to the caller that opened it.
 * - With the tool policy on, refuses `tools/call` for tools LumoAuth does
 *   not allow and removes them from `tools/list` answers.
 */

export interface ProxyOptions {
    auth: LumoMcpAuth;
    /** Absolute URL of the upstream MCP endpoint, e.g. `http://127.0.0.1:8000/mcp`. */
    upstream?: string;
    /** Serve a stdio MCP server instead of forwarding to an upstream URL. */
    bridge?: StdioBridge;
    /** Public path of the MCP endpoint on this proxy, e.g. `/mcp`. */
    path: string;
    /** Ask LumoAuth's per-tool policy. */
    toolPolicy: boolean;
    /** Send `X-LumoAuth-*` identity headers to the upstream. */
    identityHeaders: boolean;
    /** Paths forwarded without authentication (health checks). */
    publicPaths: string[];
    /** Largest request body to buffer (default 4 MiB). */
    maxBodyBytes?: number;
    log?: (line: string) => void;
}

// Hop-by-hop and length headers are never copied; fetch decodes bodies, so
// content-encoding is dropped from upstream answers too.
const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade'];
const REQUEST_DROP = new Set([...HOP_BY_HOP, 'host', 'content-length', 'authorization', 'dpop', 'accept-encoding']);
const RESPONSE_DROP = new Set([...HOP_BY_HOP, 'content-length', 'content-encoding', 'set-cookie']);
const IDENTITY_PREFIX = 'x-lumoauth-';

class SessionOwners {
    private readonly owners = new Map<string, string>();

    /** `true` when `owner` may use `sessionId`; an unknown session is bound to it. */
    claim(sessionId: string, owner: string): boolean {
        const current = this.owners.get(sessionId);
        if (current === undefined) {
            this.bind(sessionId, owner);
            return true;
        }
        return current === owner;
    }

    bind(sessionId: string, owner: string): void {
        if (this.owners.size >= 50_000) {
            const oldest = this.owners.keys().next().value;
            if (oldest !== undefined) this.owners.delete(oldest);
        }
        this.owners.set(sessionId, owner);
    }

    forget(sessionId: string): void {
        this.owners.delete(sessionId);
    }
}

function principal(caller: LumoCaller): string {
    return JSON.stringify([caller.issuer, caller.sub, caller.clientId ?? null]);
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
    const value = req.headers[name];
    return Array.isArray(value) ? value[0] : value;
}

function writeSimple(res: ServerResponse, response: SimpleResponse): void {
    res.statusCode = response.status;
    for (const [name, value] of Object.entries(response.headers)) res.setHeader(name, value);
    res.end(response.body);
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
    const text = JSON.stringify(body);
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Length', Buffer.byteLength(text));
    res.end(text);
}

class BodyTooLargeError extends Error {}

async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
        size += (chunk as Buffer).length;
        if (size > limit) throw new BodyTooLargeError();
        chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks);
}

async function* sseEvents(body: ReadableStream<Uint8Array>, transform: (event: string) => Promise<string>) {
    const decoder = new TextDecoder();
    let buffer = '';
    for await (const chunk of Readable.fromWeb(body as unknown as NodeReadableStream<Uint8Array>)) {
        buffer += decoder.decode(chunk as Uint8Array, { stream: true });
        let match: RegExpExecArray | null;
        while ((match = /\r?\n\r?\n/.exec(buffer)) !== null) {
            const event = buffer.slice(0, match.index);
            buffer = buffer.slice(match.index + match[0].length);
            yield (await transform(event)) + match[0];
        }
    }
    buffer += decoder.decode();
    if (buffer) yield buffer;
}

/** The tool names, of `names`, that LumoAuth lets `caller` run (8 questions at a time). */
export async function allowedToolNames(auth: LumoMcpAuth, caller: LumoCaller, names: string[]): Promise<Set<string>> {
    const policy = auth.toolPolicy();
    const allowed = new Set<string>();
    for (let i = 0; i < names.length; i += 8) {
        await Promise.all(
            names.slice(i, i + 8).map(async (name) => {
                if (name && (await policy.isAllowed(caller, name))) allowed.add(name);
            }),
        );
    }
    return allowed;
}

export function createSecureProxy(options: ProxyOptions): Server {
    const { auth } = options;
    const log = options.log ?? ((line: string) => console.error(line));
    if (!options.upstream && !options.bridge) throw new Error('createSecureProxy needs an upstream URL or a stdio bridge');
    const upstream = new URL(options.upstream ?? 'http://stdio.invalid/');
    const maxBody = options.maxBodyBytes ?? 4 * 1024 * 1024;
    const sessions = new SessionOwners();

    function targetFor(pathname: string, search: string): string {
        const target = new URL(upstream.href);
        target.pathname = pathname === options.path ? upstream.pathname : pathname;
        target.search = search;
        return target.href;
    }

    async function forward(
        req: IncomingMessage,
        res: ServerResponse,
        url: URL,
        body: Buffer | undefined,
        caller: LumoCaller | undefined,
        inspection: Inspection | undefined,
    ): Promise<void> {
        const headers = new Headers();
        for (const [name, value] of Object.entries(req.headers)) {
            const lower = name.toLowerCase();
            if (value === undefined || REQUEST_DROP.has(lower) || lower.startsWith(IDENTITY_PREFIX)) continue;
            for (const item of Array.isArray(value) ? value : [value]) headers.append(lower, item);
        }
        headers.set('accept-encoding', 'identity');
        if (req.headers.host) headers.set('x-forwarded-host', req.headers.host);
        const remote = req.socket.remoteAddress;
        if (remote) headers.set('x-forwarded-for', [headerOf(req, 'x-forwarded-for'), remote].filter(Boolean).join(', '));
        if (caller && options.identityHeaders) {
            headers.set('x-lumoauth-subject', caller.sub);
            headers.set('x-lumoauth-subject-type', caller.isAgent ? 'agent' : 'user');
            if (caller.agentId) headers.set('x-lumoauth-agent-id', caller.agentId);
            if (caller.actor) headers.set('x-lumoauth-actor', caller.actor);
            if (caller.clientId) headers.set('x-lumoauth-client-id', caller.clientId);
            headers.set('x-lumoauth-scopes', caller.scopes.join(' '));
        }

        const controller = new AbortController();
        res.on('close', () => controller.abort());
        let answer: Response;
        try {
            answer = await fetch(targetFor(url.pathname, url.search), {
                method: req.method,
                headers,
                // undici takes a Buffer; the DOM typings only list ArrayBuffer views.
                body: body && body.length > 0 ? (body as unknown as BodyInit) : undefined,
                redirect: 'manual',
                signal: controller.signal,
            });
        } catch (error) {
            if (controller.signal.aborted) return;
            log(`lumoauth: upstream ${upstream.origin} is not reachable: ${(error as Error).message}`);
            writeJson(res, 502, { error: 'bad_gateway', error_description: 'The MCP server is not reachable' });
            return;
        }

        const sessionId = answer.headers.get('mcp-session-id');
        if (sessionId && caller) {
            if (req.method === 'DELETE' && answer.ok) sessions.forget(sessionId);
            else sessions.bind(sessionId, principal(caller));
        }

        res.statusCode = answer.status;
        answer.headers.forEach((value, name) => {
            if (!RESPONSE_DROP.has(name)) res.setHeader(name, value);
        });
        const cookies = answer.headers.getSetCookie();
        if (cookies.length > 0) res.setHeader('set-cookie', cookies);

        if (!answer.body) {
            res.end();
            return;
        }
        const listIds = inspection?.toolListIds;
        const contentType = answer.headers.get('content-type') ?? '';
        if (caller && listIds && listIds.size > 0) {
            const decide = (names: string[]) => allowedToolNames(auth, caller, names);
            if (contentType.includes('application/json')) {
                const filtered = await filterJsonBody(await answer.text(), listIds, decide);
                res.setHeader('content-length', Buffer.byteLength(filtered));
                res.end(filtered);
                return;
            }
            if (contentType.includes('text/event-stream')) {
                res.flushHeaders();
                await pipeline(Readable.from(sseEvents(answer.body, (event) => filterSseEvent(event, listIds, decide))), res).catch(() => {});
                return;
            }
        }
        if (contentType.includes('text/event-stream')) res.flushHeaders();
        await pipeline(Readable.fromWeb(answer.body as unknown as NodeReadableStream<Uint8Array>), res).catch(() => {});
    }

    async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
        const method = req.method ?? 'GET';
        const url = new URL(req.url ?? '/', 'http://proxy.invalid');

        const discovery = await auth.discoveryResponse(method, url.pathname);
        if (discovery) {
            writeSimple(res, discovery);
            return;
        }
        if (options.bridge && url.pathname !== options.path) {
            writeJson(res, 404, { error: 'not_found' });
            return;
        }
        if (!options.bridge && options.publicPaths.includes(url.pathname)) {
            await forward(req, res, url, await readBody(req, maxBody), undefined, undefined);
            return;
        }

        let info: LumoAuthInfo;
        try {
            info = await auth.authenticate({ method, url: req.url ?? '/', headers: req.headers });
        } catch (error) {
            if (error instanceof LumoAuthChallenge) {
                writeChallenge(res, error);
                return;
            }
            throw error;
        }
        const caller = info.extra.caller;

        // The stdio bridge binds its own sessions to their callers.
        const sessionId = headerOf(req, 'mcp-session-id');
        if (!options.bridge && sessionId && !sessions.claim(sessionId, principal(caller))) {
            writeJson(res, 404, { jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Session not found' } });
            return;
        }

        const body = method === 'POST' ? await readBody(req, maxBody) : undefined;
        let inspection: Inspection | undefined;
        if (body && options.toolPolicy) {
            inspection = inspect(body.toString('utf8'));
            const refused: Inspection['toolCalls'] = [];
            for (const call of inspection.toolCalls) {
                if (!(await auth.toolPolicy().isAllowed(caller, call.name))) refused.push(call);
            }
            if (refused.length > 0) {
                const reason = (name: string) => `LumoAuth policy does not allow this caller to run '${name}'.`;
                log(`lumoauth: refused ${refused.map((c) => c.name).join(', ')} for ${caller.sub}`);
                if (inspection.isBatch) {
                    // Batches (MCP 2025-03-26 only) are refused whole.
                    writeJson(res, 200, inspection.toolCalls.map((c) => refusedToolResult(c.id, reason(refused[0].name))));
                } else {
                    writeJson(res, 200, refusedToolResult(refused[0].id, reason(refused[0].name)));
                }
                return;
            }
        }
        if (options.bridge) {
            let parsed: unknown;
            if (body && body.length > 0) {
                try {
                    parsed = JSON.parse(body.toString('utf8'));
                } catch {
                    writeJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
                    return;
                }
            }
            await options.bridge.handle(req, res, info, parsed);
            return;
        }
        await forward(req, res, url, body, caller, inspection);
    }

    return createServer((req, res) => {
        handle(req, res).catch((error: unknown) => {
            if (error instanceof BodyTooLargeError) {
                writeJson(res, 413, { error: 'request_too_large' });
                return;
            }
            log(`lumoauth: ${(error as Error).stack ?? error}`);
            if (!res.headersSent) writeJson(res, 500, { error: 'server_error' });
            else res.destroy();
        });
    });
}
