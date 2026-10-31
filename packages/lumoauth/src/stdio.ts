import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
    LATEST_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    isInitializeRequest,
    type JSONRPCMessage,
} from '@modelcontextprotocol/sdk/types.js';
import type { LumoAuthInfo, LumoCaller } from '@lumoauth/mcp';

/**
 * Serves a stdio MCP server over Streamable HTTP: one child process per MCP
 * session, so callers never share a process, and each session belongs to
 * the caller that opened it.
 *
 * The HTTP side is the MCP SDK's own transport. A client that asks for a
 * protocol revision the transport does not serve gets the latest one it
 * does, through normal version negotiation.
 */

export interface StdioBridgeOptions {
    command: string[];
    /** Filters `tools/list` answers (the per-tool policy); returns the allowed names. */
    filterTools?: (caller: LumoCaller, names: string[]) => Promise<Set<string>>;
    log?: (line: string) => void;
}

interface Session {
    http: StreamableHTTPServerTransport;
    child: StdioClientTransport;
    owner: string;
    /** `tools/list` requests in flight: JSON-encoded id → caller. */
    listRequests: Map<string, LumoCaller>;
    /** Progress tokens in flight → the request they report on. */
    progress: Map<string | number, string | number>;
}

type MessageRecord = Record<string, unknown> & { id?: string | number; method?: string; params?: Record<string, unknown> };

function principal(caller: LumoCaller): string {
    return JSON.stringify([caller.issuer, caller.sub, caller.clientId ?? null]);
}

function jsonRpcError(res: ServerResponse, status: number, message: string): void {
    const body = JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32000, message } });
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(body);
}

export class StdioBridge {
    private readonly sessions = new Map<string, Session>();
    private readonly log: (line: string) => void;

    constructor(private readonly options: StdioBridgeOptions) {
        this.log = options.log ?? ((line) => console.error(line));
    }

    async handle(req: IncomingMessage, res: ServerResponse, info: LumoAuthInfo, body: unknown): Promise<void> {
        const caller = info.extra.caller;
        const request = req as IncomingMessage & { auth?: LumoAuthInfo };
        request.auth = info;
        const sessionId = req.headers['mcp-session-id'];
        if (typeof sessionId === 'string') {
            const session = this.sessions.get(sessionId);
            if (!session || session.owner !== principal(caller)) {
                jsonRpcError(res, 404, 'Session not found');
                return;
            }
            await session.http.handleRequest(request, res, body);
            return;
        }
        if (req.method !== 'POST' || !isInitializeRequest(body)) {
            jsonRpcError(res, 400, 'Bad Request: start a session with an initialize request');
            return;
        }
        const params = (body as { params: { protocolVersion: string } }).params;
        if (!SUPPORTED_PROTOCOL_VERSIONS.includes(params.protocolVersion)) {
            params.protocolVersion = LATEST_PROTOCOL_VERSION;
        }
        const session = await this.open(principal(caller));
        await session.http.handleRequest(request, res, body);
    }

    private async open(owner: string): Promise<Session> {
        const [command, ...args] = this.options.command;
        const env: Record<string, string> = { ...getDefaultEnvironment() };
        for (const [name, value] of Object.entries(process.env)) if (value !== undefined) env[name] = value;
        const child = new StdioClientTransport({ command, args, env, stderr: 'inherit' });
        let session: Session | undefined;
        const http = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (id) => {
                if (session) this.sessions.set(id, session);
            },
            onsessionclosed: (id) => {
                this.sessions.delete(id);
                void child.close();
            },
        });
        session = { http, child, owner, listRequests: new Map(), progress: new Map() };
        const current = session;

        http.onmessage = (message, extra) => {
            const record = message as MessageRecord;
            const caller = (extra?.authInfo as LumoAuthInfo | undefined)?.extra?.caller;
            if (record.method === 'tools/list' && record.id !== undefined && caller && this.options.filterTools) {
                current.listRequests.set(JSON.stringify(record.id), caller);
            }
            const meta = record.params?._meta as { progressToken?: string | number } | undefined;
            if (meta?.progressToken !== undefined && record.id !== undefined) current.progress.set(meta.progressToken, record.id);
            child.send(message).catch((error: unknown) => this.log(`lumoauth: cannot reach the stdio server: ${(error as Error).message}`));
        };
        child.onmessage = (message) => {
            void this.relay(current, message);
        };
        http.onclose = () => {
            void child.close();
        };
        child.onclose = () => {
            void http.close();
        };
        child.onerror = (error) => this.log(`lumoauth: stdio server error: ${error.message}`);
        await child.start();
        await http.start();
        return current;
    }

    private async relay(session: Session, message: JSONRPCMessage): Promise<void> {
        const record = message as MessageRecord;
        let outgoing: JSONRPCMessage = message;
        if (record.id !== undefined && !('method' in record)) {
            // A response: filter tools/list answers, forget its progress token.
            const key = JSON.stringify(record.id);
            const caller = session.listRequests.get(key);
            const result = record.result as { tools?: Array<{ name?: unknown }> } | undefined;
            if (caller && this.options.filterTools && Array.isArray(result?.tools)) {
                session.listRequests.delete(key);
                const names = result.tools.map((tool) => (typeof tool.name === 'string' ? tool.name : ''));
                const allowed = await this.options.filterTools(caller, names);
                outgoing = {
                    ...record,
                    result: { ...result, tools: result.tools.filter((t) => typeof t.name === 'string' && allowed.has(t.name)) },
                } as unknown as JSONRPCMessage;
            }
            for (const [token, requestId] of session.progress) if (requestId === record.id) session.progress.delete(token);
        }
        let relatedRequestId: string | number | undefined;
        if (record.method === 'notifications/progress') {
            const token = (record.params as { progressToken?: string | number } | undefined)?.progressToken;
            if (token !== undefined) relatedRequestId = session.progress.get(token);
        }
        await session.http
            .send(outgoing, relatedRequestId !== undefined ? { relatedRequestId } : undefined)
            .catch((error: unknown) => this.log(`lumoauth: cannot deliver a message to the client: ${(error as Error).message}`));
    }

    async close(): Promise<void> {
        await Promise.all([...this.sessions.values()].map((s) => s.http.close()));
        this.sessions.clear();
    }
}
