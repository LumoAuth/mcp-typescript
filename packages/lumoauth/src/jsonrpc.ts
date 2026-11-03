/**
 * Just enough JSON-RPC to enforce per-tool policy in front of a server
 * whose code we do not touch: find `tools/call` and `tools/list` requests
 * in a POST body, answer a refused call, and filter `tools/list` results in
 * JSON and Server-Sent Events responses.
 */

import type { AuthorizationDetail } from '@lumoauth/mcp';

export type JsonRpcId = string | number | null;

export interface Inspection {
    /** `tools/call` requests: id and tool name. */
    toolCalls: Array<{ id: JsonRpcId; name: string }>;
    /** Ids (JSON-encoded) of `tools/list` requests, whose results get filtered. */
    toolListIds: Set<string>;
    /** W3C `traceparent` found in `params._meta.traceparent`, if any. */
    traceparent?: string;
    isBatch: boolean;
}

interface JsonRpcRequestLike {
    jsonrpc?: unknown;
    id?: unknown;
    method?: unknown;
    params?: { name?: unknown; _meta?: { traceparent?: unknown } } | unknown;
}

function asId(value: unknown): JsonRpcId {
    return typeof value === 'string' || typeof value === 'number' ? value : null;
}

/** Look at a request body. Anything that is not JSON-RPC is left alone. */
export function inspect(body: string): Inspection {
    const result: Inspection = { toolCalls: [], toolListIds: new Set(), isBatch: false };
    let parsed: unknown;
    try {
        parsed = JSON.parse(body);
    } catch {
        return result;
    }
    result.isBatch = Array.isArray(parsed);
    const messages = (Array.isArray(parsed) ? parsed : [parsed]) as JsonRpcRequestLike[];
    for (const message of messages) {
        if (typeof message !== 'object' || message === null) continue;
        const params = message.params as { name?: unknown; _meta?: { traceparent?: unknown } } | undefined;
        if (!result.traceparent && typeof params?._meta?.traceparent === 'string') {
            result.traceparent = params._meta.traceparent;
        }
        if (message.id === undefined) continue;
        if (message.method === 'tools/call') {
            result.toolCalls.push({ id: asId(message.id), name: typeof params?.name === 'string' ? params.name : '' });
        } else if (message.method === 'tools/list') {
            result.toolListIds.add(JSON.stringify(message.id));
        }
    }
    return result;
}

/** A refused `tools/call`: an error result the model can read. */
export function refusedToolResult(id: JsonRpcId, message: string): Record<string, unknown> {
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: message }], isError: true } };
}

/** A refused `tools/call` due to missing JIT / RFC 9396 `authorization_details`. */
export function refusedJitToolResult(
    id: JsonRpcId,
    tool: string,
    requiredDetails: AuthorizationDetail[],
): { body: Record<string, unknown>; headerValue: string } {
    const hintJson = JSON.stringify(requiredDetails);
    const headerValue = Buffer.from(hintJson, 'utf8').toString('base64');
    const types = requiredDetails.map((d) => d.type).join(', ');
    const message = `Tool '${tool}' requires JIT authorization_details (${types}); authorization_details_hint=${hintJson}`;
    return {
        headerValue,
        body: {
            jsonrpc: '2.0',
            id,
            result: {
                content: [{ type: 'text', text: message }],
                isError: true,
                _meta: {
                    error: 'insufficient_authorization_details',
                    authorization_details_hint: requiredDetails,
                    'Insufficient-Authorization-Details': headerValue,
                },
            },
        },
    };
}

type Decide = (toolNames: string[]) => Promise<Set<string>>;

/** Filter the tools of one JSON-RPC message when it answers a `tools/list` request. */
async function filterMessage(message: unknown, ids: Set<string>, decide: Decide): Promise<unknown> {
    if (typeof message !== 'object' || message === null) return message;
    const response = message as { id?: unknown; result?: { tools?: unknown } };
    if (!ids.has(JSON.stringify(response.id)) || !Array.isArray(response.result?.tools)) return message;
    const tools = response.result.tools as Array<{ name?: unknown }>;
    const allowed = await decide(tools.map((t) => (typeof t.name === 'string' ? t.name : '')));
    return { ...response, result: { ...response.result, tools: tools.filter((t) => typeof t.name === 'string' && allowed.has(t.name)) } };
}

/** Filter a JSON response body (one message or a batch). */
export async function filterJsonBody(body: string, ids: Set<string>, decide: Decide): Promise<string> {
    let parsed: unknown;
    try {
        parsed = JSON.parse(body);
    } catch {
        return body;
    }
    const filtered = Array.isArray(parsed)
        ? await Promise.all(parsed.map((m) => filterMessage(m, ids, decide)))
        : await filterMessage(parsed, ids, decide);
    return JSON.stringify(filtered);
}

/**
 * Filter one Server-Sent Event. Events without a `data:` payload that
 * answers a pending `tools/list` request come back unchanged.
 */
export async function filterSseEvent(event: string, ids: Set<string>, decide: Decide): Promise<string> {
    const lines = event.split(/\r?\n/);
    const dataLines = lines.filter((line) => line.startsWith('data:'));
    if (dataLines.length === 0) return event;
    const data = dataLines.map((line) => line.slice(5).replace(/^ /, '')).join('\n');
    let message: unknown;
    try {
        message = JSON.parse(data);
    } catch {
        return event;
    }
    const filtered = await filterMessage(message, ids, decide);
    if (filtered === message) return event;
    const others = lines.filter((line) => !line.startsWith('data:') && line !== '');
    return [...others, `data: ${JSON.stringify(filtered)}`].join('\n');
}
