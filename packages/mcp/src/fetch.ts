import type { LumoAuthInfo, LumoMcpAuth } from './auth';
import { LumoAuthChallenge } from './challenge';

/**
 * Web-standard adapters for `fetch(request)` handlers: the MCP SDK v2's
 * `createMcpHandler`, Hono, Bun and Deno servers.
 *
 * ```ts
 * async function fetchHandler(request: Request): Promise<Response> {
 *     const discovery = await auth.discovery(request);
 *     if (discovery) return discovery;
 *     const authInfo = await auth.gate(request);
 *     if (authInfo instanceof Response) return authInfo;
 *     return handler.fetch(request, { authInfo });
 * }
 * ```
 */

export function challengeResponse(challenge: LumoAuthChallenge): Response {
    const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    if (challenge.wwwAuthenticate) {
        headers.set('WWW-Authenticate', challenge.wwwAuthenticate);
        headers.set('Access-Control-Expose-Headers', 'WWW-Authenticate');
    }
    return new Response(JSON.stringify(challenge.body), { status: challenge.status, headers });
}

/** The discovery document for this request, or `undefined` for other paths. */
export async function discoveryFetchResponse(auth: LumoMcpAuth, request: Request): Promise<Response | undefined> {
    const response = await auth.discoveryResponse(request.method, new URL(request.url).pathname);
    if (!response) return undefined;
    return new Response(request.method === 'HEAD' ? null : (response.body ?? null), {
        status: response.status,
        headers: response.headers,
    });
}

/** The verified auth info, or the `Response` to send back instead. */
export async function fetchGate(
    auth: LumoMcpAuth,
    request: Request,
    options: { requiredScopes?: string[] } = {},
): Promise<LumoAuthInfo | Response> {
    try {
        return await auth.authenticate({ method: request.method, url: request.url, headers: request.headers }, options);
    } catch (error) {
        if (error instanceof LumoAuthChallenge) return challengeResponse(error);
        console.error('[lumoauth] authentication is not configured correctly:', error);
        return Response.json(
            { error: 'server_error', error_description: 'Authentication is not configured' },
            { status: 500 },
        );
    }
}
