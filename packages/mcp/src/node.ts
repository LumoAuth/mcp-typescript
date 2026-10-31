import type { LumoAuthInfo, LumoMcpAuth } from './auth';
import { LumoAuthChallenge, type SimpleResponse } from './challenge';

/**
 * Express and plain `node:http` adapters.
 *
 * They need no Express dependency: both are `(req, res, next)` functions that
 * write the answer through the Node `ServerResponse` API, which Express
 * responses extend.
 */

export interface NodeRequestLike {
    method?: string;
    url?: string;
    /** Express sets it to the URL before mounting rewrote `url`. */
    originalUrl?: string;
    headers: Record<string, string | string[] | undefined>;
    auth?: unknown;
}

export interface NodeResponseLike {
    statusCode: number;
    headersSent?: boolean;
    setHeader(name: string, value: string): unknown;
    end(body?: string): unknown;
}

export type NextFunction = (error?: unknown) => void;
export type NodeMiddleware = (req: NodeRequestLike, res: NodeResponseLike, next?: NextFunction) => Promise<void>;

function write(res: NodeResponseLike, response: SimpleResponse): void {
    res.statusCode = response.status;
    for (const [name, value] of Object.entries(response.headers)) res.setHeader(name, value);
    res.end(response.body);
}

export function writeChallenge(res: NodeResponseLike, challenge: LumoAuthChallenge): void {
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
    if (challenge.wwwAuthenticate) {
        headers['WWW-Authenticate'] = challenge.wwwAuthenticate;
        // Browser clients (MCP Inspector) must be able to read the challenge.
        headers['Access-Control-Expose-Headers'] = 'WWW-Authenticate';
    }
    write(res, { status: challenge.status, headers, body: JSON.stringify(challenge.body) });
}

function serverError(res: NodeResponseLike, error: unknown): void {
    console.error('[lumoauth] authentication is not configured correctly:', error);
    write(res, {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'server_error', error_description: 'Authentication is not configured' }),
    });
}

function pathOf(req: NodeRequestLike): string {
    return (req.originalUrl ?? req.url ?? '/').split('?')[0];
}

/**
 * Serves `/.well-known/oauth-protected-resource[...]` (and LumoAuth's
 * authorization server metadata for older clients). Mount it at the root:
 * `app.use(auth.router())`.
 */
export function discoveryMiddleware(auth: LumoMcpAuth): NodeMiddleware {
    return async (req, res, next) => {
        try {
            const response = await auth.discoveryResponse(req.method ?? 'GET', pathOf(req));
            if (response) {
                write(res, response);
                return;
            }
        } catch (error) {
            serverError(res, error);
            return;
        }
        next?.();
    };
}

/**
 * Requires a valid LumoAuth token and sets `req.auth`, which the MCP SDK's
 * Streamable HTTP transport passes to tool handlers.
 */
export function protectMiddleware(auth: LumoMcpAuth, options: { requiredScopes?: string[] } = {}): NodeMiddleware {
    return async (req, res, next) => {
        let info: LumoAuthInfo;
        try {
            info = await auth.authenticate(
                { method: req.method ?? 'GET', url: req.originalUrl ?? req.url ?? '/', headers: req.headers },
                options,
            );
        } catch (error) {
            if (error instanceof LumoAuthChallenge) writeChallenge(res, error);
            else serverError(res, error);
            return;
        }
        req.auth = info;
        next?.();
    };
}
