import { LumoAuthAuthenticationError, LumoAuthConfigError, McpModule } from '@lumoauth/shared';
import type { LumoAuthInfo, LumoCaller, LumoMcpAuth } from './auth';
import { capabilityCovered, missingScopes } from './scopes';

/**
 * Per-tool authorization.
 *
 * A valid token proves the caller may reach the MCP server. Whether that user
 * or agent may run a particular tool can be a LumoAuth policy (roles,
 * relationships, ABAC rules, agent capabilities), asked through
 * `POST /orgs/{org}/api/v1/mcp/servers/{id}/tools/authorize`.
 *
 * The MCP server asks as itself, with its own client-credentials token
 * (scope `mcp:authorize`); it never forwards the caller's token, which the
 * MCP specification forbids.
 */

export const MCP_AUTHORIZE_SCOPE = 'mcp:authorize';

/** Read the auth info from an SDK v1 `extra` or an SDK v2 `ctx`. */
export function getAuthInfo(extraOrCtx: unknown): LumoAuthInfo | undefined {
    if (typeof extraOrCtx !== 'object' || extraOrCtx === null) return undefined;
    const holder = extraOrCtx as { authInfo?: unknown; http?: { authInfo?: unknown } };
    const info = holder.authInfo ?? holder.http?.authInfo;
    if (typeof info !== 'object' || info === null) return undefined;
    return (info as LumoAuthInfo).extra?.caller ? (info as LumoAuthInfo) : undefined;
}

/**
 * The verified caller inside a tool handler:
 * `getCaller(extra)` (SDK v1) or `getCaller(ctx)` (SDK v2).
 */
export function getCaller(extraOrCtx: unknown): LumoCaller | undefined {
    return getAuthInfo(extraOrCtx)?.extra.caller;
}

/** Raised from a guarded tool handler; the SDKs turn it into an error result. */
export class ToolAccessDeniedError extends Error {
    constructor(message: string, public readonly missingScopes: string[] = []) {
        super(message);
        this.name = 'ToolAccessDeniedError';
    }
}

/** A cached client-credentials token for the MCP server's own client. */
export class ServerToken {
    private token: string | undefined;
    private expiresAt = 0;
    private pending: Promise<string> | undefined;

    constructor(
        private readonly tokenEndpoint: string,
        private readonly clientId: string,
        private readonly clientSecret: string,
        private readonly fetchFn: typeof globalThis.fetch,
        private readonly scopes: string[] = [MCP_AUTHORIZE_SCOPE],
    ) {}

    async get(): Promise<string> {
        if (this.token && Date.now() < this.expiresAt) return this.token;
        this.pending ??= this.fetchToken().finally(() => {
            this.pending = undefined;
        });
        return this.pending;
    }

    invalidate(): void {
        this.token = undefined;
        this.expiresAt = 0;
    }

    private async fetchToken(): Promise<string> {
        const response = await this.fetchFn(this.tokenEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
            body: new URLSearchParams({
                grant_type: 'client_credentials',
                client_id: this.clientId,
                client_secret: this.clientSecret,
                scope: this.scopes.join(' '),
            }).toString(),
        });
        const body = (await response.json().catch(() => ({}))) as { access_token?: unknown; expires_in?: unknown };
        if (!response.ok || typeof body.access_token !== 'string') {
            throw new LumoAuthConfigError(
                `LumoAuth refused the MCP server's client credentials (HTTP ${response.status}). Check ` +
                    'LUMOAUTH_MCP_CLIENT_ID / LUMOAUTH_MCP_CLIENT_SECRET and that the client has the mcp:authorize scope.',
            );
        }
        const lifetime = typeof body.expires_in === 'number' ? body.expires_in : 300;
        this.token = body.access_token;
        this.expiresAt = Date.now() + Math.max(0, lifetime - 60) * 1000;
        return body.access_token;
    }
}

export interface ToolPolicyOptions {
    /** Seconds to remember a decision. Default 30; 0 disables the cache. */
    cacheTtl?: number;
}

/** LumoAuth's per-tool decisions, cached and failing closed. */
export class ToolPolicy {
    private readonly mcp: McpModule;
    private readonly serverToken: ServerToken;
    private readonly serverId: string;
    private readonly ttlMs: number;
    private readonly cache = new Map<string, { allowed: boolean; until: number }>();

    constructor(auth: LumoMcpAuth, fetchFn: typeof globalThis.fetch, options: ToolPolicyOptions = {}) {
        if (!auth.serverId) {
            throw new LumoAuthConfigError('The tool policy needs the registered MCP server id (LUMOAUTH_MCP_SERVER_ID).');
        }
        if (!auth.orgId) {
            throw new LumoAuthConfigError('The tool policy needs the organization (LUMOAUTH_ORG_ID).');
        }
        if (!auth.clientId || !auth.clientSecret) {
            throw new LumoAuthConfigError(
                'The tool policy asks LumoAuth as the MCP server itself. Set LUMOAUTH_MCP_CLIENT_ID and ' +
                    'LUMOAUTH_MCP_CLIENT_SECRET to an OAuth client with the client_credentials grant and the ' +
                    "mcp:authorize scope, and add that client under Per-tool authorization on the server's page.",
            );
        }
        this.serverId = auth.serverId;
        this.ttlMs = (options.cacheTtl ?? 30) * 1000;
        this.serverToken = new ServerToken(`${auth.issuer}/oauth/token`, auth.clientId, auth.clientSecret, fetchFn);
        this.mcp = new McpModule({
            baseUrl: auth.lumoauthUrl,
            orgId: auth.orgId,
            token: () => this.serverToken.get(),
            fetch: fetchFn,
        });
    }

    /** Whether LumoAuth lets `caller` run `tool`. Errors count as a refusal. */
    async isAllowed(caller: LumoCaller, tool: string): Promise<boolean> {
        const type = caller.isAgent ? 'agent' : 'user';
        const key = `${type}\u0000${caller.sub}\u0000${tool}`;
        const cached = this.cache.get(key);
        if (cached && cached.until > Date.now()) return cached.allowed;

        let allowed: boolean;
        try {
            allowed = await this.decide(type, caller.sub, tool);
        } catch (error) {
            console.warn(`[lumoauth] tool authorization failed for '${tool}', refusing:`, (error as Error).message);
            return false;
        }
        if (this.ttlMs > 0) {
            if (this.cache.size >= 10_000) this.cache.clear();
            this.cache.set(key, { allowed, until: Date.now() + this.ttlMs });
        }
        return allowed;
    }

    private async decide(type: 'user' | 'agent', id: string, tool: string): Promise<boolean> {
        const ask = () => this.mcp.authorizeTool({ serverId: this.serverId, subject: { type, id }, tool });
        try {
            return (await ask()).allowed;
        } catch (error) {
            if (!(error instanceof LumoAuthAuthenticationError)) throw error;
            // The cached server token was revoked or rotated: fetch a new one once.
            this.serverToken.invalidate();
            return (await ask()).allowed;
        }
    }
}

export interface GuardOptions {
    /** Scopes the tool needs; a wildcard grant counts. */
    scopes?: string[];
    /** Only AI agents (with these capabilities, when given). */
    agents?: boolean | string[];
    /** Only human users; `'delegated'` also admits an agent acting for a user. */
    users?: boolean | 'delegated';
    /** Ask LumoAuth's per-tool policy. Default: on when the server's client credentials are set. */
    policy?: boolean;
    /** Run the handler when there is no auth info (stdio). Default `false`: refuse. */
    allowUnauthenticated?: boolean;
}

/** The access checks of {@link GuardOptions} for one call. Throws when refused. */
export async function checkToolAccess(
    auth: LumoMcpAuth,
    tool: string,
    extraOrCtx: unknown,
    options: GuardOptions,
): Promise<void> {
    const info = getAuthInfo(extraOrCtx);
    if (!info) {
        if (options.allowUnauthenticated) return;
        throw new ToolAccessDeniedError(
            `Tool '${tool}' needs a verified caller. Put auth.protect() in front of the MCP endpoint.`,
        );
    }
    const caller = info.extra.caller;
    if (options.scopes && options.scopes.length > 0) {
        const missing = missingScopes(options.scopes, caller.scopes);
        if (missing.length > 0) {
            throw new ToolAccessDeniedError(`Tool '${tool}' needs the scope ${missing.join(', ')}.`, missing);
        }
    }
    if (options.agents) {
        const capabilities = Array.isArray(options.agents) ? options.agents : [];
        if (!caller.isAgent || !capabilities.every((c) => capabilityCovered(c, caller.capabilities))) {
            throw new ToolAccessDeniedError(`Tool '${tool}' is for AI agents with the required capabilities.`);
        }
    }
    if (options.users) {
        if (caller.isAgent || (caller.isDelegated && options.users !== 'delegated')) {
            throw new ToolAccessDeniedError(`Tool '${tool}' can only be run by a person.`);
        }
    }
    const policy = options.policy ?? auth.hasToolPolicy;
    if (policy && !(await auth.toolPolicy().isAllowed(caller, tool))) {
        throw new ToolAccessDeniedError(`LumoAuth policy does not allow this caller to run '${tool}'.`);
    }
}

// The SDK callbacks are `(args, extra)` or `(extra)`; the last argument is
// always the request context.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Handler = (...args: any[]) => unknown;

/** Wrap a tool handler with access checks. */
export function guardHandler<H extends Handler>(auth: LumoMcpAuth, tool: string, handler: H, options: GuardOptions = {}): H {
    const guarded = async (...args: unknown[]) => {
        await checkToolAccess(auth, tool, args[args.length - 1], options);
        return handler(...args);
    };
    return guarded as unknown as H;
}

export interface SecureToolsOptions extends Omit<GuardOptions, 'scopes'> {
    /** Scopes per tool name. */
    scopes?: Record<string, string[]>;
}

/**
 * Guard every tool registered on `server` from now on (`registerTool`, and
 * the older `tool()` of SDK v1). Call it before registering tools.
 */
export function secureServerTools<S extends object>(auth: LumoMcpAuth, server: S, options: SecureToolsOptions = {}): S {
    const target = server as {
        registerTool?: (name: string, config: unknown, callback: Handler) => unknown;
        tool?: (name: string, ...rest: unknown[]) => unknown;
    };
    const guardOptions = (name: string): GuardOptions => ({ ...options, scopes: options.scopes?.[name] });
    if (typeof target.registerTool === 'function') {
        const register = target.registerTool.bind(server);
        target.registerTool = (name, config, callback) =>
            register(name, config, guardHandler(auth, name, callback, guardOptions(name)));
    }
    if (typeof target.tool === 'function') {
        const legacy = target.tool.bind(server);
        target.tool = (name: string, ...rest: unknown[]) => {
            const callback = rest.pop();
            if (typeof callback !== 'function') return legacy(name, ...rest, callback);
            return legacy(name, ...rest, guardHandler(auth, name, callback as Handler, guardOptions(name)));
        };
    }
    return server;
}

/**
 * An SDK v2 `scopeChallenge` with LumoAuth's wildcard rule: the SDK answers
 * `403 insufficient_scope` naming `scopes`, so the client can step up.
 */
export function lumoScopeChallenge(...scopes: [string, ...string[]]) {
    return ({ authInfo }: { authInfo?: { scopes: string[] } }) => {
        if (!authInfo) return undefined; // the authentication gate answers first
        return missingScopes(scopes, authInfo.scopes).length > 0 ? { scopes } : undefined;
    };
}
