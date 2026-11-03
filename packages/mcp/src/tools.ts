import { AsyncLocalStorage } from 'node:async_hooks';
import {
    LumoAuthApiError,
    LumoAuthAuthenticationError,
    LumoAuthConfigError,
    LumoAuthNetworkError,
    LumoAuthNotFoundError,
    LumoAuthPermissionDeniedError,
    LumoAuthValidationError,
    McpModule,
} from '@lumoauth/shared';
import type { LumoAuthInfo, LumoCaller, LumoMcpAuth } from './auth';
import { capabilityCovered, missingScopes } from './scopes';

/**
 * Per-tool authorization, JIT/RAR step-up guards, and Token Vault helpers.
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

const GUARD_OPTIONS_SYMBOL = Symbol.for('lumoauth.mcp.guardOptions');

/** RFC 9396 Rich Authorization Requests entry. */
export interface AuthorizationDetail {
    type: string;
    actions?: string[];
    locations?: string[];
    identifier?: string;
    [key: string]: unknown;
}

/** Read the auth info from an SDK v1 `extra` or an SDK v2 `ctx`. */
export function getAuthInfo(extraOrCtx: unknown): LumoAuthInfo | undefined {
    if (typeof extraOrCtx !== 'object' || extraOrCtx === null) return undefined;
    const holder = extraOrCtx as {
        authInfo?: unknown;
        http?: { authInfo?: unknown };
        mcpReq?: { authInfo?: unknown };
    };
    const info = holder.authInfo ?? holder.http?.authInfo ?? holder.mcpReq?.authInfo;
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

/**
 * Raised when a tool requires a task-bound JIT grant (RFC 9396 `authorization_details`).
 * Includes `requiredDetails` (`authorization_details_hint`) and base64 `headerValue`
 * (`Insufficient-Authorization-Details`) so self-escalating agents can request human approval.
 */
export class InsufficientAuthorizationDetailsError extends ToolAccessDeniedError {
    readonly error = 'insufficient_authorization_details';
    readonly requiredDetails: AuthorizationDetail[];
    readonly headerValue: string;

    constructor(tool: string, requiredDetails: AuthorizationDetail[], message?: string) {
        const hintJson = JSON.stringify(requiredDetails);
        const headerValue = Buffer.from(hintJson, 'utf8').toString('base64');
        const types = requiredDetails.map((d) => d.type).join(', ');
        super(
            message ??
                `Tool '${tool}' requires JIT authorization_details (${types}); authorization_details_hint=${hintJson}`,
        );
        this.name = 'InsufficientAuthorizationDetailsError';
        this.requiredDetails = requiredDetails;
        this.headerValue = headerValue;
    }

    toJSON(): Record<string, unknown> {
        return {
            error: this.error,
            error_description: this.message,
            authorization_details_hint: this.requiredDetails,
            'Insufficient-Authorization-Details': this.headerValue,
        };
    }
}

export function normalizeAuthorizationDetails(
    spec: string | AuthorizationDetail | AuthorizationDetail[],
): AuthorizationDetail[] {
    if (typeof spec === 'string') {
        return [{ type: spec.trim() }];
    }
    const list = Array.isArray(spec) ? spec : [spec];
    return list
        .filter((item): item is AuthorizationDetail => typeof item === 'object' && item !== null && typeof item.type === 'string')
        .map((item) => {
            const clean: AuthorizationDetail = { type: item.type.trim() };
            if (Array.isArray(item.actions) && item.actions.length > 0) {
                clean.actions = item.actions.map((a) => String(a).trim()).filter(Boolean);
            }
            if (Array.isArray(item.locations) && item.locations.length > 0) {
                clean.locations = item.locations.map((l) => String(l).trim()).filter(Boolean);
            }
            if (typeof item.identifier === 'string' && item.identifier.trim()) {
                clean.identifier = item.identifier.trim();
            }
            return clean;
        });
}

/** `true` when at least one entry in `granted` covers `required`. */
export function authorizationDetailCovered(
    required: AuthorizationDetail,
    granted: readonly AuthorizationDetail[],
): boolean {
    return granted.some((entry) => {
        if (!entry || typeof entry.type !== 'string') return false;
        if (entry.type !== required.type && entry.type !== '*') return false;
        if (Array.isArray(required.actions) && required.actions.length > 0) {
            if (!Array.isArray(entry.actions)) return false;
            const actionsSet = new Set(entry.actions.map(String));
            if (!actionsSet.has('*') && !required.actions.every((a) => actionsSet.has(a))) return false;
        }
        if (Array.isArray(required.locations) && required.locations.length > 0) {
            if (!Array.isArray(entry.locations)) return false;
            const locSet = new Set(entry.locations.map(String));
            if (!locSet.has('*') && !required.locations.every((l) => locSet.has(l))) return false;
        }
        if (typeof required.identifier === 'string' && required.identifier) {
            if (entry.identifier !== required.identifier && entry.identifier !== '*') return false;
        }
        return true;
    });
}

/** Return the entries of `required` that `granted` does not cover. */
export function missingAuthorizationDetails(
    required: readonly AuthorizationDetail[],
    granted: readonly AuthorizationDetail[],
): AuthorizationDetail[] {
    return required.filter((req) => !authorizationDetailCovered(req, granted));
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
    private readonly traceStore = new AsyncLocalStorage<string | undefined>();

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
        const tracedFetch: typeof globalThis.fetch = (input, init) => {
            const tp = this.traceStore.getStore();
            if (!tp) return fetchFn(input, init);
            const headers = new Headers(init?.headers);
            if (!headers.has('traceparent')) headers.set('traceparent', tp);
            const mergedHeaders: Record<string, string> = {};
            headers.forEach((v, k) => {
                mergedHeaders[k] = v;
            });
            return fetchFn(input, { ...init, headers: mergedHeaders });
        };
        this.mcp = new McpModule({
            baseUrl: auth.lumoauthUrl,
            orgId: auth.orgId,
            token: () => this.serverToken.get(),
            fetch: tracedFetch,
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
            allowed = await this.decide(type, caller.sub, tool, caller.traceparent);
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

    private async decide(
        type: 'user' | 'agent',
        id: string,
        tool: string,
        traceparent?: string,
    ): Promise<boolean> {
        const ask = () =>
            this.traceStore.run(traceparent, () =>
                this.mcp.authorizeTool({
                    serverId: this.serverId,
                    subject: { type, id },
                    tool,
                }),
            );
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

// ── Token Vault Helper ───────────────────────────────────────────────

/** Short-lived outbound OAuth access token minted by LumoAuth's Token Vault. */
export interface VaultToken {
    accessToken: string;
    tokenType: string;
    expiresAt?: string;
    scopes: string[];
    connectionId: string;
    userId?: string;
    headers(): Record<string, string>;
}

export interface VaultTokenOptions {
    /** Explicit `user_id` to pass to the Token Vault. */
    userId?: string;
    /** Verified caller (used to auto-resolve `user_id` and `traceparent`). */
    caller?: LumoCaller;
    /** Explicit W3C `traceparent` header. */
    traceparent?: string;
}

export function resolveVaultUserId(caller?: LumoCaller, explicitUserId?: string): string | undefined {
    if (typeof explicitUserId === 'string') {
        const trimmed = explicitUserId.trim();
        return trimmed || undefined;
    }
    if (!caller) return undefined;
    if (!caller.isAgent || caller.isDelegated) {
        return caller.sub || undefined;
    }
    return undefined;
}

function parseVaultOptions(extraOrCtxOrOptions?: VaultTokenOptions | unknown): VaultTokenOptions {
    if (!extraOrCtxOrOptions || typeof extraOrCtxOrOptions !== 'object') return {};
    const maybeCaller = getCaller(extraOrCtxOrOptions);
    if (maybeCaller) {
        return { caller: maybeCaller };
    }
    const bag = extraOrCtxOrOptions as Record<string, unknown>;
    if (typeof bag.sub === 'string' && Array.isArray(bag.scopes)) {
        return { caller: bag as unknown as LumoCaller };
    }
    return {
        userId: typeof bag.userId === 'string' ? bag.userId : undefined,
        caller:
            typeof bag.caller === 'object' && bag.caller !== null
                ? (bag.caller as LumoCaller)
                : undefined,
        traceparent: typeof bag.traceparent === 'string' ? bag.traceparent : undefined,
    };
}

export class VaultClient {
    private readonly issuer: string;
    private readonly fetchFn: typeof globalThis.fetch;
    private readonly ttlMs: number;
    private readonly staticToken: string | undefined;
    private readonly serverToken: ServerToken | undefined;
    private readonly cache = new Map<string, { token: VaultToken; until: number }>();

    constructor(
        auth: LumoMcpAuth,
        fetchFn: typeof globalThis.fetch,
        options: { cacheTtl?: number } = {},
    ) {
        this.issuer = auth.issuer;
        this.fetchFn = fetchFn;
        this.ttlMs = (options.cacheTtl ?? 60) * 1000;
        if (auth.agentToken) {
            this.staticToken = auth.agentToken;
        } else if (auth.clientId && auth.clientSecret) {
            this.serverToken = new ServerToken(
                `${auth.issuer}/oauth/token`,
                auth.clientId,
                auth.clientSecret,
                fetchFn,
                ['vault:token', MCP_AUTHORIZE_SCOPE],
            );
        } else {
            throw new LumoAuthConfigError(
                'Token Vault access requires an agent token (agentToken or LUMOAUTH_AGENT_TOKEN) or ' +
                    'MCP client credentials (LUMOAUTH_MCP_CLIENT_ID and LUMOAUTH_MCP_CLIENT_SECRET).',
            );
        }
    }

    async getToken(connectionId: string, extraOrCtxOrOptions?: VaultTokenOptions | unknown): Promise<VaultToken> {
        if (typeof connectionId !== 'string' || !connectionId.trim()) {
            throw new LumoAuthValidationError('connectionId is required.', [
                { field: 'connectionId', value: connectionId },
            ]);
        }
        const conn = connectionId.trim();
        const opts = parseVaultOptions(extraOrCtxOrOptions);
        const resolvedUser = resolveVaultUserId(opts.caller, opts.userId);
        const cacheKey = `${conn}\u0000${resolvedUser ?? ''}`;

        if (this.ttlMs > 0) {
            const cached = this.cache.get(cacheKey);
            if (cached && cached.until > Date.now()) {
                return cached.token;
            }
        }

        const tp = opts.traceparent ?? opts.caller?.traceparent;
        const url = `${this.issuer}/agents/me/connections/${encodeURIComponent(conn)}/token`;
        const payload = resolvedUser ? { user_id: resolvedUser } : {};
        const body = await this.send('POST', url, payload, tp);

        if (typeof body !== 'object' || body === null || typeof (body as { access_token?: unknown }).access_token !== 'string') {
            throw new LumoAuthValidationError('Unexpected Token Vault response from LumoAuth.', []);
        }
        const record = body as Record<string, unknown>;
        const accessToken = record.access_token as string;
        const tokenType = typeof record.token_type === 'string' && record.token_type ? record.token_type : 'Bearer';
        const expiresAt = typeof record.expires_at === 'string' ? record.expires_at : undefined;
        const scopes = Array.isArray(record.scopes)
            ? record.scopes.filter((s): s is string => typeof s === 'string')
            : typeof record.scope === 'string'
              ? record.scope.split(/\s+/).filter(Boolean)
              : [];

        const vaultToken: VaultToken = {
            accessToken,
            tokenType,
            expiresAt,
            scopes,
            connectionId: conn,
            userId: resolvedUser,
            headers() {
                return { Authorization: `${tokenType} ${accessToken}` };
            },
        };

        if (this.ttlMs > 0) {
            let until = Date.now() + this.ttlMs;
            if (expiresAt) {
                const parsedMs = Date.parse(expiresAt);
                if (!Number.isNaN(parsedMs)) {
                    until = Math.max(Date.now(), parsedMs - 30_000);
                }
            }
            if (until > Date.now()) {
                this.cache.set(cacheKey, { token: vaultToken, until });
            }
        }
        return vaultToken;
    }

    async listConnections(extraOrCtxOrOptions?: VaultTokenOptions | unknown): Promise<Record<string, unknown>[]> {
        const opts = parseVaultOptions(extraOrCtxOrOptions);
        const tp = opts.traceparent ?? opts.caller?.traceparent;
        const url = `${this.issuer}/agents/me/connections`;
        const body = await this.send('GET', url, undefined, tp);
        if (Array.isArray(body)) return body as Record<string, unknown>[];
        if (typeof body === 'object' && body !== null && Array.isArray((body as { connections?: unknown }).connections)) {
            return (body as { connections: Record<string, unknown>[] }).connections;
        }
        return [];
    }

    clearCache(): void {
        this.cache.clear();
    }

    private async send(
        method: 'GET' | 'POST',
        url: string,
        payload: Record<string, unknown> | undefined,
        traceparent?: string,
    ): Promise<unknown> {
        for (const attempt of [0, 1]) {
            const bearer = this.staticToken ?? (await this.serverToken!.get());
            const headers: Record<string, string> = {
                Authorization: `Bearer ${bearer}`,
                Accept: 'application/json',
            };
            if (payload !== undefined) headers['Content-Type'] = 'application/json';
            if (traceparent) headers.traceparent = traceparent;

            let response: Response;
            try {
                response = await this.fetchFn(url, {
                    method,
                    headers,
                    body: payload !== undefined ? JSON.stringify(payload) : undefined,
                });
            } catch (error) {
                throw new LumoAuthNetworkError(
                    `Token Vault request to ${url} failed: ${(error as Error).message}`,
                    error,
                );
            }

            if (response.status === 401 && attempt === 0 && this.serverToken) {
                this.serverToken.invalidate();
                continue;
            }

            const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;
            if (response.ok) return data;

            const message =
                (typeof data.error_description === 'string' && data.error_description) ||
                (typeof data.message === 'string' && data.message) ||
                (typeof data.error === 'string' && data.error) ||
                `HTTP ${response.status}`;
            if (response.status === 401) throw new LumoAuthAuthenticationError(message, data);
            if (response.status === 403) throw new LumoAuthPermissionDeniedError(message, data);
            if (response.status === 404) throw new LumoAuthNotFoundError(message, data);
            throw new LumoAuthApiError(
                message,
                typeof data.code === 'string' ? data.code : 'VAULT_ERROR',
                response.status,
                data,
            );
        }
        return {};
    }
}

export interface GuardOptions {
    /** Scopes the tool needs; a wildcard grant counts. */
    scopes?: string[];
    /** Only AI agents (with these capabilities, when given). */
    agents?: boolean | string[];
    /** Only human users; `'delegated'` also admits an agent acting for a user. */
    users?: boolean | 'delegated';
    /** Require a task-bound JIT grant (RFC 9396 `authorization_details`). */
    jit?: string | AuthorizationDetail | AuthorizationDetail[];
    /** Ask LumoAuth's per-tool policy. Default: on when the server's client credentials are set. */
    policy?: boolean;
    /** Run the handler when there is no auth info (stdio). Default `false`: refuse. */
    allowUnauthenticated?: boolean;
}

/** Synchronous local access checks (`scopes`, `agents`, `users`, and optional `jit`). */
function checkLocalAccess(
    tool: string,
    caller: LumoCaller,
    options: GuardOptions,
    checkJit = true,
): void {
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
    if (checkJit && options.jit) {
        const required = normalizeAuthorizationDetails(options.jit);
        const missing = missingAuthorizationDetails(required, caller.authorizationDetails);
        if (missing.length > 0) {
            throw new InsufficientAuthorizationDetailsError(tool, missing);
        }
    }
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
    checkLocalAccess(tool, caller, options, true);
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
export function guardHandler<H extends Handler>(
    auth: LumoMcpAuth,
    tool: string,
    handler: H,
    options: GuardOptions = {},
): H {
    const existing = (handler as unknown as Record<symbol, GuardOptions | undefined>)[GUARD_OPTIONS_SYMBOL];
    const mergedOptions: GuardOptions = existing ? { ...existing, ...options } : options;
    const guarded = async (...args: unknown[]) => {
        await checkToolAccess(auth, tool, args[args.length - 1], mergedOptions);
        return handler(...args);
    };
    (guarded as unknown as Record<symbol, GuardOptions>)[GUARD_OPTIONS_SYMBOL] = mergedOptions;
    return guarded as unknown as H;
}

export interface SecureToolsOptions extends Omit<GuardOptions, 'scopes' | 'jit'> {
    /** Scopes per tool name. */
    scopes?: Record<string, string[]>;
    /** JIT / RAR `authorization_details` requirement per tool name, or a default for all tools. */
    jit?:
        | string
        | AuthorizationDetail
        | AuthorizationDetail[]
        | Record<string, string | AuthorizationDetail | AuthorizationDetail[]>;
    /**
     * Also filter `tools/list` responses so callers only see tools they are
     * permitted to run. Default `true`.
     */
    filterList?: boolean;
    /**
     * When `true`, `tools/list` also hides tools whose `jit` requirement is not
     * yet present on the caller's token. Default `false` so agents can discover
     * the tool and trigger JIT step-up on `tools/call`.
     */
    hideJitUntilGranted?: boolean;
}

function resolveToolJit(
    jitOption: SecureToolsOptions['jit'],
    toolName: string,
): string | AuthorizationDetail | AuthorizationDetail[] | undefined {
    if (!jitOption) return undefined;
    if (typeof jitOption === 'string' || Array.isArray(jitOption)) return jitOption;
    if (typeof (jitOption as AuthorizationDetail).type === 'string') {
        return jitOption as AuthorizationDetail;
    }
    return (jitOption as Record<string, string | AuthorizationDetail | AuthorizationDetail[]>)[toolName];
}

/**
 * Guard every tool on `server` (`registerTool` and the older `tool()` of SDK v1,
 * plus any tools already registered before `secureServerTools` was called) and
 * filter `tools/list` responses so unauthorized tools are hidden.
 */
export function secureServerTools<S extends object>(auth: LumoMcpAuth, server: S, options: SecureToolsOptions = {}): S {
    const target = server as {
        registerTool?: (name: string, config: unknown, callback: Handler) => unknown;
        tool?: (name: string, ...rest: unknown[]) => unknown;
        setToolRequestHandlers?: () => void;
        _registeredTools?: Record<
            string,
            {
                handler?: Handler;
                update?: (updates: { callback: Handler }) => void;
            }
        >;
        server?: {
            _requestHandlers?: Map<string, (request: unknown, extra: unknown) => Promise<unknown>>;
        };
    };

    const toolOptionsMap = new Map<string, GuardOptions>();

    const guardOptions = (name: string, cb?: Handler): GuardOptions => {
        const attached = cb
            ? (cb as unknown as Record<symbol, GuardOptions | undefined>)[GUARD_OPTIONS_SYMBOL]
            : undefined;
        const combined: GuardOptions = {
            ...options,
            ...attached,
            scopes: options.scopes?.[name] ?? attached?.scopes,
            jit: resolveToolJit(options.jit, name) ?? attached?.jit,
        };
        toolOptionsMap.set(name, combined);
        return combined;
    };

    let listHandlerWrapped = false;
    const ensureListFilterInstalled = () => {
        if (listHandlerWrapped || options.filterList === false) return;
        const handlers = target.server?._requestHandlers;
        if (!handlers) return;
        let originalList = handlers.get('tools/list');
        if (!originalList && typeof target.setToolRequestHandlers === 'function') {
            try {
                target.setToolRequestHandlers();
                originalList = handlers.get('tools/list');
            } catch {
                // Will retry on first tool registration
            }
        }
        if (!originalList) return;
        listHandlerWrapped = true;

        handlers.set('tools/list', async (request: unknown, extra: unknown) => {
            const result = (await originalList!(request, extra)) as { tools?: Array<{ name?: string }> } | undefined;
            if (!result || !Array.isArray(result.tools) || result.tools.length === 0) {
                return result;
            }
            const info = getAuthInfo(extra);
            if (!info) {
                return options.allowUnauthenticated ? result : { ...result, tools: [] };
            }
            const caller = info.extra.caller;

            // 1. Synchronous local checks (scopes, agents, users, and optional JIT)
            const localSurvivors: Array<{ name?: string }> = [];
            const needsPolicyCheck: string[] = [];
            for (const tool of result.tools) {
                const name = typeof tool.name === 'string' ? tool.name : '';
                if (!name) continue;
                const opts = toolOptionsMap.get(name) ?? guardOptions(name);
                try {
                    checkLocalAccess(name, caller, opts, Boolean(options.hideJitUntilGranted));
                } catch {
                    continue;
                }
                localSurvivors.push(tool);
                if (opts.policy ?? auth.hasToolPolicy) {
                    needsPolicyCheck.push(name);
                }
            }

            if (needsPolicyCheck.length === 0) {
                return { ...result, tools: localSurvivors };
            }

            // 2. Remote per-tool Zanzibar checks (bounded concurrency 8, fail closed)
            const policy = auth.toolPolicy();
            const allowedPolicy = new Set<string>();
            for (let i = 0; i < needsPolicyCheck.length; i += 8) {
                await Promise.all(
                    needsPolicyCheck.slice(i, i + 8).map(async (name) => {
                        if (await policy.isAllowed(caller, name)) {
                            allowedPolicy.add(name);
                        }
                    }),
                );
            }

            const policyCheckedSet = new Set(needsPolicyCheck);
            const filtered = localSurvivors.filter((tool) => {
                const name = tool.name!;
                return !policyCheckedSet.has(name) || allowedPolicy.has(name);
            });
            return { ...result, tools: filtered };
        });
    };

    // Wrap any tools that were already registered before secureServerTools() was called
    if (target._registeredTools && typeof target._registeredTools === 'object') {
        for (const [name, entry] of Object.entries(target._registeredTools)) {
            if (entry && typeof entry.handler === 'function' && typeof entry.update === 'function') {
                const opts = guardOptions(name, entry.handler);
                entry.update({ callback: guardHandler(auth, name, entry.handler, opts) });
            }
        }
    }

    ensureListFilterInstalled();

    if (typeof target.registerTool === 'function') {
        const register = target.registerTool.bind(server);
        target.registerTool = (name, config, callback) => {
            const opts = guardOptions(name, callback);
            const res = register(name, config, guardHandler(auth, name, callback, opts));
            ensureListFilterInstalled();
            return res;
        };
    }
    if (typeof target.tool === 'function') {
        const legacy = target.tool.bind(server);
        target.tool = (name: string, ...rest: unknown[]) => {
            const callback = rest.pop();
            if (typeof callback !== 'function') return legacy(name, ...rest, callback);
            const opts = guardOptions(name, callback as Handler);
            const res = legacy(name, ...rest, guardHandler(auth, name, callback as Handler, opts));
            ensureListFilterInstalled();
            return res;
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
