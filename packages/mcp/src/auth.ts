import {
    AccessTokenError,
    InMemoryDpopReplayCache,
    JwksCache,
    accessTokenScopes,
    parseAuthorizationHeader,
    verifyAccessToken,
    type AccessTokenClaims,
    type ActorClaim,
    type DpopReplayCache,
} from '@lumoauth/agent';
import { LumoAuthConfigError, LumoAuthNetworkError } from '@lumoauth/shared';
import { LumoAuthChallenge, type SimpleResponse } from './challenge';
import { discoveryFetchResponse, fetchGate } from './fetch';
import { discoveryMiddleware, protectMiddleware, type NodeMiddleware } from './node';
import { DEFAULT_DPOP_ALGS, fetchRegistration, registrationFromMetadata, type Registration } from './registration';
import { matchingAudiences, originOf, protectedResourceMetadataUrl, sameResource } from './resource';
import { missingScopes, scopeCovered } from './scopes';
import {
    ToolPolicy,
    guardHandler,
    lumoScopeChallenge,
    secureServerTools,
    type GuardOptions,
    type SecureToolsOptions,
} from './tools';

export { LumoAuthChallenge, type SimpleResponse };

/**
 * LumoAuth as the authorization server of an MCP server.
 *
 * LumoAuth registers MCP clients (Client ID Metadata Documents or dynamic
 * registration), shows consent and issues access tokens whose `aud` is the
 * MCP server's Resource URI. The MCP server stays a pure resource server;
 * this class gives it what the MCP authorization specification asks of one:
 * RFC 9728 protected resource metadata at its own origin, a `401` challenge
 * that points at it, local verification of LumoAuth `at+jwt` tokens
 * (including the RFC 9449 DPoP binding), and the verified caller.
 */

export const DEFAULT_LUMOAUTH_URL = 'https://app.lumoauth.dev';
const METADATA_TTL_MS = 3_600_000;

export interface LumoMcpAuthOptions {
    /** Organization slug, e.g. `acme`. Env: `LUMOAUTH_ORG_ID`. */
    orgId?: string;
    /**
     * Registered MCP server id (`mcp_…`). Env: `LUMOAUTH_MCP_SERVER_ID`. With
     * it, the Resource URI, the advertised scopes and the DPoP requirement
     * are read from the registration in LumoAuth.
     */
    serverId?: string;
    /** Registered Resource URI (the token `aud`). Env: `LUMOAUTH_MCP_RESOURCE`. */
    resource?: string;
    /** LumoAuth instance. Env: `LUMOAUTH_URL`. Default `https://app.lumoauth.dev`. */
    lumoauthUrl?: string;
    /**
     * Organization issuer. Env: `LUMOAUTH_ISSUER`. Default
     * `{lumoauthUrl}/orgs/{orgId}/api/v1`; set it for a custom domain.
     */
    issuer?: string;
    /**
     * Public origin of this server, for the DPoP `htu` check. Default: the
     * origin of the Resource URI.
     */
    publicUrl?: string;
    /** Builds the public URL of a request when a proxy rewrites paths. */
    requestUrl?: (request: IncomingRequestLike) => string;
    /** Scopes every request must carry. A wildcard grant (`mcp:*`) satisfies them. */
    requiredScopes?: string[];
    /** Scopes to advertise. Default: the registration's basic scopes. */
    scopesSupported?: string[];
    /** Refuse tokens that are not DPoP-bound. Default: the registration's switch. */
    requireDpop?: boolean;
    resourceName?: string;
    resourceDocumentation?: string;
    /** The MCP server's own client, for per-tool policy. Env: `LUMOAUTH_MCP_CLIENT_ID`. */
    clientId?: string;
    /** Env: `LUMOAUTH_MCP_CLIENT_SECRET`. */
    clientSecret?: string;
    /** The registration to use instead of fetching it (tests, offline). */
    registration?: Registration | Record<string, unknown>;
    /** Custom fetch for the registration, discovery, JWKS and policy calls. */
    fetch?: typeof globalThis.fetch;
    /** DPoP proof-id store. Default: in memory; share one between replicas. */
    replayCache?: DpopReplayCache;
    /** Leeway in seconds for `exp` and `nbf`. Default 60. */
    clockSkew?: number;
    /**
     * Also serve LumoAuth's authorization server metadata at
     * `/.well-known/oauth-authorization-server`, for clients written before
     * protected resource metadata existed. Default `true`.
     */
    authorizationServerMetadata?: boolean;
    /** Seconds to cache a per-tool decision. Default 30; 0 disables. */
    toolDecisionTtl?: number;
    /** Environment to read (default `process.env`). */
    env?: Record<string, string | undefined>;
}

/** The verified caller of a request. */
export interface LumoCaller {
    /** `agent_agt_…` for an agent, the user id for a user. */
    sub: string;
    issuer: string;
    /** The OAuth client (RFC 9068 `client_id`); the agent id for agent tokens. */
    clientId?: string;
    scopes: string[];
    isAgent: boolean;
    /** `agt_…` for an agent token. */
    agentId?: string;
    /** `true` when someone acts for `sub` (the token has an `act` claim). */
    isDelegated: boolean;
    /** `sub` of the immediate actor of a delegated token. */
    actor?: string;
    /** The `act` claims from the outermost actor inwards. */
    actChain: ActorClaim[];
    capabilities: string[];
    /** `cnf.jkt` of a DPoP-bound token. */
    dpopJkt?: string;
    claims: AccessTokenClaims;
}

/**
 * What `protect()` puts on `req.auth` and `fetchGate()` resolves to. The MCP
 * SDK transports hand it to tool handlers as `extra.authInfo` (SDK v1) or
 * `ctx.http.authInfo` (SDK v2); `getCaller()` reads either.
 */
export interface LumoAuthInfo {
    token: string;
    clientId: string;
    scopes: string[];
    expiresAt: number;
    resource: URL;
    resourceMetadataUrl: string;
    extra: { caller: LumoCaller; [key: string]: unknown };
}

export type HeadersLike = Headers | Record<string, string | string[] | undefined>;

/** The parts of an incoming request that authentication reads. */
export interface IncomingRequestLike {
    method: string;
    /** A path (`/mcp?x=1`) or an absolute URL. */
    url: string;
    headers: HeadersLike;
}

/** Everything resolved from options, environment and the registration. */
export interface ResolvedConfig {
    issuer: string;
    orgId?: string;
    serverId?: string;
    lumoauthUrl: string;
    resource: string;
    resourceMetadataUrl: string;
    publicOrigin: string;
    requireDpop: boolean;
    dpopAlgs: string[];
    scopesSupported: string[];
    requiredScopes: string[];
    resourceName?: string;
    resourceDocumentation?: string;
}

export function headerValue(headers: HeadersLike, name: string): string | undefined {
    if (typeof (headers as Headers).get === 'function') {
        return (headers as Headers).get(name) ?? undefined;
    }
    const record = headers as Record<string, string | string[] | undefined>;
    const key = Object.keys(record).find((k) => k.toLowerCase() === name);
    const value = key === undefined ? undefined : record[key];
    return Array.isArray(value) ? value[0] : value;
}

function decodePayload(token: string): Record<string, unknown> | undefined {
    const parts = token.split('.');
    if (parts.length !== 3) return undefined;
    try {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        return typeof payload === 'object' && payload !== null ? payload : undefined;
    } catch {
        return undefined;
    }
}

function quoted(value: string): string {
    // RFC 6750 §3: no '"' or '\' in a quoted value, one line.
    return value.replace(/[\\"]/g, "'").replace(/\s+/g, ' ').trim();
}

function canonicalScheme(scheme: string): 'Bearer' | 'DPoP' | undefined {
    const lower = scheme.toLowerCase();
    return lower === 'bearer' ? 'Bearer' : lower === 'dpop' ? 'DPoP' : undefined;
}

function toCaller(claims: AccessTokenClaims, scopes: string[]): LumoCaller {
    const isAgent = claims.is_agent === true;
    const actChain: ActorClaim[] = [];
    let current: ActorClaim | undefined = typeof claims.act === 'object' && claims.act !== null ? claims.act : undefined;
    while (current) {
        const { act, ...actor } = current;
        actChain.push(actor as ActorClaim);
        current = typeof act === 'object' && act !== null ? act : undefined;
    }
    return {
        sub: claims.sub,
        issuer: claims.iss,
        clientId: typeof claims.client_id === 'string' ? claims.client_id : undefined,
        scopes,
        isAgent,
        agentId: isAgent && claims.sub.startsWith('agent_') ? claims.sub.slice('agent_'.length) : undefined,
        isDelegated: actChain.length > 0,
        actor: actChain[0]?.sub,
        actChain,
        capabilities: Array.isArray(claims.capabilities)
            ? claims.capabilities.filter((c): c is string => typeof c === 'string')
            : [],
        dpopJkt: typeof claims.cnf?.jkt === 'string' ? claims.cnf.jkt : undefined,
        claims,
    };
}

export class LumoMcpAuth {
    readonly issuer: string;
    readonly orgId: string | undefined;
    readonly serverId: string | undefined;
    readonly lumoauthUrl: string;
    readonly clientId: string | undefined;
    readonly clientSecret: string | undefined;

    private readonly options: LumoMcpAuthOptions;
    private readonly env: Record<string, string | undefined>;
    private readonly fetchFn: typeof globalThis.fetch;
    private readonly jwksCache: JwksCache;
    private readonly replayCache: DpopReplayCache;
    private configPromise: Promise<ResolvedConfig> | undefined;
    private asMetadata: { at: number; document: unknown } | undefined;
    private policy: ToolPolicy | undefined;

    constructor(options: LumoMcpAuthOptions = {}) {
        this.options = options;
        this.env = options.env ?? (typeof process !== 'undefined' ? process.env : {});
        const env = this.env;
        this.lumoauthUrl = (options.lumoauthUrl ?? env.LUMOAUTH_URL ?? DEFAULT_LUMOAUTH_URL).replace(/\/+$/, '');
        this.orgId = options.orgId ?? (env.LUMOAUTH_ORG_ID || undefined);
        this.serverId = options.serverId ?? (env.LUMOAUTH_MCP_SERVER_ID || undefined);
        const issuer = options.issuer ?? (env.LUMOAUTH_ISSUER || undefined);
        if (!issuer && !this.orgId) {
            throw new LumoAuthConfigError(
                'LumoAuth needs the organization: pass orgId or set LUMOAUTH_ORG_ID (or pass the issuer).',
            );
        }
        this.issuer = (issuer ?? `${this.lumoauthUrl}/orgs/${this.orgId}/api/v1`).replace(/\/+$/, '');
        if (!this.serverId && !options.registration && !options.resource && !env.LUMOAUTH_MCP_RESOURCE) {
            throw new LumoAuthConfigError(
                "LumoAuth needs this server's Resource URI: set LUMOAUTH_MCP_SERVER_ID to the registered " +
                    'server id, or pass resource.',
            );
        }
        this.clientId = options.clientId ?? (env.LUMOAUTH_MCP_CLIENT_ID || undefined);
        this.clientSecret = options.clientSecret ?? (env.LUMOAUTH_MCP_CLIENT_SECRET || undefined);
        this.fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
        this.jwksCache = new JwksCache(this.fetchFn);
        this.replayCache = options.replayCache ?? new InMemoryDpopReplayCache();
    }

    // ── Adapters ──────────────────────────────────────────────────────

    /** Express / `node:http` middleware serving the discovery documents. Mount at the root. */
    router(): NodeMiddleware {
        return discoveryMiddleware(this);
    }

    /** Express / `node:http` middleware requiring a valid token; sets `req.auth`. */
    protect(options: { requiredScopes?: string[] } = {}): NodeMiddleware {
        return protectMiddleware(this, options);
    }

    /** Fetch handlers: the discovery document for this request, or `undefined`. */
    discovery(request: Request): Promise<Response | undefined> {
        return discoveryFetchResponse(this, request);
    }

    /** Fetch handlers: the verified auth info, or the `Response` to return instead. */
    gate(request: Request, options: { requiredScopes?: string[] } = {}): Promise<LumoAuthInfo | Response> {
        return fetchGate(this, request, options);
    }

    // ── Tools ─────────────────────────────────────────────────────────

    /** `true` when the server's own client credentials are configured. */
    get hasToolPolicy(): boolean {
        return Boolean(this.serverId && this.orgId && this.clientId && this.clientSecret);
    }

    /** LumoAuth's per-tool decisions for this server. */
    toolPolicy(): ToolPolicy {
        this.policy ??= new ToolPolicy(this, this.fetchFn, { cacheTtl: this.options.toolDecisionTtl });
        return this.policy;
    }

    /** Wrap one tool handler with access checks (scopes, caller kind, LumoAuth policy). */
    guard<H extends (...args: any[]) => unknown>(tool: string, handler: H, options: GuardOptions = {}): H {
        return guardHandler(this, tool, handler, options);
    }

    /** Guard every tool registered on an SDK `McpServer` from now on. */
    secureTools<S extends object>(server: S, options: SecureToolsOptions = {}): S {
        return secureServerTools(this, server, options);
    }

    /** An SDK v2 `scopeChallenge` that honours LumoAuth wildcards. */
    scopeChallenge(...scopes: [string, ...string[]]) {
        return lumoScopeChallenge(...scopes);
    }

    // ── Configuration ─────────────────────────────────────────────────

    /** Resolve the configuration, fetching the registration once. Call it at start-up to fail fast. */
    ready(): Promise<ResolvedConfig> {
        if (!this.configPromise) {
            this.configPromise = this.resolve().catch((error: unknown) => {
                this.configPromise = undefined; // try again on the next request
                throw error;
            });
        }
        return this.configPromise;
    }

    private async resolve(): Promise<ResolvedConfig> {
        const options = this.options;
        let registration: Registration | undefined;
        if (options.registration) {
            registration =
                'scopesSupported' in options.registration
                    ? (options.registration as Registration)
                    : registrationFromMetadata(options.registration);
        } else if (this.serverId) {
            registration = await fetchRegistration(this.issuer, this.serverId, this.fetchFn);
        }

        const explicit = options.resource ?? (this.env.LUMOAUTH_MCP_RESOURCE || undefined);
        if (explicit && registration && !sameResource(explicit, registration.resource)) {
            throw new LumoAuthConfigError(
                `resource '${explicit}' is not the Resource URI '${registration.resource}' registered for ` +
                    `${this.serverId ?? 'this MCP server'}.`,
            );
        }
        const resource = explicit ?? registration?.resource;
        if (!resource) {
            throw new LumoAuthConfigError("LumoAuth needs this server's Resource URI (LUMOAUTH_MCP_RESOURCE).");
        }
        let resourceUrl: URL;
        try {
            resourceUrl = new URL(resource);
        } catch {
            throw new LumoAuthConfigError(`The Resource URI '${resource}' is not an absolute URL.`);
        }
        if (resourceUrl.protocol !== 'https:' && resourceUrl.protocol !== 'http:') {
            throw new LumoAuthConfigError(`The Resource URI '${resource}' must be an https URL.`);
        }

        const requiredScopes = options.requiredScopes ?? [];
        return {
            issuer: this.issuer,
            orgId: this.orgId,
            serverId: this.serverId,
            lumoauthUrl: this.lumoauthUrl,
            resource,
            resourceMetadataUrl: protectedResourceMetadataUrl(resource),
            publicOrigin: originOf(options.publicUrl ?? resource),
            requireDpop: options.requireDpop ?? registration?.requireDpop ?? false,
            dpopAlgs: registration?.dpopAlgs ?? [...DEFAULT_DPOP_ALGS],
            scopesSupported: options.scopesSupported ?? registration?.scopesSupported ?? requiredScopes,
            requiredScopes,
            resourceName: options.resourceName ?? registration?.resourceName,
            resourceDocumentation: options.resourceDocumentation ?? registration?.resourceDocumentation,
        };
    }

    // ── Authentication ────────────────────────────────────────────────

    /**
     * Verify the request's access token (Bearer or DPoP) and return the
     * auth info, or throw a {@link LumoAuthChallenge} with the HTTP answer.
     */
    async authenticate(
        request: IncomingRequestLike,
        options: { requiredScopes?: string[] } = {},
    ): Promise<LumoAuthInfo> {
        const config = await this.ready();
        const required = options.requiredScopes ?? config.requiredScopes;
        const authorization = parseAuthorizationHeader(headerValue(request.headers, 'authorization'));
        const scheme = authorization ? canonicalScheme(authorization.scheme) : undefined;
        if (!authorization || !scheme) {
            throw this.challenge(config, 401, { body: 'Missing access token', scope: required });
        }

        const token = authorization.token;
        // Verify against the spelling of the resource found in the token when
        // LumoAuth would match it; the verifier checks `aud` again.
        const audience = matchingAudiences(decodePayload(token)?.aud, config.resource)[0] ?? config.resource;
        let claims: AccessTokenClaims;
        try {
            claims = await verifyAccessToken(token, {
                issuer: config.issuer,
                resource: audience,
                fetch: this.fetchFn,
                clockSkew: this.options.clockSkew,
                requireDpop: config.requireDpop,
                jwksCache: this.jwksCache,
                replayCache: this.replayCache,
                dpop: {
                    method: request.method,
                    url: this.requestUrl(request, config),
                    proof: headerValue(request.headers, 'dpop') ?? null,
                    authorizationScheme: scheme,
                },
            });
        } catch (error) {
            if (error instanceof AccessTokenError) {
                if (error.code === 'jwks_fetch_failed') {
                    throw new LumoAuthChallenge(503, undefined, {
                        error: 'temporarily_unavailable',
                        error_description: error.message,
                    });
                }
                const dpop = error.code === 'invalid_dpop_proof';
                throw this.challenge(config, 401, {
                    error: dpop ? 'invalid_dpop_proof' : 'invalid_token',
                    description:
                        token.split('.').length !== 3
                            ? 'The access token is not a JWT. Set the client to JWT access tokens in LumoAuth.'
                            : error.message,
                    dpop,
                    scope: required,
                });
            }
            throw error;
        }

        const granted = accessTokenScopes(claims);
        const missing = missingScopes(required, granted);
        if (missing.length > 0) {
            throw this.challenge(config, 403, {
                error: 'insufficient_scope',
                description: `Missing scope: ${missing.join(' ')}`,
                scope: required,
            });
        }
        // Exact-match scope checks downstream (the SDKs' requireScopes) see
        // required scopes that a granted wildcard covers.
        const scopes = [
            ...granted,
            ...config.requiredScopes.filter((s) => !granted.includes(s) && scopeCovered(s, granted)),
        ];
        return {
            token,
            clientId: claims.client_id ?? claims.sub,
            scopes,
            expiresAt: claims.exp,
            resource: new URL(config.resource),
            resourceMetadataUrl: config.resourceMetadataUrl,
            extra: { caller: toCaller(claims, scopes) },
        };
    }

    /** The public URL of a request, for the DPoP `htu` check. */
    requestUrl(request: IncomingRequestLike, config: ResolvedConfig): string {
        if (this.options.requestUrl) return this.options.requestUrl(request);
        const path = /^https?:\/\//i.test(request.url) ? new URL(request.url).pathname : request.url.split('?')[0];
        return `${config.publicOrigin}${path.startsWith('/') ? path : `/${path}`}`;
    }

    /** Build the refusal for a status, in LumoAuth's challenge format. */
    challenge(
        config: ResolvedConfig,
        status: 401 | 403,
        details: { error?: string; description?: string; body?: string; scope?: string[]; dpop?: boolean } = {},
    ): LumoAuthChallenge {
        const scheme = config.requireDpop || details.dpop ? 'DPoP' : 'Bearer';
        const params: Array<[string, string]> = [];
        if (details.error) params.push(['error', details.error]);
        if (details.description) params.push(['error_description', details.description]);
        const scope = details.scope && details.scope.length > 0 ? details.scope : config.scopesSupported;
        if (scope.length > 0) params.push(['scope', scope.join(' ')]);
        params.push(['resource_metadata', config.resourceMetadataUrl]);
        if (scheme === 'DPoP') params.push(['algs', config.dpopAlgs.join(' ')]);
        const header = `${scheme} ${params.map(([key, value]) => `${key}="${quoted(value)}"`).join(', ')}`;
        return new LumoAuthChallenge(status, header, {
            error: details.error ?? 'invalid_token',
            error_description: details.description ?? details.body,
        });
    }

    // ── Discovery documents ───────────────────────────────────────────

    /** The RFC 9728 document this server publishes. */
    async protectedResourceMetadata(): Promise<Record<string, unknown>> {
        const config = await this.ready();
        const document: Record<string, unknown> = {
            resource: config.resource,
            // RFC 9728: issuer identifiers. MCP clients find LumoAuth's
            // metadata from it ({issuer}/.well-known/openid-configuration).
            authorization_servers: [config.issuer],
            bearer_methods_supported: ['header'],
        };
        if (config.scopesSupported.length > 0) document.scopes_supported = config.scopesSupported;
        if (config.resourceName) document.resource_name = config.resourceName;
        if (config.resourceDocumentation) document.resource_documentation = config.resourceDocumentation;
        if (config.requireDpop) {
            document.dpop_bound_access_tokens_required = true;
            document.dpop_signing_alg_values_supported = config.dpopAlgs;
        }
        return document;
    }

    /** LumoAuth's authorization server metadata, cached for an hour. */
    async authorizationServerMetadata(): Promise<unknown> {
        if (this.asMetadata && Date.now() - this.asMetadata.at < METADATA_TTL_MS) return this.asMetadata.document;
        const url = `${this.issuer}/.well-known/oauth-authorization-server`;
        let response: Response;
        try {
            response = await this.fetchFn(url, { headers: { Accept: 'application/json' } });
        } catch (error) {
            throw new LumoAuthNetworkError(`Cannot reach LumoAuth at ${url}: ${(error as Error).message}`, error);
        }
        if (!response.ok) throw new LumoAuthConfigError(`LumoAuth answered HTTP ${response.status} for ${url}.`);
        const document: unknown = await response.json();
        this.asMetadata = { at: Date.now(), document };
        return document;
    }

    /**
     * Answer a request for one of this server's discovery documents, or
     * return `undefined` when the path is not one of them.
     */
    async discoveryResponse(method: string, pathname: string): Promise<SimpleResponse | undefined> {
        const config = await this.ready();
        const metadataPath = new URL(config.resourceMetadataUrl).pathname;
        const isResource = pathname === metadataPath;
        const isServer =
            this.options.authorizationServerMetadata !== false && pathname === '/.well-known/oauth-authorization-server';
        if (!isResource && !isServer) return undefined;

        const cors = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Authorization, Content-Type, MCP-Protocol-Version',
        };
        if (method === 'OPTIONS') return { status: 204, headers: cors };
        if (method !== 'GET' && method !== 'HEAD') {
            return { status: 405, headers: { ...cors, Allow: 'GET, OPTIONS' } };
        }
        try {
            const document = isResource ? await this.protectedResourceMetadata() : await this.authorizationServerMetadata();
            return {
                status: 200,
                headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' },
                body: JSON.stringify(document),
            };
        } catch (error) {
            return {
                status: 502,
                headers: { ...cors, 'Content-Type': 'application/json' },
                body: JSON.stringify({ error: 'server_error', error_description: (error as Error).message }),
            };
        }
    }
}
