/**
 * @lumoauth/mcp — LumoAuth authentication and authorization for MCP servers
 * built with the official TypeScript SDK (v1 `@modelcontextprotocol/sdk` and
 * v2 `@modelcontextprotocol/server`).
 *
 * ```ts
 * import { lumoAuth } from '@lumoauth/mcp';
 *
 * const auth = lumoAuth();                  // LUMOAUTH_ORG_ID + LUMOAUTH_MCP_SERVER_ID
 * app.use(auth.router());                   // RFC 9728 discovery
 * app.post('/mcp', auth.protect(), mcp);    // 401 challenge, Bearer + DPoP, req.auth
 * ```
 */

import { LumoMcpAuth, type LumoMcpAuthOptions } from './auth';

/** Create the LumoAuth integration for one MCP server. */
export function lumoAuth(options: LumoMcpAuthOptions = {}): LumoMcpAuth {
    return new LumoMcpAuth(options);
}

export {
    LumoMcpAuth,
    DEFAULT_LUMOAUTH_URL,
    headerValue,
    type LumoMcpAuthOptions,
    type LumoAuthInfo,
    type LumoCaller,
    type ResolvedConfig,
    type IncomingRequestLike,
    type HeadersLike,
} from './auth';
export { LumoAuthChallenge, type SimpleResponse } from './challenge';
export { challengeResponse, discoveryFetchResponse, fetchGate } from './fetch';
export {
    discoveryMiddleware,
    protectMiddleware,
    writeChallenge,
    type NodeMiddleware,
    type NodeRequestLike,
    type NodeResponseLike,
    type NextFunction,
} from './node';
export {
    DEFAULT_DPOP_ALGS,
    fetchRegistration,
    registrationFromMetadata,
    registrationUrl,
    type Registration,
} from './registration';
export {
    matchingAudiences,
    normalizeResource,
    originOf,
    protectedResourceMetadataUrl,
    sameResource,
} from './resource';
export { capabilityCovered, missingScopes, scopeCovered } from './scopes';
export {
    MCP_AUTHORIZE_SCOPE,
    ServerToken,
    ToolAccessDeniedError,
    ToolPolicy,
    checkToolAccess,
    getAuthInfo,
    getCaller,
    guardHandler,
    lumoScopeChallenge,
    secureServerTools,
    type GuardOptions,
    type SecureToolsOptions,
    type ToolPolicyOptions,
} from './tools';
