import { LumoAuthConfigError, LumoAuthNetworkError } from '@lumoauth/shared';

/**
 * An MCP server's registration, as LumoAuth publishes it.
 *
 * LumoAuth serves each registered server's protected resource metadata
 * (RFC 9728) at `{issuer}/.well-known/oauth-protected-resource/mcp/{serverId}`.
 * That public document holds everything a resource server needs from the
 * registration: the Resource URI (the token audience), the advertised scopes
 * and whether only DPoP-bound tokens are accepted.
 */
export interface Registration {
    /** The registered Resource URI: the `aud` of tokens for this server. */
    resource: string;
    /** The scopes LumoAuth advertises for the server (its basic scopes). */
    scopesSupported: string[];
    /** The registration's *Require DPoP* switch. */
    requireDpop: boolean;
    /** DPoP proof algorithms the authorization server accepts. */
    dpopAlgs: string[];
    resourceName?: string;
    resourceDocumentation?: string;
}

/** The proof algorithms LumoAuth accepts (`McpServer::DPOP_PROOF_ALGS`). */
export const DEFAULT_DPOP_ALGS = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'EdDSA'];

function strings(value: unknown): string[] {
    return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string' && v !== '') : [];
}

/** Read a protected resource metadata document. */
export function registrationFromMetadata(document: unknown): Registration {
    if (typeof document !== 'object' || document === null || Array.isArray(document)) {
        throw new LumoAuthConfigError('The MCP server metadata is not a JSON object.');
    }
    const doc = document as Record<string, unknown>;
    if (typeof doc.resource !== 'string' || doc.resource === '') {
        throw new LumoAuthConfigError("The MCP server metadata has no 'resource'.");
    }
    const algs = strings(doc.dpop_signing_alg_values_supported);
    return {
        resource: doc.resource,
        scopesSupported: strings(doc.scopes_supported),
        requireDpop: doc.dpop_bound_access_tokens_required === true,
        dpopAlgs: algs.length > 0 ? algs : [...DEFAULT_DPOP_ALGS],
        resourceName: typeof doc.resource_name === 'string' && doc.resource_name ? doc.resource_name : undefined,
        resourceDocumentation:
            typeof doc.resource_documentation === 'string' && doc.resource_documentation ? doc.resource_documentation : undefined,
    };
}

/** URL of LumoAuth's hosted metadata document for one MCP server. */
export function registrationUrl(issuer: string, serverId: string): string {
    return `${issuer.replace(/\/+$/, '')}/.well-known/oauth-protected-resource/mcp/${encodeURIComponent(serverId)}`;
}

/** Fetch and read the registration of `serverId`. */
export async function fetchRegistration(
    issuer: string,
    serverId: string,
    fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<Registration> {
    const url = registrationUrl(issuer, serverId);
    let response: Response;
    try {
        response = await fetchFn(url, { headers: { Accept: 'application/json' } });
    } catch (error) {
        throw new LumoAuthNetworkError(`Cannot reach LumoAuth at ${url}: ${(error as Error).message}`, error);
    }
    if (response.status === 404) {
        throw new LumoAuthConfigError(
            `LumoAuth has no active MCP server '${serverId}' at ${issuer}. Check LUMOAUTH_MCP_SERVER_ID and ` +
                "LUMOAUTH_ORG_ID: the server id is shown on the server's page under AI Agents > MCP servers.",
        );
    }
    if (response.status === 400) {
        throw new LumoAuthConfigError(
            `MCP server '${serverId}' is registered as Public, so LumoAuth issues no tokens for it. ` +
                "Switch its authorization mode to 'OAuth 2.1 protected'.",
        );
    }
    if (!response.ok) {
        throw new LumoAuthConfigError(`LumoAuth answered HTTP ${response.status} for ${url}.`);
    }
    return registrationFromMetadata(await response.json());
}
