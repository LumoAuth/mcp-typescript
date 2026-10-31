/**
 * Resource URI helpers.
 *
 * LumoAuth puts the client's `resource` parameter into the token's `aud` as
 * the client spelled it, so `https://mcp.example.com` and
 * `https://mcp.example.com/` can both appear for one registration. Audiences
 * are therefore compared the way LumoAuth compares resource URIs
 * (`McpResourceEnforcementService::normalizeResourceUri`), not byte for byte.
 */

/**
 * Comparison form of a resource URI: lower-cased scheme and host, default
 * port dropped, trailing slashes stripped from the path, query kept,
 * fragment dropped. Path and query case stay significant.
 */
export function normalizeResource(uri: string): string {
    const trimmed = uri.trim();
    let url: URL;
    try {
        url = new URL(trimmed);
    } catch {
        return trimmed.replace(/\/+$/, '');
    }
    if (!url.hostname) return trimmed.replace(/\/+$/, '');
    // WHATWG URL already lower-cases scheme and host and drops default ports.
    const auth = url.username ? `${url.username}${url.password ? `:${url.password}` : ''}@` : '';
    const port = url.port ? `:${url.port}` : '';
    const path = url.pathname.replace(/\/+$/, '');
    return `${url.protocol}//${auth}${url.hostname}${port}${path}${url.search}`;
}

/** `true` when two resource URIs name the same resource. */
export function sameResource(a: string, b: string): boolean {
    return normalizeResource(a) === normalizeResource(b);
}

/** The entries of an `aud` claim that name `resource`, in token order. */
export function matchingAudiences(aud: unknown, resource: string): string[] {
    const values = typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud : [];
    return values.filter((a): a is string => typeof a === 'string' && a !== '' && sameResource(a, resource));
}

/** `scheme://host[:port]` of an absolute URL. */
export function originOf(url: string): string {
    return new URL(url).origin;
}

/**
 * The RFC 9728 metadata URL of a resource: the well-known segment goes
 * between the host and the path (`https://x.com/mcp` →
 * `https://x.com/.well-known/oauth-protected-resource/mcp`). Same rule as the
 * MCP SDK's `getOAuthProtectedResourceMetadataUrl`.
 */
export function protectedResourceMetadataUrl(resource: string): string {
    const url = new URL(resource);
    const path = url.pathname === '/' ? '' : url.pathname;
    return `${url.origin}/.well-known/oauth-protected-resource${path}`;
}
