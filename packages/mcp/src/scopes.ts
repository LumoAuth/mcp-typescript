/**
 * LumoAuth's matching rules for scopes and agent capabilities.
 */

/**
 * `true` when `required` is granted exactly or by a `prefix:*` scope, the one
 * wildcard rule LumoAuth has (`McpAuthorizationController::scopeCovered`):
 * `invoices:*` covers `invoices:refund` and `invoices:refund:partial`, never
 * `invoices` itself. Every other scope compares exactly, so `invoices.*` is
 * an ordinary scope.
 */
export function scopeCovered(required: string, granted: readonly string[]): boolean {
    for (const scope of granted) {
        if (scope === required) return true;
        if (scope.endsWith(':*')) {
            const prefix = scope.slice(0, -1); // keeps the ':'
            if (prefix !== ':' && required.startsWith(prefix) && required.length > prefix.length) return true;
        }
    }
    return false;
}

/** The entries of `required` that `granted` does not cover, in order. */
export function missingScopes(required: readonly string[], granted: readonly string[]): string[] {
    return required.filter((scope) => !scopeCovered(scope, granted));
}

function normalizeCapability(capability: string): string {
    return capability
        .trim()
        .toLowerCase()
        .replace(/[:-]/g, '.')
        .replace(/\.{2,}/g, '.')
        .replace(/^\.+|\.+$/g, '');
}

/**
 * LumoAuth's agent capability match (`AgentCapability::covers`): canonical
 * form (lower case, `:` and `-` read as `.`); `*` covers everything and
 * `users.*` covers `users.delete` but not `users`.
 */
export function capabilityCovered(required: string, granted: readonly string[]): boolean {
    const wanted = normalizeCapability(required);
    if (wanted === '') return false;
    return granted.some((capability) => {
        const have = normalizeCapability(capability);
        if (have === '') return false;
        if (have === '*' || have === wanted) return true;
        return have.endsWith('.*') && wanted.startsWith(have.slice(0, -1));
    });
}
