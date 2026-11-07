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

// The server trims with PHP's trim() default set: space, tab, LF, CR, NUL and
// vertical tab. String.prototype.trim() strips a different set (Unicode
// spaces, but not NUL).
const CAPABILITY_TRIM = /^[ \t\n\r\0\x0B]+|[ \t\n\r\0\x0B]+$/g;

/**
 * A capability in the form that the server stores: trimmed, ASCII letters in
 * lower case, `:` and `-` turned into `.`, runs of `.` collapsed, `.` trimmed
 * from both ends. `'Invoices:Read'` and `'invoices-read'` both become
 * `'invoices.read'`. Only ASCII letters are lower-cased, as on the server, so
 * `'Ünits.Read'` becomes `'Ünits.read'`.
 */
export function normalizeCapability(capability: string): string {
    return capability
        .replace(CAPABILITY_TRIM, '')
        .replace(/[A-Z]/g, (letter) => letter.toLowerCase())
        .replace(/[:-]/g, '.')
        .replace(/\.{2,}/g, '.')
        .replace(/^\.+|\.+$/g, '');
}

/**
 * LumoAuth's agent capability match (`AgentCapability::covers`), in the
 * stored form of {@link normalizeCapability}: `*` covers everything, and
 * `users.*` covers `users.delete` but not `users`. Entries of `granted` that
 * are not strings are ignored.
 */
export function capabilityCovered(required: string, granted: readonly string[]): boolean {
    const wanted = normalizeCapability(required);
    if (wanted === '') return false;
    return granted.some((capability) => {
        if (typeof capability !== 'string') return false;
        const have = normalizeCapability(capability);
        if (have === '') return false;
        if (have === '*' || have === wanted) return true;
        return have.endsWith('.*') && wanted.startsWith(have.slice(0, -1));
    });
}
