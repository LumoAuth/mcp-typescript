/**
 * Programmatic API of `lumoauth secure`: the authenticating proxy and the
 * stdio bridge, for embedding them in your own process.
 */
export { allowedToolNames, createSecureProxy, type ProxyOptions } from './proxy';
export { createExtAuthzServer, type ExtAuthzOptions } from './ext-authz';
export { StdioBridge, type StdioBridgeOptions } from './stdio';
export { startUpstream, waitForUpstream } from './supervise';
export {
    filterJsonBody,
    filterSseEvent,
    inspect,
    refusedJitToolResult,
    refusedToolResult,
    type Inspection,
} from './jsonrpc';
export { main } from './cli';
