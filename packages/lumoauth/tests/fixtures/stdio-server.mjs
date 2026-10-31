// A stdio MCP server without any authentication, for the bridge tests.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const server = new McpServer({ name: 'stdio-fixture', version: '1.0.0' });
server.registerTool('whoami', { description: 'Process id' }, async () => ({
    content: [{ type: 'text', text: `pid ${process.pid}` }],
}));
server.registerTool('export', { description: 'Export everything' }, async () => ({
    content: [{ type: 'text', text: 'exported' }],
}));
await server.connect(new StdioServerTransport());
