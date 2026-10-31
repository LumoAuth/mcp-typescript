import { spawn, type ChildProcess } from 'node:child_process';
import { connect } from 'node:net';

/** Start the command that runs the upstream MCP server, sharing our stdio and environment. */
export function startUpstream(command: string[]): ChildProcess {
    const [file, ...args] = command;
    return spawn(file, args, { stdio: 'inherit', env: process.env });
}

function canConnect(host: string, port: number): Promise<boolean> {
    return new Promise((resolve) => {
        const socket = connect({ host, port });
        socket.setTimeout(1000);
        socket.once('connect', () => {
            socket.destroy();
            resolve(true);
        });
        socket.once('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        socket.once('error', () => resolve(false));
    });
}

/** Wait until the upstream accepts TCP connections, or fail when its process exits. */
export async function waitForUpstream(url: string, child: ChildProcess | undefined, timeoutMs = 30_000): Promise<void> {
    const target = new URL(url);
    const host = target.hostname.replace(/^\[|\]$/g, '');
    const port = Number(target.port) || (target.protocol === 'https:' ? 443 : 80);
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (child && child.exitCode !== null) {
            throw new Error(`the upstream command exited with code ${child.exitCode} before it started listening`);
        }
        if (await canConnect(host, port)) return;
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error(`nothing accepted connections at ${target.host} within ${Math.round(timeoutMs / 1000)} s`);
}
