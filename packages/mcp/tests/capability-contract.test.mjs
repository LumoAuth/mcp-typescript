// normalizeCapability and capabilityCovered must answer exactly as the
// LumoAuth server does. The contract cases
// (sdk-contract/vectors/agent-capabilities.json) are checked against the
// server's own matcher by the contract repo. The test is skipped when no
// contract checkout is found: set LUMO_SDK_CONTRACT or keep sdk-contract next
// to this repository.
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { capabilityCovered, normalizeCapability } from '../dist/index.mjs';

const candidates = [
    process.env.LUMO_SDK_CONTRACT,
    fileURLToPath(new URL('../../../../sdk-contract', import.meta.url)),
].filter(Boolean);
const vectorPath = candidates
    .map((dir) => join(dir, 'vectors', 'agent-capabilities.json'))
    .find((path) => existsSync(path));

test('capability matching follows the contract cases', { skip: vectorPath ? false : 'sdk-contract not found (set LUMO_SDK_CONTRACT)' }, () => {
    const vector = JSON.parse(readFileSync(vectorPath, 'utf8'));
    const failures = [];
    for (const c of vector.normalize) {
        const got = normalizeCapability(c.input);
        if (got !== c.expected) failures.push(`normalize ${JSON.stringify(c)}: got ${JSON.stringify(got)}`);
    }
    for (const c of vector.covers) {
        const got = capabilityCovered(c.action, [c.capability]);
        if (got !== c.expected) failures.push(`covers ${JSON.stringify(c)}: got ${got}`);
    }
    for (const c of vector.any_covers) {
        const got = capabilityCovered(c.action, c.capabilities);
        if (got !== c.expected) failures.push(`any_covers ${JSON.stringify(c)}: got ${got}`);
    }
    assert.ok(vector.normalize.length && vector.covers.length && vector.any_covers.length);
    assert.deepEqual(failures, []);
});
