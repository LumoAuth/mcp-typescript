import { defineConfig } from 'tsup';

export default defineConfig([
    {
        entry: { cli: 'src/bin.ts' },
        format: ['cjs'],
        platform: 'node',
        clean: true,
        sourcemap: true,
        banner: { js: '#!/usr/bin/env node' },
    },
    {
        entry: { index: 'src/index.ts' },
        format: ['cjs', 'esm'],
        platform: 'node',
        dts: true,
        sourcemap: true,
    },
]);
