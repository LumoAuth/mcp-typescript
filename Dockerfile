# Multi-stage container build for `lumoauth` (MCP reverse proxy & Envoy ext_authz server)
FROM node:22-alpine AS builder
WORKDIR /build

COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/mcp/package.json packages/mcp/
COPY packages/lumoauth/package.json packages/lumoauth/

RUN npm ci --ignore-scripts
COPY packages/ packages/
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    PORT=8080

COPY --from=builder /build/package.json ./
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/packages/mcp/package.json ./packages/mcp/package.json
COPY --from=builder /build/packages/mcp/dist ./packages/mcp/dist
COPY --from=builder /build/packages/lumoauth/package.json ./packages/lumoauth/package.json
COPY --from=builder /build/packages/lumoauth/dist ./packages/lumoauth/dist

USER 65532:65532
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

ENTRYPOINT ["node", "packages/lumoauth/dist/bin.js"]
CMD ["secure", "--help"]
