# syntax=docker/dockerfile:1
# Multi-arch build:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t <registry>/web-app:<tag> --push .

ARG BUILDPLATFORM

FROM --platform=$BUILDPLATFORM node:20.19-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --no-audit --fund=false; else npm install --no-audit --fund=false; fi

FROM --platform=$BUILDPLATFORM node:20.19-bookworm-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20.19-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=8080 \
    HOSTNAME=0.0.0.0
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 --ingroup nodejs nextjs
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
USER nextjs
EXPOSE 8080
CMD ["node", "server.js"]
