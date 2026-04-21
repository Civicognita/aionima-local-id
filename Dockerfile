# Build stage — compile TS → dist/ and generate migrations from bundled schema.
FROM node:22-slim AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

# Schema files are bundled at build time from the sibling @agi/db-schema
# package in the AGI workspace. The sync-schema.sh script copies source
# files into src/db/schema/; they're committed to this repo so the build
# doesn't require the sibling repo at image-build time.
COPY tsconfig.json drizzle.config.ts ./
COPY scripts/ ./scripts/
COPY src/ ./src/

RUN npm run build

# Regenerate drizzle migrations against the (possibly-updated) bundled schema.
# Idempotent — drizzle-kit only emits a new migration if the schema shape changes.
RUN npx drizzle-kit generate || true

# Runtime stage — production deps only plus drizzle-kit for boot-time migrate.
FROM node:22-slim AS runner

WORKDIR /app

ENV NODE_ENV=production
# Local-ID listens on 3200 per the production .env; the Dockerfile only
# documents it — the actual bind port comes from the PORT env var.
ENV PORT=3200

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm install drizzle-kit

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/drizzle ./drizzle
COPY src/views/*.html ./dist/views/
COPY drizzle.config.ts ./

# Startup script: migrate then run
COPY start.sh ./
RUN chmod +x start.sh

EXPOSE 3200

CMD ["./start.sh"]
