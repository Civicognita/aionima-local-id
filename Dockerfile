# Build stage
FROM node:22-slim AS builder

WORKDIR /app

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

COPY tsconfig.json ./
COPY drizzle.config.ts ./
COPY src/ ./src/

RUN pnpm build

# Generate migrations from schema (if not already committed)
RUN pnpm db:generate || true

# Runtime stage
FROM node:22-slim AS runner

WORKDIR /app

ENV NODE_ENV=production

# Install pnpm for production install
RUN corepack enable && corepack prepare pnpm@latest --activate

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile --prod

# Also install drizzle-kit for runtime migrations
RUN pnpm add drizzle-kit

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/drizzle ./drizzle
COPY src/views/*.html ./dist/views/
COPY drizzle.config.ts ./

# Startup script: migrate then run
COPY start.sh ./
RUN chmod +x start.sh

EXPOSE 3000

CMD ["./start.sh"]
