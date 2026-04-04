#!/bin/sh
set -e

echo "Running database migrations..."
npx drizzle-kit migrate 2>&1 || echo "Migration warning (may already be applied)"

echo "Starting Aionima ID Service..."
exec node dist/index.js
