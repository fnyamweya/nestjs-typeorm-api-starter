#!/usr/bin/env bash
set -euo pipefail

echo "Running migrations (first pass)..."
npx ts-node -r tsconfig-paths/register ./node_modules/typeorm/cli.js migration:run -d src/data-source.ts

echo "Running migrations (second pass to ensure idempotency)..."
npx ts-node -r tsconfig-paths/register ./node_modules/typeorm/cli.js migration:run -d src/data-source.ts

echo "Listing migrations..."
npx ts-node -r tsconfig-paths/register ./node_modules/typeorm/cli.js migration:show -d src/data-source.ts

echo "Migration idempotency check finished."
