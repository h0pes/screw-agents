#!/usr/bin/env bash
# Deploy MoreFixes Postgres dump via docker-compose.
# Idempotent — skips download if dump already present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DUMP_DIR="$ROOT_DIR/external/morefixes/dump"
DUMP_FILE="$DUMP_DIR/postgrescvedumper-2024-09-26.sql"
ZENODO_URL="https://zenodo.org/record/13983082/files/postgrescvedumper-2024-09-26.sql"
COMPOSE_FILE="$ROOT_DIR/external/morefixes/docker-compose.yml"

mkdir -p "$DUMP_DIR"

if [ ! -f "$DUMP_FILE" ]; then
    echo "Downloading MoreFixes dump from $ZENODO_URL ..."
    echo "(This is a 16 GB file — be patient)"
    curl -L --output "$DUMP_FILE" "$ZENODO_URL"
else
    echo "Dump already present: $DUMP_FILE"
fi

echo "Starting docker-compose ..."
docker compose -f "$COMPOSE_FILE" up -d

echo ""
echo "Waiting for Postgres to finish loading the dump ..."
echo "(First-time load may take 10-20 minutes for 16 GB.)"

for i in {1..120}; do
    if docker compose -f "$COMPOSE_FILE" exec -T morefixes-db pg_isready -U morefixes -d morefixes >/dev/null 2>&1; then
        echo "Database is ready."
        break
    fi
    sleep 15
    if [ $i -eq 120 ]; then
        echo "ERROR: database did not become ready after 30 minutes" >&2
        exit 1
    fi
done

echo ""
echo "Verify with: docker compose -f $COMPOSE_FILE exec morefixes-db psql -U morefixes -d morefixes -c '\\dt'"
