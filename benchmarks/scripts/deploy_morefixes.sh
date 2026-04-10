#!/usr/bin/env bash
# Deploy MoreFixes Postgres dump via docker-compose.
# Idempotent — skips download if dump already present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DUMP_DIR="$ROOT_DIR/external/morefixes/dump"
ZIP_FILE="$DUMP_DIR/postgrescvedumper.sql.zip"
DUMP_FILE="$DUMP_DIR/postgrescvedumper.sql"
ZENODO_URL="https://zenodo.org/api/records/13983082/files/postgrescvedumper.sql.zip/content"
COMPOSE_FILE="$ROOT_DIR/external/morefixes/docker-compose.yml"

mkdir -p "$DUMP_DIR"

if [ ! -f "$DUMP_FILE" ]; then
    if [ ! -f "$ZIP_FILE" ]; then
        echo "Downloading MoreFixes dump from Zenodo ..."
        echo "(This is a 3.5 GB zip — be patient)"
        curl -L --output "$ZIP_FILE" "$ZENODO_URL"
    else
        echo "Zip already present: $ZIP_FILE"
    fi

    echo "Extracting SQL dump from zip ..."
    unzip -o "$ZIP_FILE" -d "$DUMP_DIR"

    # Find the extracted SQL file (name may vary)
    EXTRACTED=$(find "$DUMP_DIR" -name '*.sql' -not -name '*.sql.zip' | head -1)
    if [ -z "$EXTRACTED" ]; then
        echo "ERROR: no .sql file found after extraction" >&2
        exit 1
    fi
    if [ "$EXTRACTED" != "$DUMP_FILE" ]; then
        mv "$EXTRACTED" "$DUMP_FILE"
    fi
    echo "SQL dump ready: $DUMP_FILE"
else
    echo "Dump already present: $DUMP_FILE"
fi

echo "Starting docker-compose ..."
docker compose -f "$COMPOSE_FILE" up -d

echo ""
echo "Waiting for Postgres to finish loading the dump ..."
echo "(First-time load may take 10-20 minutes.)"

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
