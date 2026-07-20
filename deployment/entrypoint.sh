#!/bin/sh
set -e

echo "Starting NetFusion Production Service Container..."
mkdir -p /app/data /app/backups

exec "$@"
