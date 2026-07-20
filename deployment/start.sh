#!/bin/sh
set -e

echo "Deploying NetFusion Platform with Docker Compose..."
docker-compose -f deployment/docker-compose.yml up -d --build
echo "NetFusion Platform services started successfully."
