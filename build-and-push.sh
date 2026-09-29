#!/usr/bin/env bash
# Publish the vulnerable MCP server so Obot can run it as a Container-runtime custom server.
# Run this ONCE during facilitator prep, before the workshop.
#
# Usage:
#   IMAGE=ghcr.io/<your-org>/vuln-support-mcp:latest ./build-and-push.sh
#
# Then in the workshop, participants add a custom MCP server in Obot with:
#   runtime = Container, image = $IMAGE, port = 8000, path = /mcp
set -euo pipefail

IMAGE="${IMAGE:-ghcr.io/obotchris/vuln-support-mcp:latest}"

echo ">> Building $IMAGE (linux/amd64 for Obot's runtime)"
# --platform ensures the image runs on Obot's amd64 hosts even if you build on Apple Silicon.
docker buildx build --platform linux/amd64 -t "$IMAGE" --push .

echo ">> Pushed $IMAGE"
echo ">> In Obot: Add Server -> runtime Container, image $IMAGE, port 8000, path /mcp"
