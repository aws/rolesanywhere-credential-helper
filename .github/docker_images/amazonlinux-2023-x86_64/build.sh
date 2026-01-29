#!/bin/bash
set -e

# Build script for Amazon Linux 2023 x86_64 Docker image
# Usage: ./build.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="rolesanywhere-credential-helper-al2023-x86_64-builder"
IMAGE_TAG="latest"

echo "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"

# Build for x86_64
docker buildx build \
    --platform linux/amd64 \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    --load \
    "${SCRIPT_DIR}"

echo "Build complete."