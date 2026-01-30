#!/bin/bash
set -e

# Build script for Amazon Linux 2023 aarch64 Docker image
# Usage: ./build.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="rolesanywhere-credential-helper-al2023-aarch64-builder"
IMAGE_TAG="latest"

echo "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"

# Build for aarch64
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
docker buildx build \
    --platform linux/arm64 \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    --load \
    "${WORKSPACE_ROOT}"

echo "Build complete."