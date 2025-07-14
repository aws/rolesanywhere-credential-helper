#!/bin/bash
set -euo pipefail

# Configuration
VERSION="${VERSION:-latest}"
REGISTRY="${REGISTRY:-local}"
IMAGE_NAME="${IMAGE_NAME:-iamra-credential-helper}"

if [ $(uname -m) = "x86_64" ]; then
  PLATFORM=amd64
elif [ $(uname -m) = "aarch64" ]; then
  PLATFORM=arm64
else
  echo "Error: Invalid platform. Supported values are 'amd64' or 'arm64'"
  exit 1
fi

# Set platform-specific build arguments
PLATFORM_ARG="--platform=linux/${PLATFORM}"

# Build the image
echo "Building ${REGISTRY}/${IMAGE_NAME}:${VERSION} for ${PLATFORM}..."
echo ${PLATFORM_ARG}
docker buildx build \
  ${PLATFORM_ARG} \
  --load \
  -t "${REGISTRY}/${IMAGE_NAME}:${VERSION}-${PLATFORM}" \
  -t "${REGISTRY}/${IMAGE_NAME}:${VERSION}" \
  -f Dockerfile \
  ..

echo "Build completed successfully"
echo "Created tags:"
echo "- ${REGISTRY}/${IMAGE_NAME}:${VERSION}-${PLATFORM} (platform-specific)"
echo "- ${REGISTRY}/${IMAGE_NAME}:${VERSION} (default)"