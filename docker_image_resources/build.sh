#!/bin/bash
set -euo pipefail

# Configuration
VERSION="${VERSION:-latest}"
REGISTRY="${REGISTRY:-local}"
REPOSITORY="${REPOSITORY:-iamra-credential-helper}"

if [ $(uname -m) = "x86_64" ]; then
  PLATFORM=amd64
elif [ $(uname -m) = "aarch64" ]; then
  PLATFORM=arm64
else
  echo "Error: Invalid platform. Supported platforms are arm64 and amd64 linux."
  exit 1
fi

# Set platform-specific build arguments
PLATFORM_ARG="--platform=linux/${PLATFORM}"

# Build the image
echo "Building ${REGISTRY}/${REPOSITORY}:${VERSION} for ${PLATFORM}..."
echo ${PLATFORM_ARG}
docker buildx build \
  ${PLATFORM_ARG} \
  --load \
  -t "${REGISTRY}/${REPOSITORY}:${VERSION}-${PLATFORM}" \
  -t "${REGISTRY}/${REPOSITORY}:${VERSION}" \
  -f Dockerfile \
  ..

echo "Build completed successfully"
echo "Created tags:"
echo "- ${REGISTRY}/${REPOSITORY}:${VERSION}-${PLATFORM} (platform-specific)"
echo "- ${REGISTRY}/${REPOSITORY}:${VERSION} (default)"
