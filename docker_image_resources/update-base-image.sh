#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile"

IMAGE="public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-glibc"
TAG="latest-al23"

echo "Pulling ${IMAGE}:${TAG}..."
docker pull "${IMAGE}:${TAG}"

DIGEST=$(docker inspect "${IMAGE}:${TAG}" --format '{{index .RepoDigests 0}}' | cut -d'@' -f2)
CREATED=$(docker inspect "${IMAGE}:${TAG}" --format '{{.Created}}' | cut -d'T' -f1)

echo "Digest: ${DIGEST}"
echo "Created: ${CREATED}"

NEW_REF="${IMAGE}:${TAG}@${DIGEST}"

sed -i.bak "s|FROM --platform=\$TARGETPLATFORM ${IMAGE}:[^ ]*|FROM --platform=\$TARGETPLATFORM ${NEW_REF}|" "${DOCKERFILE}"
rm "${DOCKERFILE}.bak"

echo "Updated Dockerfile to ${NEW_REF}"
