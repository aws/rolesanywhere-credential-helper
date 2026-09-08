#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="${VERSION:-$(grep '^VERSION=' "${REPO_ROOT}/Makefile" | cut -d'=' -f2)}"
GO_VERSION="${GO_VERSION:-$(grep '^toolchain' "${REPO_ROOT}/go.mod" | awk '{print $2}' | sed 's/go//')}"
if [ -z "${GO_VERSION}" ]; then
  GO_VERSION=$(grep '^go ' "${REPO_ROOT}/go.mod" | awk '{print $2}')
fi

REGISTRY="${REGISTRY:-local}"
REPOSITORY="${REPOSITORY:-iamra-credential-helper}"

case "$(uname -m)" in
  x86_64|amd64)   PLATFORM=amd64 ;;
  aarch64|arm64)  PLATFORM=arm64 ;;
  *) echo "Error: unsupported platform $(uname -m)"; exit 1 ;;
esac

echo "Building ${REGISTRY}/${REPOSITORY}:${VERSION} for ${PLATFORM} (Go ${GO_VERSION})..."
docker buildx build \
  --platform "linux/${PLATFORM}" \
  --load \
  --build-arg "VERSION=${VERSION}" \
  --build-arg "GO_VERSION=${GO_VERSION}" \
  -t "${REGISTRY}/${REPOSITORY}:${VERSION}-${PLATFORM}" \
  -t "${REGISTRY}/${REPOSITORY}:${VERSION}" \
  -f "${SCRIPT_DIR}/Dockerfile" \
  "${REPO_ROOT}"

echo "Build complete: ${REGISTRY}/${REPOSITORY}:${VERSION}"
