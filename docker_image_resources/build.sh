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

if ! command -v docker &> /dev/null; then
  echo "Docker not found, installing..."
  # Docker installation retrieved from source: https://docs.docker.com/engine/install/ubuntu/
  # Add Docker's official GPG key
  apt-get update
  apt-get install -y ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  # Add the repository to Apt sources
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update

  # Install Docker packages
  # Pinned to most recent stable ubuntu version
  VERSION_STRING=5:28.2.2-1~ubuntu.24.04~noble
  apt-get install docker-ce=$VERSION_STRING docker-ce-cli=$VERSION_STRING containerd.io docker-buildx-plugin docker-compose-plugin

  # Add user to the docker group
  groupadd docker 2>/dev/null || true
  usermod -aG docker $USER
  
  # Change current group ID to docker's
  echo "Changing current user group to docker user group. If script exits call ./build.sh to continue the build"
  newgrp docker

  echo "Docker installed successfully"
else
  echo "Docker already installed: $(docker --version)"
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