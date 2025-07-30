#!/bin/bash
set -euo pipefail

if [ $(uname -m) = "x86_64" ]; then
  PLATFORM=amd64
elif [ $(uname -m) = "aarch64" ]; then
  PLATFORM=arm64
else
  echo "Error: Invalid platform. Supported values are 'amd64' or 'arm64'"
  exit 1
fi

echo "Beginning dependency installation and verification"

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
  DOCKER_VERSION=5:28.2.2-1~ubuntu.24.04~noble
  apt-get install docker-ce=$DOCKER_VERSION docker-ce-cli=$DOCKER_VERSION containerd.io docker-buildx-plugin docker-compose-plugin

  # Add user to the docker group
  groupadd docker 2>/dev/null || true
  usermod -aG docker $USER
  
  # Change current group ID to docker's
  echo "Changing current user group to docker user group. If script exits call ./setup-dependencies.sh to continue the build"
  newgrp docker

  echo "Docker installed successfully"
else
  echo "Docker already installed: $(docker --version)"
fi

# Check and install Kind if neededAdd commentMore actions
if ! command -v kind &> /dev/null; then
  echo "kind not found, installing..."
  KIND_VERSION="v0.29.0"
  # Download kind binary
  curl -LO "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${PLATFORM}"
  
  # Download and verify checksum
  echo "Verifying kind checksum..."
  curl -LO "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-${PLATFORM}.sha256sum"
  if ! sha256sum -c kind-linux-${PLATFORM}.sha256sum; then
    echo "ERROR: kind checksum verification failed!"
    exit 1
  fi
  
  # Rename executable after checksum is verified and install KinD
  mv kind-linux-$PLATFORM kind
  chmod +x ./kind
  mv ./kind /usr/local/bin/
  rm -f kind-linux-${PLATFORM}.sha256sum
  echo "kind installed successfully"
else
  echo "kind already installed: $(kind --version)"
fi

# Check and install kubectl if needed
if ! command -v kubectl &> /dev/null; then
  echo "kubectl not found, installing..."
  KUBECTL_VERSION="v1.33.1"

  # Download kubectl binary
  curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${PLATFORM}/kubectl"

  # Download and verify checksum
  echo "Verifying kubectl checksum..."
  curl -LO https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${PLATFORM}/kubectl.sha256
  echo "$(cat kubectl.sha256)  kubectl" > kubectl.sha256sum
  if ! sha256sum -c kubectl.sha256sum; then
    echo "ERROR: kubectl checksum verification failed!"
    exit 1
  fi

  # Install kubectl after checksum verification
  chmod +x kubectl
  install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
  rm -f kubectl.sha256 kubectl.sha256sum
  echo "kubectl installed successfully"
else
  echo "kubectl already installed: $(kubectl version --client)"
fi

echo "All dependencies installed or validated!"
echo "To build the image locally run ./build.sh"
echo "To run image integration tests run ./tests/run-tests.sh"
