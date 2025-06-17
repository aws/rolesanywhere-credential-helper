#!/bin/bash
set -euo pipefail

# Configuration
export VERSION="${VERSION:-latest}"
export REGISTRY="${REGISTRY:-local}"
export IMAGE_NAME="${IMAGE_NAME:-iamra-credential-helper}"
export CERTIFICATE_PATH="${CERTIFICATE_PATH:-tests/certs/certificate.pem}"
export PRIVATE_KEY_PATH="${PRIVATE_KEY_PATH:-tests/certs/private_key.pem}"
export CLUSTER_NAME="credential-helper-test"

echo "=== Setting up IAM Roles Anywhere Credential Helper Test Environment ==="


if [ $(uname -m) = "x86_64" ]; then
    PLATFORM="amd64"
elif [ $(uname -m) = "aarch64" ]; then
    PLATFORM="arm64"
else
  echo "Unsupported architecture: $(uname -m)"
  exit 1
fi

# Check and install Kind if needed
if ! command -v kind &> /dev/null; then
  echo "kind not found, installing..."
  KIND_VERSION="v0.29.0"
  # Download kind binary
  curl -LO "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${PLATFORM}"
  
  # Download and verify checksum
  echo "Verifying kind checksum..."
  curl -LO "https://github.com/kubernetes-sigs/kind/releases/download/v0.29.0/kind-linux-${PLATFORM}.sha256sum"
  if ! sha256sum -c kind-linux-${PLATFORM}.sha256sum; then
    echo "ERROR: kind checksum verification failed!"
    exit 1
  fi
  
  # Rename executable after checksum is verified and install KinD
  mv kind-linux-$PLATFORM kind
  chmod +x ./kind
  mv ./kind /usr/local/bin/
  rm -f kind-linux-${PLATFORM}.sha256
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


# Check if the desired cluster already exists. If it does then delete all existing pod configurations if they are present. 
if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
  echo "Cluster '${CLUSTER_NAME}' already exists, skipping creation."
  echo "Cleaning up existing pods..."
  kubectl delete pods --all -n default || true 
  echo "Continuing with existing cluster..."
else
  # If the cluster does not exist then create it
  echo "Creating Kind cluster..."
  kind create cluster --config tests/kind-config.yaml
fi

# Load the image into Kind
echo "Loading image into Kind cluster..."
kind load docker-image "${REGISTRY}/${IMAGE_NAME}:${VERSION}" --name credential-helper-test

# Create ConfigMap for certificates
echo "Creating ConfigMap for certificates..."
kubectl delete configmap cert-files --ignore-not-found
kubectl create configmap cert-files \
  --from-file=certificate.pem=$CERTIFICATE_PATH \
  --from-file=private_key.pem=$PRIVATE_KEY_PATH

# Create the ConfigMap for test-client script
echo "Creating ConfigMap for testing resources..."
kubectl delete configmap test-resources --ignore-not-found
kubectl create configmap test-resources \
  --from-file=evaluate-caller-identity.sh=tests/scripts/evaluate-caller-identity.sh

echo "Setup completed successfully"
