#!/bin/bash
set -euo pipefail

# Configuration
export VERSION="${VERSION:-latest}"
export REGISTRY="${REGISTRY:-local}"
export REPOSITORY="${REPOSITORY:-iamra-credential-helper}"
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
kind load docker-image "${REGISTRY}/${REPOSITORY}:${VERSION}" --name credential-helper-test

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

echo "Creating default serviceaccount if it is not present..."
kubectl get sa default -n default 2>/dev/null || kubectl create sa default -n default

echo "Setup completed successfully"
