#!/bin/bash
set -euo pipefail

#set defaults in the event tests are ran outside of test driver
export VERSION="${VERSION:-latest}"
export REGISTRY="${REGISTRY:-local}"
export REPOSITORY="${REPOSITORY:-iamra-credential-helper}"

# Simple argument handling
if [ $# -lt 1 ]; then
  echo "Usage: $0 <test-case>"
  echo "Available test cases: serve, update, update-custom-credentials-file"
  exit 1
fi

TEST_CASE=$1
TIMEOUT=${2:-30}  # Optional timeout parameter with default

# Validate test case
if [ ! -f "tests/pod_configurations/${TEST_CASE}.yaml" ]; then
  echo "Error: Invalid test case '${TEST_CASE}'"
  exit 1
fi

# Determine the pod name and yaml file
POD_NAME="${TEST_CASE}-test"

echo "Running ${TEST_CASE} test..."

# Apply the test pod and substitute required environment variables
envsubst '$TRUST_ANCHOR_ARN,$PROFILE_ARN,$ROLE_ARN,$VERSION,$REGISTRY,$REPOSITORY' < "tests/pod_configurations/${TEST_CASE}.yaml" | kubectl apply -f -

# Wait for pod to be ready
echo "Waiting for pod to be ready..."
if ! kubectl wait --for=condition=Ready "pod/${POD_NAME}" --timeout="${TIMEOUT}s"; then
  # If pod does not become ready before timeout then emit pod events as debug output
  echo "Pod did not become ready in time. Current status:"
  kubectl get pod "${POD_NAME}" -o wide
  echo "Pod events:"
  kubectl describe pod "${POD_NAME}"
  exit 1
fi

# Follow the test-client container logs and capture the last line to determine success
echo "Test output:"
LOG_OUTPUT=$(kubectl logs -f "${POD_NAME}" -c test-client)
echo "$LOG_OUTPUT"

# Check if the logs contain the success message
if echo "$LOG_OUTPUT" | grep -q "Test passed successfully"; then
  # Cleanup
  echo "Cleaning up..."
  kubectl delete pod "${POD_NAME}" --grace-period=0 --force
  
  echo "${TEST_CASE} test passed"
  exit 0
else
  # Cleanup
  echo "Cleaning up..."
  kubectl delete pod "${POD_NAME}" --grace-period=0 --force
  
  echo "${TEST_CASE} test failed - success message not found in logs"
  exit 1
fi
