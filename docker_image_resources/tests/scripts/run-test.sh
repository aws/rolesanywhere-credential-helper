#!/bin/bash
set -euo pipefail

#set defaults in the event tests are ran outside of test driver
export VERSION="${VERSION:-latest}"
export REGISTRY="${REGISTRY:-local}"
export IMAGE_NAME="${IMAGE_NAME:-iamra-credential-helper}"

# Simple argument handling
if [ $# -lt 1 ]; then
  echo "Usage: $0 <test-case>"
  echo "Available test cases: serve, update, update-credentials-file"
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
envsubst '$TRUST_ANCHOR_ARN,$PROFILE_ARN,$ROLE_ARN,$VERSION,$REGISTRY,$IMAGE_NAME' < "tests/pod_configurations/${TEST_CASE}.yaml" | kubectl apply -f -

# Wait for pod to be ready
echo "Waiting for pod to be ready..."
if ! kubectl wait --for=condition=Ready "pod/${POD_NAME}" --timeout="${TIMEOUT}s"; then
  # If pod does not become ready before timeout then show debug output
  echo "Pod did not become ready in time. Current status:"
  kubectl get pod "${POD_NAME}" -o wide
  echo "Pod events:"
  kubectl describe pod "${POD_NAME}"
  echo "Credential helper logs (if available):"
  kubectl logs "${POD_NAME}" -c credential-helper || echo "No logs available"
  echo "Pod left running for debugging. Delete manually when done."
  exit 1
fi

# Follow the test-client container logs
echo "Test output:"
kubectl logs -f "${POD_NAME}" -c test-client

# Get the exit code of the test-client container
TEST_EXIT_CODE=$(kubectl get pod "${POD_NAME}" --output='jsonpath={.status.containerStatuses[?(@.name=="test-client")].state.terminated.exitCode}')

# Cleanup
echo "Cleaning up..."
kubectl delete pod "${POD_NAME}" --grace-period=0 --force

# Report test result
if [ "$TEST_EXIT_CODE" = "0" ]; then
  echo "${TEST_CASE} test passed"
  exit 0
else
  echo "${TEST_CASE} test failed with exit code: ${TEST_EXIT_CODE:-unknown}"
  exit 1
fi