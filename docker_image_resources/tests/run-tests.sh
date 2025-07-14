#!/bin/bash
set -euo pipefail

echo "=== Starting IAM Roles Anywhere Credential Helper Tests ==="

#Make scripts executable
chmod +x tests/scripts/*.sh

# Setup KinD cluster, load image and config maps
echo "Setting up test environment..."
./tests/setup.sh

# Run tests
echo "Running tests..."

FAILED_TESTS=()

# Run serve mode test
echo "=== Running Serve Test ==="
if ./tests/scripts/run-test.sh serve; then
  echo "Serve mode test PASSED"
else
  echo "Serve mode test FAILED"
  FAILED_TESTS+=("serve")
fi

echo ""

# Run update mode test
echo "=== Running Update Test ==="
if ./tests/scripts/run-test.sh update; then
  echo "Update test PASSED"
else
  echo "Update test FAILED"
  FAILED_TESTS+=("update")
fi

echo ""

# Run update mode non root test
echo "=== Running Update with Credentials File Test ==="
if ./tests/scripts/run-test.sh update-credentials-file; then
  echo "Update with Credentials File test PASSED"
else
  echo "Update with Credentials File test FAILED"
  FAILED_TESTS+=("update with credentials file")
fi

echo ""
echo "=== Test Summary ==="

# Check if any tests failed
if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
  echo "All tests passed successfully!"
  exit 0
else
  echo "The following tests failed:"
  for test in "${FAILED_TESTS[@]}"; do
    echo "- $test"
  done
  exit 1
fi