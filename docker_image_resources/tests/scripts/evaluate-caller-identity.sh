#!/bin/bash
set -euo pipefail

# Test credentials and capture the output
echo "Running get-caller-identity..."
CALLER_ARN=$(aws sts get-caller-identity \
    --query 'Arn' \
    --output text)

echo "sts get-caller-identity call succeeded"

# Transform the caller ARN to match the IAM role ARN format
# 1. Replace "sts" with "iam"
# 2. Replace "assumed-role" with "role"
# 3. Remove everything after the role name (the session ID)
TRANSFORMED_ARN=$(echo $CALLER_ARN | sed 's/sts/iam/g; s/assumed-role/role/g; s/\/[^\/]*$//g')

echo "Transformed ARN: $TRANSFORMED_ARN"
echo "Expected Role ARN: $ROLE_ARN"

# Compare the transformed ARN with the role ARN
if [ "$TRANSFORMED_ARN" != "$ROLE_ARN" ]; then
  echo "ERROR: The assumed role does not match the expected role ARN"
  echo "Expected role ARN: $ROLE_ARN"
  echo "Actual caller ARN: $CALLER_ARN"
  echo "Transformed caller ARN: $TRANSFORMED_ARN"
  exit 1
fi

echo "Role ARN verification passed successfully"
echo "Test passed successfully"
exit 0
