#!/bin/bash
set -euo pipefail

IMAGE_REFERENCE=$1

SCAN_OUTPUT=$(trivy image --ignorefile docker_image_resources/tests/.trivyignore --no-progress --severity CRITICAL,HIGH,MEDIUM,LOW $IMAGE_REFERENCE --format json)

# Initialize counts with default values
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

if [ -n "$SCAN_OUTPUT" ]; then

# Function to count vulnerabilities of a specific severity
count_vulnerabilities() {
    local severity="$1"
    echo "$SCAN_OUTPUT" | \
        jq --arg sev "$severity" \
        '[.Results[] | select(.Vulnerabilities != null) | .Vulnerabilities | map(select(.Severity == $sev)) | length] | add // 0' \
        2>/dev/null || echo 0
}

# Check if we have vulnerabilities in the results
if echo "$SCAN_OUTPUT" | jq -e '.Results[] | select(.Vulnerabilities != null)' > /dev/null; then
    CRITICAL_COUNT=$(count_vulnerabilities "CRITICAL")
    HIGH_COUNT=$(count_vulnerabilities "HIGH")
    MEDIUM_COUNT=$(count_vulnerabilities "MEDIUM")
    LOW_COUNT=$(count_vulnerabilities "LOW")
else
    echo "No vulnerabilities found in scan results."
fi
else
    echo "Warning: Empty scan output from Trivy."
fi

# Ensure counts are valid integers
CRITICAL_COUNT=${CRITICAL_COUNT:-0}
HIGH_COUNT=${HIGH_COUNT:-0}
MEDIUM_COUNT=${MEDIUM_COUNT:-0}
LOW_COUNT=${LOW_COUNT:-0}

# Print vulnerability counts
echo "Vulnerability counts:"
echo "Critical: $CRITICAL_COUNT"
echo "High: $HIGH_COUNT"
echo "Medium: $MEDIUM_COUNT"
echo "Low: $LOW_COUNT"

# Check if vulnerability thresholds are exceeded
if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ] || [ "$MEDIUM_COUNT" -ge 8 ] || [ "$LOW_COUNT" -ge 15 ]; then
    echo "::error::Vulnerability thresholds exceeded!"
    echo "Threshold criteria:"
    echo "- Critical: 0 (found: $CRITICAL_COUNT)"
    echo "- High: 0 (found: $HIGH_COUNT)"
    echo "- Medium: <8 (found: $MEDIUM_COUNT)"
    echo "- Low: <15 (found: $LOW_COUNT)"
    exit 1
else
    echo "Vulnerability scan passed. All thresholds are within acceptable limits."
fi
