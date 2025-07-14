#!/bin/bash
set -euo pipefail

PCA_ARN=$1

# Generate private key
openssl genrsa -out docker_image_resources/tests/certs/private_key.pem 2048

# Create CSR (Certificate Signing Request)
openssl req -new -key docker_image_resources/tests/certs/private_key.pem \
-out /tmp/certificate.csr \
-subj "/CN=credential-helper-test/O=Amazon/OU=Cryptography"

# Convert CSR to base64 for AWS CLI
CSR_CONTENT=$(cat /tmp/certificate.csr | base64 -w 0)

# Issue certificate using AWS Private CA
CERTIFICATE_ARN=$(aws acm-pca issue-certificate \
--certificate-authority-arn $PCA_ARN \
--csr $CSR_CONTENT \
--signing-algorithm "SHA256WITHRSA" \
--validity Value=1,Type=DAYS \
--query 'CertificateArn' \
--output text)

aws acm-pca wait certificate-issued --certificate-authority-arn $PCA_ARN --certificate-arn $CERTIFICATE_ARN

# Get the issued certificate
aws acm-pca get-certificate \
--certificate-authority-arn $PCA_ARN \
--certificate-arn $CERTIFICATE_ARN \
--query 'Certificate' \
--output text > docker_image_resources/tests/certs/certificate.pem
