#!/bin/bash
set -euo pipefail

PCA_ARN=$1

# Generate private key
openssl genrsa -out docker_image_resources/tests/certs/private_key.pem 2048

# Create CSR (Certificate Signing Request)
openssl req -new -key docker_image_resources/tests/certs/private_key.pem \
-out /tmp/certificate.csr \
-subj "/CN=credential-helper-test/O=Amazon/OU=Cryptography"

# Issue certificate using AWS Private CA
CERTIFICATE_ARN=$(aws acm-pca issue-certificate \
--certificate-authority-arn $PCA_ARN \
--csr fileb:///tmp/certificate.csr \
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
