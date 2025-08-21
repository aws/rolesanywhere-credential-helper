# Docker Image Verification with Notation

This guide provides instructions for verifying the authenticity and integrity of the AWS IAM Roles Anywhere Credential Helper Docker images using [Notation](https://notaryproject.dev/), a CNCF project that implements the Notary v2 specification for container image signing and verification.

## Overview

The AWS IAM Roles Anywhere Credential Helper Docker images are signed using AWS Signer, and you can verify these signatures using the AWS Signer plugin with Notation to ensure you're using untampered images from AWS.

## Prerequisites

- Docker or compatible container runtime
- Internet access for downloading Notation and certificates

## Installation

### Install Notation CLI

Follow the installation instructions for your desired platform [here](https://docs.aws.amazon.com/signer/latest/developerguide/image-signing-prerequisites.html)

### Install Certificates

If you decide to install only the AWS Signer extension on a pre-existing installation of notation you will have to manually import the [AWS Commercial root certificate](https://d2hvyiie56hcat.cloudfront.net/aws-signer-notation-root.cert) and [AWS GovCloud root certificate](https://d2hvyiie56hcat.cloudfront.net/aws-us-gov-signer-notation-root.cert). 

To import certificates use:
`notation cert add --type <STORE TYPE> --store <STORE NAME> <local/path/to/certificate.crt>`


The results of calling `notation cert list` should look like the following after installation:
```
STORE TYPE         STORE NAME             CERTIFICATE
signingAuthority   aws-signer-ts          aws-signer-notation-root.crt
signingAuthority   aws-us-gov-signer-ts   aws-us-gov-signer-notation-root.crt
```

## Trust Policy Setup

Notation uses trust policies to define which signatures to trust. This directory contains two pre-configured trust policy files:

### Standard Trust Policy (`notationtrustpolicy.json`)
- **Use case**: For environments where image attestation is needed and aws credentials are available.
- **Features**: Strict signature verification with revocation checking.

### Skip Revocation Trust Policy (`notationtrustpolicyskiprevocation.json`)
- **Use case**: For environments where AWS credentials are unavailable but image verification is required.
- **Warning**: This configuration skips revocation checks for the signing profile used. While this is currently the only way to verify images without AWS credentials, be aware that you won't be able to verify if the signing certificate of the signing profile has been revoked.


### Configure Trust Policy

Choose the appropriate trust policy for your environment:

#### For environments that have aws credentials (recommended):
```bash
notation policy import docker_image_resources/notation/<trustpolicy.json>
```

### Verify Trust Policy Configuration
```bash
notation policy show
```

## Image Verification

### Basic Verification Command

To verify a Docker image, use the following command format:

```bash
notation verify <image> --plugin-config aws-region=us-east-1
```

### Example

#### Verify latest image:
```bash
notation verify public.ecr.aws/rolesanywhere/credential-helper:latest --plugin-config aws-region=us-east-1
```


### Successful Verification Output

A successful verification will show output similar to:
```
Successfully verified signature for public.ecr.aws/rolesanywhere/credential-helper:latest
```

