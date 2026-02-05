# Testing

This section describes how to test TPM support in the AWS IAM Roles Anywhere Credential Helper.

## Unit Tests for TPM Support

The unit tests for TPM support use keys bound to either a hardware TPM or a software TPM. For software TPM testing, we use `swtpm`. You can find the repository at [https://github.com/stefanberger/swtpm](https://github.com/stefanberger/swtpm).

### Prerequisites

To create the keys and certificates for unit testing, you need:

- [Intel TSS](https://github.com/tpm2-software/tpm2-tss)
- [Intel OpenSSL provider](https://github.com/tpm2-software/tpm2-openssl)
- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
- [tpm2-tabrmd](https://github.com/tpm2-software/tpm2-abrmd) (resource manager)

These dependencies are available on many Linux distributions through standard package managers.

### Running TPM Unit Tests

To run only the TPM-related unit tests:

```
make test-tpm-signer
```

Note: `swtpm` must run in UNIX socket mode for the tests, as that's all `go-tpm` supports. However, key and certificate fixtures are created when `swtpm` runs in TCP socket mode. The `Makefile` handles switching `swtpm` to UNIX socket mode before running the unit tests.

## Testing TPM Key Files with Permanent Handle Parents

See [create_tpm2_key.sh][#create_tpm2_key.sh] for more information.

## Notes on Tooling

`tpm2-tools` and `tpm2-openssl` create RSA keys with the sign attribute by default. However, other tools might not. For example, the IBM OpenSSL ENGINE tools create RSA keys with the decrypt attribute but not the sign attribute by default.

To use an RSA key with the credential helper, it must have the sign attribute set. The credential helper delegates the signing operation to the TPM, rather than using a raw RSA decrypt and implementing PKCS#1 v1.5 padding.

## Scripts

The project includes two bash scripts: `generate-credential-process-data.sh` and `create_tpm2_key.sh`. These scripts currently work only on Unix-based systems and require additional dependencies.

### generate-credential-process-data.sh

This script creates a CA certificate/private key pair and a leaf certificate/private key for testing. It's used by unit tests and for manual testing of the credential-process command.

Requirements:
- OpenSSL 3.x

Usage:

```bash
/bin/sh generate-credential-process-data.sh

# Create a trust anchor using the generated CA certificate
TA_ARN=$(aws rolesanywhere create-trust-anchor \
    --name "Test TA" \
    --source "sourceType=CERTIFICATE_BUNDLE,sourceData={x509CertificateData=$(cat credential-process-data/root-cert.pem)}" \
    --enabled \
    --query 'trustAnchor.trustAnchorArn')

# Create a profile that maps to your role
PROFILE_ARN=$(aws rolesanywhere create-profile \
    --name "Test Profile" \
    --role-arns '["<your-role-arn>"]' \
    --enabled | --query -r '.profile.profileArn')

# Use the credential helper with the generated certificate and key
aws_signing_helper credential-process \
    --certificate credential-process-data/client-cert.pem \
    --private-key credential-process-data/client-key.pem \
    --role-arn <your-role-arn> \
    --trust-anchor-arn ${TA_ARN} \
    --profile-arn ${PROFILE_ARN}
```

The script stores test data in the `credential-process-data` directory. When testing IAM Roles Anywhere, upload the CA certificate as a trust anchor and create a profile within Roles Anywhere before using the binary with the leaf certificate/private key to call credential-process.

### create_tpm2_key.sh

We include a small script that emulates a subset of the `create_tpm2_key` utility from the [IBM OpenSSL ENGINE](https://git.kernel.org/pub/scm/linux/kernel/git/jejb/openssl_tpm2_engine.git/). This script tests TPM key files that include a permanent handle as their parent.
