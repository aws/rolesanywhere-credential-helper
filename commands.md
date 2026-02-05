# AWS IAM Roles Anywhere Credential Helper Reference

## Overview

The AWS IAM Roles Anywhere Credential Helper is a tool that uses certificates and their associated private keys to sign requests to the AWS IAM Roles Anywhere CreateSession API and retrieve temporary AWS security credentials.

## Syntax

```bash
aws_signing_helper [command]
```

### Commands

* `credential-process`: Retrieves AWS credentials by sending a CreateSession request to the IAM Roles Anywhere service.
* `update`: Updates a profile in the AWS credentials file with new AWS credentials.
* `serve`: Serves AWS credentials through a local endpoint that is compatible with IMDSv2.
* `sign-string`: Signs a fixed string using the specified private key or certificate.
* `read-certificate-data`: Reads and displays certificate data from a file, PKCS#11 token, or certificate store.
* `version`: Prints the version number of the credential helper.

### Global Options

* `--help` `-h` Show help for the aws_signing_helper or its subcommands.

* Type: String
* Required: No

Example:

```bash
aws_signing_helper --help
```

## credential-process

Retrieves temporary AWS credentials by sending a CreateSession request to the IAM Roles Anywhere service.

### Syntax

```bash
aws_signing_helper credential-process --certificate <path> --private-key <path> --role-arn <arn> --trust-anchor-arn <arn> [options]
```

### Options

`--certificate <path>`

Path to the end-entity certificate file.

* Type: String
* Required: No
  * Alternatively, provide `--cert-selector`

`--private-key <path>`
Path to the private key file. Encrypted and plaintext private keys are supported.

* Type: String
* Required: Yes

`--role-arn <arn>`

ARN of the role to obtain temporary credentials for.

* Type: String
* Required: Yes

`--trust-anchor-arn <arn>`

ARN of the trust anchor used for authentication.

* Type: String
* Required: Yes

`--profile-arn <arn>`

ARN of the profile that provides a mapping for the specified role.

* Type: String
* Required: Yes

`--debug`

Provide debugging output about the request.

* Type: Boolean
* Required: No

`--no-verify-ssl`

Skip verification of the SSL certificate on the endpoint.

* Type: Boolean
* Required: No

### Example

```bash
aws_signing_helper credential-process \
  --certificate client-cert.pem \
  --private-key client-key.pem \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890
```

## update

Updates a profile in the AWS credentials file with temporary AWS credentials.

### Syntax

```bash
aws_signing_helper update [--profile <name>] [--once] [options]
```

### Options

(All options from `credential-process` are also available)

`--profile <name>`

Named profile to update in the AWS credentials file.

* Type: String
* Required: No
* Default: "default"

`--once`

Update credentials only once instead of continuously.

* Type: Boolean
* Required: No
* Default: false

### Example

```bash
aws_signing_helper update \
  --profile my-profile \
  --certificate client-cert.pem \
  --private-key client-key.pem \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890
```

## serve

Serves AWS credentials through a local endpoint that is compatible with IMDSv2.

### Syntax

```bash
aws_signing_helper serve [--port <number>] [--hop-limit <number>] [options]
```

### Options

(All options from `credential-process` are also available)

`--port <number>`

The port used to run the local server.

* Type: Integer
* Required: No
* Default: 9911

`--hop-limit <number>`

The IP TTL to set on responses.

* Type: Integer
* Required: No
* Default: 64

### Example

```bash
aws_signing_helper serve \
  --port 1338 \
  --certificate client-cert.pem \
  --private-key client-key.pem \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890
```

## sign-string

Signs a fixed string using the specified private key or certificate.

### Syntax

```bash
aws_signing_helper sign-string [--private-key <path>] [--certificate <uri>] [--format <format>] [--digest <algorithm>] [options]
```

### Options

`--private-key <path>`

Path to the private key file or PKCS#11 URI to identify the private key.

* Type: String
* Required: No

`--certificate <uri>`

PKCS#11 URI to identify the certificate.

* Type: String
* Required: No

`--format <format>`

Output format for the signature.

* Type: String
* Required: No
* Default: "json"
* Valid values: "json", "text", "bin"

`--digest <algorithm>`

Digest algorithm to use for signing.

* Type: String
* Required: No
* Default: "SHA256"
* Valid values: "SHA256", "SHA384", "SHA512"

### Example

```bash
aws_signing_helper sign-string \
  --private-key client-key.pem \
  --format text
```

## read-certificate-data

Reads and displays certificate data from a file, PKCS#11 token, or certificate store.

### Syntax

```bash
aws_signing_helper read-certificate-data [--certificate <path>] [--cert-selector <selector>] [options]
```

### Options

`--certificate <string or path>`

Path to the certificate file or PKCS#11 URI to identify the certificate.

* Type: String
* Required: No

`--cert-selector <selector>`

JSON structure to identify a certificate from a certificate store.

* Type: String
* Required: No

### Example

```bash
aws_signing_helper read-certificate-data --certificate client-cert.pem
```

## version

Displays the current version number of the AWS IAM Roles Anywhere Credential Helper.

### Syntax

```bash
aws_signing_helper version
```

## Environment Variables

The AWS IAM Roles Anywhere Credential Helper supports several environment variables:

* `AWS_EC2_METADATA_SERVICE_ENDPOINT`: Used with the `serve` command to make credentials available to AWS SDKs.
* `AWS_PROFILE`: Specifies the named profile in the AWS credentials file for the `update` command.
* `CREDENTIAL_HELPER_KEYCHAIN_PASSWORD`: Stores the password for the custom Keychain created for the credential helper on macOS.
* `TPM_PRIMARY_KEY_PASSWORD` and `TPM_CHILD_KEY_PASSWORD`: Store passwords for TPM keys.
* `PKCS11_MODULE_PATH`: Specifies a custom PKCS#11 module.
* `AWS_CA_BUNDLE`: Specifies a custom CA bundle for SSL/TLS connections.

Note: Exercise caution when setting environment variables containing sensitive information. Ensure your environment is secure and follow best practices for managing secrets.
