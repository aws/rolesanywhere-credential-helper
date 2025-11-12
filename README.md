# AWS IAM Roles Anywhere Credential Helper

The `rolesanywhere-credential-helper` implements the [signing process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html) for the AWS IAM Roles Anywhere CreateSession API. It returns temporary credentials in a standard JSON format compatible with the `credential_process` feature available across AWS SDKs. For more information, see the [AWS IAM Roles Anywhere documentation](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html).

## Installation

### Dependencies

To build the source code, you need `git`, `gcc`, GNU `make`, and `golang`.

#### Linux

On Debian-based systems, install the dependencies:

```bash
sudo apt-get install git build-essential golang-go
```

For other Linux distributions, use the appropriate package manager.

#### macOS

If you don't have Apple clang, download it from the [Apple Developer website](https://developer.apple.com/download/). Install other dependencies using Homebrew:

```bash
brew install git make go
```

#### Windows

Get gcc on Windows using [MinGW-w64](https://www.mingw-w64.org/downloads/). Install golang through the [installer](https://go.dev/doc/install). Install git and make using Chocolatey:

```bash
choco install git make
```

### Build

After installing the tools and adding them to your `PATH`, build the package from the package root:

```bash
make release
```

You will find the `aws_signing_helper` binary for your system in `build/bin/aws_signing_helper`.

### Troubleshooting

You might need to set the [GOPROXY](https://go.dev/ref/mod#resolve-pkg-mod) environment variable: `export GOPROXY="direct"`

## Usage

`aws_signing_helper` supports these commands:

* [credential-process](commands.md#credential-process)
* [update](commands.md#update)
* [read-certificate-data](commands.md#read-certificate-data)
* [sign-string](commands.md#sign-string)
* [version](commands.md#version)

For full command documentation, including available [environment variables](commands.md#environment-variables), see the[Credential helper reference](commands.md).

### Getting temporary credentials

Use `credential-process` to vend temporary credentials.  `credential-process` sends a CreateSession request to the IAM Roles Anywhere service.

Command:

```
aws_signing_helper credential-process \
  --certificate client-cert.pem \
  --private-key client-key.pem \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890
```

For more information about the signing process, see [Signing process for IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html).

### Serving temporary credentials

Use `serve` to provide temporary credentials through a local endpoint compatible with IMDSv2. Note that any process that can reach 127.0.0.1 can retrieve AWS credentials from the credential helper.

#### Example

Command:

```
aws_signing_helper serve \
  --certificate client-cert.pem \
  --private-key client-key.pem \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890 \
  --port 1338
```

Output:

```txt
Starting server on port 1338...
```
## Docker Image

The AWS IAM Roles Anywhere Credential Helper is also available as a Docker image, providing a containerized deployment option for environments like Kubernetes, Docker Compose, or other container orchestration platforms.

### When to Use the Docker Image

The Docker image is recommended when:

- **Container environments**: You're deploying in Kubernetes, Docker Swarm, or other container orchestration platforms
- **Consistent runtime**: You need a consistent, reproducible runtime environment across different systems. Particularly useful for environments where glibc is not available (ex. alpine linux)

### Quick Start

```bash
docker pull public.ecr.aws/rolesanywhere/credential-helper:latest
```

The official Docker image is available from the AWS ECR Public Gallery at [gallery.ecr.aws/rolesanywhere/credential-helper](https://gallery.ecr.aws/rolesanywhere/credential-helper).
See the [Docker image documentation](docker_image_resources/README.md) for more information.

### Image Tags

This repository follows 3 tagging schemas for images:

- `latest`: Offers the latest image for both amd64 and arm64 images.
- `latest-<platform>`: Offers the latest image for a specified platform
- `<version>-<platform>-<timestamp>`: Offers a specific, immutable image with a precise version number, platform architecture, and build timestamp.

### Supported Architectures

OS/Arch: Linux, ARM 64, x86-64

### Image Verification

For security-conscious deployments, you can verify the authenticity of Docker images using notation. See the [image verification guide](docker_image_resources/notation/README.md) for detailed instructions on setting up and using notation to verify image signatures and attestations.

## Diagnostic Command Tools

To retrieve credentials from the server:

```bash
# Get a token
TOKEN=$(curl -X PUT "http://localhost:1338/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Get the role name
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://localhost:1338/latest/meta-data/iam/security-credentials/

# Get the credentials
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://localhost:1338/latest/meta-data/iam/security-credentials/default
```

When using `serve`, AWS SDKs can discover the credentials using their credential providers without code changes. To make the credentials available to the SDK, set the `AWS_EC2_METADATA_SERVICE_ENDPOINT` environment variable to `http://localhost:1338`.

### Getting credentials from secure stores

On Windows or macOS, the credential helper supports using private keys and certificates from OS-specific secure stores. Use the `--cert-selector` flag to specify the certificate for the CreateSession API call. The credential helper delegates signing operations to the keys in those stores, without the keys leaving the stores.

#### Using the --cert-selector flag

```
aws_signing_helper credential-process \
    --cert-selector <string or path>
    --private-key <path>
    --role-arn <arn>
    --trust-anchor-arn <arn> [options]
```

If more than one certificate matches the `--cert-selector` within the secure store, the `credential-process` command will fail. To find the list of certificates that match a given `--cert-selector` parameter, use this flag with the `read-certificate-data` command.

#### Searching for a certificate and private key

The `--cert-selector` flag supports searching for a specific certificate and its associated private key by the certificate Subject, Issuer, and Serial Number. The corresponding keys are `x509Subject`, `x509Issuer`, and `x509Serial`, respectively. You can specify these either through a JSON file or command line.

In these examples, the subject and Issuer each contain a single RDN.

##### Using a JSON file

Create a file called `selector.json`:

```json
[
  {
    "Key": "x509Subject",
    "Value": "CN=Subject"
  },
  {
    "Key": "x509Issuer",
    "Value": "CN=Issuer"
  },
  {
    "Key": "x509Serial",
    "Value": "15D19632234BF759A32802C0DA88F9E8AFC8702D"
  }
]
```

Use it with:

```
aws_signing_helper credential-process \
  --cert-selector file://path/to/selector.json \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890
```

##### Using command line parameters

```
aws_signing_helper credential-process \
  --cert-selector Key=x509Subject,Value=CN=Subject Key=x509Issuer,Value=CN=Issuer Key=x509Serial,Value=15D19632234BF759A32802C0DA88F9E8AFC8702D \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890
```

## Operating-system specific credential stores

### macOS Keychain

To securely store keys for use with IAM Roles Anywhere, we recommend creating a dedicated Keychain that only the credential helper can access. This approach enhances security by isolating these sensitive credentials. The credential helper will search for credentials only from Keychains on the search list.

#### Creating and configuring a new Keychain

1. Create a new Keychain

```bash
security create-keychain -p ${CREDENTIAL_HELPER_KEYCHAIN_PASSWORD} credential-helper.keychain
```

1. Unlock the Keychain:

```bash
security unlock-keychain -p ${CREDENTIAL_HELPER_KEYCHAIN_PASSWORD} credential-helper.keychain
```

1. Add New Keychain to search List

Ensure the new Keychain is included in the system's search list. This command extracts existing Keychains in the search list and adds the newly created Keychain to the top of it.

```bash
EXISTING_KEYCHAINS=$(security list-keychains | cut -d '"' -f2) security list-keychains -s credential-helper.keychain $(echo ${EXISTING_KEYCHAINS} | awk -v ORS=" " '{print $1}')
```

4. Import certificates and private keys

Finally, add your PFX file (containing your client certificate and associated private key) to the Keychain. Replace `\path\to\identity.pfx` with the actual path to your PFX file.

```bash
security import /path/to/identity.pfx -T /path/to/aws_signing_helper -P ${UNWRAPPING_PASSWORD} -k credential-helper.keychain
```

#### Troubleshooting

* Credential helper is signed but not notarized. You may need to [manually override your macOS security settings]( https://support.apple.com/guide/mac-help/apple-cant-check-app-for-malicious-software-mchleab3a043/mac) to use the credential helper with your Keychain.
* You might need to specify your Keychain password for signing operations or choose to always allow the credential helper to use the Keychain item.

#### Important Considerations

Note that since the credential helper isn't signed, it isn't trusted by macOS by default. As a result, you may need to enter the Keychain password each time the credential helper performs a signing operation. If you prefer not to enter the password repeatedly, you can choose to "always allow" the credential helper to use the Keychain item. However, carefully consider the security implications of this setting in your specific environment.

#### Alternative Methods

These steps can also be performed using macOS Keychain APIs or through the Keychain Access application. Choose the method that best fits your workflow and security requirements.

### Windows CNG

The credential helper for IAM Roles Anywhere is designed to work exclusively with the user's "MY" certificate store on Windows. This integration allows for secure key management through Windows CNG (Cryptography API: Next Generation).
To use your keys with IAM Roles Anywhere, you need to import your certificate and its associated private key into your user's "MY" certificate store.

##### Using Command Prompt

To import a PFX file containing your certificate and private key, open Command Prompt and run:

```cmd
certutil -user -p %UNWRAPPING_PASSWORD% -importPFX "MY" \path\to\identity.pfx
```

Replace `\path\to\identity.pfx` with the actual path to your PFX file. The `%UNWRAPPING_PASSWORD%` environment variable should contain the password to decrypt the PFX file.

#### Alternative Methods

You can also import your certificate using a PowerShell cmdlet or Windows CNG/Cryptography APIs.

#### Importing certificates into the user's "MY" store

To secure keys through Windows CNG, import your certificate into your user's "MY" certificate store:

```cmd
certutil -user -p %UNWRAPPING_PASSWORD% -importPFX "MY" \path\to\identity.pfx
```

## Platform-independent cryptographic token interface (PKCS#11)

The credential helper supports using a PKCS#11 URI instead of a filename to use certificates and keys from hardware or software PKCS#11 tokens/HSMs. For help with URIs, consult this documentation or use the `read-certificate-data` command. Most Linux systems use p11-kit to provide configuration of PKCS#11 providers. If your system lacks p11-kit, use the `--pkcs11-lib` parameter to specify a provider library.

### PKCS#11 Examples

These examples show how to use the `aws_signing_helper credential-process` command with different PKCS#11 configurations.

```
# Using a certificate from a PKCS#11 token
aws_signing_helper credential-process \
  --certificate 'pkcs11:manufacturer=piv_II;id=%01' \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890

# Using both certificate and key from a PKCS#11 token
aws_signing_helper credential-process \
  --certificate 'pkcs11:object=My%20RA%20key' \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890

# Using a certificate from a file but the key from a PKCS#11 token
aws_signing_helper credential-process \
  --certificate client-cert.pem \
  --private-key 'pkcs11:model=SoftHSM%20v2;object=My%20RA%20key' \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890
```

The `--reuse-pin` parameter is useful when the private key object has `CKA_ALWAYS_AUTHENTICATE` set and the `CKU_CONTEXT_SPECIFIC` PIN matches the CKU_USER PIN. If `--reuse-pin` isn't set, you will be prompted to enter the PIN in the console. If `--reuse-pin` is set, but the `CKU_USER` PIN is different from the `CKU_CONTEXT_SPECIFIC` PIN, the credential helper will prompt you to enter the `CKU_CONTEXT_SPECIFIC` PIN. This is helpful for unattended workloads.

### Unattended workloads limitation

The credential helper doesn't currently support specifying the `CKU_CONTEXT_SPECIFIC` PIN programmatically. For unattended workloads, this presents a challenge when the `CKU_CONTEXT_SPECIFIC` PIN of the private key object differs from the `CKU_USER` PIN of its token. In such cases, the system will always prompt for the PIN, making unattended operations impossible

## Trusted platform module (TPMv2)

The credential helper supports private key files containing a TPM wrapped key in the `-----BEGIN TSS2 PRIVATE KEY-----` format. You can use such a file as you would any plain key file:

```
aws_signing_helper credential-process \
  --certificate client-cert.pem \
  --private-key tpm-key.pem \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890
```

You can also use a TPM key handle:

```
aws_signing_helper credential-process \
  --certificate client-cert.pem \
  --private-key handle:${CHILD_HANDLE} \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcdef1234567890
```


The credential helper requires a TPM key password on the child key by default. If you don't use a child key, add the `--no-tpm-key-password` option.

### Limitations

The current implementation of TSS private key format support has these limitations:

* Password authentication on parent keys (and hierarchies)
* Use of a persistent handle as a parent
* Importable keys
* TPM Policy / AuthPolicy
* Sealed keys

We're working on addressing these limitations. Future releases may include support for some or all of these features. For the latest updates on feature support, refer to our release notes or documentation.

### Workaround for parent key password authentication

To work around the parent key password authentication limitation:

1. Load the signing key into the TPM using external tools. This process requires you to provide your parent key password.
2. Reference the loaded key's handle in your credential helper command.

This approach allows you to use the signing key without the credential helper needing to handle the parent key password authentication directly.

### Creating and using TPM keys

Requirements:

* OpenSSL 3.x
* [TPM 2.0 provider for OpenSSL](https://github.com/tpm2-software/tpm2-openssl)

Important: If your TPM's owner hierarchy is not yet initialized, configure it with a high-entropy password. The owner hierarchy lacks dictionary attack protections, making a strong password crucial for security.

1. Create a primary key in the TPM owner hierarchy:

```bash
tpm2_createprimary -G rsa -g sha256 -p ${TPM_PRIMARY_KEY_PASSWORD} -c parent.ctx -P ${OWNER_HIERARCHY_PASSWORD}
```

This command creates a primary key in the TPM owner hierarchy with the password specified in `${TPM_PRIMARY_KEY_PASSWORD}`.
Note: If your TPM's owner hierarchy doesn't have a password (not recommended), omit the `-P` option from the command.

2. Create a child key:

```bash
tpm2_create -C parent.ctx -u child.pub -r child.priv -P ${TPM_PRIMARY_KEY_PASSWORD} -p ${TPM_CHILD_KEY_PASSWORD}
```

3. Load the child key:

```bash
tpm2_load -C parent.ctx -u child.pub -r child.priv -c child.ctx -P ${TPM_PRIMARY_KEY_PASSWORD}
```

4. Make it persistent:

```bash
CHILD_HANDLE=$(tpm2_evictcontrol -c child.ctx | cut -d ' ' -f 2 | head -n 1)
```

You will be prompted for your password (`TPM_CHILD_KEY_PASSWORD`).

5. Create a CSR:

```bash
openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' \
                 -new -key handle:${CHILD_HANDLE} \
                 -out client-csr.pem
```

6. Once you have your CSR, you can provide it to a CA so that it can issue a client certificate for you. The client certificate and TPM key can then be used with the credential helper application as follows:

```
/path/to/aws_signing_helper credential-process \
    —certificate /path/to/certificate/file \
    —private-key handle:${CHILD_HANDLE} \
    —role-arn ${ROLE_ARN} \
    —trust-anchor-arn ${TA_ARN} \
    —profile-arn ${PROFILE_ARN}
```

### Security considerations

When using TPM persistent objects:

* You are responsible for clearing persistent and temporary objects from the TPM when no longer needed.
* Failure to do so might allow others with machine access to escalate privileges.
* Non-password-protected keys loaded into the TPM can be used by anyone with machine access.

### Alternative: Using a TPM key PEM file

You can use a TPM key PEM file with the credential helper. This approach:

* Loads the wrapped private key as a transient object in the TPM.
* Automatically flushes the key from the TPM after signing.
* Reloads the key for each signing operation.

Limitation: The parent of the signing key cannot be password-protected, as there's currently no way to pass this password to the credential helper.
For the TPM key PEM file format, refer to: TPM2 Key Format Specification

#### Example: Using the credential helper with a TPM key file

To use the credential helper with a TPM key file, run the following command:

```
aws_signing_helper credential-process \
    --certificate /path/to/certificate/file \
    --private-key /path/to/tpm/key/file \
    --role-arn ${ROLE_ARN} \
    --trust-anchor-arn ${TA_ARN} \
    --profile-arn ${PROFILE_ARN}
```

Replace the placeholder values with your specific file paths and ARNs.

## YubiKey and Attestation Certificates

YubiKeys with PIV support automatically generate attestation certificates for key pairs in Slot 9a (PIV authentication) and Slot 9c (digital signature). These attestation certificates cannot be deleted

### Handling Multiple Certificates in PIV Slots

When using a `PKCS#11 URI` with `CKA_ID` (id path attribute) to identify a certificate, two matching certificates will be found (user certificate and attestation certificate). This duplication occurs in slots 9a and 9c due to the presence of attestation certificates

### Using CKA_LABEL for Certificate Identification

To distinguish between user and attestation certificates, use `CKA_LABEL` (the object path attribute) in your `PKCS#11 URI`. Attestation certificates in either of these two slots can be identified through the hard-coded labels:

* Slot 9a: `X.509 Certificate for PIV Attestation 9a`
* Slot 9c: `X.509 Certificate for PIV Attestation 9c`

## Security

See CONTRIBUTING for more information.

## License

This project is licensed under the Apache License 2.0.
