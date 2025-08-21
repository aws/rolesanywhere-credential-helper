## AWS IAM Roles Anywhere Credential Helper
rolesanywhere-credential-helper implements the [signing process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html) for IAM Roles Anywhere's [CreateSession](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html) API and returns temporary credentials in a standard JSON format that is compatible with the `credential_process` feature available across the language SDKs. More information can be found [here](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html). It is released and licensed under the Apache License 2.0.

## Building

### Dependencies
In order to build the source code, you will need to install git, gcc, GNU make, and golang.

#### Linux

On Debian-based systems, you can do so using `sudo apt-get install git build-essential golang-go`. For other Linux distributions, replace `apt-get` with the package manager on your system.

#### Darwin

You can download Apple clang through the [following link](https://developer.apple.com/download/) if you don't already have it installed on your system. You can install git, make, and golang through Homebrew through `brew install git`, `brew install make` and `brew install go`, respectively.

#### Windows

In order to get gcc on Windows, one option is to use [MinGW-w64](https://www.mingw-w64.org/downloads/). After obtaining gcc, you can install golang through the [installer](https://go.dev/doc/install). Lastly, you can install git and make through `Chocolatey` with `choco install git` and `choco install make`, respectively.

### Build

After obtaining these tools, and making sure they are on your `PATH`, you can build the package (assuming you are currently at the package root):

```
make release
```

After building, you should see the `aws_signing_helper` binary built for your system at `build/bin/aws_signing_helper`. Usage can be found in [AWS's documentation](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html). A later section also goes into how you can use the scripts provided in this repository to test out the credential helper binary.

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

### read-certificate-data

Reads a certificate. Either the path to the certificate on disk or PKCS#11 URI to identify the certificate is provided with the `--certificate` parameter, or the `--cert-selector` flag is provided to select a certificate within an OS certificate store. Further details about the `--cert-selector` flag are provided below.

If there are multiple certificates that match a given `--cert-selector` or PKCS#11 URI (as specified through the `--certificate` parameter), information about each of them is printed. For PKCS#11, URIs for each matched certificate is also printed in the hopes that it will be useful in uniquely identifying a certificate. 

#### cert-selector flag

If you use Windows or MacOS, the credential helper also supports leveraging private keys and certificates that are in their OS-specific secure stores. In Windows, both CNG and Cryptography are supported, while on MacOS, Keychain Access is supported. Through the `--cert-selector` flag, it is possible to specify which certificate (and associated private key) to use in calling `CreateSession`. The credential helper will then delegate signing operations to the keys within those secure stores, without those keys ever having to leave those stores. It is important to note that on Windows, only the user's "MY" certificate store will be searched by the credential helper, while for MacOS, Keychains on the search list will be searched.

The `--cert-selector` flag allows one to search for a specific certificate (and associated private key) through the certificate Subject, Issuer, and Serial Number. The corresponding keys are `x509Subject`, `x509Issuer`, and `x509Serial`, respectively. These keys can be specified either through a JSON file format or through the command line. An example of both approaches can be found below.

If you would like to use a JSON file, it should look something like this:

```
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

If the above is placed in a file called `selector.json`, it can be specified with the `--cert-selector` flag through `file://path/to/selector.json`. The very same certificate selector argument can be specified through the command line as follows:

```
--cert-selector "Key=x509Subject,Value=CN=Subject Key=x509Issuer,Value=CN=Issuer Key=x509Serial,Value=15D19632234BF759A32802C0DA88F9E8AFC8702D"
```

The example given here is quite simple (the Subject and Issuer each contain only a single RDN), so it may not be obvious, but the Subject and Issuer values roughly follow the [RFC 2253](https://www.rfc-editor.org/rfc/rfc2253.html) Distinguished Names syntax.

### sign-string

Signs a fixed strings: `"AWS Roles Anywhere Credential Helper Signing Test" || SIGN_STRING_TEST_VERSION || SHA256("IAM RA" || PUBLIC_KEY_BYTE_ARRAY)`. Useful for validating your private key and digest. Either the path to the private key must be provided with the `--private-key` parameter, or a certificate selector must be provided through the `--cert-selector` parameter (if you want to use the OS certificate store integration). Other parameters that can be used are `--digest`, which must be one of `SHA256 (*default*) | SHA384 | SHA512`, and `--format`, which must be one of `text (*default*) | json | bin`.

### credential-process

Vends temporary credentials by sending a `CreateSession` request to the Roles Anywhere service. The request is signed by the private key whose path can be provided with the `--private-key` parameter. Currently, only plaintext private keys are supported. Other parameters include `--certificate` (the path to the end-entity certificate), `--role-arn` (the ARN of the role to obtain temporary credentials for), `--profile-arn` (the ARN of the profile that provides a mapping for the specified role), and `--trust-anchor-arn` (the ARN of the trust anchor used to authenticate). Optional parameters that can be used are `--debug` (to provide debugging output about the request sent), `--no-verify-ssl` (to skip verification of the SSL certificate on the endpoint called), `--intermediates` (the path to intermediate certificates), `--with-proxy` (to make the binary proxy aware), `--endpoint` (the endpoint to call), `--region` (the region to scope the request to), `--session-duration` (the duration of the vended session), and `--role-session-name` (an identifier of the role session). Instead of passing in paths to the plaintext private key on your file system, another option could be to use the [PKCS#11 integration](#pkcs11-integration) (using the `--pkcs11-pin` flag to locate objects in PKCS#11 tokens) or (depending on your OS) use the `--cert-selector` flag. More details about the `--cert-selector` flag can be found in [this section](#cert-selector-flag). 

Note that if more than one certificate matches the `--cert-selector` parameter within the OS-specific secure store, the `credential-process` command will fail. To find the list of certificates that match a given `--cert-selector` parameter, you can use the same flag with the `read-certificate-data` command.

Also note that in Windows, if you would like the credential helper to search a system certificate store other than "MY" ("MY" will be the default) in the `CERT_SYSTEM_STORE_CURRENT_USER` context, you can specify the name of the certificate store through the `--system-store-name` flag. It's not possible for the credential helper to search multiple Windows system certificate stores at once currently. But it will indirectly search certificate stores in the `CERT_SYSTEM_STORE_LOCAL_MACHINE` context since all current user certificate stores will inherit contents of local machine certificate stores. The only exception to this rule is the Current User/Personal ("MY") store. Please see the [Microsoft documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores?source=recommendations) for more details. 

When `credential-process` is used, AWS SDKs store the returned AWS credentials in memory. AWS SDKs will keep track of the credential expiration and generate new AWS session credentials via the credential process, provided the certificate has not expired or been revoked.

When the AWS CLI uses a `credential-process`, the AWS CLI calls the `credential-process` for every CLI command issued, which will result in the creation of a new role session and a slight delay when excuting commands. To avoid this delay from getting new credentials when using the AWS CLI, you can use `serve` or `update`.

#### MacOS Keychain Guidance

If you would like to secure keys through MacOS Keychain and use them with IAM Roles Anywhere, you may want to consider creating a new Keychain that only the credential helper can access and store your keys there. The steps to do this are listed below. Note that the commands should be executed in bash.

First, create the new Keychain:

```
security create-keychain -p ${CREDENTIAL_HELPER_KEYCHAIN_PASSWORD} credential-helper.keychain
```

In the above command line, `${CREDENTIAL_HELPER_KEYCHAIN_PASSWORD}` should contain the password you want the new Keychain to have. Next, unlock the Keychain:

```
security unlock-keychain -p ${CREDENTIAL_HELPER_KEYCHAIN_PASSWORD} credential-helper.keychain
```

Once again, you will have to specify the password to the Keychain, but this time it will be used to unlock it. Next, modify the Keychain search list to include your newly created Keychain:

```
EXISTING_KEYCHAINS=$(security list-keychains | cut -d '"' -f2) security list-keychains -s credential-helper.keychain $(echo ${EXISTING_KEYCHAINS} | awk -v ORS=" " '{print $1}')
```

The above command line will extract existing Keychains in the search list and add the newly created Keychain to the top of it. Lastly, add your PFX file (that contains your client certificate and associated private key) to the Keychain:

```
security import /path/to/identity.pfx -T /path/to/aws_signing_helper -P ${UNWRAPPING_PASSWORD} -k credential-helper.keychain
```

The above command line will import your client certificate and private key that are in a PFX file (which will be unwrapped using the `UNWRAPPING_PASSWORD` environment variable) into the newly created Keychain and only allow for the credential helper to access it. It's important to note that since the credential helper isn't signed, it isn't trusted by MacOS. To get around this, you may have to specify your Keychain password whenever the credential helper wants to use the private key to perform a signing operation. If you don't want to have to specify the password each time, you can choose to always allow the credential helper to use the Keychain item.

Also note that the above steps can be done through [MacOS Keychain APIs](https://developer.apple.com/documentation/security/keychain_services/keychains), as well as through the [Keychain Access application](https://support.apple.com/guide/keychain-access/welcome/mac).

#### Windows CNG Guidance

If you would like to secure keys through Windows CNG and use them with IAM Roles Anywhere, it should be sufficient to to import your certificate (and associated private key) into your user's "MY" certificate store.

Add your certificate (and associated private key) to the certificate store by importing e.g. a PFX file through the below command line in Command Prompt:

```
certutil -user -p %UNWRAPPING_PASSWORD% -importPFX "MY" \path\to\identity.pfx
```

The above command will import the PFX file into the user's "MY" certificate store. The `UNWRAPPING_PASSWORD` environment variable should contain the password to unwrap the PFX file.

Also note that the above step can be done through a [Powershell cmdlet](https://learn.microsoft.com/en-us/powershell/module/pki/import-pfxcertificate?view=windowsserver2022-ps) or through [Windows CNG/Cryptography APIs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-pfximportcertstore).

#### PKCS#11 Integration

As you should expect from all applications which use keys and certificates, you can simply give a
[PKCS#11 URI](https://datatracker.ietf.org/doc/html/rfc7512) in place of a filename in order to
use certificates and/or keys from hardware or software PKCS#11 tokens / HSMs. A hybrid mode
using a certificate from a file but only the key in the token is also supported. Some examples:

  * `--certificate 'pkcs11:manufacturer=piv_II;id=%01'`
  * `--certificate 'pkcs11:object=My%20RA%20key'`
  * `--certificate client-cert.pem --private-key 'pkcs11:model=SoftHSM%20v2;object=My%20RA%20key'`

Some documentation which may assist with finding the correct URI for
your key can be found [here](https://www.infradead.org/openconnect/pkcs11.html). Otherwise, you 
can also potentially scope down your PKCS#11 URI by using the `read-certificate-data` diagnostic 
command. 

Most Linux and similar *nix systems use
[p11-kit](https://p11-glue.github.io/p11-glue/p11-kit/manual/config.html)
to provide consistent system-wide and per-user configuration of
available PKCS#11 providers. Any properly packaged provider module
will register itself with p11-kit and will be automatically visible
through the `p11-kit-proxy.{dylib, dll, so}` provider which is used by default.

If you have a poorly packaged provider module from a vendor, then
after you have filed a bug, you can manually create a p11-kit [module
file](https://p11-glue.github.io/p11-glue/p11-kit/manual/pkcs11-conf.html)
for it.

For systems or containers which lack p11-kit, a specific PKCS#11
provider library can be specified using the `--pkcs11-lib` parameter.

The other relevant parameter is `--reuse-pin`. This is a boolean parameter that can 
be specified if the private key object you would like to use to sign data has the 
`CKA_ALWAYS_AUTHENTICATE` attribute set and the `CKU_CONTEXT_SPECIFIC` PIN for the 
object matches the `CKU_USER` PIN. If this parameter isn't set, you will be prompted 
to provide the `CKU_CONTEXT_SPECIFIC` PIN for the object through the console. If this 
parameter is set and the `CKU_USER` PIN doesn't match the `CKU_CONTEXT_SPECIFIC` PIN, 
the credential helper application will fall back to prompting you. In an unattended 
scenario, this flag is very helpful. There is currently no way in which to specify 
the `CKU_CONTEXT_SPECIFIC` PIN without being prompted for it, so you are out of luck 
for the time being when it comes to unattended workloads if the `CKU_CONTEXT_SPECIFIC` 
PIN of the private key object you want to use is different from the `CKU_USER` PIN of 
the token that it belongs to. 

The searching methodology used to find objects within PKCS#11 tokens can largely be found 
[here](https://datatracker.ietf.org/doc/html/draft-woodhouse-cert-best-practice-01). Do note 
that there are some slight differences in how objects are found in the credential helper 
application. 

#### TPMv2 Integration

Private key files containing a TPM wrapped key in the `-----BEGIN TSS2 PRIVATE KEY-----`
form as described [here](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html)
are transparently supported. You can just use such a file as you would any plain key
file and expect it to work, just as you should expect with any well-behaved application. 

These files are supported, and can be created by, both TPMv2 OpenSSL engines/providers, and GnuTLS.

Note that some features of the TSS private key format are not yet supported. Some or all
of these may be implemented in future versions. In some semblance of the order in which
they're likely to be added:
 * Password authentication on parent keys (and hierarchies)
 as a parent
 * Importable keys
 * TPM Policy / AuthPolicy
 * Sealed keys

Note that it is possible to get around the parent key password authentication limit by loading 
the signing key (the loading process will have to be done with other tools and will require 
you to provivde your parent key password) into the TPM and referencing its handle in the command 
you want to call with the credential helper. 

##### Testing
Currently, unit tests for testing TPM support are written in such a way that TPM keys that are used 
for testing are either bound to a hardware TPM, or are bound to a software TPM. For software TPM 
testing, `swtpm` is used. You can find the repository [here](https://github.com/stefanberger/swtpm). 
Also, to create the keys and certificates that are required for unit testing, you will need to install 
the [Intel TSS](https://github.com/tpm2-software/tpm2-tss), 
[Intel OpenSSL provider](https://github.com/tpm2-software/tpm2-openssl), [`tpm2-tools`](https://github.com/tpm2-software/tpm2-tools), 
 and the [`tpm2-tabrmd`](https://github.com/tpm2-software/tpm2-abrmd) (resource manager). 

Once you've installed all the dependencies (which should be available on many Linux distributions 
through standard package managers), you can run just the unit tests related to TPM support 
through `make test-tpm-signer`. Note that `swtpm` will have to be run in UNIX socket mode (it can't 
be run in TCP socket mode) for the tests since that is all `go-tpm` can cope with. But key and 
certificate fixtures will be created when `swtpm` is running in TCP socket mode (as a part of the 
appropriate `Makefile` targets). Afterwards, right before the unit tests are run, we switch `swtpm` 
over to run in UNIX socket mode. 

Also, for the sake of testing, a small script is included that emulates a subset of the functionality 
that can be achieved with `create_tpm2_key`, a utility program that comes with the 
[IBM OpenSSL ENGINE](https://git.kernel.org/pub/scm/linux/kernel/git/jejb/openssl_tpm2_engine.git/). It 
is used to test TPM key files that include a permanent handle as their parent. 

##### Notes on Tooling Used

`tpm2-tools` and `tpm2-openssl` will by default create RSA keys that have the sign attribute, but that may 
not be the case for other tools that you may find. As an example, the tools that come with the IBM OpenSSL 
ENGINE will create RSA keys with the decrypt attribute but not the sign attribute by default. In order to 
be able to use an RSA key with the credential helper it must have the sign attribute set. The credential 
helper will delegate the signing operation to the TPM as opposed to using a raw RSA decrypt and deriving 
the signature by implementing PKCS#1 v1.5 padding. 

##### Guidance
If you haven't already initialized your TPM's owner hierarchy yet, it is recommended that you configure 
it with a password that has high entropy, as there are no dictionary attack protections for it. 

Once you have initialized the TPM's owner hierarchy, you can create a primary key in it. You can do so 
using one of the utility programs that comes with `tpm2-tools`: 

```
tpm2_createprimary -G rsa -g sha256 -p ${TPM_PRIMARY_KEY_PASSWORD} -c parent.ctx -P ${OWNER_HIERARCHY_PASSWORD}
```

This will create a primary key in the TPM owner hierarchy, with a key password of 
`${TPM_PRIMARY_KEY_PASSWORD}`. If the owner hierarchy in your TPM doesn't have a password (not recommended) 
you can omit the `-P` option in the above command. 

Next, you can create a child key with the primary you just created as its parent: 
```
tpm2_create -C parent.ctx -u child.pub -r child.priv -P ${TPM_PRIMARY_KEY_PASSWORD} -p ${TPM_CHILD_KEY_PASSWORD}
```

Next, load the child key that was just created into the TPM as a transient object: 
```
tpm2_load -C parent.ctx -u child.pub -r child.priv -c child.ctx -P ${TPM_PRIMARY_KEY_PASSWORD} 
```

Afterwards, make the transient object that is the child key into a persistent one and save its handle: 
```
CHILD_HANDLE=$(tpm2_evictcontrol -c child.ctx | cut -d ' ' -f 2 | head -n 1)
```

Then, you can create a CSR, using the [`tpm2-openssl`](https://github.com/tpm2-software/tpm2-openssl) OpenSSL 
provider. 
```
openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' \
            -new -key handle:${CHILD_HANDLE} \
            -out client-csr.pem
```

Note that the above will prompt you for your password (`TPM_CHILD_KEY_PASSWORD`). 

Lastly, once you have your CSR, you can provide it to a CA so that it can issue a client certificate for 
you. The client certificate and TPM key can then be used with the credential helper application as follows: 
```
/path/to/aws_signing_helper credential-process \
    --certificate /path/to/certificate/file \
    --private-key handle:${CHILD_HANDLE} \
    --role-arn ${ROLE_ARN} \
    --trust-anchor-arn ${TA_ARN} \
    --profile-arn ${PROFILE_ARN}
```

Please note that with this approach, it is your responsibility for clearing out the persistent and 
temporary objects from the TPM after you no longer need them, so that they can't be used by others 
on the same machine to escalate their privilege. Beware that if you load a key into the TPM that 
isn't password-protected, anyone that has access to the machine will be able to use that key. 

The alternative is to use a TPM key PEM file in the format described 
[here](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html), for use with the credential 
helper. If a TPM key file is used, the wrapped private key within the key file will be loaded into the 
TPM as a transient object and automatically flushed from the TPM after use by the credential helper (so 
after signing). If signing needs to occur multiple times, the key will be loaded into the TPM each 
time. The limitation with this approach is that the parent of the signing key can't be password-protected, 
as there is no way currently for you to pass this password to the credential helper. 

Below is an example of how you can use the credential helper with a TPM key file: 
```
/path/to/aws_signing_helper credential-process \
    --certificate /path/to/certificate/file \
    --private-key /path/to/tpm/key/file \
    --role-arn ${ROLE_ARN} \
    --trust-anchor-arn ${TA_ARN} \
    --profile-arn ${PROFILE_ARN}
```

#### Password-Encrypted Private Keys
You can pass a password-encrypted private key to the credential helper for signing the request. The credential helper supports two formats of PKCS#8 private key files:
- Unencrypted: `-----BEGIN PRIVATE KEY-----`
- Password-encrypted: `-----BEGIN ENCRYPTED PRIVATE KEY-----` (using PBES2)

To encrypt a plaintext private key stored on disk, you can use `openssl`:

```bash
openssl pkcs8 -topk8 -in unencrypted-key.pem -out encrypted-key.pem -passout pass:password -v2 aes-256-cbc
```

This command encrypts a PEM file containing an unencrypted private key in PKCS#8 format using the AES-256-CBC cipher with the password "password". The encrypted key is saved to a PEM file. Supported ciphers include:

- AES-128-CBC
- AES-192-CBC
- AES-256-CBC

You can also encrypt the key using a different pseudorandom function (PRF):

```bash
openssl pkcs8 -topk8 -in unencrypted-key.pem -out encrypted-key.pem -passout pass:password -v2prf hmacWithSHA256
```

Supported PRFs include:

- HMACWithSHA256
- HMACWithSHA384
- HMACWithSHA512

If you don't specify a cipher or PRF, the key is converted to PKCS#8 format using PKCS#5 v2.0 with AES-256-CBC and HMACWithSHA256.
The credential helper supports decrypting PKCS#8-encrypted private keys using PBES2, as defined in PKCS#5 (RFC 8018), with the options mentioned earlier. The key derivation function is PBKDF2, as specified in RFC 8018.
To enhance key protection, you can use scrypt to secure the PKCS#8-encoded key. Scrypt, defined in RFC 7914, is a memory-intensive KDF that improves resistance to attacks.
To encrypt a key using scrypt with OpenSSL:

```bash
openssl pkcs8 -topk8 -in unencrypted-key.pem -out encrypted-key.pem -passout pass:password -scrypt
```

This command uses the default scrypt parameters: N=16,384, r=8, and p=1.
After obtaining the encrypted key in a PEM file, pass it to the credential helper along with the password as the value for the `--pkcs8-password` option during signing. Note the following:

- If you don't want to encrypt a private key and are using OpenSSL, use the `-nocrypt` flag.
- Zero-length passwords are treated as no password.
- Only UTF-8-encoded passwords are supported.


#### Other Notes

##### YubiKey Attestation Certificates

Note that if you're using a YubiKey device with PIV support, when a key pair 
and certificate exist in slots 9a or 9c (PIV authentication and digital signature, 
respectively), the YubiKey will automatically generate an attestation certificate 
for the slot. Testing has shown that the attestation certificate can't be deleted. 
In this case, if you attempt to use the `CKA_ID` (the `id` path attribute in a URI) 
of your certificate to identify it in your supplied PKCS#11 URI, there will be 
two certificates that match. One way in which you can disambiguate between the 
two in your PKCS#11 URI can be through `CKA_LABEL` (the `object` path attribute 
in a URI). Attestation certificates in either of these two slots can be 
identified through the hard-coded labels, `X.509 Certificate for PIV Attestation 
9a` or `X.509 Certificate for PIV Attestation 9c`. 

##### Implementation Note

Due to this package's use of a dependency to integrate with PKCS#11 modules, we are unable 
to guarantee that PINs are zeroized in memory after they are no longer needed. We will continue 
to explore options to overcome this. Customers are encouraged to study the impact of this limitation 
and determine whether compensating controls are warranted for their system and threat model.

### update

Updates temporary credentials in the [credential file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html). Parameters for this command include those for the `credential-process` command, as well as `--profile`, which specifies the named profile for which credentials should be updated (if the profile doesn't already exist, it will be created), and `--once`, which specifies that credentials should be updated only once. Both arguments are optional. If `--profile` isn't specified, the default profile will have its credentials updated, and if `--once` isn't specified, credentials will be continuously updated. In this case, credentials will be updated through a call to `CreateSession` five minutes before the previous set of credentials are set to expire. Please note that running the `update` command multiple times, creating multiple processes, may not work as intended. There may be issues with concurrent writes to the credentials file.

Because when you use `update` credentials are written to a credential file on disk, it's important to understand that any user or process who can read the credential file may be able to read and use those AWS credentials. If using `update` to update any profile other than default, your application must be reference the correct profile to use. AWS SDKs will request new AWS credentials from the from the credential file as required.


### serve

Vends temporary credentials through an endpoint running on localhost. Parameters for this command include those for the `credential-process` command, as well as an optional `--port`, to specify the port on which the local endpoint will be exposed. By default, the port will be `9911`. Once again, credentials will be updated through a call to `CreateSession` five minutes before the previous set of credentials are set to expire. Note that the URIs and request headers are the same as those used in [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) (only the address of the endpoint changes from `169.254.169.254` to `127.0.0.1`). In order to make the credentials served from the local endpoint available to the SDK, set the `AWS_EC2_METADATA_SERVICE_ENDPOINT` environment variable appropriately.

When you use `serve` AWS SDKs will be able to discover the credentials from the credential helper using their [credential providers](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html) without any changes to code or configuration.  AWS SDKs will request new AWS credentials from the credential helper's server listening on 127.0.0.1 as required. 

When using `serve` it is important to understand that processes running on a system that can reach 127.0.0.1 will be able to retrieve AWS credentials from the credential helper. 

The `serve` command also supports a `--hop-limit` flag to limit the IP TTL on response packets. This defaults to a value of 64 but can be set to a value of 1 to maintain parity with EC2's IMDSv2 hop count behavior.

### Scripts

The project also comes with two bash scripts at its root, called `generate-credential-process-data.sh` and `create_tpm2_key.sh`. Please note that these scripts currently only work on Unix-based systems and require additional dependencies to be installed (further documented below). 

#### generate-credential-process-data.sh

Used by unit tests and for manual testing of the credential-process command. Creates a CA certificate/private key pair as well as a leaf certificate/private key. Test data is stored in the credential-process-data directory. When testing IAM Roles Anywhere, you will have to upload the CA certificate as a trust anchor and create a profile within Roles Anywhere before using the binary along with the leaf certificate/private key to call credential-process.

### Example Usage
```
/bin/sh generate-credential-process-data.sh

TA_ARN=$(aws rolesanywhere create-trust-anchor \
    --name "Test TA" \
    --source "sourceType=CERTIFICATE_BUNDLE,sourceData={x509CertificateData=$(cat credential-process-data/root-cert.pem)}" \
    --enabled | jq -r '.trustAnchor.trustAnchorArn')

PROFILE_ARN=$(aws rolesanywhere create-profile \
    --name "Test Profile" \
    --role-arns '["<your-role-arn>"]' \
    --enabled | jq -r '.profile.profileArn')

/path/to/aws_signing_helper credential-process \
    --certificate credential-process-data/client-cert.pem \
    --private-key credential-process-data/client-key.pem \
    --role-arn <your-role-arn> \
    --trust-anchor-arn ${TA_ARN} \
    --profile-arn ${PROFILE_ARN}
```

In the above example, you will have to create a role with a trust policy as documented [here](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html). After having done so, record the role ARN and use it both when creating a profile and when obtaining temporary security credentials through `credential-process`.

#### create_tpm2_key.sh

Used in the Makefile to emulate the `create_tpm2_key` utility that comes with the IBM OpenSSL TPM 2.0 ENGINE. Note that this script only supports a limited subset of the functionality that's available with the utility that comes with the OpenSSL ENGINE. The purpose is so that keys can be created with the appropriate attributes for the sake of testing, and error handling may not bbe very good. It is not recommended to use this script for other purposes. If you have a need to use the script, it is recommended that you install the OpenSSL ENGINE and use the utility that comes with it instead. 

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

