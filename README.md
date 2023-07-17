## AWS IAM Roles Anywhere Credential Helper
rolesanywhere-credential-helper implements the [signing process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html) for IAM Roles Anywhere's [CreateSession](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html) API and returns temporary credentials in a standard JSON format that is compatible with the `credential_process` feature available across the language SDKs. More information can be found [here](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html). It is released and licensed under the Apache License 2.0.

## Building

### Dependencies
In order to build the source code, you will need to install git, gcc, make, and golang.

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

### Scripts

The project also comes with two bash scripts at its root, called `generate-certs.sh` and `generate-credential-process-data.sh`. The former script is used strictly for unit testing, and it generates certificate and private key data with different parameters that are supported by IAM Roles Anywhere. You can run the bash script using `/bin/bash generate-certs.sh`, and you will see the generated certificates and keys under the `tst/certs` directory. The latter script is used both for unit testing and can also be used for testing the `credential-process` command after having built the binary. It will create a CA certificate/private key as well as a leaf certificate/private key. When testing IAM Roles Anywhere, you will have to upload the CA certificate a trust anchor and create a profile within Roles Anywhere before using the binary along with the leaf certificate/private key to call `credential-process` (more instructions can be found in the next section). You can run the bash script using `/bin/bash generate-credential-process-data.sh`, and you will see the generated certificate hierarchy (and corresponding keys) under the `credential-process-data` directory. Note that the unit tests that require these fixtures to exist will run the bash script themselves, before executing those tests that depend on the fixtures existing. Please note that these scripts currently only work on Unix-based systems and require `openssl` to be installed.

## Diagnostic Command Tools

### read-certificate-data

Reads a certificate that is on disk. Either the path to the certificate on disk is provided with the `--certificate` parameter, or the `--cert-selector` flag is provided to select a certificate within an OS certificate store or PKCS#11 module. Further details about the flag are provided below.

#### cert-selector flag

If you use Windows or MacOS, the credential helper also supports leveraging private keys and certificates that are in their OS-specific secure stores. In Windows, both CNG and Cryptography are supported, while on MacOS, Keychain Access is supported. Through the `--cert-selector` flag, it is possible to specify which certificate (and associated private key) to use in calling `CreateSession`. The credential helper will then delegate signing operations to the keys within those secure stores, without those keys ever having to leave those stores. It is important to note that on Windows, only the user's "MY" certificate store will be searched by the credential helper, while for MacOS, those Keychains on the search list will be searched.

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
--cert-selector Key=x509Subject,Value=CN=Subject Key=x509Issuer,Value=CN=Issuer Key=x509Serial,Value=15D19632234BF759A32802C0DA88F9E8AFC8702D
```

The example given here is quite simple (they each only contain a single RDN), so it may not be obvious, but the Subject and Issuer values roughly follow the [RFC 2253](https://www.rfc-editor.org/rfc/rfc2253.html) Distinguished Names syntax.

Note that the `--cert-selector` flag can also be used to match certificates in PKCS#11 modules.

### sign-string

Signs a string from standard input. Useful for validating your on-disk private key and digest. The path to the private key must be provided with the `--private-key` parameter. Other parameters that can be used are `--digest`, which must be one of `SHA256 (*default*) | SHA384 | SHA512`, and `--format`, which must be one of `text (*default*) | json | bin`.

### credential-process

Vends temporary credentials by sending a `CreateSession` request to the Roles Anywhere service. The request is signed by the private key whose path can be provided with the `--private-key` parameter. Other parameters include `--certificate` (the path to the end-entity certificate), `--role-arn` (the ARN of the role to obtain temporary credentials for), `--profile-arn` (the ARN of the profile that provides a mapping for the specified role), and `--trust-anchor-arn` (the ARN of the trust anchor used to authenticate). Optional parameters that can be used are `--debug` (to provide debugging output about the request sent), `--no-verify-ssl` (to skip verification of the SSL certificate on the endpoint called), `--intermediates` (the path to intermediate certificates), `--with-proxy` (to make the binary proxy aware), `--endpoint` (the endpoint to call), `--region` (the region to scope the request to), and `--session-duration` (the duration of the vended session). Instead of passing in paths to the plaintext private key on your file system, another option (depending on your OS) could be to use the `--cert-selector` flag. More details can be found below.

Note that if more than one certificate matches the `--cert-selector` parameter within the OS-specific secure store, the `credential-process` command will fail. To find the list of certificates that match a given `--cert-selector` parameter, you can use the same flag with the `read-certificate-data` command.

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
using a certificate from a file but only the key in PKCS#11 is also supported. Some examples:

  * `--certificate 'pkcs11:manufacturer=piv_II;id=%01'`
  * `--certificate 'pkcs11:object=My%20RA%20key'`
  * `--certificate client-cert.pem --private-key 'pkcs11:model=SoftHSM%20v2;object=My%20RA%20key'`

Some documentation which may assist with finding the correct URI for
your key can be found [here](https://www.infradead.org/openconnect/pkcs11.html).

Most Linux and similar *nix systems use
[p11-kit](https://p11-glue.github.io/p11-glue/p11-kit/manual/config.html)
to provide consistent system-wide and per-user configuration of
available PKCS#11 providers. Any properly packaged provider module
will register itself with p11-kit and will be automatically visible
through the `p11-kit-proxy.so` provider which is used by default.

If you have a poorly packaged provider module from a vendor, then
after you have filed a bug you can manually create a p11-kit [module
file](https://p11-glue.github.io/p11-glue/p11-kit/manual/pkcs11-conf.html)
for it.

For systems or containers which lack p11-kit, a specific PKCS#11
provider library can be specified using the `--pkcs11-lib` command
line option.

The PKCS#11 URI is itself a set of search terms to find a matching object
in the PKCS#11 token, but if that is not sufficient to uniquely identify
the certificate, further refinement of matching certificates can be
achieved through the `--cert-selector` flag.

#### TPMv2 Integration

Private key files containing a TPM wrapped key in the `-----BEGIN TSS2 PRIVATE KEY-----`
form as described [here](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html)
are transparently supported. You can just use such a file as you would any plain key
file and expect it to work, just as you should expect with any well-behaved application.

These files are supported, and can be created by, both TPMv2 OpenSSL engines/providers, and GnuTLS.

Note that some features of the TSS private key format are not yet supported. Some or all
of these may be implemented in future versions. In some semblance of the order in which
they're likely to be added:
 * Password authentication on keys (and parent keys)
 * Importable keys
 * TPM Policy / AuthPolicy
 * Sealed keys

### update

Updates temporary credentials in the [credential file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html). Parameters for this command include those for the `credential-process` command, as well as `--profile`, which specifies the named profile for which credentials should be updated (if the profile doesn't already exist, it will be created), and `--once`, which specifies that credentials should be updated only once. Both arguments are optional. If `--profile` isn't specified, the default profile will have its credentials updated, and if `--once` isn't specified, credentials will be continuously updated. In this case, credentials will be updated through a call to `CreateSession` five minutes before the previous set of credentials are set to expire. Please note that running the `update` command multiple times, creating multiple processes, may not work as intended. There may be issues with concurrent writes to the credentials file.

### serve

Vends temporary credentials through an endpoint running on localhost. Parameters for this command include those for the `credential-process` command, as well as an optional `--port`, to specify the port on which the local endpoint will be exposed. By default, the port will be `9911`. Once again, credentials will be updated through a call to `CreateSession` five minutes before the previous set of credentials are set to expire. Note that the URIs and request headers are the same as those used in [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) (only the address of the endpoint changes from `169.254.169.254` to `127.0.0.1`). In order to make the credentials served from the local endpoint available to the SDK, set the `AWS_EC2_METADATA_SERVICE_ENDPOINT` environment variable appropriately.

### Scripts

The project also comes with two bash scripts at its root, called `generate-certs.sh` and `generate-credential-process-data.sh`. Note that these scripts currently only work on Unix-based systems and require `openssl` to be installed.

#### generate-certs.sh

Used by unit tests to generate test certificates and private keys supported by IAM Roles Anywhere. The test data is stored in the tst/certs directory.

#### generate-credential-process-data.sh

Used by unit tests and for manual testing of the credential-process command. Creates a CA certificate/private key pair as well as a leaf certificate/private key. Test data is stored in the credential-process-data directory. When testing IAM Roles Anywhere, you will have to upload the CA certificate as a trust anchor and create a profile within Roles Anywhere before using the binary along with the leaf certificate/private key to call credential-process.

### Example Usage
```
/bin/bash generate-credential-process-data.sh

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

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

