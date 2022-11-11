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

Reads a certificate that is on disk. The path to the certificate must be provided with the `--certificate` parameter.

### sign-string

Signs a string from standard input. Useful for validating your on-disk private key and digest. The path to the private key must be provided with the `--private-key` parameter. Other parameters that can be used are `--digest`, which must be one of `SHA256 (*default*) | SHA384 | SHA512`, and `--format`, which must be one of `text (*default*) | json | bin`. 

### credential-process

Vends temporary credentials by sending a `CreateSession` request to the Roles Anywhere service. The request is signed by the private key whose path must be provided with the `--private-key` parameter. Other required parameters include `--certificate` (the path to the end-entity certificate), `--role-arn` (the ARN of the role to obtain temporary credentials for), `--profile-arn` (the ARN of the profile that provides a mapping for the specified role), and `--trust-anchor-arn` (the ARN of the trust anchor used to authenticate). Optional parameters that can be used are `--debug` (to provide debugging output about the request sent), `--no-verify-ssl` (to skip verification of the SSL certificate on the endpoint called), `--intermediates` (the path to intermediate certificates), `--with-proxy` (to make the binary proxy aware), `--endpoint` (the endpoint to call), `--region` (the region to scope the request to), and `--session-duration` (the duration of the vended session).

### update

Updates temporary credentials in the [credential file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html). Parameters for this command include those for the `credential-process` command, as well as `--profile`, which specifies the named profile for which credentials should be updated (if the profile doesn't already exist, it will be created), and `--once`, which specifies that credentials should be updated only once. Both arguments are optional. If `--profile` isn't specified, the default profile will have its credentials updated, and if `--once` isn't specified, credentials will be continuously updated. In this case, credentials will be updated through a call to `CreateSession` five minutes before the previous set of credentials are set to expire.

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

