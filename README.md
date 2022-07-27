## AWS IAM Roles Anywhere Credential Helper

rolesanywhere-credential-helper implements the [signing process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html) for IAM Roles Anywhere's [CreateSession](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html) API and returns temporary credentials in a standard JSON format that is compatible with the `credential_process` feature available across the language SDKs. More information can be found [here](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html). It is released and licensed under the Apache License 2.0.

## Building

### Dependencies

In order to build the source code, you will need to install a C compiler, along with make and golang. 

#### Linux

On Debian-based systems, you can do so using `sudo apt-get install build-essential golang-go`. For other Linux systems, replace `apt-get` with the package manager on your system.

#### Darwin

You can download Apple clang through the [following link](https://developer.apple.com/download/) if you don't already have it installed on your system. You can install make and golang through Homebrew through `brew install make` and `brew install go`, respectively.

#### Windows

In order to get a C compile on Windows, one option is to use [MinGW-w64](https://www.mingw-w64.org/downloads/). After obtaining a C compiler, you can install golang through the [installer](https://go.dev/doc/install). Lastly, you can install make through `Chocolatey` with `choco install make`. 

### Build

After obtaining these tools, and making sure they are on your `PATH`, you can build the package (assuming you are currently at the package root):

```
make release
```

After building, you should see the `aws_signing_helper` binary built for your system at `build/bin/aws_signing_helper`. Usage is discussed briefly in the next section.

### Scripts

The project also comes with two bash scripts at its root, called `generate-certs.sh` and `generate-credential-process-data.sh`. The former script is used strictly for unit testing, and it generates certificate and private key data with different parameters that are supported by IAM Roles Anywhere. You can run the bash script using `/bin/bash generate-certs.sh`, and you will see the generated certificates and keys under the `tst/certs` directory. The latter script is used both for unit testing and can also be used for testing the `credential-process` command after having built the binary. It will create a CA certificate/private key as well as a leaf certificate/private key. When testing IAM Roles Anywhere, you will have to upload the CA certificate a trust anchor and create a profile within Roles Anywhere before using the binary along with the leaf certificate/private key to call `credential-process` (more instructions can be found in the next section). You can run the bash script using `/bin/bash generate-credential-process-data.sh`, and you will see the generated certificate hierarchy (and corresponding keys) under the `credential-process-data` directory. Note that the unit tests that require these fixtures to exist will run the bash script themselves, before executing those tests that depend on the fixtures existing. 

## Usage

There are three commands that are currently implemented within the source code. Two of these commands, `sign-string` and `read-certificate-data` are given as diagnostic tools. The former command allows one to sign a string that comes from standard input. The command requires one to pass in the path of a private key on disk to perform the signing (`--private-key`), as well as two optional arguments for the digest (`--digest`) and output format (`--format`). The digest has to be one of `SHA256`, `SHA384`, and `SHA512` if specified. The default value will be `SHA256` if it isn't specified. The output format has to be one of `text`, `json`, and `bin` if specified. The default value will be `text` if it isn't specified. The latter command allows one to read a certificate that is on disk. The path to the certificate (`--certificate`) is required. 

The last command is `credential-process`, which returns temporary credentials in a JSON format that is compatible with the `credential_process` feature available across language SDKs. Documentation on usage, along with examples can be found [here](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html). A script called `generate-credential-process-data.sh` can be found at the root of the project, which will generate RSA private keys and their corresponding certificates, that you can use to obtain temporary credentials from IAM Roles Anywhere. You can run the script using `/bin/bash generate-credential-process-data.sh`. Afterwards, you should see the generated private keys and certificates under the `credential-process-data` directory. The following example showcases how to use the data to obtain temporary credentials (assuming you are on a unix-based system):

```
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

