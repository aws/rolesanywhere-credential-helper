## AWS IAM Roles Anywhere Credential Helper

rolesanywhere-credential-helper implements the [signing process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html) for IAM Roles Anywhere's [CreateSession](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html) API and returns temporary credentials in a standard JSON format that is compatible with the `credential_process` feature available across the language SDKs. More information can be found [here](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html). It is released and licensed under the Apache License 2.0.

## Building

In order to build the source code, you will need to install a C compiler, along with make and golang. On Debian-based systems, you can do so using `sudo apt-get install build-essential golang-go`. After obtaining these tools, you can build the package (assuming you are currently at the package root):

```
make release
```

After building, you should see the `aws_signing_helper` binary built for your system at `build/bin/aws_signing_helper`. Usage is discussed briefly in the next section.

## Usage

There are three commands that are currently implemented within the source code. Two of these commands, `sign-string` and `read-certificate-data` are given as diagnostic tools. The former command allows one to sign a string that comes from standard input. The command requires one to pass in the path of a private key on disk to perform the signing (`--private-key`), as well as two optional arguments for the digest (`--digest`) and output format (`--format`). The digest has to be one of `SHA256`, `SHA384`, and `SHA512` if specified. The default value will be `SHA256` if it isn't specified. The output format has to be one of `text`, `json`, and `bin` if specified. The default value will be `text` if it isn't specified. The latter command allows one to read a certificate that is on disk. The path to the certificate (`--certificate`) is required. 

The last command is `credential-process`, which returns temporary credentials in a JSON format that is compatible with the `credential_process` feature available across language SDKs. Documentation on usage, along with examples can be found [here](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html). A script called `generate-credential-process-data.sh` can be found at the root of the project, which will generate RSA private keys and their corresponding certificates, that you can use to obtain temporary credentials from IAM Roles Anywhere. You can run the script using `/bin/bash generate-credential-process-data.sh`. Afterwards, you should see the generated private keys and certificates under the `credential-process-data` directory. The following example showcases how to use the data to obtain temporary credentials:

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

