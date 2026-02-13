package aws_signing_helper

import (
	"errors"
	"fmt"
	"time"
)

// fileCredentialsUpdater writes new temporary credentials to the AWS credentials file
// for an specific profile.
type fileCredentialsUpdater struct {
	profile string
}

// updateCredentialsFile writes new temporary credentials to the AWS credentials file.
func (u fileCredentialsUpdater) updateCredentialsFile(opts *CredentialsOpts, signer Signer, signatureAlgorithm string) (CredentialProcessOutput, error) {
	credentialProcessOutput, err := GenerateCredentials(opts, signer, signatureAlgorithm)
	if err != nil {
		return CredentialProcessOutput{}, nil
	}

	refreshableCred := TemporaryCredential{}

	// Assign credential values
	refreshableCred.AccessKeyId = credentialProcessOutput.AccessKeyId
	refreshableCred.SecretAccessKey = credentialProcessOutput.SecretAccessKey
	refreshableCred.SessionToken = credentialProcessOutput.SessionToken // nosemgrep
	refreshableCred.Expiration, _ = time.Parse(time.RFC3339, credentialProcessOutput.Expiration)
	if (refreshableCred == TemporaryCredential{}) {
		return CredentialProcessOutput{}, errors.New("no credentials created")
	}

	// Get credentials file contents
	lines, err := GetCredentialsFileContents()
	if err != nil {
		return CredentialProcessOutput{}, fmt.Errorf("unable to get credentials file contents: %w", err)
	}

	// Write to credentials file
	if err = WriteTo(u.profile, lines, &refreshableCred); err != nil {
		return CredentialProcessOutput{}, fmt.Errorf("unable to write to AWS credentials file: %w", err)
	}

	return credentialProcessOutput, nil
}
