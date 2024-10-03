package aws_signing_helper

import (
	"log"
	"time"
)

type credentialProcess func(opts *CredentialsOpts, signer Signer, signatureAlgorithm string) (CredentialProcessOutput, error)

// refreshCredentials invokes the credential process continuously to refresh the credentials before they expire.
func refreshCredentials(process credentialProcess, opts *CredentialsOpts, signer Signer, signatureAlgorithm string) error {
	for {
		creds, err := process(opts, signer, signatureAlgorithm)
		if err != nil {
			return nil
		}

		expiration, err := time.Parse(time.RFC3339, creds.Expiration)
		if err != nil {
			return err
		}

		nextRefreshTime := expiration.Add(-UpdateRefreshTime)
		log.Println("Credentials will be refreshed at", nextRefreshTime.String())
		time.Sleep(time.Until(nextRefreshTime))
	}
}
