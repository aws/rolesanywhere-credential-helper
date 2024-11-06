//go:build windows

package aws_signing_helper

import (
	"errors"
)

func GetTPMv2Signer(certIdentifier CertIdentifier) (signer Signer, signingAlgorithm string, err error) {
	return nil, "", errors.New("unable to use tpm v2 signer on windows")
}
