//go:build linux

package aws_signing_helper

import (
	"errors"
)

func GetMatchingCerts(certIdentifier CertIdentifier) ([]CertificateContainer, error) {
	return nil, errors.New("unable to use cert store signer on linux")
}

func GetCertStoreSigner(certIdentifier CertIdentifier, useLatestExpiringCert bool) (signer Signer, signingAlgorithm string, err error) {
	return nil, "", errors.New("unable to use cert store signer on linux")
}
