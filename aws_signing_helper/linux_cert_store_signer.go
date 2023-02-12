//go:build linux

package aws_signing_helper

import "errors"

func GetMatchingCerts(certIdentifier CertIdentifier) ([]*x509.Certificate, error) {
	return nil, errors.New("unable to use cert store signer on linux")
}

func GetCertStoreSigner(certIdentifier CertIdentifier) (signer Signer, signingAlgorithm string, err error) {
	return nil, "", errors.New("unable to use cert store signer on linux")
}
