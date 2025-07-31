//go:build !with_pkcs11

package aws_signing_helper

// This file exists to mock out the necessary functions called by core project code, but without actually bringing in
// a dependency on external PKCS#11 libraries (and thus, the requirement to link to them and enable CGO).  It is
// supposed to fail whenever called, because users who intentionally adopt the version of this code without PKCS#11
// support should not be calling PKCS#11 functions.

import (
	"crypto/x509"
	"errors"
)

var Pkcs11NotImplementedError = errors.New("This software has not been compiled with PKCS#11 support.")

func GetPKCS11Signer(libPkcs11 string, cert *x509.Certificate, certChain []*x509.Certificate, privateKeyId string, certificateId string, reusePin bool) (signer Signer, signingAlgorithm string, err error) {
	return nil, "", Pkcs11NotImplementedError
}

func GetMatchingPKCSCerts(uriStr string, lib string) (matchingCerts []CertificateContainer, err error) {
	return nil, Pkcs11NotImplementedError
}
