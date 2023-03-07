package aws_signing_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/miekg/pkcs11"
	"golang.org/x/term"
)

var MAX_OBJECT_LIMIT int = 1000

type PKCS11Signer struct {
	cert             *x509.Certificate
	certChain        []*x509.Certificate
	module           *pkcs11.Ctx
	session          pkcs11.SessionHandle
	privateKeyHandle pkcs11.ObjectHandle
}

// Gets certificates that match the passed in CertIdentifier
func GetMatchingPKCSCerts(certIdentifier CertIdentifier, lib string) (module *pkcs11.Ctx, session pkcs11.SessionHandle, cert *x509.Certificate, matchingCerts []*x509.Certificate, err error) {
	var slots []uint
	var sessionCertObjects []pkcs11.ObjectHandle
	var certObjects []pkcs11.ObjectHandle
	var templateCrt []*pkcs11.Attribute

	module = pkcs11.New(lib)
	if err = module.Initialize(); err != nil {
		goto fail
	}

	slots, err = module.GetSlotList(true)
	if err != nil {
		goto fail
	}

	if len(slots) == 0 {
		goto fail
	}

	session, err = module.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		goto fail
	}

	// Finds certificates within the cryptographic device
	templateCrt = append(templateCrt, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE))

	if err = module.FindObjectsInit(session, templateCrt); err != nil {
		goto fail
	}

	for true {
		sessionCertObjects, _, err = module.FindObjects(session, MAX_OBJECT_LIMIT)
		if err != nil {
			goto fail
		}
		if len(sessionCertObjects) == 0 {
			break
		}
		certObjects = append(certObjects, sessionCertObjects...)
	}

	err = module.FindObjectsFinal(session)
	if err != nil {
		goto fail
	}

	// Matches certificates based on the CertIdentifier
	for i := range sessionCertObjects {
		crtAttributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
		}

		if crtAttributes, err = module.GetAttributeValue(session, sessionCertObjects[i], crtAttributes); err != nil {
			goto fail
		}

		rawCert := crtAttributes[0].Value
		curCert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			err = errors.New("error parsing certificate")
			goto fail
		}
		if certMatches(certIdentifier, curCert) {
			matchingCerts = append(matchingCerts, curCert)
		}
	}
	if len(matchingCerts) == 0 {
		err = errors.New("no matching certificates")
		goto fail
	}

	return module, session, nil, matchingCerts, nil

fail:
	if module != nil {
		if session != 0 {
			module.CloseSession(session)
		}
		module.Finalize()
		module.Destroy()
	}

	return nil, 0, nil, nil, err
}

// Returns the public key associated with this PKCS11Signer
func (pkcs11Signer *PKCS11Signer) Public() crypto.PublicKey {
	return pkcs11Signer.cert.PublicKey
}

// Closes this PKCS11Signer
func (pkcs11Signer *PKCS11Signer) Close() {
	if module := pkcs11Signer.module; module != nil {
		if session := pkcs11Signer.session; session != 0 {
			module.CloseSession(session)
		}
		module.Finalize()
		module.Destroy()
	}
}

// Implements the crypto.Signer interface and signs the passed in digest
func (pkcs11Signer *PKCS11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	module := pkcs11Signer.module
	session := pkcs11Signer.session
	privateKeyHandle := pkcs11Signer.privateKeyHandle
	cert := pkcs11Signer.cert

	var mechanism uint
	if cert.PublicKeyAlgorithm == x509.ECDSA {
		mechanism = pkcs11.CKM_ECDSA
	} else {
		switch opts.HashFunc() {
		case crypto.SHA256:
			mechanism = pkcs11.CKM_SHA256_RSA_PKCS
		case crypto.SHA384:
			mechanism = pkcs11.CKM_SHA384_RSA_PKCS
		case crypto.SHA512:
			mechanism = pkcs11.CKM_SHA512_RSA_PKCS
		}
	}

	err = module.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}, privateKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("signing initiation failed (%s)", err.Error())
	}

	sig, err := module.Sign(session, digest)
	if err != nil {
		return nil, fmt.Errorf("signing failed (%s)", err.Error())
	}

	return sig, nil
}

// Gets the x509.Certificate associated with this PKCS11Signer
func (pkcs11Signer PKCS11Signer) Certificate() (*x509.Certificate, error) {
	return pkcs11Signer.cert, nil
}

// Gets the certificate chain associated with this PKCS11Signer
// Note that this method is unimplemented right now (no certificate chain is returned)
func (pkcs11Signer PKCS11Signer) CertificateChain() ([]*x509.Certificate, error) {
	return pkcs11Signer.certChain, nil
}

// Checks whether the private key and certificate are associated with each other
func checkPrivateKeyMatchesCert(module *pkcs11.Ctx, session pkcs11.SessionHandle, privateKeyHandle pkcs11.ObjectHandle, certificate *x509.Certificate) bool {
	pkcs11Signer := PKCS11Signer{certificate, nil, module, session, privateKeyHandle}
	hash := sha256.Sum256(certificate.RawTBSCertificate)
	var signature []byte
	var err error

	// Derive signature based on algorithm (for a subset of possible algorithms)
	// Other algorithms are unsupported and therefore won't match
	switch certificate.SignatureAlgorithm {
	case x509.SHA256WithRSA:
	case x509.ECDSAWithSHA256:
		signature, err = pkcs11Signer.Sign(rand.Reader, hash[:], crypto.SHA256)
		break
	case x509.SHA384WithRSA:
	case x509.ECDSAWithSHA384:
		signature, err = pkcs11Signer.Sign(rand.Reader, hash[:], crypto.SHA384)
		break
	case x509.SHA512WithRSA:
	case x509.ECDSAWithSHA512:
		signature, err = pkcs11Signer.Sign(rand.Reader, hash[:], crypto.SHA512)
		break
	}

	if err != nil {
		return false
	}
	return reflect.DeepEqual(signature, certificate.Signature)
}

// Returns a PKCS11Signer, that can be used to sign a payload through a PKCS11-compatible
// cryptographic device
func GetPKCS11Signer(certIdentifier CertIdentifier, libPkcs11 string, pinPkcs11 string, certificate *x509.Certificate, certificateChain []*x509.Certificate) (signer Signer, signingAlgorithm string, err error) {
	var templatePrivateKey []*pkcs11.Attribute
	var sessionPrivateKeyObjects []pkcs11.ObjectHandle
	var privateKeyHandle pkcs11.ObjectHandle
	var pinPkcs11Bytes []byte

	module, session, cert, _, err := GetMatchingPKCSCerts(certIdentifier, libPkcs11)
	if err != nil {
		goto fail
	}

	if pinPkcs11 == "-" {
		fmt.Println("Please enter your user pin:")
		pinPkcs11Bytes, err = term.ReadPassword(0) // Read from stdin
		if err != nil {
			err = errors.New("unable to read PKCS#11 pin")
			goto fail
		}

		pinPkcs11 = string(pinPkcs11Bytes[:])
		strings.Replace(pinPkcs11, "\r", "", -1) // Remove CR
	}

	err = module.Login(session, pkcs11.CKU_USER, pinPkcs11)
	if err != nil {
		goto fail
	}

	templatePrivateKey = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	if err = module.FindObjectsInit(session, templatePrivateKey); err != nil {
		goto fail
	}
	sessionPrivateKeyObjects, _, err = module.FindObjects(session, MAX_OBJECT_LIMIT)
	if err != nil {
		goto fail
	}
	if err = module.FindObjectsFinal(session); err != nil {
		goto fail
	}
	if certificate == nil {
		privateKeyHandle = sessionPrivateKeyObjects[0]
	} else {
		for _, curPrivateKeyHandle := range sessionPrivateKeyObjects {
			if checkPrivateKeyMatchesCert(module, session, curPrivateKeyHandle, certificate) {
				privateKeyHandle = curPrivateKeyHandle
			}
		}
	}

	// Find the signing algorithm
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		signingAlgorithm = aws4_x509_ecdsa_sha256
	case *rsa.PublicKey:
		signingAlgorithm = aws4_x509_rsa_sha256
	default:
		return nil, "", errors.New("unsupported algorithm")
	}

	return &PKCS11Signer{cert, certificateChain, module, session, privateKeyHandle}, signingAlgorithm, nil

fail:
	if module != nil {
		if session != 0 {
			module.Logout(session)
			module.CloseSession(session)
		}
		module.Finalize()
		module.Destroy()
	}

	return nil, "", err
}
