package aws_signing_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"reflect"

	"github.com/miekg/pkcs11"
)


type PKCS11Signer struct {
	cert      *x509.Certificate
	certChain []*x509.Certificate
	libpkcs11			 string
	pinpkcs11			 string
	idpkcs11			 int

}

func GetMatchingPKCSCerts(certIdentifier CertIdentifier, lib string) (slot int, cert *x509.Certificate, err error) {
	var certLocated CertIdentifier

	p := pkcs11.New(lib)
	err = p.Initialize()
	if err != nil {
		return 0, nil, err
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return 0, nil, err
	}

	if len(slots) == 0 {
		log.Println("No slots identified on the security device")
		err = errors.New("No slots")
		return 0, nil, err
	} 

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, nil, err
	}
	defer p.CloseSession(session)

	var templatecrt []*pkcs11.Attribute


	templatecrt = append(templatecrt, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE))

	if err = p.FindObjectsInit(session, templatecrt); err != nil {
		fmt.Println("nil, err")
	}

	objs, b, err := p.FindObjects(session, 1)
	for err == nil {
		var o []pkcs11.ObjectHandle
		o, b, err = p.FindObjects(session, 1)
		if err != nil {
			continue
		}
		if len(o) == 0 {
			break
		}
		objs = append(objs, o...)
	}
	if err != nil {
		log.Println("Failed to find: ", b)
		if len(objs) == 0 {
			fmt.Println("nil")
		}
	}

	_ = p.FindObjectsFinal(session)  // found nothing

	for i := range objs {
		attributescrt := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
		}

		if attributescrt, err = p.GetAttributeValue(session, objs[i], attributescrt); err != nil {
			fmt.Println("nil, err2")
		}

		rawCertificate := attributescrt[0].Value
		cert, err := x509.ParseCertificate(rawCertificate)
		if err != nil {fmt.Println("Error parsing certificate")}
		serialNumber := cert.SerialNumber.String()
		certLocated.Subject = cert.Subject.CommonName 
		certLocated.Issuer = cert.Issuer.CommonName
		certLocated.SerialNumber, _ = new(big.Int).SetString(serialNumber, 16)
		if reflect.DeepEqual(certLocated, certIdentifier) {
			return i, cert, nil
		} else {
		}
	}


	return 0, nil, errors.New("unsupported certificate")
}

func (pkcs11Signer PKCS11Signer) Public() crypto.PublicKey {
	return nil
}

func (pkcs11Signer PKCS11Signer) Close() {
	p := pkcs11.New(pkcs11Signer.libpkcs11)
	p.Finalize()
	p.Destroy()

}

func (signer PKCS11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
		lib := signer.libpkcs11
		pin := signer.pinpkcs11
		id := signer.idpkcs11

		p := pkcs11.New(lib) 
		err = p.Initialize()
		if err != nil {
			return nil, err
		}

		slots, err := p.GetSlotList(true)
		if err != nil {
			return nil, err
		}

		session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return nil, err
		}
		defer p.CloseSession(session)

		err = p.Login(session, pkcs11.CKU_USER, pin)
		if err != nil {
			return nil, err
		}
		defer p.Logout(session)

		templatepk := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		}
		_ = p.FindObjectsInit(session, templatepk) 
		objspk, _, _ := p.FindObjects(session, 100)
		_ = p.FindObjectsFinal(session)  // found nothing

		err = p.Login(session, pkcs11.CKU_CONTEXT_SPECIFIC, pin)

		err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, objspk[id]) // CKM_SHA256_RSA_PKCS
		if err != nil {
			log.Fatalf("Signing Initiation failed (%s)\n", err.Error())
		}

		sig, err := p.Sign(session, digest)
		if err != nil {
		err = fmt.Errorf("Signing failed (%s)\n", err.Error())
		}


		if err == nil {
			return sig, nil
		}

	log.Println("unsupported algorithm")
	return nil, errors.New("unsupported algorithm")
}

func (pkcs11Signer PKCS11Signer) Certificate() (*x509.Certificate, error) {
	return pkcs11Signer.cert, nil
}

func (pkcs11Signer PKCS11Signer) CertificateChain() ([]*x509.Certificate, error) {
	return pkcs11Signer.certChain, nil
}


// Returns a PKCS11Signer, that signs a payload using the
// private key passed in
func GetPKCS11Signer(certIdentifier CertIdentifier, libpkcs11 string, pin string) (signer Signer, signingAlgorithm string, err error) {
	idpkcs11, cert, err := GetMatchingPKCSCerts(certIdentifier, libpkcs11)
	if err != nil {
		return nil, "", err
	}
	pinpkcs11 := pin

	// Find the signing algorithm
	switch cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			signingAlgorithm = aws4_x509_ecdsa_sha256
		case *rsa.PublicKey:
			signingAlgorithm = aws4_x509_rsa_sha256
		default:
			return nil, "", errors.New("unsupported algorithm")
	}

	return PKCS11Signer{cert, nil, libpkcs11, pinpkcs11, idpkcs11}, signingAlgorithm, nil
}
