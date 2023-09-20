//go:build darwin

package aws_signing_helper

// This code is based on the smimesign repository at
// https://github.com/github/smimesign

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"unsafe"
)

type DarwinCertStoreSigner struct {
	identRef  C.SecIdentityRef
	keyRef    C.SecKeyRef
	certRef   C.SecCertificateRef
	cert      *x509.Certificate
	certChain []*x509.Certificate
}

// osStatus wraps a C.OSStatus
type osStatus C.OSStatus

const (
	errSecItemNotFound = osStatus(C.errSecItemNotFound)
)

// Gets the matching identity and certificate for this CertIdentifier
// If there is more than one, only a list of the matching certificates is returned
func GetMatchingCertsAndIdentity(certIdentifier CertIdentifier) (C.SecIdentityRef, C.SecCertificateRef, []CertificateContainer, error) {
	queryMap := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):      C.CFTypeRef(C.kSecClassIdentity),
		C.CFTypeRef(C.kSecReturnRef):  C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit): C.CFTypeRef(C.kSecMatchLimitAll),
	}

	query := mapToCFDictionary(queryMap)
	if query == 0 {
		return 0, 0, nil, errors.New("error creating CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var absResult C.CFTypeRef
	if err := osStatusError(C.SecItemCopyMatching(query, &absResult)); err != nil {
		if err == errSecItemNotFound {
			return 0, 0, nil, errors.New("unable to find matching identity in cert store")
		}
		return 0, 0, nil, err
	}
	defer C.CFRelease(C.CFTypeRef(absResult))
	aryResult := C.CFArrayRef(absResult)

	// identRefs aren't owned by us initially
	numIdentRefs := C.CFArrayGetCount(aryResult)
	identRefs := make([]C.CFTypeRef, numIdentRefs)
	C.CFArrayGetValues(aryResult, C.CFRange{0, numIdentRefs}, (*unsafe.Pointer)(unsafe.Pointer(&identRefs[0])))
	var certContainers []CertificateContainer
	var certRef C.SecCertificateRef
	var identRef C.SecIdentityRef
	var isMatch bool
	for _, curIdentRef := range identRefs {
		curCertRef, err := getCertRef(C.SecIdentityRef(curIdentRef))
		if err != nil {
			return 0, 0, nil, errors.New("unable to get cert ref")
		}
		curCert, err := exportCertRef(curCertRef)
		if err != nil {
			if Debug {
				log.Printf("unable to parse certificate with error (%s) - skipping\n", err)
			}
			goto nextIteration
		}

		// Find whether there is a matching certificate
		isMatch = certMatches(certIdentifier, *curCert)
		if isMatch {
			certContainers = append(certContainers, CertificateContainer{curCert, ""})
			// Assign to certRef and identRef at most once in the loop
			// Both values are only useful if there is exactly one match in the certificate store
			// When creating a signer, there has to be exactly one matching certificate
			if certRef == 0 {
				certRef = curCertRef
				identRef = C.SecIdentityRef(curIdentRef)
			}
		}

	nextIteration:
	}

	if Debug {
		log.Printf("found %d matching identities\n", len(certContainers))
	}

	// Only retain the SecIdentityRef if it should be used later on
	// Note that only the SecIdentityRef needs to be retained since it was neither created nor copied
	if len(certContainers) == 1 {
		C.CFRetain(C.CFTypeRef(identRef))
		return identRef, certRef, certContainers, nil
	} else {
		return 0, 0, certContainers, nil
	}
}

// Gets the certificates that match the CertIdentifier
func GetMatchingCerts(certIdentifier CertIdentifier) ([]CertificateContainer, error) {
	identRef, certRef, certContainers, err := GetMatchingCertsAndIdentity(certIdentifier)
	if len(certContainers) == 1 {
		C.CFRelease(C.CFTypeRef(identRef))
		C.CFRelease(C.CFTypeRef(certRef))
	}
	return certContainers, err
}

// Creates a DarwinCertStoreSigner based on the identifying certificate
func GetCertStoreSigner(certIdentifier CertIdentifier) (signer Signer, signingAlgorithm string, err error) {
	identRef, certRef, certContainers, err := GetMatchingCertsAndIdentity(certIdentifier)
	if err != nil {
		return nil, "", err
	}
	if len(certContainers) == 0 {
		return nil, "", errors.New("no matching identities")
	}
	if len(certContainers) > 1 {
		return nil, "", errors.New("multiple matching identities")
	}
	cert := certContainers[0].Cert

	// Find the signing algorithm
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		signingAlgorithm = aws4_x509_ecdsa_sha256
	case *rsa.PublicKey:
		signingAlgorithm = aws4_x509_rsa_sha256
	default:
		return nil, "", errors.New("unsupported algorithm")
	}

	keyRef, err := getKeyRef(identRef)
	if err != nil {
		return nil, "", errors.New("unable to get key reference")
	}

	return &DarwinCertStoreSigner{identRef, keyRef, certRef, cert, nil}, signingAlgorithm, nil
}

// Gets the certificate associated with this DarwinCertStoreSigner
func (signer *DarwinCertStoreSigner) Certificate() (*x509.Certificate, error) {
	if signer.cert != nil {
		return signer.cert, nil
	}

	certRef, err := signer.getCertRef()
	if err != nil {
		return nil, err
	}

	cert, err := exportCertRef(certRef)
	if err != nil {
		return nil, err
	}
	signer.cert = cert

	return signer.cert, nil
}

// Gets the certificate chain associated with this DarwinCertStoreSigner
func (signer *DarwinCertStoreSigner) CertificateChain() ([]*x509.Certificate, error) {
	if signer.certChain != nil {
		return signer.certChain, nil
	}

	certRef, err := signer.getCertRef()
	if err != nil {
		return nil, err
	}

	policy := C.SecPolicyCreateSSL(0, 0)

	var trustRef C.SecTrustRef
	if err := osStatusError(C.SecTrustCreateWithCertificates(C.CFTypeRef(certRef), C.CFTypeRef(policy), &trustRef)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(trustRef))

	// var status C.SecTrustResultType
	var cfErrRef C.CFErrorRef
	if C.SecTrustEvaluateWithError(trustRef, &cfErrRef) {
		return nil, cfErrorError(cfErrRef)
	}

	var (
		nChain    = C.SecTrustGetCertificateCount(trustRef)
		certChain = make([]*x509.Certificate, 0, int(nChain))
	)

	certChainArr := C.SecTrustCopyCertificateChain(trustRef)
	defer C.CFRelease(C.CFTypeRef(certChainArr))
	for i := C.CFIndex(0); i < nChain; i++ {
		chainCertRef := C.SecCertificateRef(C.CFArrayGetValueAtIndex(certChainArr, i))
		if chainCertRef == 0 {
			return nil, errors.New("nil certificate in chain")
		}

		chainCert, err := exportCertRef(chainCertRef)
		if err != nil {
			return nil, err
		}

		certChain = append(certChain, chainCert)
	}

	certChain = certChain[1:]
	signer.certChain = certChain

	return signer.certChain, nil
}

// Public implements the crypto.Signer interface and returns the public key associated with the signer
func (signer *DarwinCertStoreSigner) Public() crypto.PublicKey {
	cert, err := signer.Certificate()
	if err != nil {
		return nil
	}

	return cert.PublicKey
}

// Closes the DarwinCertStoreSigner
func (signer *DarwinCertStoreSigner) Close() {
	if signer.identRef != 0 {
		C.CFRelease(C.CFTypeRef(signer.identRef))
		signer.identRef = 0
	}

	if signer.keyRef != 0 {
		C.CFRelease(C.CFTypeRef(signer.keyRef))
		signer.keyRef = 0
	}

	if signer.certRef != 0 {
		C.CFRelease(C.CFTypeRef(signer.certRef))
		signer.certRef = 0
	}
}

// Sign implements the crypto.Signer interface and signs the digest
func (signer *DarwinCertStoreSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var hash []byte
	switch opts.HashFunc() {
	case crypto.SHA256:
		sum := sha256.Sum256(digest)
		hash = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(digest)
		hash = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(digest)
		hash = sum[:]
	default:
		return nil, ErrUnsupportedHash
	}

	keyRef, err := signer.getKeyRef()
	if err != nil {
		return nil, err
	}

	chash, err := bytesToCFData(hash)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(chash))

	cert, err := signer.Certificate()
	if err != nil {
		return nil, err
	}

	algo, err := getAlgo(cert, opts.HashFunc())
	if err != nil {
		return nil, err
	}

	// sign the digest
	var cfErrRef C.CFErrorRef
	cSig := C.SecKeyCreateSignature(keyRef, algo, chash, &cfErrRef)

	if err := cfErrorError(cfErrRef); err != nil {
		C.CFRelease(C.CFTypeRef(cfErrRef))

		return nil, err
	}

	if cSig == 0 {
		return nil, errors.New("nil signature from SecKeyCreateSignature")
	}
	defer C.CFRelease(C.CFTypeRef(cSig))

	sig := cfDataToBytes(cSig)

	return sig, nil
}

// getAlgo decides which algorithm to use with this key type for the given hash.
func getAlgo(cert *x509.Certificate, hash crypto.Hash) (algo C.SecKeyAlgorithm, err error) {
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA1
		case crypto.SHA256:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
		case crypto.SHA384:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384
		case crypto.SHA512:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512
		default:
			err = ErrUnsupportedHash
		}
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
		case crypto.SHA256:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
		case crypto.SHA384:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
		case crypto.SHA512:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
		default:
			err = ErrUnsupportedHash
		}
	default:
		err = errors.New("unsupported key type")
	}

	return algo, err
}

// exportCertRef gets a *x509.Certificate for the given SecCertificateRef.
func exportCertRef(certRef C.SecCertificateRef) (*x509.Certificate, error) {
	derRef := C.SecCertificateCopyData(certRef)
	if derRef == 0 {
		return nil, errors.New("error getting certificate from identity")
	}
	defer C.CFRelease(C.CFTypeRef(derRef))

	der := cfDataToBytes(derRef)
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

// getKeyRef gets the SecKeyRef for this identity's private key.
func getKeyRef(ref C.SecIdentityRef) (C.SecKeyRef, error) {
	var keyRef C.SecKeyRef
	if err := osStatusError(C.SecIdentityCopyPrivateKey(ref, &keyRef)); err != nil {
		return 0, err
	}

	return keyRef, nil
}

// getKeyRef gets the SecKeyRef for this identity's private key.
func (signer DarwinCertStoreSigner) getKeyRef() (C.SecKeyRef, error) {
	if signer.keyRef != 0 {
		return signer.keyRef, nil
	}

	keyRef, err := getKeyRef(signer.identRef)
	signer.keyRef = keyRef

	return signer.keyRef, err
}

// getCertRef gets the SecCertificateRef for this identity's certificate.
func getCertRef(ref C.SecIdentityRef) (C.SecCertificateRef, error) {
	var certRef C.SecCertificateRef
	if err := osStatusError(C.SecIdentityCopyCertificate(ref, &certRef)); err != nil {
		return 0, err
	}

	return certRef, nil
}

// getCertRef gets the identity's certificate reference
func (signer *DarwinCertStoreSigner) getCertRef() (C.SecCertificateRef, error) {
	if signer.certRef != 0 {
		return signer.certRef, nil
	}

	certRef, err := getCertRef(signer.identRef)
	signer.certRef = certRef

	return signer.certRef, err
}

// stringToCFData converts a Go string to a CFDataRef
func stringToCFData(str string) (C.CFDataRef, error) {
	return bytesToCFData([]byte(str))
}

// cfDataToBytes converts a CFDataRef to a Go byte slice
func cfDataToBytes(cfdata C.CFDataRef) []byte {
	nBytes := C.CFDataGetLength(cfdata)
	bytesPtr := C.CFDataGetBytePtr(cfdata)
	return C.GoBytes(unsafe.Pointer(bytesPtr), C.int(nBytes))
}

// bytesToCFData converts a Go byte slice to a CFDataRef
func bytesToCFData(gobytes []byte) (C.CFDataRef, error) {
	var (
		cptr = (*C.UInt8)(nil)
		clen = C.CFIndex(len(gobytes))
	)

	if len(gobytes) > 0 {
		cptr = (*C.UInt8)(&gobytes[0])
	}

	cdata := C.CFDataCreate(0, cptr, clen)
	if cdata == 0 {
		return 0, errors.New("error creating cdata")
	}

	return cdata, nil
}

// cfErrorError returns an error for a CFErrorRef unless it is nil
func cfErrorError(cerr C.CFErrorRef) error {
	if cerr == 0 {
		return nil
	}

	code := int(C.CFErrorGetCode(cerr))

	if cdescription := C.CFErrorCopyDescription(cerr); cdescription != 0 {
		defer C.CFRelease(C.CFTypeRef(cdescription))

		if cstr := C.CFStringGetCStringPtr(cdescription, C.kCFStringEncodingUTF8); cstr != nil {
			str := C.GoString(cstr)

			return fmt.Errorf("CFError %d (%s)", code, str)
		}

	}

	return fmt.Errorf("CFError %d", code)
}

// mapToCFDictionary converts a Go map[C.CFTypeRef]C.CFTypeRef to a CFDictionaryRef
func mapToCFDictionary(gomap map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	var (
		n      = len(gomap)
		keys   = make([]unsafe.Pointer, 0, n)
		values = make([]unsafe.Pointer, 0, n)
	)

	for k, v := range gomap {
		keys = append(keys, unsafe.Pointer(k))
		values = append(values, unsafe.Pointer(v))
	}

	return C.CFDictionaryCreate(0, &keys[0], &values[0], C.CFIndex(n), nil, nil)
}

// osStatusError returns an error for an OSStatus unless it is errSecSuccess
func osStatusError(s C.OSStatus) error {
	if s == C.errSecSuccess {
		return nil
	}

	return osStatus(s)
}

// Error implements the error interface and returns a stringified error for this osStatus
func (s osStatus) Error() string {
	return fmt.Sprintf("OSStatus %d", s)
}
