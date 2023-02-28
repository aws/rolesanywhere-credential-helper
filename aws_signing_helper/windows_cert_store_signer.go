//go:build windows

package aws_signing_helper

/*
#cgo windows LDFLAGS: -lcrypt32 -lncrypt
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>

//
// Go complains about LPCWSTR constants and the MAKELANGID function not being
// defined, so we define methods for them.
//

LPCWSTR GET_BCRYPT_SHA1_ALGORITHM() { return BCRYPT_SHA1_ALGORITHM; }
LPCWSTR GET_BCRYPT_SHA256_ALGORITHM() { return BCRYPT_SHA256_ALGORITHM; }
LPCWSTR GET_BCRYPT_SHA384_ALGORITHM() { return BCRYPT_SHA384_ALGORITHM; }
LPCWSTR GET_BCRYPT_SHA512_ALGORITHM() { return BCRYPT_SHA512_ALGORITHM; }

int MAKE_LANG_ID(int p, int s) {
    return MAKELANGID(p, s);
}

*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf16"
	"unsafe"
)

// winPrivateKey is a wrapper around a HCRYPTPROV_OR_NCRYPT_KEY_HANDLE.
type winPrivateKey struct {
	publicKey crypto.PublicKey

	// CryptoAPI fields
	cspHandle C.HCRYPTPROV
	keySpec   C.DWORD

	// CNG fields
	cngKeyHandle C.NCRYPT_KEY_HANDLE
}

type WindowsCertStoreSigner struct {
	store       C.HCERTSTORE
	cert        *x509.Certificate
	certChain   []*x509.Certificate
	pcCertChain []C.PCCERT_CONTEXT
	privateKey  *winPrivateKey
}

const (
	WIN_TRUE  C.WINBOOL = 1
	WIN_FALSE C.WINBOOL = 0

	// ERROR_SUCCESS — The call succeeded
	ERROR_SUCCESS = 0x00000000

	// CRYPT_E_NOT_FOUND — Cannot find object or property
	CRYPT_E_NOT_FOUND = 0x80092004

	// NTE_BAD_ALGID — Invalid algorithm specified
	NTE_BAD_ALGID = 0x80090008

	// WIN_API_FLAG specifies the flags that should be passed to
	// CryptAcquireCertificatePrivateKey. This impacts whether the CryptoAPI or CNG
	// API will be used.
	//
	// Possible values are:
	//
	//	0x00000000 —                                      — Only use CryptoAPI.
	//	0x00010000 — CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG  — Prefer CryptoAPI.
	//	0x00020000 — CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG — Prefer CNG.
	//	0x00040000 — CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG   — Only use CNG.
	WIN_API_FLAG C.DWORD = C.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
)

// Error codes for Windows APIs - implements the error interface
type errCode uint64

// Security status for Windows APIs - implements the error interface
// Go representation of the C SECURITY_STATUS
type securityStatus uint64

// Gets the certificates that match the given CertIdentifier within the user's "MY" certificate store.
// If there is only a single matching certificate, then its chain will be returned too
func GetMatchingCertsAndChain(certIdentifier CertIdentifier) (store C.HCERTSTORE, pcCertChain []C.PCCERT_CONTEXT, matchingCerts []*x509.Certificate, err error) {
	storeName := unsafe.Pointer(stringToUTF16("MY"))
	defer C.free(storeName)

	store = C.CertOpenStore(C.CERT_STORE_PROV_SYSTEM_W, 0, 0, C.CERT_SYSTEM_STORE_CURRENT_USER, storeName)
	if store == nil {
		return nil, nil, nil, lastError("failed to open system cert store")
	}

	var (
		// CertFindChainInStore parameters
		encoding  = C.DWORD(C.X509_ASN_ENCODING)
		flags     = C.DWORD(C.CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG | C.CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG)
		findType  = C.DWORD(C.CERT_CHAIN_FIND_BY_ISSUER)
		params    = &C.CERT_CHAIN_FIND_BY_ISSUER_PARA{cbSize: C.DWORD(unsafe.Sizeof(C.CERT_CHAIN_FIND_BY_ISSUER_PARA{}))}
		paramsPtr = unsafe.Pointer(params)
		chainCtx  = C.PCCERT_CHAIN_CONTEXT(nil)
	)

	for {
		// The previous chainCtx will be freed if necessary
		if chainCtx = C.CertFindChainInStore(store, encoding, flags, findType, paramsPtr, chainCtx); chainCtx == nil {
			break
		}
		if chainCtx.cChain < 1 {
			err = errors.New("bad chain")
			goto fail
		}

		// Not sure why this isn't 1 << 29
		const maxPointerArray = 1 << 28

		// rgpChain is actually an array, but we only care about the first one
		simpleChain := *chainCtx.rgpChain
		if simpleChain.cElement < 1 || simpleChain.cElement > maxPointerArray {
			err = errors.New("bad chain")
			goto fail
		}

		// Hacky way to get chain elements (C array) as a slice.
		// Converts the chain C array into a pointer to a pointer array of maximum size
		// and slices it down into the appropriate size (the number of elements in the chain)
		chainElts := (*[maxPointerArray]C.PCERT_CHAIN_ELEMENT)(unsafe.Pointer(simpleChain.rgpElement))[:simpleChain.cElement:simpleChain.cElement]

		// Build chain of certificates from each element's certificate context.
		curPcCertChain := make([]C.PCCERT_CONTEXT, len(chainElts))
		for j := range chainElts {
			curPcCertChain[j] = chainElts[j].pCertContext
		}

		cert, err := exportCertCtx(chainElts[0].pCertContext)
		if err != nil {
			goto fail
		}
		if certMatches(certIdentifier, *cert) {
			matchingCerts = append(matchingCerts, cert)

			// Assign to pcCertChain at most once in the loop
			// The value is only useful if there is exactly one match in the certificate store
			// When creating a signer, there has to be exactly one matching certificate
			if pcCertChain == nil {
				pcCertChain = curPcCertChain
				for _, ctx := range pcCertChain {
					C.CertDuplicateCertificateContext(ctx)
				}
			}
		}
	}

	if chainCtx != nil {
		C.CertFreeCertificateChain(chainCtx)
	}

	if err = checkError("failed to iterate certs in store"); err != nil && errCause(err) != errCode(CRYPT_E_NOT_FOUND) &&
		errCause(err) != errCode(ERROR_SUCCESS) {
		goto fail
	}

	return store, pcCertChain, matchingCerts, nil

fail:
	if chainCtx != nil {
		C.CertFreeCertificateChain(chainCtx)
	}
	if pcCertChain != nil {
		for _, ctx := range pcCertChain {
			C.CertFreeCertificateContext(ctx)
		}
	}
	C.CertCloseStore(store, 0)

	return nil, nil, nil, err
}

// Gets the certificates that match a CertIdentifier
func GetMatchingCerts(certIdentifier CertIdentifier) ([]*x509.Certificate, error) {
	store, pcCertChain, certificates, err := GetMatchingCertsAndChain(certIdentifier)
	for _, ctx := range pcCertChain {
		C.CertFreeCertificateContext(ctx)
	}
	C.CertCloseStore(store, 0)

	return certificates, err
}

// Gets a WindowsCertStoreSigner based on the CertIdentifier
func GetCertStoreSigner(certIdentifier CertIdentifier) (signer Signer, signingAlgorithm string, err error) {
	var privateKey *winPrivateKey
	store, pcCertChain, matchingCerts, err := GetMatchingCertsAndChain(certIdentifier)
	if err != nil {
		goto fail
	}
	if len(matchingCerts) > 1 {
		err = errors.New("more than one matching cert found in cert store")
		goto fail
	}
	if len(matchingCerts) == 0 {
		err = errors.New("no matching certs found in cert store")
		goto fail
	}

	signer = &WindowsCertStoreSigner{store: store, pcCertChain: pcCertChain}
	privateKey, err = signer.(*WindowsCertStoreSigner).getPrivateKey()
	if err != nil {
		goto fail
	}

	// Find the signing algorithm
	switch privateKey.publicKey.(type) {
	case *ecdsa.PublicKey:
		signingAlgorithm = aws4_x509_ecdsa_sha256
	case *rsa.PublicKey:
		signingAlgorithm = aws4_x509_rsa_sha256
	default:
		err = errors.New("unsupported algorithm")
		goto fail
	}

	return signer, signingAlgorithm, err

fail:
	if pcCertChain != nil {
		for _, ctx := range pcCertChain {
			C.CertFreeCertificateContext(ctx)
		}
	}
	if signer != nil {
		signer.Close()
	}
	C.CertCloseStore(store, 0)

	return nil, "", err
}

// Certificate implements the aws_signing_helper.Signer interface and returns a pointer
// to the x509.Certificate associated with this signer
func (signer *WindowsCertStoreSigner) Certificate() (cert *x509.Certificate, err error) {
	if signer.cert != nil {
		return signer.cert, nil
	}
	cert, err = exportCertCtx(signer.pcCertChain[0])
	if err != nil {
		return nil, err
	}
	signer.cert = cert

	return signer.cert, nil
}

// CertificateChain implements the aws_signing_helper.Signer interface and returns
// the certificate chain associated with this signer
func (signer *WindowsCertStoreSigner) CertificateChain() ([]*x509.Certificate, error) {
	if signer.certChain != nil {
		return signer.certChain, nil
	}

	certChain, err := getCertificates(signer.pcCertChain)
	if err != nil {
		return nil, err
	}
	signer.certChain = certChain

	return signer.certChain, nil
}

// Close implements the aws_signing_helper.Signer interface and closes the signer
func (signer *WindowsCertStoreSigner) Close() {
	C.CertCloseStore(signer.store, 0)
	signer.store = nil

	if signer.privateKey != nil {
		if signer.privateKey.cngKeyHandle != 0 {
			C.NCryptFreeObject(C.NCRYPT_HANDLE(signer.privateKey.cngKeyHandle))
			signer.privateKey.cngKeyHandle = 0
		}

		if signer.privateKey.cspHandle != 0 {
			C.CryptReleaseContext(signer.privateKey.cspHandle, 0)
			signer.privateKey.cspHandle = 0
		}

		signer.privateKey = nil
	}

	for _, pcCert := range signer.pcCertChain {
		C.CertFreeCertificateContext(pcCert)
	}
	signer.pcCertChain = nil
}

// getPrivateKey gets this identity's private *winPrivateKey
func (signer *WindowsCertStoreSigner) getPrivateKey() (*winPrivateKey, error) {
	if signer.privateKey != nil {
		return signer.privateKey, nil
	}

	cert, err := signer.Certificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity certificate: %w", err)
	}

	privateKey, err := newWinPrivateKey(signer.pcCertChain[0], cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load identity private key: %w", err)
	}

	signer.privateKey = privateKey

	return signer.privateKey, nil
}

// Gets a *winPrivateKey for the given certificate
func newWinPrivateKey(certCtx C.PCCERT_CONTEXT, publicKey crypto.PublicKey) (*winPrivateKey, error) {
	var (
		cspHandleOrCngKey C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
		keySpec           C.DWORD
		mustFree          C.WINBOOL
	)

	if publicKey == nil {
		return nil, errors.New("nil public key")
	}

	// Get a handle for the found private key
	if ok := C.CryptAcquireCertificatePrivateKey(certCtx, WIN_API_FLAG, nil, &cspHandleOrCngKey, &keySpec, &mustFree); ok == WIN_FALSE {
		return nil, lastError("failed to get private key for certificate")
	}

	if mustFree != WIN_TRUE {
		// This shouldn't happen since we're not asking for cached keys
		return nil, errors.New("CryptAcquireCertificatePrivateKey set mustFree")
	}

	if keySpec == C.CERT_NCRYPT_KEY_SPEC {
		return &winPrivateKey{
			publicKey:    publicKey,
			cngKeyHandle: C.NCRYPT_KEY_HANDLE(cspHandleOrCngKey),
		}, nil
	} else {
		return &winPrivateKey{
			publicKey: publicKey,
			cspHandle: C.HCRYPTPROV(cspHandleOrCngKey),
			keySpec:   keySpec,
		}, nil
	}
}

// Public implements the crypto.Signer interface.
func (signer *WindowsCertStoreSigner) Public() crypto.PublicKey {
	privateKey, err := signer.getPrivateKey()
	if err != nil {
		return nil
	}

	return privateKey.publicKey
}

// Sign implements the crypto.Signer interface and signs the digest
func (signer *WindowsCertStoreSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	privateKey, err := signer.getPrivateKey()
	if err != nil {
		return nil, err
	}

	if privateKey.cspHandle != 0 {
		return signer.cryptoSignHash(opts.HashFunc(), digest)
	} else if privateKey.cngKeyHandle != 0 {
		return signer.cngSignHash(opts.HashFunc(), digest)
	} else {
		return nil, errors.New("bad private key")
	}
}

// cngSignHash signs a digest using CNG APIs
func (signer *WindowsCertStoreSigner) cngSignHash(hash crypto.Hash, digest []byte) ([]byte, error) {
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	var (
		// Input
		padPtr    = unsafe.Pointer(nil)
		digestPtr = (*C.BYTE)(&digest[0])
		digestLen = C.DWORD(len(digest))
		flags     = C.DWORD(0)

		// Output
		sigLen = C.DWORD(0)
	)

	// Set up pkcs1v1.5 padding for RSA
	privateKey, _ := signer.getPrivateKey()
	if _, isRSA := privateKey.publicKey.(*rsa.PublicKey); isRSA {
		flags |= C.BCRYPT_PAD_PKCS1
		padInfo := C.BCRYPT_PKCS1_PADDING_INFO{}
		padPtr = unsafe.Pointer(&padInfo)

		switch hash {
		case crypto.SHA1:
			padInfo.pszAlgId = C.GET_BCRYPT_SHA1_ALGORITHM()
		case crypto.SHA256:
			padInfo.pszAlgId = C.GET_BCRYPT_SHA256_ALGORITHM()
		case crypto.SHA384:
			padInfo.pszAlgId = C.GET_BCRYPT_SHA384_ALGORITHM()
		case crypto.SHA512:
			padInfo.pszAlgId = C.GET_BCRYPT_SHA512_ALGORITHM()
		default:
			return nil, ErrUnsupportedHash
		}
	}

	// Get signature length
	if err := checkStatus(C.NCryptSignHash(privateKey.cngKeyHandle, padPtr, digestPtr, digestLen, nil, 0, &sigLen, flags)); err != nil {
		return nil, fmt.Errorf("failed to get signature length: %w", err)
	}

	// Get signature
	sig := make([]byte, sigLen)
	sigPtr := (*C.BYTE)(&sig[0])
	if err := checkStatus(C.NCryptSignHash(privateKey.cngKeyHandle, padPtr, digestPtr, digestLen, sigPtr, sigLen, &sigLen, flags)); err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	// CNG returns a raw ECDSA signature, but we want ASN.1 DER encoding
	if _, isEC := privateKey.publicKey.(*ecdsa.PublicKey); isEC {
		if len(sig)%2 != 0 {
			return nil, errors.New("bad ecdsa signature from CNG")
		}

		type ecdsaSignature struct {
			R, S *big.Int
		}

		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])

		encoded, err := asn1.Marshal(ecdsaSignature{r, s})
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 encode EC signature: %w", err)
		}

		return encoded, nil
	}

	return sig, nil
}

// Signs a digest using CryptoAPI
func (signer *WindowsCertStoreSigner) cryptoSignHash(hash crypto.Hash, digest []byte) ([]byte, error) {
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	// Figure out which CryptoAPI hash algorithm we're using
	var hash_alg C.ALG_ID

	switch hash {
	case crypto.SHA1:
		hash_alg = C.CALG_SHA1
	case crypto.SHA256:
		hash_alg = C.CALG_SHA_256
	case crypto.SHA384:
		hash_alg = C.CALG_SHA_384
	case crypto.SHA512:
		hash_alg = C.CALG_SHA_512
	default:
		return nil, ErrUnsupportedHash
	}

	// Instantiate a CryptoAPI hash object
	var cryptoHash C.HCRYPTHASH

	privateKey, _ := signer.getPrivateKey()
	if ok := C.CryptCreateHash(C.HCRYPTPROV(privateKey.cspHandle), hash_alg, 0, 0, &cryptoHash); ok == WIN_FALSE {
		if err := lastError("failed to create hash"); errCause(err) == errCode(NTE_BAD_ALGID) {
			return nil, ErrUnsupportedHash
		} else {
			return nil, err
		}
	}
	defer C.CryptDestroyHash(cryptoHash)

	// Make sure the hash size matches
	var (
		hashSize    C.DWORD
		hashSizePtr = (*C.BYTE)(unsafe.Pointer(&hashSize))
		hashSizeLen = C.DWORD(unsafe.Sizeof(hashSize))
	)

	if ok := C.CryptGetHashParam(cryptoHash, C.HP_HASHSIZE, hashSizePtr, &hashSizeLen, 0); ok == WIN_FALSE {
		return nil, lastError("failed to get hash size")
	}

	if hash.Size() != int(hashSize) {
		return nil, errors.New("invalid CryptoAPI hash")
	}

	// Put our digest into the hash object
	digestPtr := (*C.BYTE)(unsafe.Pointer(&digest[0]))
	if ok := C.CryptSetHashParam(cryptoHash, C.HP_HASHVAL, digestPtr, 0); ok == WIN_FALSE {
		return nil, lastError("failed to set hash digest")
	}

	// Get signature length
	var sigLen C.DWORD

	if ok := C.CryptSignHash(cryptoHash, privateKey.keySpec, nil, 0, nil, &sigLen); ok == WIN_FALSE {
		return nil, lastError("failed to get signature length")
	}

	// Get signature
	var (
		sig    = make([]byte, int(sigLen))
		sigPtr = (*C.BYTE)(unsafe.Pointer(&sig[0]))
	)

	if ok := C.CryptSignHash(cryptoHash, privateKey.keySpec, nil, 0, sigPtr, &sigLen); ok == WIN_FALSE {
		return nil, lastError("failed to sign digest")
	}

	// Reversing signature since it is little endian, but we want big endian
	for i := len(sig)/2 - 1; i >= 0; i-- {
		opp := len(sig) - 1 - i
		sig[i], sig[opp] = sig[opp], sig[i]
	}

	return sig, nil
}

// Exports a slice of *x509.Certificate to a slice of PCCERT_CONTEXT
func getCertificates(pcCerts []C.PCCERT_CONTEXT) (certs []*x509.Certificate, err error) {
	certs = make([]*x509.Certificate, len(pcCerts))

	for j := range pcCerts {
		if certs[j], err = exportCertCtx(pcCerts[j]); err != nil {
			return nil, err
		}
	}

	return certs, nil
}

// Exports a PCCERT_CONTEXT to a *x509.Certificate
func exportCertCtx(ctx C.PCCERT_CONTEXT) (*x509.Certificate, error) {
	der := C.GoBytes(unsafe.Pointer(ctx.pbCertEncoded), C.int(ctx.cbCertEncoded))

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certificate parsing failed: %w", err)
	}

	return cert, nil
}

// Finds the error code for the given error
func errCause(err error) errCode {
	msg := err.Error()
	codeStr := msg[strings.LastIndex(msg, " ")+1:]
	code, _ := strconv.ParseUint(codeStr, 16, 64)
	return errCode(code)
}

// Gets the last error from the current thread. If there isn't one, it
// returns a new error
func lastError(msg string) error {
	if err := checkError(msg); err != nil {
		return err
	}

	return errors.New(msg)
}

// checkError tries to get the last error from the current thread. If there
// isn't one, it returns nil
func checkError(msg string) error {
	if code := errCode(C.GetLastError()); code != 0 {
		return fmt.Errorf("%s: %w", msg, code)
	}

	return nil
}

// Implements the error interface for errCode and returns a string
// version of the errCode
func (c errCode) Error() string {
	var cMsg C.LPSTR
	ret := C.FormatMessage(
		C.FORMAT_MESSAGE_ALLOCATE_BUFFER|
			C.FORMAT_MESSAGE_FROM_SYSTEM|
			C.FORMAT_MESSAGE_IGNORE_INSERTS,
		nil,
		C.DWORD(c),
		C.ulong(C.MAKE_LANG_ID(C.LANG_NEUTRAL, C.SUBLANG_DEFAULT)),
		cMsg,
		0, nil)
	if ret == 0 {
		return fmt.Sprintf("Error %X", int(c))
	}

	if cMsg == nil {
		return fmt.Sprintf("Error %X", int(c))
	}

	goMsg := C.GoString(cMsg)

	return fmt.Sprintf("Error: %X %s", int(c), goMsg)
}

// Converts a SECURITY_STATUS into a securityStatus
func checkStatus(s C.SECURITY_STATUS) error {
	secStatus := securityStatus(s)

	if secStatus == ERROR_SUCCESS {
		return nil
	}

	if secStatus == NTE_BAD_ALGID {
		return ErrUnsupportedHash
	}

	return secStatus
}

// Implements the error interface
func (secStatus securityStatus) Error() string {
	return fmt.Sprintf("SECURITY_STATUS %d", int(secStatus))
}

// Converts a string to a UTF16 LPCWSTR
func stringToUTF16(s string) C.LPCWSTR {
	// Not sure why this isn't 1 << 30...
	const maxUint16Array = 1 << 29

	if len(s) > maxUint16Array {
		panic("string too long")
	}

	wstr := utf16.Encode([]rune(s))

	p := C.calloc(C.size_t(len(wstr)+1), C.size_t(unsafe.Sizeof(uint16(0))))
	pp := (*[maxUint16Array]uint16)(p)
	copy(pp[:], wstr)

	return (C.LPCWSTR)(p)
}
