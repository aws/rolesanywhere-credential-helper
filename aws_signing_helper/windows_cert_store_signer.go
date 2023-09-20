//go:build windows

package aws_signing_helper

// This code is based on the smimesign repository at
// https://github.com/github/smimesign

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
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"strconv"
	"strings"
	"unsafe"
)

// winPrivateKey is a wrapper around a HCRYPTPROV_OR_NCRYPT_KEY_HANDLE.
type winPrivateKey struct {
	publicKey crypto.PublicKey
	mustFree  bool

	// CryptoAPI fields
	cspHandle windows.Handle
	keySpec   uint32

	// CNG fields
	cngKeyHandle windows.Handle
}

type WindowsCertStoreSigner struct {
	store      windows.Handle
	certCtx    *windows.CertContext
	cert       *x509.Certificate
	certChain  []*x509.Certificate
	privateKey *winPrivateKey
}

const (
	WIN_FALSE C.WINBOOL = 0

	// ERROR_SUCCESS — The call succeeded
	ERROR_SUCCESS = 0x00000000

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
	WIN_API_FLAG = windows.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
)

// Error codes for Windows APIs - implements the error interface
type errCode uint64

// Security status for Windows APIs - implements the error interface
// Go representation of the C SECURITY_STATUS
type securityStatus uint64

// Gets the certificates that match the given CertIdentifier within the user's "MY" certificate store.
// If there is only a single matching certificate, then its chain will be returned too
func GetMatchingCertsAndChain(certIdentifier CertIdentifier) (store windows.Handle, certCtx *windows.CertContext, certChain []*x509.Certificate, certContainers []CertificateContainer, err error) {
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return 0, nil, nil, nil, errors.New("unable to UTF-16 encode personal certificate store name")
	}

	store, err = windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, windows.CERT_SYSTEM_STORE_CURRENT_USER, uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return 0, nil, nil, nil, errors.New("failed to open system cert store")
	}

	var (
		// CertFindChainInStore parameters
		encoding  = uint32(windows.X509_ASN_ENCODING)
		flags     = uint32(windows.CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG | windows.CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG)
		findType  = uint32(windows.CERT_CHAIN_FIND_BY_ISSUER)
		params    windows.CertChainFindByIssuerPara
		paramsPtr unsafe.Pointer
		chainCtx  *windows.CertChainContext = nil
	)
	params.Size = uint32(unsafe.Sizeof(params))
	paramsPtr = unsafe.Pointer(&params)

	var curCertCtx *windows.CertContext
	var curCert *x509.Certificate
	for {
		// Previous chainCtx should be freed here if it isn't nil
		chainCtx, err = windows.CertFindChainInStore(store, encoding, flags, findType, paramsPtr, chainCtx)
		if err != nil {
			if strings.Contains(err.Error(), "Cannot find object or property.") {
				break
			}
			err = errors.New("unable to find certificate chain in store")
			goto fail
		}

		if chainCtx.ChainCount < 1 {
			err = errors.New("bad chain")
			goto fail
		}

		// When multiple valid certification paths that are found for a given
		// certificate, only the first one is considered
		simpleChain := *chainCtx.Chains
		if simpleChain.NumElements < 1 {
			err = errors.New("bad chain")
			goto fail
		}

		// Convert the array into a pointer
		chainElts := unsafe.Slice(simpleChain.Elements, simpleChain.NumElements)

		// Build chain of certificates from each element's certificate context.
		x509CertChain := make([]*x509.Certificate, len(chainElts))
		for j := range chainElts {
			curCertCtx = chainElts[j].CertContext
			x509CertChain[j], err = exportCertContext(curCertCtx)
			if err != nil {
				if Debug {
					log.Printf("unable to parse certificate with error (%s) - skipping\n", err)
				}
				goto nextIteration
			}
		}

		curCert = x509CertChain[0]
		if certMatches(certIdentifier, *curCert) {
			certContainers = append(certContainers, CertificateContainer{curCert, ""})

			// Assign to certChain and certCtx at most once in the loop.
			// The value is only useful if there is exactly one match in the certificate store.
			// When creating a signer, there has to be exactly one matching certificate.
			if certChain == nil {
				certChain = x509CertChain[:]
				certCtx = chainElts[0].CertContext
				// This is required later on when creating the WindowsCertStoreSigner
				// If this method isn't being called in order to create a WindowsCertStoreSigner,
				// this return value will have to be freed explicitly.
				windows.CertDuplicateCertificateContext(certCtx)
			}
		}

	nextIteration:
	}

	if Debug {
		log.Printf("found %d matching identities\n", len(certContainers))
	}

	return store, certCtx, certChain, certContainers, nil

fail:
	if chainCtx != nil {
		windows.CertFreeCertificateChain(chainCtx)
	}
	if certCtx != nil {
		windows.CertFreeCertificateContext(certCtx)
	}
	windows.CertCloseStore(store, 0)

	return 0, nil, nil, nil, err
}

// Gets the certificates that match a CertIdentifier
func GetMatchingCerts(certIdentifier CertIdentifier) ([]CertificateContainer, error) {
	store, certCtx, _, certContainers, err := GetMatchingCertsAndChain(certIdentifier)
	if certCtx != nil {
		windows.CertFreeCertificateContext(certCtx)
	}
	windows.CertCloseStore(store, 0)

	return certContainers, err
}

// Gets a WindowsCertStoreSigner based on the CertIdentifier
func GetCertStoreSigner(certIdentifier CertIdentifier) (signer Signer, signingAlgorithm string, err error) {
	var privateKey *winPrivateKey
	store, certCtx, certChain, certContainers, err := GetMatchingCertsAndChain(certIdentifier)
	if err != nil {
		goto fail
	}
	if len(certContainers) > 1 {
		err = errors.New("more than one matching cert found in cert store")
		goto fail
	}
	if len(certContainers) == 0 {
		err = errors.New("no matching certs found in cert store")
		goto fail
	}

	signer = &WindowsCertStoreSigner{store: store, cert: certContainers[0].Cert, certCtx: certCtx, certChain: certChain}

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
	if certCtx != nil {
		windows.CertFreeCertificateContext(certCtx)
	}
	if signer != nil {
		signer.Close()
	}
	if store != 0 {
		windows.CertCloseStore(store, 0)
	}

	return nil, "", err
}

// Certificate implements the aws_signing_helper.Signer interface and returns a pointer
// to the x509.Certificate associated with this signer
func (signer *WindowsCertStoreSigner) Certificate() (cert *x509.Certificate, err error) {
	return signer.cert, nil
}

// CertificateChain implements the aws_signing_helper.Signer interface and returns
// the certificate chain associated with this signer
func (signer *WindowsCertStoreSigner) CertificateChain() ([]*x509.Certificate, error) {
	return signer.certChain, nil
}

// Close implements the aws_signing_helper.Signer interface and closes the signer
func (signer *WindowsCertStoreSigner) Close() {
	if signer.privateKey != nil && signer.privateKey.mustFree {
		if signer.privateKey.cngKeyHandle != 0 {
			cngHandle := (*C.NCRYPT_KEY_HANDLE)(unsafe.Pointer(&signer.privateKey.cngKeyHandle))
			C.NCryptFreeObject(*cngHandle)
		}
		if signer.privateKey.cspHandle != 0 {
			windows.CryptReleaseContext(signer.privateKey.cspHandle, 0)
		}
	}
	signer.privateKey = nil

	// If signer.privateKey.mustFree is false, key handles will be released on the
	// last free action of the certificate context.
	// See https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
	if signer.certCtx != nil {
		windows.CertFreeCertificateContext(signer.certCtx)
		signer.certCtx = nil
	}

	windows.CertCloseStore(signer.store, 0)
	signer.store = 0
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

	signer.privateKey, err = newWinPrivateKey(signer.certCtx, cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load identity private key: %w", err)
	}

	return signer.privateKey, nil
}

// Gets a *winPrivateKey for the given certificate
func newWinPrivateKey(certCtx *windows.CertContext, publicKey crypto.PublicKey) (*winPrivateKey, error) {
	var (
		cspHandleOrCngKey windows.Handle
		keySpec           uint32
		mustFree          bool
	)

	if publicKey == nil {
		return nil, errors.New("nil public key")
	}

	// Get a handle for the found private key
	if err := windows.CryptAcquireCertificatePrivateKey(certCtx, WIN_API_FLAG, nil, &cspHandleOrCngKey, &keySpec, &mustFree); err != nil {
		return nil, err
	}

	if keySpec == C.CERT_NCRYPT_KEY_SPEC {
		return &winPrivateKey{
			publicKey:    publicKey,
			cngKeyHandle: cspHandleOrCngKey,
			mustFree:     mustFree,
		}, nil
	} else {
		return &winPrivateKey{
			publicKey: publicKey,
			cspHandle: cspHandleOrCngKey,
			keySpec:   keySpec,
			mustFree:  mustFree,
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

	privateKey, err := signer.getPrivateKey()
	if err != nil {
		return nil, err
	}

	if privateKey.cspHandle != 0 {
		return signer.cryptoSignHash(hash, opts.HashFunc())
	} else if privateKey.cngKeyHandle != 0 {
		return signer.cngSignHash(hash, opts.HashFunc())
	} else {
		return nil, errors.New("bad private key")
	}
}

// cngSignHash signs a digest using CNG APIs
func (signer *WindowsCertStoreSigner) cngSignHash(digest []byte, hash crypto.Hash) ([]byte, error) {
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

	// Get C.NCRYPT_KEY_HANDLE in order to do the signature
	cngKeyHandle := (*C.NCRYPT_KEY_HANDLE)(unsafe.Pointer(&privateKey.cngKeyHandle))

	// Get signature length
	if err := checkStatus(C.NCryptSignHash(*cngKeyHandle, padPtr, digestPtr, digestLen, nil, 0, &sigLen, flags)); err != nil {
		return nil, fmt.Errorf("failed to get signature length: %w", err)
	}

	// Get signature
	sig := make([]byte, sigLen)
	sigPtr := (*C.BYTE)(&sig[0])
	if err := checkStatus(C.NCryptSignHash(*cngKeyHandle, padPtr, digestPtr, digestLen, sigPtr, sigLen, &sigLen, flags)); err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	// CNG returns a raw ECDSA signature, but we want ASN.1 DER encoding
	if _, isEC := privateKey.publicKey.(*ecdsa.PublicKey); isEC {
		if len(sig)%2 != 0 {
			return nil, errors.New("bad ecdsa signature from CNG")
		}

		return encodeEcdsaSigValue(sig)
	}

	return sig, nil
}

// Signs a digest using CryptoAPI
func (signer *WindowsCertStoreSigner) cryptoSignHash(digest []byte, hash crypto.Hash) ([]byte, error) {
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
	cspHandle := (*C.HCRYPTPROV)(unsafe.Pointer(&privateKey.cspHandle))
	if ok := C.CryptCreateHash(*cspHandle, hash_alg, 0, 0, &cryptoHash); ok == WIN_FALSE {
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

	if ok := C.CryptSignHash(cryptoHash, C.ulong(privateKey.keySpec), nil, 0, nil, &sigLen); ok == WIN_FALSE {
		return nil, lastError("failed to get signature length")
	}

	// Get signature
	var (
		sig    = make([]byte, int(sigLen))
		sigPtr = (*C.BYTE)(unsafe.Pointer(&sig[0]))
	)

	if ok := C.CryptSignHash(cryptoHash, C.ulong(privateKey.keySpec), nil, 0, sigPtr, &sigLen); ok == WIN_FALSE {
		return nil, lastError("failed to sign digest")
	}

	// Reversing signature since it is little endian, but we want big endian
	for i := len(sig)/2 - 1; i >= 0; i-- {
		opp := len(sig) - 1 - i
		sig[i], sig[opp] = sig[opp], sig[i]
	}

	return sig, nil
}

// Exports a windows.CertContext as an *x509.Certificate.
func exportCertContext(certCtx *windows.CertContext) (*x509.Certificate, error) {
	// Technically, we should never throw here, since the exportCertContext function
	// is only called when searching for certificates
	if certCtx.EncodingType != windows.X509_ASN_ENCODING {
		return nil, errors.New("unknown certificate encoding type")
	}

	der := unsafe.Slice(certCtx.EncodedCert, certCtx.Length)
	return x509.ParseCertificate(der)
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
