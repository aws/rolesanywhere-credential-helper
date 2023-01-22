//go:build windows

package aws_signing_helper

/*
#cgo windows LDFLAGS: -lcrypt32 -lncrypt
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
char* errMsg(DWORD code) {
	char* lpMsgBuf;
	DWORD ret = 0;
	ret = FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			code,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL);
	if (ret == 0) {
		return NULL;
	} else {
		return lpMsgBuf;
	}
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
	capiProv C.HCRYPTPROV

	// CNG fields
	cngHandle C.NCRYPT_KEY_HANDLE
	keySpec   C.DWORD
}

type WindowsCertStoreSigner struct {
	store       C.HCERTSTORE
	certChain   []*x509.Certificate
	pcCertChain []C.PCCERT_CONTEXT
	privateKey  *winPrivateKey
}

const (
	winTrue  C.WINBOOL = 1
	winFalse C.WINBOOL = 0

	// ERROR_SUCCESS
	ERROR_SUCCESS = 0x00000000

	// CRYPT_E_NOT_FOUND — Cannot find object or property.
	CRYPT_E_NOT_FOUND = 0x80092004

	// NTE_BAD_ALGID — Invalid algorithm specified.
	NTE_BAD_ALGID = 0x80090008
)

// winAPIFlag specifies the flags that should be passed to
// CryptAcquireCertificatePrivateKey. This impacts whether the CryptoAPI or CNG
// API will be used.
//
// Possible values are:
//
//	0x00000000 —                                      — Only use CryptoAPI.
//	0x00010000 — CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG  — Prefer CryptoAPI.
//	0x00020000 — CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG — Prefer CNG.
//	0x00040000 — CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG   — Only uyse CNG.
var winAPIFlag C.DWORD = C.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG

func GetMatchingCertsAndChain(certIdentifier CertIdentifier) (store C.HCERTSTORE, pcCertChain []C.PCCERT_CONTEXT, matchingCerts []*x509.Certificate, err error) {
	storeName := unsafe.Pointer(stringToUTF16("MY"))
	defer C.free(storeName)

	store = C.CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, C.CERT_SYSTEM_STORE_CURRENT_USER, storeName)
	if store == nil {
		return nil, nil, nil, lastError("failed to open system cert store")
	}

	var (
		matchingPcCerts []C.PCCERT_CONTEXT

		// CertFindChainInStore parameters
		encoding  = C.DWORD(C.X509_ASN_ENCODING)
		flags     = C.DWORD(C.CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG | C.CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG)
		findType  = C.DWORD(C.CERT_CHAIN_FIND_BY_ISSUER)
		params    = &C.CERT_CHAIN_FIND_BY_ISSUER_PARA{cbSize: C.DWORD(unsafe.Sizeof(C.CERT_CHAIN_FIND_BY_ISSUER_PARA{}))}
		paramsPtr = unsafe.Pointer(params)
		chainCtx  = C.PCCERT_CHAIN_CONTEXT(nil)
	)

	for {
		if chainCtx = C.CertFindChainInStore(store, encoding, flags, findType, paramsPtr, chainCtx); chainCtx == nil {
			break
		}
		if chainCtx.cChain < 1 {
			err = errors.New("bad chain")
			goto fail
		}

		// not sure why this isn't 1 << 29
		const maxPointerArray = 1 << 28

		// rgpChain is actually an array, but we only care about the first one.
		simpleChain := *chainCtx.rgpChain
		if simpleChain.cElement < 1 || simpleChain.cElement > maxPointerArray {
			err = errors.New("bad chain")
			goto fail
		}

		// Hacky way to get chain elements (c array) as a slice.
		chainElts := (*[maxPointerArray]C.PCERT_CHAIN_ELEMENT)(unsafe.Pointer(simpleChain.rgpElement))[:simpleChain.cElement:simpleChain.cElement]

		// Build chain of certificates from each element's certificate context.
		pcCertChain := make([]C.PCCERT_CONTEXT, len(chainElts))
		for j := range chainElts {
			pcCertChain[j] = chainElts[j].pCertContext
		}

		cert, err := exportCertCtx(chainElts[0].pCertContext)
		if err != nil {
			goto fail
		}
		certMatches := certMatches(certIdentifier, *cert)
		if certMatches {
			matchingCerts = append(matchingCerts, cert)
		}
	}

	if err = checkError("failed to iterate certs in store"); err != nil && errCause(err) != errCode(CRYPT_E_NOT_FOUND) {
		goto fail
	}

	for _, ctx := range pcCertChain {
		C.CertDuplicateCertificateContext(ctx)
	}

	return store, pcCertChain, matchingCerts, nil

fail:
	for _, certCtx := range matchingPcCerts {
		C.CertFreeCertificateContext(certCtx)
	}
	matchingPcCerts = nil

	return nil, nil, nil, err
}

func GetMatchingCerts(certIdentifier CertIdentifier) ([]*x509.Certificate, error) {
	store, _, certificates, err := GetMatchingCertsAndChain(certIdentifier)
	C.CertCloseStore(store, 0)
	return certificates, err
}

func GetCertStoreSigner(certIdentifier CertIdentifier) (signer Signer, signingAlgorithm string, err error) {
	store, pcCertChain, matchingCerts, err := GetMatchingCertsAndChain(certIdentifier)
	if err != nil {
		return nil, "", err
	}
	if len(matchingCerts) < 1 || len(matchingCerts) > 1 {
		return nil, "", errors.New("more than one matching cert found in cert store")
	}

	signer = WindowsCertStoreSigner{store: store, pcCertChain: pcCertChain}
	_, err = signer.(WindowsCertStoreSigner).getPrivateKey()
	if err != nil {
		return nil, "", err
	}

	// Find the signing algorithm
	switch signer.(WindowsCertStoreSigner).privateKey.publicKey.(type) {
	case *ecdsa.PublicKey:
		signingAlgorithm = aws4_x509_ecdsa_sha256
	case *rsa.PublicKey:
		signingAlgorithm = aws4_x509_rsa_sha256
	default:
		return nil, "", errors.New("unsupported algorithm")
	}

	return signer, signingAlgorithm, err
}

// Certificate implements the Identity interface.
func (signer WindowsCertStoreSigner) Certificate() (*x509.Certificate, error) {
	return exportCertCtx(signer.pcCertChain[0])
}

// CertificateChain implements the Identity interface.
func (signer WindowsCertStoreSigner) CertificateChain() ([]*x509.Certificate, error) {
	certChain, err := GetCertificates(signer.pcCertChain)
	if err != nil {
		return nil, err
	}
	signer.certChain = certChain

	return signer.certChain, nil
}

func (signer WindowsCertStoreSigner) Close() {
	C.CertCloseStore(signer.store, 0)
	signer.store = nil

	if signer.privateKey != nil {
		if signer.privateKey.cngHandle != 0 {
			C.NCryptFreeObject(C.NCRYPT_HANDLE(signer.privateKey.cngHandle))
			signer.privateKey.cngHandle = 0
		}

		if signer.privateKey.capiProv != 0 {
			C.CryptReleaseContext(signer.privateKey.capiProv, 0)
			signer.privateKey.capiProv = 0
		}

		signer.privateKey = nil
	}

	for _, pcCert := range signer.pcCertChain {
		C.CertFreeCertificateContext(pcCert)
	}
	signer.pcCertChain = nil
}

// getPrivateKey gets this identity's private *winPrivateKey.
func (signer WindowsCertStoreSigner) getPrivateKey() (*winPrivateKey, error) {
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

// newWinPrivateKey gets a *winPrivateKey for the given certificate.
func newWinPrivateKey(certCtx C.PCCERT_CONTEXT, publicKey crypto.PublicKey) (*winPrivateKey, error) {
	var (
		provOrKey C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
		keySpec   C.DWORD
		mustFree  C.WINBOOL
	)

	if publicKey == nil {
		return nil, errors.New("nil public key")
	}

	// Get a handle for the found private key.
	if ok := C.CryptAcquireCertificatePrivateKey(certCtx, winAPIFlag, nil, &provOrKey, &keySpec, &mustFree); ok == winFalse {
		return nil, lastError("failed to get private key for certificate")
	}

	if mustFree != winTrue {
		// This shouldn't happen since we're not asking for cached keys.
		return nil, errors.New("CryptAcquireCertificatePrivateKey set mustFree")
	}

	if keySpec == C.CERT_NCRYPT_KEY_SPEC {
		return &winPrivateKey{
			publicKey: publicKey,
			cngHandle: C.NCRYPT_KEY_HANDLE(provOrKey),
		}, nil
	} else {
		return &winPrivateKey{
			publicKey: publicKey,
			capiProv:  C.HCRYPTPROV(provOrKey),
			keySpec:   keySpec,
		}, nil
	}
}

// Public implements the crypto.Signer interface.
func (signer WindowsCertStoreSigner) Public() crypto.PublicKey {
	return signer.privateKey.publicKey
}

// Sign implements the crypto.Signer interface.
func (signer WindowsCertStoreSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if signer.privateKey.capiProv != 0 {
		return signer.capiSignHash(opts.HashFunc(), digest)
	} else if signer.privateKey.cngHandle != 0 {
		return signer.cngSignHash(opts.HashFunc(), digest)
	} else {
		return nil, errors.New("bad private key")
	}
}

// cngSignHash signs a digest using the CNG APIs.
func (signer WindowsCertStoreSigner) cngSignHash(hash crypto.Hash, digest []byte) ([]byte, error) {
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	var (
		// input
		padPtr    = unsafe.Pointer(nil)
		digestPtr = (*C.BYTE)(&digest[0])
		digestLen = C.DWORD(len(digest))
		flags     = C.DWORD(0)

		// output
		sigLen = C.DWORD(0)
	)

	// setup pkcs1v1.5 padding for RSA
	if _, isRSA := signer.privateKey.publicKey.(*rsa.PublicKey); isRSA {
		flags |= C.BCRYPT_PAD_PKCS1
		padInfo := C.BCRYPT_PKCS1_PADDING_INFO{}
		padPtr = unsafe.Pointer(&padInfo)

		switch hash {
		case crypto.SHA1:
			padInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM
		case crypto.SHA256:
			padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM
		case crypto.SHA384:
			padInfo.pszAlgId = BCRYPT_SHA384_ALGORITHM
		case crypto.SHA512:
			padInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM
		default:
			return nil, ErrUnsupportedHash
		}
	}

	// get signature length
	if err := checkStatus(C.NCryptSignHash(signer.privateKey.cngHandle, padPtr, digestPtr, digestLen, nil, 0, &sigLen, flags)); err != nil {
		return nil, fmt.Errorf("failed to get signature length: %w", err)
	}

	// get signature
	sig := make([]byte, sigLen)
	sigPtr := (*C.BYTE)(&sig[0])
	if err := checkStatus(C.NCryptSignHash(signer.privateKey.cngHandle, padPtr, digestPtr, digestLen, sigPtr, sigLen, &sigLen, flags)); err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	// CNG returns a raw ECDSA signature, but we wan't ASN.1 DER encoding.
	if _, isEC := signer.privateKey.publicKey.(*ecdsa.PublicKey); isEC {
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

// capiSignHash signs a digest using the CryptoAPI APIs.
func (signer WindowsCertStoreSigner) capiSignHash(hash crypto.Hash, digest []byte) ([]byte, error) {
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	// Figure out which CryptoAPI hash algorithm we're using.
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

	// Instantiate a CryptoAPI hash object.
	var chash C.HCRYPTHASH

	if ok := C.CryptCreateHash(C.HCRYPTPROV(signer.privateKey.capiProv), hash_alg, 0, 0, &chash); ok == winFalse {
		if err := lastError("failed to create hash"); errCause(err) == errCode(NTE_BAD_ALGID) {
			return nil, ErrUnsupportedHash
		} else {
			return nil, err
		}
	}
	defer C.CryptDestroyHash(chash)

	// Make sure the hash size matches.
	var (
		hashSize    C.DWORD
		hashSizePtr = (*C.BYTE)(unsafe.Pointer(&hashSize))
		hashSizeLen = C.DWORD(unsafe.Sizeof(hashSize))
	)

	if ok := C.CryptGetHashParam(chash, C.HP_HASHSIZE, hashSizePtr, &hashSizeLen, 0); ok == winFalse {
		return nil, lastError("failed to get hash size")
	}

	if hash.Size() != int(hashSize) {
		return nil, errors.New("invalid CryptoAPI hash")
	}

	// Put our digest into the hash object.
	digestPtr := (*C.BYTE)(unsafe.Pointer(&digest[0]))
	if ok := C.CryptSetHashParam(chash, C.HP_HASHVAL, digestPtr, 0); ok == winFalse {
		return nil, lastError("failed to set hash digest")
	}

	// Get signature length.
	var sigLen C.DWORD

	if ok := C.CryptSignHash(chash, signer.privateKey.keySpec, nil, 0, nil, &sigLen); ok == winFalse {
		return nil, lastError("failed to get signature length")
	}

	// Get signature
	var (
		sig    = make([]byte, int(sigLen))
		sigPtr = (*C.BYTE)(unsafe.Pointer(&sig[0]))
	)

	if ok := C.CryptSignHash(chash, signer.privateKey.keySpec, nil, 0, sigPtr, &sigLen); ok == winFalse {
		return nil, lastError("failed to sign digest")
	}

	// Signature is little endian, but we want big endian. Reverse it.
	for i := len(sig)/2 - 1; i >= 0; i-- {
		opp := len(sig) - 1 - i
		sig[i], sig[opp] = sig[opp], sig[i]
	}

	return sig, nil
}

func GetCertificates(pcCerts []C.PCCERT_CONTEXT) ([]*x509.Certificate, error) {
	var (
		certs = make([]*x509.Certificate, len(pcCerts))
		err   error
	)

	for j := range pcCerts {
		if certs[j], err = exportCertCtx(pcCerts[j]); err != nil {
			return nil, err
		}
	}

	return certs, nil
}

// exportCertCtx exports a PCCERT_CONTEXT as an *x509.Certificate.
func exportCertCtx(ctx C.PCCERT_CONTEXT) (*x509.Certificate, error) {
	der := C.GoBytes(unsafe.Pointer(ctx.pbCertEncoded), C.int(ctx.cbCertEncoded))

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certificate parsing failed: %w", err)
	}

	return cert, nil
}

type errCode uint64

func errCause(err error) errCode {
	msg := err.Error()
	codeStr := msg[strings.LastIndex(msg, " ")+1:]
	code, _ := strconv.ParseUint(codeStr, 10, 64)
	return errCode(code)
}

// lastError gets the last error from the current thread. If there isn't one, it
// returns a new error.
func lastError(msg string) error {
	if err := checkError(msg); err != nil {
		return err
	}

	return errors.New(msg)
}

// checkError tries to get the last error from the current thread. If there
// isn't one, it returns nil.
func checkError(msg string) error {
	if code := errCode(C.GetLastError()); code != 0 {
		return fmt.Errorf("%s: %w", msg, code)
	}

	return nil
}

func (c errCode) Error() string {
	cmsg := C.errMsg(C.DWORD(c))
	if cmsg == nil {
		return fmt.Sprintf("Error %X", int(c))
	}
	// TODO: Not sure why this doens't work yet
	// defer C.LocalFree(C.HLOCAL(cmsg))

	gomsg := C.GoString(cmsg)

	return fmt.Sprintf("Error: %X %s", int(c), gomsg)
}

type securityStatus uint64

func checkStatus(s C.SECURITY_STATUS) error {
	ss := securityStatus(s)

	if ss == ERROR_SUCCESS {
		return nil
	}

	if ss == NTE_BAD_ALGID {
		return ErrUnsupportedHash
	}

	return ss
}

func (ss securityStatus) Error() string {
	return fmt.Sprintf("SECURITY_STATUS %d", int(ss))
}

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
