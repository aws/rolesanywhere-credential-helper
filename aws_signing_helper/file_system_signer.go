package aws_signing_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"io"
	"log"
)

type FileSystemSigner struct {
	PrivateKey crypto.PrivateKey
	cert       *x509.Certificate
	certChain  []*x509.Certificate
}

func (fileSystemSigner FileSystemSigner) Public() crypto.PublicKey {
	{
		privateKey, ok := fileSystemSigner.PrivateKey.(ecdsa.PrivateKey)
		if ok {
			return &privateKey.PublicKey
		}
	}
	{
		privateKey, ok := fileSystemSigner.PrivateKey.(rsa.PrivateKey)
		if ok {
			return &privateKey.PublicKey
		}
	}
	return nil
}

func (fileSystemSigner FileSystemSigner) Close() {}

func (fileSystemSigner FileSystemSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
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

	ecdsaPrivateKey, ok := fileSystemSigner.PrivateKey.(ecdsa.PrivateKey)
	if ok {
		sig, err := ecdsa.SignASN1(rand, &ecdsaPrivateKey, hash[:])
		if err == nil {
			return sig, nil
		}
	}

	rsaPrivateKey, ok := fileSystemSigner.PrivateKey.(rsa.PrivateKey)
	if ok {
		sig, err := rsa.SignPKCS1v15(rand, &rsaPrivateKey, opts.HashFunc(), hash[:])
		if err == nil {
			return sig, nil
		}
	}

	log.Println("unsupported algorithm")
	return nil, errors.New("unsupported algorithm")
}

func (fileSystemSigner FileSystemSigner) Certificate() (*x509.Certificate, error) {
	return fileSystemSigner.cert, nil
}

func (fileSystemSigner FileSystemSigner) CertificateChain() ([]*x509.Certificate, error) {
	return fileSystemSigner.certChain, nil
}

// Returns a FileSystemSigner, that signs a payload using the private key passed in
func GetFileSystemSigner(privateKey crypto.PrivateKey, certificate *x509.Certificate, certificateChain []*x509.Certificate) (signer Signer, signingAlgorithm string, err error) {
	// Find the signing algorithm
	_, isRsaKey := privateKey.(rsa.PrivateKey)
	if isRsaKey {
		signingAlgorithm = aws4_x509_rsa_sha256
	}
	_, isEcKey := privateKey.(ecdsa.PrivateKey)
	if isEcKey {
		signingAlgorithm = aws4_x509_ecdsa_sha256
	}
	if signingAlgorithm == "" {
		log.Println("unsupported algorithm")
		return nil, "", errors.New("unsupported algorithm")
	}

	return FileSystemSigner{privateKey, certificate, certificateChain}, signingAlgorithm, nil
}
