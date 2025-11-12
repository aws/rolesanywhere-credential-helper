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
	"os"
)

type FileSystemSigner struct {
	bundlePath     string
	certPath       string
	isPkcs12       bool
	privateKeyPath string
	pkcs8Password  string
}

func (fileSystemSigner *FileSystemSigner) Public() crypto.PublicKey {
	privateKey, _, _ := fileSystemSigner.readCertFiles()
	{
		privateKey, ok := privateKey.(*ecdsa.PrivateKey)
		if ok {
			return &privateKey.PublicKey
		}
	}
	{
		privateKey, ok := privateKey.(*rsa.PrivateKey)
		if ok {
			return &privateKey.PublicKey
		}
	}
	return nil
}

func (fileSystemSigner *FileSystemSigner) Close() {}

func (fileSystemSigner *FileSystemSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	privateKey, _, _ := fileSystemSigner.readCertFiles()
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

	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if ok {
		sig, err := ecdsa.SignASN1(rand, ecdsaPrivateKey, hash[:])
		if err == nil {
			return sig, nil
		}
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if ok {
		sig, err := rsa.SignPKCS1v15(rand, rsaPrivateKey, opts.HashFunc(), hash[:])
		if err == nil {
			return sig, nil
		}
	}

	log.Println("unsupported algorithm")
	return nil, errors.New("unsupported algorithm")
}

func (fileSystemSigner *FileSystemSigner) Certificate() (*x509.Certificate, error) {
	_, cert, _ := fileSystemSigner.readCertFiles()
	return cert, nil
}

func (fileSystemSigner *FileSystemSigner) CertificateChain() ([]*x509.Certificate, error) {
	_, _, certChain := fileSystemSigner.readCertFiles()
	return certChain, nil
}

// GetFileSystemSigner returns a FileSystemSigner, that signs a payload using the private key passed in
func GetFileSystemSigner(privateKeyPath string, certPath string, bundlePath string, isPkcs12 bool, pkcs8Password string) (signer Signer, signingAlgorithm string, err error) {
	fsSigner := &FileSystemSigner{bundlePath: bundlePath, certPath: certPath, isPkcs12: isPkcs12, privateKeyPath: privateKeyPath, pkcs8Password: pkcs8Password}
	privateKey, _, _ := fsSigner.readCertFiles()
	// Find the signing algorithm
	_, isRsaKey := privateKey.(*rsa.PrivateKey)
	if isRsaKey {
		signingAlgorithm = aws4_x509_rsa_sha256
	}
	_, isEcKey := privateKey.(*ecdsa.PrivateKey)
	if isEcKey {
		signingAlgorithm = aws4_x509_ecdsa_sha256
	}
	if signingAlgorithm == "" {
		log.Println("unsupported algorithm")
		return nil, "", errors.New("unsupported algorithm")
	}

	return fsSigner, signingAlgorithm, nil
}

func (fileSystemSigner *FileSystemSigner) readCertFiles() (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate) {
	if fileSystemSigner.isPkcs12 {
		chain, privateKey, err := ReadPKCS12Data(fileSystemSigner.certPath)
		if err != nil {
			log.Printf("failed to read PKCS12 certificate: %s\n", err)
			os.Exit(1)
		}
		return privateKey, chain[0], chain
	} else {
		var privateKey crypto.PrivateKey
		var err error
		if len(fileSystemSigner.pkcs8Password) > 0 || isPKCS8EncryptedBlockType(fileSystemSigner.privateKeyPath) {
			passwordPromptInput := PasswordPromptProps{
				InitialPassword: fileSystemSigner.pkcs8Password,
				NoPassword:      false,
				CheckPassword: func(password string) (any, error) {
					return ReadPrivateKeyData(fileSystemSigner.privateKeyPath, password)
				},
				IncorrectPasswordMsg:               "incorrect PKCS#8 private key password",
				Prompt:                             "Please enter your PKC8 private key password:",
				Reprompt:                           "Incorrect PKCS#8 private key password. Please try again:",
				ParseErrMsg:                        "unable to read your PKCS#8 private key password",
				CheckPasswordAuthorizationErrorMsg: "unable to parse private key",
			}
			password, signingPrivKey, err := PasswordPrompt(passwordPromptInput)
			if err != nil {
				log.Printf("failed to read private key: %s\n", err)
				os.Exit(1)
			}

			fileSystemSigner.pkcs8Password = password
			privateKey, _ = signingPrivKey.(crypto.PrivateKey)
		} else {
			privateKey, err = ReadPrivateKeyData(fileSystemSigner.privateKeyPath, "")
			if err != nil {
				log.Printf("failed to read private key: %s\n", err)
				os.Exit(1)
			}
		}

		var chain []*x509.Certificate
		if fileSystemSigner.bundlePath != "" {
			chain, err = GetCertChain(fileSystemSigner.bundlePath)
			if err != nil {
				privateKey = nil
				log.Printf("failed to read certificate bundle: %s\n", err)
				os.Exit(1)
			}
		}
		var cert *x509.Certificate
		if fileSystemSigner.certPath != "" {
			_, cert, err = ReadCertificateData(fileSystemSigner.certPath)
			if err != nil {
				privateKey = nil
				log.Printf("failed to read certificate: %s\n", err)
				os.Exit(1)
			}
		} else if len(chain) > 0 {
			cert = chain[0]
		} else {
			log.Println("No certificate path or certificate bundle path provided")
			os.Exit(1)
		}

		return privateKey, cert, chain
	}
}
