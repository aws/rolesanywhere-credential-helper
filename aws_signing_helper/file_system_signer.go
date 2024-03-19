package aws_signing_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"github.com/fsnotify/fsnotify"
	"io"
	"log"
	"os"
	"sync"
)

type FileSystemSigner struct {
	sync.RWMutex

	PrivateKey     crypto.PrivateKey
	bundlePath     string
	cert           *x509.Certificate
	certChain      []*x509.Certificate
	certPath       string
	isPkcs12       bool
	privateKeyPath string

	watcher *fsnotify.Watcher
}

func (fileSystemSigner *FileSystemSigner) Public() crypto.PublicKey {
	fileSystemSigner.RLock()
	defer fileSystemSigner.RUnlock()
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

func (fileSystemSigner *FileSystemSigner) Close() {
	fileSystemSigner.watcher.Close()
}

func (fileSystemSigner *FileSystemSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fileSystemSigner.RLock()
	defer fileSystemSigner.RUnlock()
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

func (fileSystemSigner *FileSystemSigner) Certificate() (*x509.Certificate, error) {
	fileSystemSigner.RLock()
	defer fileSystemSigner.RUnlock()
	return fileSystemSigner.cert, nil
}

func (fileSystemSigner *FileSystemSigner) CertificateChain() ([]*x509.Certificate, error) {
	fileSystemSigner.RLock()
	defer fileSystemSigner.RUnlock()
	return fileSystemSigner.certChain, nil
}

// GetFileSystemSigner returns a FileSystemSigner, that signs a payload using the private key passed in
func GetFileSystemSigner(privateKey crypto.PrivateKey, certificate *x509.Certificate, certificateChain []*x509.Certificate, privateKeyPath string, certPath string, bundlePath string, isPkcs12 bool) (signer Signer, signingAlgorithm string, err error) {
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

	fsSigner := &FileSystemSigner{PrivateKey: privateKey, bundlePath: bundlePath, cert: certificate, certChain: certificateChain, certPath: certPath, isPkcs12: isPkcs12, privateKeyPath: privateKeyPath}
	fsSigner.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, "", err
	}
	if certPath != "" {
		fsSigner.watcher.Add(certPath)
	}
	if privateKeyPath != "" {
		fsSigner.watcher.Add(privateKeyPath)
	}
	if bundlePath != "" {
		fsSigner.watcher.Add(bundlePath)
	}

	if Debug {
		log.Println("Starting file watcher")
	}
	go fsSigner.watch()

	return fsSigner, signingAlgorithm, nil
}

func (fileSystemSigner *FileSystemSigner) watch() {
	for {
		select {
		case event, ok := <-fileSystemSigner.watcher.Events:
			// Channel is closed.
			if !ok {
				return
			}

			fileSystemSigner.handleEvent(event)

		case err, ok := <-fileSystemSigner.watcher.Errors:
			// Channel is closed.
			if !ok {
				return
			}

			if Debug {
				log.Printf("Certificate watch error: %s", err)
			}
		}
	}
}

func (fileSystemSigner *FileSystemSigner) handleEvent(event fsnotify.Event) {
	if !(isWrite(event) || isRemove(event) || isCreate(event)) {
		return
	}

	if Debug {
		log.Printf("Certificate event :%v", event)
	}

	if isRemove(event) {
		if err := fileSystemSigner.watcher.Add(event.Name); err != nil {
			if Debug {
				log.Printf("Error re-watching file: %s", err)
			}
		}
	}

	if event.Name == fileSystemSigner.certPath {
		if fileSystemSigner.isPkcs12 {
			chain, privateKey, err := ReadPKCS12Data(fileSystemSigner.certPath)
			if err != nil {
				log.Printf("Failed to read modified PKCS12 certificate: %s\n", err)
				os.Exit(1)
			}
			fileSystemSigner.Lock()
			fileSystemSigner.PrivateKey = privateKey
			fileSystemSigner.cert = chain[0]
			fileSystemSigner.certChain = chain
			fileSystemSigner.Unlock()
		} else {
			_, cert, err := ReadCertificateData(fileSystemSigner.certPath)
			if err != nil {
				log.Printf("Failed to read modified certificate: %s\n", err)
				os.Exit(1)
			}
			fileSystemSigner.Lock()
			fileSystemSigner.cert = cert
			fileSystemSigner.Unlock()
		}
		if Debug {
			log.Printf("Replaced certificate from updated file")
		}
	}

	if event.Name == fileSystemSigner.privateKeyPath {
		privateKey, err := ReadPrivateKeyData(fileSystemSigner.privateKeyPath)
		if err != nil {
			log.Printf("Failed to read modified private key: %s\n", err)
			os.Exit(1)
		}
		fileSystemSigner.Lock()
		fileSystemSigner.PrivateKey = privateKey
		fileSystemSigner.Unlock()
		if Debug {
			log.Printf("Replaced private key from updated file")
		}
	}

	if event.Name == fileSystemSigner.bundlePath {
		chain, err := GetCertChain(fileSystemSigner.bundlePath)
		if err != nil {
			log.Printf("Failed to read modified certificate bundle: %s\n", err)
			os.Exit(1)
		}
		fileSystemSigner.Lock()
		fileSystemSigner.certChain = chain
		fileSystemSigner.Unlock()
		if Debug {
			log.Printf("Replaced certificate chain from updated file")
		}
	}
}

func isWrite(event fsnotify.Event) bool {
	return event.Op&fsnotify.Write == fsnotify.Write
}

func isCreate(event fsnotify.Event) bool {
	return event.Op&fsnotify.Create == fsnotify.Create
}

func isRemove(event fsnotify.Event) bool {
	return event.Op&fsnotify.Remove == fsnotify.Remove
}
