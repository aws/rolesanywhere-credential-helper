package aws_signing_helper

// PKCS#8 is a cryptographic standard that defines a flexible format
// for encoding private key information, including both the key data
// and optional attributes such as encryption parameters. It also allows
// private keys to be encrypted using password-based encryption methods,
// providing an additional layer of security.
//
// This file contains implementations of PKCS#8 decryption, which decodes
// a PKCS#8-encrypted private key using PBES2, as defined in PKCS #5 (RFC 8018).
//
// Not all ciphers or pseudo-random function(PRF) are supported. Please refer to the list below for the supported options.
//
// Supported ciphers: AES-128/192/256-CBC
// Supported KDFs: PBKDF2, Scrypt
// Supported PRFs: HMACWithSHA256, HMACWithSHA384, HMACWithSHA512

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"errors"
	"fmt"
	"hash"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// as defined in https://datatracker.ietf.org/doc/html/rfc8018#appendix-A.4
type PBES2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

// as defined in https://datatracker.ietf.org/doc/html/rfc5958#section-3
type EncryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

// as defined in https://datatracker.ietf.org/doc/html/rfc8018#appendix-A.2
type PBKDF2RPFParams struct {
	Algorithm asn1.ObjectIdentifier
	Params    asn1.RawValue `asn1:"optional"`
}

// as defined in https://datatracker.ietf.org/doc/html/rfc8018#appendix-A.2
// and https://datatracker.ietf.org/doc/html/rfc8018#section-5.2
type PBKDF2Params struct {
	Salt      []byte
	Iteration int
	PRF       PBKDF2RPFParams
}

type ScryptParams struct {
	Salt                  []byte
	CostFactor            int
	BlockSizeFactor       int
	ParallelizationFactor int
}

// Supported PRFs
var (
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
)

// Supported KDFs
var (
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
)

// Supported Ciphers
var cipherMap = map[string]struct {
	KeySize   int
	NewCipher func([]byte) (cipher.Block, error)
}{
	"2.16.840.1.101.3.4.1.42": {32, aes.NewCipher}, // AES-256-CBC
	"2.16.840.1.101.3.4.1.22": {24, aes.NewCipher}, // AES-192-CBC
	"2.16.840.1.101.3.4.1.2":  {16, aes.NewCipher}, // AES-128-CBC
}

const unencryptedBlockType = "PRIVATE KEY"
const encryptedBlockType = "ENCRYPTED PRIVATE KEY"

// 'getNewHash' creates a new hash based on the specified PRF
func getNewHash(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case oid.Equal(oidHMACWithSHA256):
		return sha256.New, nil
	case oid.Equal(oidHMACWithSHA384):
		return sha512.New384, nil
	case oid.Equal(oidHMACWithSHA512):
		return sha512.New, nil
	default:
		return nil, errors.New("unsupported hash function")
	}
}

// 'extractCipherParams' extracts and parses cipher parameters.
// It identifies the encryption algorithm and returns the IV and key size based on the detected algorithm.
func extractCipherParams(es pkix.AlgorithmIdentifier) ([]byte, int, error) {
	algo, exist := cipherMap[es.Algorithm.String()]
	if !exist {
		return nil, 0, errors.New("unsupported encryption algorithm")
	}

	var iv []byte
	if _, err := asn1.Unmarshal(es.Parameters.FullBytes, &iv); err != nil {
		return nil, 0, errors.New("failed to parse the initialization vector")
	}
	return iv, algo.KeySize, nil
}

// PBKDF2 is a cryptographic algorithm designed to derive strong cryptographic keys from weak passwords by
// applying a hashing function iteratively.
// It takes as input a password, a cryptographic salt, an iteration count, and a desired output key length.
// PBKDF2 is formally specified in RFC 8018, which is part of the PKCS#5 standard.
func deriveKeyUsingPBKDF2(parameterBytes []byte, keySize int, password []byte) ([]byte, error) {
	var kdfParams PBKDF2Params
	if _, err := asn1.Unmarshal(parameterBytes, &kdfParams); err != nil {
		return nil, fmt.Errorf("failed to parse ASN.1 OID: %w", err)
	}

	hashFunc, err := getNewHash(kdfParams.PRF.Algorithm)
	if err != nil {
		return nil, err
	}
	key := pbkdf2.Key(password, kdfParams.Salt, kdfParams.Iteration, keySize, hashFunc)
	return key, nil
}

// Scrypt is a password-based key derivation function specifically designed to be computationally and memory-hard.
// The algorithm was specifically designed to make it costly to perform large-scale custom hardware attacks by requiring large amounts of memory.
// For more information about Scrypt:
// https://en.wikipedia.org/wiki/Scrypt
func deriveKeyUsingScrypt(parameterBytes []byte, keySize int, password []byte) ([]byte, error) {
	var kdfParams ScryptParams
	if _, err := asn1.Unmarshal(parameterBytes, &kdfParams); err != nil {
		return nil, fmt.Errorf("failed to parse ASN.1 OID: %w", err)
	}

	key, err := scrypt.Key(password, kdfParams.Salt, kdfParams.CostFactor, kdfParams.BlockSizeFactor,
		kdfParams.ParallelizationFactor, keySize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// 'parseDERFromPEMForPKCS8' parses a PEM file.
// If the blockType matches the required PEM blockType, it returns the decoded bytes.
// It is only called for verifying PKCS#8 private keys. If the blockType is "PRIVATE KEY",
// it indicates that a PKCS#8 password was provided when it should not have been.
// Conversely, if the bloclType is "ENCRYPTED PRIVATE KEY",
// it means the password was not provided when required.
func parseDERFromPEMForPKCS8(pemDataId string, blockType string) (*pem.Block, error) {
	bytes, err := os.ReadFile(pemDataId)
	if err != nil {
		return nil, err
	}

	var block *pem.Block
	for len(bytes) > 0 {
		block, bytes = pem.Decode(bytes)
		if block == nil {
			return nil, errors.New("unable to parse PEM data")
		}
		if block.Type == blockType {
			return block, nil
		}
	}
	return nil, fmt.Errorf("requested block type could not be found. The block type detected is %s", block.Type)
}

// 'isPKCS8EncryptedBlockType' tries to decode the PEM block
// and determine if the PEM block type is 'ENCRYPTED PRIVATE KEY'.
func isPKCS8EncryptedBlockType(pemDataId string) bool {
	bytes, err := os.ReadFile(pemDataId)
	if err != nil {
		return false
	}

	var block *pem.Block
	for len(bytes) > 0 {
		block, bytes = pem.Decode(bytes)
		if block == nil {
			return false
		}
		if block.Type == encryptedBlockType {
			return true
		}
	}
	return false
}

// 'readPKCS8PrivateKey' reads and parses an unencrypted PKCS#8 private key.
func readPKCS8PrivateKey(privateKeyId string) (crypto.PrivateKey, error) {
	block, err := parseDERFromPEMForPKCS8(privateKeyId, unencryptedBlockType)
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("could not parse private key")
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if ok {
		return rsaPrivateKey, nil
	}

	ecPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if ok {
		return ecPrivateKey, nil
	}

	return nil, errors.New("could not parse PKCS#8 private key")
}

// 'readPKCS8EncryptedPrivateKey' reads and parses an encrypted PKCS#8 private key, following the process defined in RFC 8018.
// Note that the encryption scheme must be PBES2, and the supported key types are limited to RSA and ECDSA.
func readPKCS8EncryptedPrivateKey(privateKeyId string, pkcs8Password []byte) (crypto.PrivateKey, error) {
	block, err := parseDERFromPEMForPKCS8(privateKeyId, encryptedBlockType)
	if err != nil {
		if Debug && strings.Contains(err.Error(), `The block type detected is PRIVATE KEY`) {
			log.Println("PKCS#8 password provided but block type indicates that one isn't required.")
		}
		return nil, errors.New("could not parse PEM data")
	}

	var privKey EncryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 structure: %w", err)
	}

	var pbes2 PBES2Params
	if _, err := asn1.Unmarshal(privKey.EncryptionAlgorithm.Parameters.FullBytes, &pbes2); err != nil {
		return nil, errors.New("invalid PBES2 parameters")
	}

	iv, keySize, err := extractCipherParams(pbes2.EncryptionScheme)
	if err != nil {
		return nil, err
	}

	kdfOid := pbes2.KeyDerivationFunc.Algorithm
	var key []byte
	// zeroing the derived key after use
	defer copy(key, make([]byte, len(key)))
	switch {
	case kdfOid.Equal(oidPBKDF2):
		key, _ = deriveKeyUsingPBKDF2(pbes2.KeyDerivationFunc.Parameters.FullBytes, keySize, pkcs8Password)
	case kdfOid.Equal(oidScrypt):
		key, _ = deriveKeyUsingScrypt(pbes2.KeyDerivationFunc.Parameters.FullBytes, keySize, pkcs8Password)
	default:
		return nil, errors.New("unsupported key derivation function")
	}

	blockCipher, err := cipherMap[pbes2.EncryptionScheme.Algorithm.String()].NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	ciphertext := privKey.EncryptedData
	mode := cipher.NewCBCDecrypter(blockCipher, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	privateKey, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return nil, errors.New("incorrect password or invalid key format")
	}

	switch privateKey.(type) {
	case *rsa.PrivateKey:
		rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
		if ok {
			return rsaPrivateKey, nil
		}
	case *ecdsa.PrivateKey:
		ecPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
		if ok {
			return ecPrivateKey, nil
		}
	default:
		return nil, errors.New("could not parse PKCS#8 private key")
	}

	return nil, errors.New("could not parse PKCS#8 private key")
}
