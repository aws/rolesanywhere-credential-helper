package aws_signing_helper

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// MLDSA OIDs as defined in NIST FIPS 204
var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17} // ML-DSA-44
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18} // ML-DSA-65
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19} // ML-DSA-87
)

// SubjectPublicKeyInfo represents the ASN.1 structure for public key information
type SubjectPublicKeyInfo struct {
	Algorithm        AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// AlgorithmIdentifier represents the ASN.1 structure for algorithm identification
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// TBSCertificate represents the "To Be Signed" portion of an X.509 certificate
// We only parse the fields we need to extract the signature algorithm
type TBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm AlgorithmIdentifier
	// We don't need to parse the rest of the fields
}

// Certificate represents the top-level ASN.1 structure of an X.509 certificate
type Certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// MLDSAPrivateKey wraps MLDSA private keys from the circl library
type MLDSAPrivateKey interface {
	Public() crypto.PublicKey
	Sign(msg []byte, ctx []byte) []byte
	Scheme() string
}

// Concrete implementations for each MLDSA variant
type MLDSA44PrivateKey struct {
	key *mldsa44.PrivateKey
}

func (k *MLDSA44PrivateKey) Public() crypto.PublicKey {
	return k.key.Public()
}

func (k *MLDSA44PrivateKey) Sign(msg []byte, ctx []byte) []byte {
	sig := make([]byte, mldsa44.SignatureSize)
	mldsa44.SignTo(k.key, msg, ctx, false, sig)
	return sig
}

func (k *MLDSA44PrivateKey) Scheme() string {
	return "ML-DSA-44"
}

type MLDSA65PrivateKey struct {
	key *mldsa65.PrivateKey
}

func (k *MLDSA65PrivateKey) Public() crypto.PublicKey {
	return k.key.Public()
}

func (k *MLDSA65PrivateKey) Sign(msg []byte, ctx []byte) []byte {
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(k.key, msg, ctx, false, sig)
	return sig
}

func (k *MLDSA65PrivateKey) Scheme() string {
	return "ML-DSA-65"
}

type MLDSA87PrivateKey struct {
	key *mldsa87.PrivateKey
}

func (k *MLDSA87PrivateKey) Public() crypto.PublicKey {
	return k.key.Public()
}

func (k *MLDSA87PrivateKey) Sign(msg []byte, ctx []byte) []byte {
	sig := make([]byte, mldsa87.SignatureSize)
	mldsa87.SignTo(k.key, msg, ctx, false, sig)
	return sig
}

func (k *MLDSA87PrivateKey) Scheme() string {
	return "ML-DSA-87"
}

// PKCS#8 structure for parsing private keys
type pkcs8PrivateKey struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// readMLDSAPrivateKey attempts to read an MLDSA private key from a PEM file
func readMLDSAPrivateKey(privateKeyId string) (MLDSAPrivateKey, error) {
	bytes, err := os.ReadFile(privateKeyId)
	if err != nil {
		return nil, err
	}

	var block *pem.Block
	for len(bytes) > 0 {
		block, bytes = pem.Decode(bytes)
		if block == nil {
			return nil, errors.New("unable to parse PEM data")
		}
		if block.Type == "PRIVATE KEY" {
			break
		}
	}

	if block == nil {
		return nil, errors.New("no PRIVATE KEY block found")
	}

	return ParseMLDSAFromPKCS8(block.Bytes)
}

func isMLDSAOid(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidMLDSA44) || oid.Equal(oidMLDSA65) || oid.Equal(oidMLDSA87)
}

func getAlgoFromOid(oid asn1.ObjectIdentifier) string {
	if oid.Equal(oidMLDSA44) {
		return "ML-DSA-44"
	}
	if oid.Equal(oidMLDSA65) {
		return "ML-DSA-65"
	}
	if oid.Equal(oidMLDSA87) {
		return "ML-DSA-87"
	}
	return ""
}

// IsMLDSACertificate checks if a certificate uses ML-DSA by examining its public key algorithm OID
func IsMLDSACertificate(cert *x509.Certificate) (bool, string, error) {
	// Parse the certificate's SubjectPublicKeyInfo
	var spki SubjectPublicKeyInfo
	rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		return false, "", fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}
	if len(rest) > 0 {
		return false, "", fmt.Errorf("trailing data after SubjectPublicKeyInfo")
	}

	// Check if the OID matches any ML-DSA variant
	oid := spki.Algorithm.Algorithm

	return isMLDSAOid(oid), getAlgoFromOid(oid), nil
}

// ParseMLDSAFromPKCS8 attempts to parse MLDSA private key from decrypted PKCS#8 data
func ParseMLDSAFromPKCS8(pkcs8Data []byte) (MLDSAPrivateKey, error) {
	// Parse PKCS#8 structure manually for MLDSA
	var privKey pkcs8PrivateKey
	if _, err := asn1.Unmarshal(pkcs8Data, &privKey); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 structure: %w", err)
	}

	// Check the algorithm OID to determine which MLDSA variant
	oid := privKey.Algo.Algorithm

	// For MLDSA in PKCS#8, the private key field contains a SEQUENCE
	// Parse as RawValue to inspect the structure
	var rawSeq asn1.RawValue
	if _, err := asn1.Unmarshal(privKey.PrivateKey, &rawSeq); err != nil {
		return nil, fmt.Errorf("failed to parse private key sequence: %w", err)
	}

	// The SEQUENCE contains the seed as an OCTET STRING (32 bytes)
	// We need to use NewKeyFromSeed to generate the full private key
	var seed []byte
	defer clear(seed)

	if _, err := asn1.Unmarshal(rawSeq.Bytes, &seed); err != nil {
		return nil, fmt.Errorf("failed to extract seed: %w", err)
	}

	var algorithm = getAlgoFromOid(oid)
	if len(seed) != 32 {
		return nil, fmt.Errorf("invalid seed length for %s: got %d, want 32", algorithm, len(seed))
	}

	switch {
	case oid.Equal(oidMLDSA44):
		var seedArray [32]byte
		copy(seedArray[:], seed)
		_, key := mldsa44.NewKeyFromSeed(&seedArray)
		return &MLDSA44PrivateKey{key: key}, nil

	case oid.Equal(oidMLDSA65):
		var seedArray [32]byte
		copy(seedArray[:], seed)
		_, key := mldsa65.NewKeyFromSeed(&seedArray)
		return &MLDSA65PrivateKey{key: key}, nil

	case oid.Equal(oidMLDSA87):
		var seedArray [32]byte
		copy(seedArray[:], seed)
		_, key := mldsa87.NewKeyFromSeed(&seedArray)
		return &MLDSA87PrivateKey{key: key}, nil

	default:
		return nil, fmt.Errorf("unsupported MLDSA algorithm OID: %v", oid)
	}
}
