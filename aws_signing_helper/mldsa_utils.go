package aws_signing_helper

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// MLDSA OIDs as defined in NIST FIPS 204
var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17} // id-ml-dsa-44
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18} // id-ml-dsa-65
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19} // id-ml-dsa-87
)

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

	// Parse PKCS#8 structure
	var privKey pkcs8PrivateKey
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
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
	if _, err := asn1.Unmarshal(rawSeq.Bytes, &seed); err != nil {
		return nil, fmt.Errorf("failed to extract seed: %w", err)
	}

	switch {
	case oid.Equal(oidMLDSA44):
		if len(seed) != 32 {
			return nil, fmt.Errorf("invalid seed length for ML-DSA-44: got %d, want 32", len(seed))
		}
		var seedArray [32]byte
		copy(seedArray[:], seed)
		_, key := mldsa44.NewKeyFromSeed(&seedArray)
		return &MLDSA44PrivateKey{key: key}, nil

	case oid.Equal(oidMLDSA65):
		if len(seed) != 32 {
			return nil, fmt.Errorf("invalid seed length for ML-DSA-65: got %d, want 32", len(seed))
		}
		var seedArray [32]byte
		copy(seedArray[:], seed)
		_, key := mldsa65.NewKeyFromSeed(&seedArray)
		return &MLDSA65PrivateKey{key: key}, nil

	case oid.Equal(oidMLDSA87):
		if len(seed) != 32 {
			return nil, fmt.Errorf("invalid seed length for ML-DSA-87: got %d, want 32", len(seed))
		}
		var seedArray [32]byte
		copy(seedArray[:], seed)
		_, key := mldsa87.NewKeyFromSeed(&seedArray)
		return &MLDSA87PrivateKey{key: key}, nil

	default:
		return nil, fmt.Errorf("unsupported MLDSA algorithm OID: %v", oid)
	}
}

// GetMLDSAAlgorithmFromOID returns the MLDSA algorithm name from an OID
func GetMLDSAAlgorithmFromOID(oid asn1.ObjectIdentifier) (string, error) {
	switch {
	case oid.Equal(oidMLDSA44):
		return "ML-DSA-44", nil
	case oid.Equal(oidMLDSA65):
		return "ML-DSA-65", nil
	case oid.Equal(oidMLDSA87):
		return "ML-DSA-87", nil
	default:
		return "", fmt.Errorf("unknown MLDSA OID: %v", oid)
	}
}

// IsMLDSAOID checks if the given OID is an MLDSA algorithm
func IsMLDSAOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidMLDSA44) || oid.Equal(oidMLDSA65) || oid.Equal(oidMLDSA87)
}
