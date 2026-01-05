package aws_signing_helper

import (
	"crypto/rand"
	"encoding/asn1"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestIsMLDSAOID(t *testing.T) {
	testCases := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected bool
	}{
		{
			name:     "ML-DSA-44 OID",
			oid:      asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17},
			expected: true,
		},
		{
			name:     "ML-DSA-65 OID",
			oid:      asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18},
			expected: true,
		},
		{
			name:     "ML-DSA-87 OID",
			oid:      asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19},
			expected: true,
		},
		{
			name:     "RSA OID",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
			expected: false,
		},
		{
			name:     "ECDSA OID",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsMLDSAOID(tc.oid)
			if result != tc.expected {
				t.Errorf("IsMLDSAOID(%v) = %v, want %v", tc.oid, result, tc.expected)
			}
		})
	}
}

func TestGetMLDSAAlgorithmFromOID(t *testing.T) {
	testCases := []struct {
		name        string
		oid         asn1.ObjectIdentifier
		expected    string
		expectError bool
	}{
		{
			name:        "ML-DSA-44 OID",
			oid:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17},
			expected:    "ML-DSA-44",
			expectError: false,
		},
		{
			name:        "ML-DSA-65 OID",
			oid:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18},
			expected:    "ML-DSA-65",
			expectError: false,
		},
		{
			name:        "ML-DSA-87 OID",
			oid:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19},
			expected:    "ML-DSA-87",
			expectError: false,
		},
		{
			name:        "Unknown OID",
			oid:         asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			expected:    "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := GetMLDSAAlgorithmFromOID(tc.oid)
			if tc.expectError {
				if err == nil {
					t.Errorf("GetMLDSAAlgorithmFromOID(%v) expected error, got nil", tc.oid)
				}
			} else {
				if err != nil {
					t.Errorf("GetMLDSAAlgorithmFromOID(%v) unexpected error: %v", tc.oid, err)
				}
				if result != tc.expected {
					t.Errorf("GetMLDSAAlgorithmFromOID(%v) = %v, want %v", tc.oid, result, tc.expected)
				}
			}
		})
	}
}

func TestMLDSA44PrivateKey(t *testing.T) {
	// Generate a test key
	var seed [32]byte
	_, err := rand.Read(seed[:])
	if err != nil {
		t.Fatalf("Failed to generate random seed: %v", err)
	}

	_, privKey := mldsa44.NewKeyFromSeed(&seed)
	mldsaKey := &MLDSA44PrivateKey{key: privKey}

	// Test Public() method
	pubKey := mldsaKey.Public()
	if pubKey == nil {
		t.Error("Public() returned nil")
	}

	// Test Scheme() method
	scheme := mldsaKey.Scheme()
	if scheme != "ML-DSA-44" {
		t.Errorf("Scheme() = %v, want ML-DSA-44", scheme)
	}

	// Test Sign() method
	message := []byte("test message")
	signature := mldsaKey.Sign(message, nil)
	if len(signature) != mldsa44.SignatureSize {
		t.Errorf("Sign() returned signature of length %d, want %d", len(signature), mldsa44.SignatureSize)
	}

	// Verify the signature
	pubKeyTyped := pubKey.(*mldsa44.PublicKey)
	if !mldsa44.Verify(pubKeyTyped, message, nil, signature) {
		t.Error("Signature verification failed")
	}
}

func TestMLDSA65PrivateKey(t *testing.T) {
	// Generate a test key
	var seed [32]byte
	_, err := rand.Read(seed[:])
	if err != nil {
		t.Fatalf("Failed to generate random seed: %v", err)
	}

	_, privKey := mldsa65.NewKeyFromSeed(&seed)
	mldsaKey := &MLDSA65PrivateKey{key: privKey}

	// Test Public() method
	pubKey := mldsaKey.Public()
	if pubKey == nil {
		t.Error("Public() returned nil")
	}

	// Test Scheme() method
	scheme := mldsaKey.Scheme()
	if scheme != "ML-DSA-65" {
		t.Errorf("Scheme() = %v, want ML-DSA-65", scheme)
	}

	// Test Sign() method
	message := []byte("test message")
	signature := mldsaKey.Sign(message, nil)
	if len(signature) != mldsa65.SignatureSize {
		t.Errorf("Sign() returned signature of length %d, want %d", len(signature), mldsa65.SignatureSize)
	}

	// Verify the signature
	pubKeyTyped := pubKey.(*mldsa65.PublicKey)
	if !mldsa65.Verify(pubKeyTyped, message, nil, signature) {
		t.Error("Signature verification failed")
	}
}

func TestMLDSA87PrivateKey(t *testing.T) {
	// Generate a test key
	var seed [32]byte
	_, err := rand.Read(seed[:])
	if err != nil {
		t.Fatalf("Failed to generate random seed: %v", err)
	}

	_, privKey := mldsa87.NewKeyFromSeed(&seed)
	mldsaKey := &MLDSA87PrivateKey{key: privKey}

	// Test Public() method
	pubKey := mldsaKey.Public()
	if pubKey == nil {
		t.Error("Public() returned nil")
	}

	// Test Scheme() method
	scheme := mldsaKey.Scheme()
	if scheme != "ML-DSA-87" {
		t.Errorf("Scheme() = %v, want ML-DSA-87", scheme)
	}

	// Test Sign() method
	message := []byte("test message")
	signature := mldsaKey.Sign(message, nil)
	if len(signature) != mldsa87.SignatureSize {
		t.Errorf("Sign() returned signature of length %d, want %d", len(signature), mldsa87.SignatureSize)
	}

	// Verify the signature
	pubKeyTyped := pubKey.(*mldsa87.PublicKey)
	if !mldsa87.Verify(pubKeyTyped, message, nil, signature) {
		t.Error("Signature verification failed")
	}
}

func TestMLDSAPrivateKeyInterface(t *testing.T) {
	// Test that all MLDSA key types implement the MLDSAPrivateKey interface
	var seed [32]byte
	_, err := rand.Read(seed[:])
	if err != nil {
		t.Fatalf("Failed to generate random seed: %v", err)
	}

	testCases := []struct {
		name string
		key  MLDSAPrivateKey
	}{
		{
			name: "MLDSA44PrivateKey",
			key: func() MLDSAPrivateKey {
				_, privKey := mldsa44.NewKeyFromSeed(&seed)
				return &MLDSA44PrivateKey{key: privKey}
			}(),
		},
		{
			name: "MLDSA65PrivateKey",
			key: func() MLDSAPrivateKey {
				_, privKey := mldsa65.NewKeyFromSeed(&seed)
				return &MLDSA65PrivateKey{key: privKey}
			}(),
		},
		{
			name: "MLDSA87PrivateKey",
			key: func() MLDSAPrivateKey {
				_, privKey := mldsa87.NewKeyFromSeed(&seed)
				return &MLDSA87PrivateKey{key: privKey}
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test that the interface methods work
			pubKey := tc.key.Public()
			if pubKey == nil {
				t.Error("Public() returned nil")
			}

			scheme := tc.key.Scheme()
			if scheme == "" {
				t.Error("Scheme() returned empty string")
			}

			message := []byte("test message")
			signature := tc.key.Sign(message, nil)
			if len(signature) == 0 {
				t.Error("Sign() returned empty signature")
			}
		})
	}
}

func TestReadMLDSAPrivateKeyInvalidFile(t *testing.T) {
	testCases := []struct {
		name     string
		filePath string
	}{
		{
			name:     "Non-existent file",
			filePath: "/tmp/non-existent-mldsa-key.pem",
		},
		{
			name:     "Invalid PEM file",
			filePath: "../tst/certs/invalid-rsa-key.pem",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readMLDSAPrivateKey(tc.filePath)
			if err == nil {
				t.Errorf("readMLDSAPrivateKey(%s) expected error, got nil", tc.filePath)
			}
		})
	}
}

func TestExtractPublicKeyAlgorithmOID(t *testing.T) {
	// Test with a real certificate that has a known algorithm
	testCases := []struct {
		name        string
		certPath    string
		expectError bool
	}{
		{
			name:        "Valid RSA certificate",
			certPath:    "../tst/certs/rsa-2048-sha256-cert.pem",
			expectError: false,
		},
		{
			name:        "Valid EC certificate",
			certPath:    "../tst/certs/ec-prime256v1-sha256-cert.pem",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Read the certificate
			_, cert, err := ReadCertificateData(tc.certPath)
			if err != nil {
				t.Fatalf("Failed to read certificate: %v", err)
			}

			// Extract the OID
			oid, err := extractPublicKeyAlgorithmOID(cert.Raw)
			if tc.expectError {
				if err == nil {
					t.Error("extractPublicKeyAlgorithmOID() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("extractPublicKeyAlgorithmOID() unexpected error: %v", err)
				}
				if len(oid) == 0 {
					t.Error("extractPublicKeyAlgorithmOID() returned empty OID")
				}
			}
		})
	}
}

func TestMLDSASigningAlgorithmConstant(t *testing.T) {
	// Verify the constant is correctly defined
	if aws4_x509_mldsa != "AWS4-X509-MLDSA" {
		t.Errorf("aws4_x509_mldsa = %v, want AWS4-X509-MLDSA", aws4_x509_mldsa)
	}
}
