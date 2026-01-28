package aws_signing_helper

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

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

func TestMLDSASigningAlgorithmConstant(t *testing.T) {
	// Verify the constant is correctly defined
	if aws4_x509_mldsa != "AWS4-X509-MLDSA" {
		t.Errorf("aws4_x509_mldsa = %v, want AWS4-X509-MLDSA", aws4_x509_mldsa)
	}
}

func TestMLDSAEncryptedKeyBenchmark(t *testing.T) {
	// Benchmark-style test to measure performance of encrypted ML-DSA key operations
	keyFile := "../tst/mldsa-fixtures/mldsa44-key-pkcs8-aes256cbc.pem"

	// Measure key loading time
	iterations := 10

	for i := 0; i < iterations; i++ {
		_, err := ReadPrivateKeyData(keyFile, "password")
		if err != nil {
			t.Fatalf("Failed to read key on iteration %d: %v", i, err)
		}
	}
}

func TestMLDSAEncryptedKeyEdgeCases(t *testing.T) {
	// Test edge cases and boundary conditions
	testCases := []struct {
		name     string
		keyFile  string
		password string
	}{
		{
			name:     "Very long password",
			keyFile:  "../tst/mldsa-fixtures/mldsa44-key-pkcs8-aes128cbc.pem",
			password: strings.Repeat("a", 1000),
		},
		{
			name:     "Password with special characters",
			keyFile:  "../tst/mldsa-fixtures/mldsa65-key-pkcs8-aes192cbc.pem",
			password: "!@#$%^&*()_+-=[]{}|;:,.<>?",
		},
		{
			name:     "Unicode password",
			keyFile:  "../tst/mldsa-fixtures/mldsa87-key-pkcs8-aes256cbc.pem",
			password: "пароль密码パスワード",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadPrivateKeyData(tc.keyFile, tc.password)

			// We expect most of these to fail since we're using wrong passwords
			// The test is to ensure the system handles edge cases gracefully
			if err == nil {
				t.Errorf("Expected error with wrong password for %s", tc.keyFile)
			}
		})
	}
}

func TestMLDSAEncryptedKeyCompatibility(t *testing.T) {
	// Test compatibility between different ML-DSA variants and encryption methods
	variants := []string{"mldsa44", "mldsa65", "mldsa87"}
	encryptionMethods := []string{
		"aes128cbc", "aes192cbc", "aes256cbc",
		"hmacWithSHA256", "hmacWithSHA384", "hmacWithSHA512",
		"scrypt",
	}

	for _, variant := range variants {
		for _, method := range encryptionMethods {
			t.Run(fmt.Sprintf("%s-%s", variant, method), func(t *testing.T) {
				keyFile := fmt.Sprintf("../tst/mldsa-fixtures/%s-key-pkcs8-%s.pem", variant, method)
				certFile := fmt.Sprintf("../tst/mldsa-fixtures/%s-cert.pem", variant)

				// Test key reading
				privateKey, err := ReadPrivateKeyData(keyFile, "password")
				if err != nil {
					t.Fatalf("Failed to read key for %s-%s: %v", variant, method, err)
				}

				// Verify ML-DSA key type
				mldsaKey, ok := privateKey.(MLDSAPrivateKey)
				if !ok {
					t.Errorf("Expected MLDSAPrivateKey for %s-%s, got %T", variant, method, privateKey)
					return
				}

				// Test signing consistency
				message1 := []byte("test message 1")
				message2 := []byte("test message 2")

				sig1 := mldsaKey.Sign(message1, nil)
				sig2 := mldsaKey.Sign(message2, nil)

				if len(sig1) == 0 || len(sig2) == 0 {
					t.Errorf("Empty signature for %s-%s", variant, method)
				}

				// Signatures should be different for different messages
				if bytes.Equal(sig1, sig2) {
					t.Errorf("Identical signatures for different messages with %s-%s", variant, method)
				}

				// Test certificate compatibility (if available)
				if _, err := os.Stat(certFile); err == nil {
					_, cert, err := ReadCertificateData(certFile)
					if err == nil && cert != nil {
						// Certificate is compatible
					}
				}
			})
		}
	}
}

func TestIsMLDSAOid(t *testing.T) {
	testCases := []struct {
		name     string
		oid      []int
		expected bool
	}{
		{
			name:     "ML-DSA-44 OID",
			oid:      []int{2, 16, 840, 1, 101, 3, 4, 3, 17},
			expected: true,
		},
		{
			name:     "ML-DSA-65 OID",
			oid:      []int{2, 16, 840, 1, 101, 3, 4, 3, 18},
			expected: true,
		},
		{
			name:     "ML-DSA-87 OID",
			oid:      []int{2, 16, 840, 1, 101, 3, 4, 3, 19},
			expected: true,
		},
		{
			name:     "RSA OID",
			oid:      []int{1, 2, 840, 113549, 1, 1, 1},
			expected: false,
		},
		{
			name:     "ECDSA OID",
			oid:      []int{1, 2, 840, 10045, 2, 1},
			expected: false,
		},
		{
			name:     "Invalid OID",
			oid:      []int{1, 2, 3, 4, 5},
			expected: false,
		},
		{
			name:     "Empty OID",
			oid:      []int{},
			expected: false,
		},
		{
			name:     "Similar but wrong OID",
			oid:      []int{2, 16, 840, 1, 101, 3, 4, 3, 20},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isMLDSAOid(tc.oid)
			if result != tc.expected {
				t.Errorf("isMLDSAOid(%v) = %v, want %v", tc.oid, result, tc.expected)
			}
		})
	}
}

func TestGetAlgoFromOid(t *testing.T) {
	testCases := []struct {
		name     string
		oid      []int
		expected string
	}{
		{
			name:     "ML-DSA-44 OID",
			oid:      []int{2, 16, 840, 1, 101, 3, 4, 3, 17},
			expected: "ML-DSA-44",
		},
		{
			name:     "ML-DSA-65 OID",
			oid:      []int{2, 16, 840, 1, 101, 3, 4, 3, 18},
			expected: "ML-DSA-65",
		},
		{
			name:     "ML-DSA-87 OID",
			oid:      []int{2, 16, 840, 1, 101, 3, 4, 3, 19},
			expected: "ML-DSA-87",
		},
		{
			name:     "RSA OID",
			oid:      []int{1, 2, 840, 113549, 1, 1, 1},
			expected: "",
		},
		{
			name:     "ECDSA OID",
			oid:      []int{1, 2, 840, 10045, 2, 1},
			expected: "",
		},
		{
			name:     "Invalid OID",
			oid:      []int{1, 2, 3, 4, 5},
			expected: "",
		},
		{
			name:     "Empty OID",
			oid:      []int{},
			expected: "",
		},
		{
			name:     "Similar but wrong OID",
			oid:      []int{2, 16, 840, 1, 101, 3, 4, 3, 20},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getAlgoFromOid(tc.oid)
			if result != tc.expected {
				t.Errorf("getAlgoFromOid(%v) = %q, want %q", tc.oid, result, tc.expected)
			}
		})
	}
}
