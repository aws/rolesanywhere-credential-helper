package aws_signing_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"log"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func RunSignTestWithTestTable(t *testing.T, testTable []CredentialsOpts) {
	msg := "test message"
	digestList := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

	for _, credOpts := range testTable {
		signer, _, err := GetSigner(&credOpts)
		if err != nil {
			var logMsg string
			if credOpts.CertificateId != "" || credOpts.PrivateKeyId != "" {
				logMsg = fmt.Sprintf("Failed to get signer for '%s'/'%s'",
					credOpts.CertificateId, credOpts.PrivateKeyId)
			} else {
				logMsg = fmt.Sprintf("Failed to get signer for '%s'",
					credOpts.CertIdentifier.Subject)
			}
			t.Log(logMsg)
			t.Fail()
			return
		}

		pubKey := signer.Public()
		if credOpts.CertificateId != "" && pubKey == nil {
			t.Log(fmt.Sprintf("Signer didn't provide public key for '%s'/'%s'",
				credOpts.CertificateId, credOpts.PrivateKeyId))
			t.Fail()
			return
		}

		for _, digest := range digestList {
			signatureBytes, err := signer.Sign(rand.Reader, []byte(msg), digest)
			// Try signing again to make sure that there aren't any issues
			// with reopening sessions. Also, in some test cases, signing again
			// makes sure that the context-specific PIN was saved.
			signer.Sign(rand.Reader, []byte(msg), digest)
			if err != nil {
				t.Log(fmt.Sprintf("Failed to %s sign the input message for '%s'/'%s': %s",
					digest, credOpts.CertificateId, credOpts.PrivateKeyId, err))
				t.Fail()
				return
			}
			_, err = signer.Sign(rand.Reader, []byte(msg), digest)
			if err != nil {
				t.Log("Failed second signature on the input message")
				t.Fail()
				return
			}

			if pubKey != nil {
				valid, _ := Verify([]byte(msg), pubKey, digest, signatureBytes)
				if !valid {
					t.Log(fmt.Sprintf("Failed to verify %s signature for '%s'/'%s'",
						digest, credOpts.CertificateId, credOpts.PrivateKeyId))
					t.Fail()
					return
				}
			}
		}

		signer.Close()
	}
}

func RunNegativeSignTestWithTestTable(t *testing.T, testTable []CredentialsOpts) {
	msg := "test message"
	digestList := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

	for _, credOpts := range testTable {
		signer, _, err := GetSigner(&credOpts)
		if err != nil {
			var logMsg string
			if credOpts.CertificateId != "" || credOpts.PrivateKeyId != "" {
				logMsg = fmt.Sprintf("Failed to get signer for '%s'/'%s'",
					credOpts.CertificateId, credOpts.PrivateKeyId)
			} else {
				logMsg = fmt.Sprintf("Failed to get signer for '%s'",
					credOpts.CertIdentifier.Subject)
			}
			t.Log(logMsg)
			t.Fail()
			return
		}

		pubKey := signer.Public()
		if credOpts.CertificateId != "" && pubKey == nil {
			t.Log(fmt.Sprintf("Signer didn't provide public key for '%s'/'%s'",
				credOpts.CertificateId, credOpts.PrivateKeyId))
			t.Fail()
			return
		}

		for _, digest := range digestList {
			_, err := signer.Sign(rand.Reader, []byte(msg), digest)
			signer.Sign(rand.Reader, []byte(msg), digest)
			if err == nil {
				t.Log(fmt.Sprintf("Expected %s sign on the input message to fail for '%s'/'%s': %s, but it succeeded",
					digest, credOpts.CertificateId, credOpts.PrivateKeyId, err))
				t.Fail()
				return
			}
		}

		signer.Close()
	}
}

// Verify that the provided payload was signed correctly with the provided options.
// This function is specifically used for unit testing.
func Verify(payload []byte, publicKey crypto.PublicKey, digest crypto.Hash, sig []byte) (bool, error) {
	// Check for ML-DSA keys first (they don't use traditional hash-based signatures)
	{
		publicKey, ok := publicKey.(*mldsa44.PublicKey)
		if ok {
			// ML-DSA signs the raw message, not a hash
			valid := mldsa44.Verify(publicKey, payload, nil, sig)
			return valid, nil
		}
	}

	{
		publicKey, ok := publicKey.(*mldsa65.PublicKey)
		if ok {
			valid := mldsa65.Verify(publicKey, payload, nil, sig)
			return valid, nil
		}
	}

	{
		publicKey, ok := publicKey.(*mldsa87.PublicKey)
		if ok {
			valid := mldsa87.Verify(publicKey, payload, nil, sig)
			return valid, nil
		}
	}

	// For traditional algorithms (RSA, ECDSA), compute the hash
	var hash []byte
	switch digest {
	case crypto.SHA256:
		sum := sha256.Sum256(payload)
		hash = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(payload)
		hash = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(payload)
		hash = sum[:]
	default:
		log.Fatal("unsupported digest")
		return false, errors.New("unsupported digest")
	}

	{
		publicKey, ok := publicKey.(*ecdsa.PublicKey)
		if ok {
			valid := ecdsa.VerifyASN1(publicKey, hash, sig)
			return valid, nil
		}
	}

	{
		publicKey, ok := publicKey.(*rsa.PublicKey)
		if ok {
			err := rsa.VerifyPKCS1v15(publicKey, digest, hash, sig)
			return err == nil, nil
		}
	}

	return false, nil
}
