package aws_signing_helper

import (
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestTPMSigner(t *testing.T) {
	testTable := []CredentialsOpts{}

	tpm_digests := []string{"sha1", "sha256", "sha384", "sha512"}
	var tpm_keys []string

	tpmdev := os.Getenv("TPM_DEVICE")
	if strings.HasPrefix(tpmdev, "/dev/") {
		tpm_keys = []string{"hw-rsa", "hw-ec", "hw-ec-81000001"}
	} else {
		tpm_keys = []string{"sw-rsa-81000001-sign", "sw-ec-prime256", "sw-ec-secp384r1"}
	}

	tpm_digests = []string{"sha256"}
	tpm_keys = []string{"sw-ec-prime256"}

	// For each of these keys, the parent key doesn't have a password
	for _, digest := range tpm_digests {
		for _, keyname := range tpm_keys {
			cert := fmt.Sprintf("../tst/certs/tpm-%s-%s-cert.pem",
				keyname, digest)
			key := fmt.Sprintf("../tst/certs/tpm-%s-key.pem", keyname)
			testTable = append(testTable, CredentialsOpts{
				CertificateId:          cert,
				PrivateKeyId:           key,
				NoTpmKeyPassword:       true,
				NoTpmParentKeyPassword: true,
			})
			keyWithPw := fmt.Sprintf("../tst/certs/tpm-%s-key-with-pw.pem", keyname)
			testTable = append(testTable, CredentialsOpts{
				CertificateId:          cert,
				PrivateKeyId:           keyWithPw,
				TpmKeyPassword:         "1234",
				NoTpmParentKeyPassword: true,
			})

			cert = fmt.Sprintf("../tst/certs/tpm-%s-%s-combo.pem",
				keyname, digest)
			testTable = append(testTable, CredentialsOpts{
				CertificateId:          cert,
				NoTpmKeyPassword:       true,
				NoTpmParentKeyPassword: true,
			})
		}
	}

	// Some positive tests, in which the parent key does have a password
	key := "../tst/certs/tpm-sw-rsa-81000001-sign-key.pem"
	testTable = append(testTable, CredentialsOpts{
		PrivateKeyId:         key,
		TpmParentKeyPassword: "123",
		NoTpmKeyPassword:     true,
	})
	keyWithPw := "../tst/certs/tpm-sw-rsa-81000001-sign-key-with-pw.pem"
	testTable = append(testTable, CredentialsOpts{
		PrivateKeyId:         keyWithPw,
		TpmParentKeyPassword: "123",
		TpmKeyPassword:       "1234",
	})

	RunSignTestWithTestTable(t, testTable)
}

func createRsaTpmPemKeyWithSignCapability(suffix string, emptyAuth bool) error {
	privKeyFileName := fmt.Sprintf("../tst/certs/tpm-sw-rsa-81000001-sign%s.key", suffix)
	privKeyBytes, err := os.ReadFile(privKeyFileName)
	if err != nil {
		return errors.New("unable to read RSA private key file")
	}
	pubKeyFileName := fmt.Sprintf("../tst/certs/tpm-sw-rsa-81000001-sign%s.pub", suffix)
	pubKeyBytes, err := os.ReadFile(pubKeyFileName)
	if err != nil {
		return errors.New("unable to read RSA public key file")
	}

	tpmData := tpm2_TPMKey{
		Oid:       oidLoadableKey,
		EmptyAuth: emptyAuth,
		Parent:    0x81000001,
		Pubkey:    pubKeyBytes,
		Privkey:   privKeyBytes,
	}

	asn1Bytes, err := asn1.Marshal(tpmData)
	if err != nil {
		return errors.New("unable to marshal TPM key ASN.1 module")
	}

	pemBlock := &pem.Block{
		Type:  "TSS2 PRIVATE KEY",
		Bytes: asn1Bytes,
	}

	pemFileName := fmt.Sprintf("../tst/certs/tpm-sw-rsa-81000001-sign-key%s.pem", suffix)
	pemFile, err := os.Create(pemFileName)
	if err != nil {
		return errors.New("unable to create TPM key PEM file")
	}
	defer pemFile.Close()

	err = pem.Encode(pemFile, pemBlock)
	if err != nil {
		return errors.New("unable to write TPM key to file")
	}

	return nil
}

// An RSA key with the Sign capability will have already been created by a Makefile
// target. Another target will be responsible for calling this testing function, which will
// then create a TPM key file that adheres to Bottomley's ASN.1 specification, so that it
// can be used for testing RSA signing.
func TestCreateRsaTpmPemKeyWithSignCapability(t *testing.T) {
	err := createRsaTpmPemKeyWithSignCapability("", true)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
}

// This function is similar to the above, but creates a TPM key file for a key that
// is protected by a password. In both cases, though, the parent key is protected by
// a password.
func TestCreateRsaTpmPemKeyWithPasswordWithSignCapability(t *testing.T) {
	err := createRsaTpmPemKeyWithSignCapability("-with-pw", false)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
}

func TestTPMSignerFails(t *testing.T) {
	testTable := []CredentialsOpts{}

	var tpm_keys []string

	tpmdev := os.Getenv("TPM_DEVICE")
	if strings.HasPrefix(tpmdev, "/dev/") {
		tpm_keys = []string{"hw-rsa", "hw-ec", "hw-ec-81000001"}
	} else {
		tpm_keys = []string{"sw-rsa", "sw-rsa-81000001-sign", "sw-ec-prime256", "sw-ec-secp384r1", "sw-ec-81000001"}
	}

	// Test that signing fails when an incorrect password is provided
	for _, keyname := range tpm_keys {
		keyWithPw := fmt.Sprintf("../tst/certs/tpm-%s-key-with-pw.pem", keyname)
		// Wrong parent key password
		testTable = append(testTable, CredentialsOpts{
			PrivateKeyId:         keyWithPw,
			TpmKeyPassword:       "1234",
			TpmParentKeyPassword: "incorrect-password",
		})

		// Wrong child key password
		testTable = append(testTable, CredentialsOpts{
			PrivateKeyId:         keyWithPw,
			TpmKeyPassword:       "incorrect-password",
			TpmParentKeyPassword: "123",
		})
	}

	// Test that RSA keys that don't have the Sign capability aren't able to
	// sign (even in the case that they have the raw Decrypt capability)
	testTable = append(testTable, CredentialsOpts{
		PrivateKeyId:           "../tst/certs/tpm-sw-rsa-key.pem",
		NoTpmKeyPassword:       true,
		NoTpmParentKeyPassword: true,
	})

	RunNegativeSignTestWithTestTable(t, testTable)
}
