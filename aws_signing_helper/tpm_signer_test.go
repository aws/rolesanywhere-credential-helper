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
		tpm_keys = []string{"sw-rsa-81000001-sign", "sw-ec-prime256", "sw-ec-secp384r1", "sw-ec-81000001"}
	}

	for _, digest := range tpm_digests {
		for _, keyname := range tpm_keys {
			cert := fmt.Sprintf("../tst/certs/tpm-%s-%s-cert.pem",
				keyname, digest)
			key := fmt.Sprintf("../tst/certs/tpm-%s-key.pem", keyname)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
				PrivateKeyId:  key,
			})
			keyWithPw := fmt.Sprintf("../tst/certs/tpm-%s-key-with-pw.pem", keyname)
			testTable = append(testTable, CredentialsOpts{
				CertificateId:  cert,
				PrivateKeyId:   keyWithPw,
				TpmKeyPassword: "1234",
			})

			cert = fmt.Sprintf("../tst/certs/tpm-%s-%s-combo.pem",
				keyname, digest)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
			})
		}
	}

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

// The RSA key with the Sign capability will have already been created
// as a part of the owner hierarchy (as a part of the Makefile testing
// target). This method will marshal the resulting data into the PEM
// TPM key format.
func TestCreateRsaTpmPemKeyWithSignCapability(t *testing.T) {
	err := createRsaTpmPemKeyWithSignCapability("", true)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
}

func TestCreateRsaTpmPemKeyWithPasswordWithSignCapability(t *testing.T) {
	err := createRsaTpmPemKeyWithSignCapability("-with-pw", false)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
}

func TestTPMSignerFails(t *testing.T) {
	testTable := []CredentialsOpts{}

	tpm_digests := []string{"sha1", "sha256", "sha384", "sha512"}
	var tpm_keys []string

	tpmdev := os.Getenv("TPM_DEVICE")
	if strings.HasPrefix(tpmdev, "/dev/") {
		tpm_keys = []string{"hw-rsa", "hw-ec", "hw-ec-81000001"}
	} else {
		tpm_keys = []string{"sw-rsa", "sw-rsa-81000001-sign", "sw-ec-prime256", "sw-ec-secp384r1", "sw-ec-81000001"}
	}

	// Test that signing fails when an incorrect password is provided
	for _, digest := range tpm_digests {
		for _, keyname := range tpm_keys {
			cert := fmt.Sprintf("../tst/certs/tpm-%s-%s-cert.pem",
				keyname, digest)
			keyWithPw := fmt.Sprintf("../tst/certs/tpm-%s-key-with-pw.pem", keyname)
			testTable = append(testTable, CredentialsOpts{
				CertificateId:  cert,
				PrivateKeyId:   keyWithPw,
				TpmKeyPassword: "incorrect-password",
			})
		}
	}

	// Test that RSA keys that don't have the Sign capability aren't able to
	// sign (even in the case that they have the raw Decrypt capability)
	for _, digest := range tpm_digests {
		cert := fmt.Sprintf("../tst/certs/tpm-sw-rsa-%s-cert.pem", digest)
		testTable = append(testTable, CredentialsOpts{
			CertificateId: cert,
			PrivateKeyId:  "../tst/certs/tpm-sw-rsa-key.pem",
		})
	}

	RunNegativeSignTestWithTestTable(t, testTable)
}
