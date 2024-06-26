package aws_signing_helper

import (
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
		// TODO: Add "sw-rsa" back in
		tpm_keys = []string{"sw-ec-prime256", "sw-ec-secp384r1", "sw-ec-81000001"}
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
				CertificateId: cert, 
				PrivateKeyId: keyWithPw, 
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

func TestTPMSignerFails(t *testing.T) {
	testTable := []CredentialsOpts{}

	tpm_digests := []string{"sha1", "sha256", "sha384", "sha512"}
	var tpm_keys []string

	tpmdev := os.Getenv("TPM_DEVICE")
	if strings.HasPrefix(tpmdev, "/dev/") {
		tpm_keys = []string{"hw-rsa", "hw-ec", "hw-ec-81000001"}
	} else {
		// TODO: Add sw-rsa back in
		tpm_keys = []string{"sw-ec-prime256", "sw-ec-secp384r1", "sw-ec-81000001"}
	}

	for _, digest := range tpm_digests {
		for _, keyname := range tpm_keys {
			cert := fmt.Sprintf("../tst/certs/tpm-%s-%s-cert.pem",
				keyname, digest)
			keyWithPw := fmt.Sprintf("../tst/certs/tpm-%s-key-with-pw.pem", keyname)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert, 
				PrivateKeyId: keyWithPw, 
				TpmKeyPassword: "incorrect-password",
			})
		}
	}

	RunNegativeSignTestWithTestTable(t, testTable)
}
