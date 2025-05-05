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
	tpm_key_handles := []string{"0x81000101", "81000101"}
	var tpm_keys []string

	tpmdev := os.Getenv("TPM_DEVICE")
	if strings.HasPrefix(tpmdev, "/dev/") {
		tpm_keys = []string{"hw-rsa", "hw-ec", "hw-ec-81000001"}
	} else {
		tpm_keys = []string{"sw-rsa-81000001-sign", "sw-ec-prime256", "sw-ec-secp384r1"}
	}

	// For each of these keys, the parent key doesn't have a password
	for _, digest := range tpm_digests {
		for _, keyname := range tpm_keys {
			cert := fmt.Sprintf("../tst/certs/tpm-%s-%s-cert.pem",
				keyname, digest)
			key := fmt.Sprintf("../tst/certs/tpm-%s-key.pem", keyname)
			testTable = append(testTable, CredentialsOpts{
				CertificateId:    cert,
				PrivateKeyId:     key,
				NoTpmKeyPassword: true,
			})
			keyWithPw := fmt.Sprintf("../tst/certs/tpm-%s-key-with-pw.pem", keyname)
			testTable = append(testTable, CredentialsOpts{
				PrivateKeyId:   keyWithPw,
				TpmKeyPassword: "1234",
			})

			cert = fmt.Sprintf("../tst/certs/tpm-%s-%s-combo.pem",
				keyname, digest)
			testTable = append(testTable, CredentialsOpts{
				CertificateId:    cert,
				NoTpmKeyPassword: true,
			})

			cert = fmt.Sprintf("../tst/certs/tpm-%s-%s-cert.pem",
				keyname, digest)
			key = fmt.Sprintf("../tst/certs/tpm-%s-key.pem", keyname)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
				PrivateKeyId:  key,
			})

			cert = fmt.Sprintf("../tst/certs/tpm-%s-%s-combo.pem",
				keyname, digest)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
			})
		}

		// Using a loaded key
		for _, handle := range tpm_key_handles {
			keyHandle := fmt.Sprintf("handle:%s", handle)
			cert := fmt.Sprintf("../tst/certs/tpm-sw-loaded-81000101-ec-secp384r1-%s-cert.pem", digest)
			testTable = append(testTable, CredentialsOpts{
				PrivateKeyId:     keyHandle,
				NoTpmKeyPassword: true,
				CertificateId:    cert,
			})
		}
	}

	// Some positive tests, without a certificate
	key := "../tst/certs/tpm-sw-rsa-81000001-sign-key.pem"
	testTable = append(testTable, CredentialsOpts{
		PrivateKeyId:     key,
		NoTpmKeyPassword: true,
	})
	testTable = append(testTable, CredentialsOpts{
		PrivateKeyId: key,
	})
	keyWithPw := "../tst/certs/tpm-sw-rsa-81000001-sign-key-with-pw.pem"
	testTable = append(testTable, CredentialsOpts{
		PrivateKeyId:   keyWithPw,
		TpmKeyPassword: "1234",
	})

	RunSignTestWithTestTable(t, testTable)
}

func TestTPMSignerWithCertificateBundle(t *testing.T) {
	keyWithPw := "../tst/certs/tpm-sw-rsa-81000001-sign-key-with-pw.pem"
	certBundle := "../tst/certs/cert-bundle.pem"
	credOpts := CredentialsOpts{
		PrivateKeyId:        keyWithPw,
		TpmKeyPassword:      "1234",
		CertificateBundleId: certBundle,
	}

	signer, _, err := GetSigner(&credOpts)
	if err != nil {
		var logMsg string
		if credOpts.CertificateId != "" || credOpts.PrivateKeyId != "" {
			logMsg = fmt.Sprintf("failed to get signer for '%s'/'%s'",
				credOpts.CertificateId, credOpts.PrivateKeyId)
		} else {
			logMsg = fmt.Sprintf("failed to get signer for '%s'",
				credOpts.CertIdentifier.Subject)
		}
		t.Log(logMsg)
		t.Fail()
		return
	}

	certChain, err := signer.CertificateChain()
	if err != nil {
		t.Log("Error when retrieving certificate chain")
		t.Fail()
	}
	if certChain == nil {
		t.Log("Expecting certificate chain but found none")
		t.Fail()
	}
}

func TestTPMSignerFails(t *testing.T) {
	testTable := []CredentialsOpts{}

	var tpm_keys []string

	tpmdev := os.Getenv("TPM_DEVICE")
	if strings.HasPrefix(tpmdev, "/dev/") {
		return // Skip this test in the case of hardware TPM, so as to not cause DA lockout
	} else {
		tpm_keys = []string{"sw-rsa", "sw-rsa-81000001-sign", "sw-ec-prime256", "sw-ec-secp384r1", "sw-ec-81000001"}
	}

	// Test that RSA keys that don't have the Sign capability aren't able to
	// sign (even in the case that they have the raw Decrypt capability)
	testTable = append(testTable, CredentialsOpts{
		PrivateKeyId:     "../tst/certs/tpm-sw-rsa-key.pem",
		NoTpmKeyPassword: true,
	})

	// Test that signing fails when an incorrect password is provided
	for _, keyname := range tpm_keys {
		keyWithPw := fmt.Sprintf("../tst/certs/tpm-%s-key-with-pw.pem", keyname)
		// Wrong child key password
		testTable = append(testTable, CredentialsOpts{
			PrivateKeyId:   keyWithPw,
			TpmKeyPassword: "incorrect-password",
		})
	}

	RunNegativeSignTestWithTestTable(t, testTable)
}

func TestTPMSignerInstantiationFails(t *testing.T) {
	var key string

	tpmdev := os.Getenv("TPM_DEVICE")
	if strings.HasPrefix(tpmdev, "/dev/") {
		key = "../tst/certs/tpm-hw-ec-key.pem"
	} else {
		key = "../tst/certs/tpm-sw-ec-prime256-key.pem"
	}

	_, _, err := GetSigner(&CredentialsOpts{
		PrivateKeyId:   key,
		TpmKeyPassword: "unneeded-password",
	})
	if err == nil {
		t.Log("expected error when instantiating signer but received none")
		t.Fail()
	}
}
