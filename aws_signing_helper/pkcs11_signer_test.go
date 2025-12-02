package aws_signing_helper

import (
	"fmt"
	"os"
	"testing"
)

func TestPKCS11Signer(t *testing.T) {
	testTable := []CredentialsOpts{}
	libPkcs11 := os.Getenv("PKCS11_MODULE")

	pkcs11_objects := []string{"rsa-2048", "ec-prime256v1"}

	for _, object := range pkcs11_objects {
		base_pkcs11_uri := "pkcs11:token=credential-helper-test?pin-value=1234"
		basic_pkcs11_uri := fmt.Sprintf("pkcs11:token=credential-helper-test;object=%s?pin-value=1234", object)
		always_auth_pkcs11_uri := fmt.Sprintf("pkcs11:token=credential-helper-test;object=%s-always-auth?pin-value=1234", object)
		cert_file := fmt.Sprintf("../tst/certs/%s-sha256-cert.pem", object)

		testTable = append(testTable, CredentialsOpts{
			CertificateId: basic_pkcs11_uri,
			LibPkcs11:     libPkcs11,
		})
		testTable = append(testTable, CredentialsOpts{
			PrivateKeyId: basic_pkcs11_uri,
			LibPkcs11:    libPkcs11,
		})
		testTable = append(testTable, CredentialsOpts{
			CertificateId: basic_pkcs11_uri,
			PrivateKeyId:  basic_pkcs11_uri,
			LibPkcs11:     libPkcs11,
		})
		testTable = append(testTable, CredentialsOpts{
			CertificateId: cert_file,
			PrivateKeyId:  basic_pkcs11_uri,
			LibPkcs11:     libPkcs11,
		})
		testTable = append(testTable, CredentialsOpts{
			CertificateId: basic_pkcs11_uri,
			PrivateKeyId:  always_auth_pkcs11_uri,
			ReusePin:      true,
			LibPkcs11:     libPkcs11,
		})
		testTable = append(testTable, CredentialsOpts{
			CertificateId: cert_file,
			PrivateKeyId:  always_auth_pkcs11_uri,
			ReusePin:      true,
			LibPkcs11:     libPkcs11,
		})
		// Note that for the below test case, there are two matching keys.
		// Both keys will validate with the certificate, and one will be chosen
		// (it doesn't matter which, since both are the exact same key - it's
		// just that one has the CKA_ALWAYS_AUTHENTICATE attribute set).
		testTable = append(testTable, CredentialsOpts{
			CertificateId: cert_file,
			PrivateKeyId:  base_pkcs11_uri,
			ReusePin:      true,
			LibPkcs11:     libPkcs11,
		})
	}

	RunSignTestWithTestTable(t, testTable)
}

func TestPKCS11SignerCreationFails(t *testing.T) {
	testTable := []CredentialsOpts{}

	template_uri := "pkcs11:token=credential-helper-test;object=%s?pin-value=1234"
	rsa_generic_uri := fmt.Sprintf(template_uri, "rsa-2048")
	ec_generic_uri := fmt.Sprintf(template_uri, "ec-prime256v1")
	always_auth_rsa_uri := fmt.Sprintf(template_uri, "rsa-2048-always-auth")
	always_auth_ec_uri := fmt.Sprintf(template_uri, "ec-prime256v1-always-auth")

	testTable = append(testTable, CredentialsOpts{
		CertificateId: rsa_generic_uri,
		PrivateKeyId:  ec_generic_uri,
	})
	testTable = append(testTable, CredentialsOpts{
		CertificateId: ec_generic_uri,
		PrivateKeyId:  rsa_generic_uri,
	})
	testTable = append(testTable, CredentialsOpts{
		CertificateId: "../tst/certs/ec-prime256v1-sha256-cert.pem",
		PrivateKeyId:  rsa_generic_uri,
	})
	testTable = append(testTable, CredentialsOpts{
		CertificateId: "../tst/certs/rsa-2048-sha256-cert.pem",
		PrivateKeyId:  ec_generic_uri,
	})
	testTable = append(testTable, CredentialsOpts{
		CertificateId: rsa_generic_uri,
		PrivateKeyId:  always_auth_ec_uri,
		ReusePin:      true,
	})
	testTable = append(testTable, CredentialsOpts{
		CertificateId: ec_generic_uri,
		PrivateKeyId:  always_auth_rsa_uri,
		ReusePin:      true,
	})
	testTable = append(testTable, CredentialsOpts{
		CertificateId: "../tst/certs/ec-prime256v1-sha256-cert.pem",
		PrivateKeyId:  always_auth_rsa_uri,
		ReusePin:      true,
	})
	testTable = append(testTable, CredentialsOpts{
		CertificateId: "../tst/certs/rsa-2048-sha256-cert.pem",
		PrivateKeyId:  always_auth_ec_uri,
		ReusePin:      true,
	})

	for _, credOpts := range testTable {
		_, _, err := GetSigner(&credOpts)
		if err == nil {
			t.Log("Expected failure when creating PKCS#11 signer, but received none")
			t.Fail()
		}
	}
}
