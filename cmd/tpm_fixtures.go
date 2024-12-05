package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(tpmFixturesCmd)
}

func createCaCertificate(certFile, keyFile string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Generate ECDSA private key for CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Define CA certificate template
	caCertTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example CA", Organization: []string{"AWS"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	// Write the CA certificate to a file
	err = writeToFile(certFile, "CERTIFICATE", caCertDER)
	if err != nil {
		return nil, nil, err
	}

	// Write the CA private key to a file
	caKeyDer, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, nil, err
	}
	err = writeToFile(keyFile, "EC PRIVATE KEY", caKeyDer)
	if err != nil {
		return nil, nil, err
	}

	// Parse and return the certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caKey, nil
}

func createEndEntityCertificate(pubKey *ecdsa.PublicKey, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, certFile string) error {
	// Define end-entity certificate template
	eeCertTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign the end-entity certificate with the CA's private key
	eeCertDER, err := x509.CreateCertificate(rand.Reader, eeCertTemplate, caCert, pubKey, caKey)
	if err != nil {
		return err
	}

	// Write the end-entity certificate to a file
	return writeToFile(certFile, "CERTIFICATE", eeCertDER)
}

func writeToFile(filename, pemType string, data []byte) error {
	// Create or overwrite the file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Encode and write the data as PEM
	return pem.Encode(file, &pem.Block{Type: pemType, Bytes: data})
}

func prependLengthForTpm2bStructures(pubKeyBytes []byte) []byte {
	var buffer bytes.Buffer
	buffer.Write([]byte{0x00, uint8(len(pubKeyBytes))})
	buffer.Write(pubKeyBytes)
	return buffer.Bytes()
}

func createTpmKeyWithParentHandle(parentHandle int, keyFile string, pubKeyBytes []byte, privKeyBytes []byte, emptyAuth bool) {
	tpmData := helper.Tpm2_TPMKey{
		Oid:       helper.OidLoadableKey,
		EmptyAuth: emptyAuth,
		Parent:    parentHandle,
		Pubkey:    prependLengthForTpm2bStructures(pubKeyBytes),
		Privkey:   prependLengthForTpm2bStructures(privKeyBytes),
	}
	asn1Bytes, err := asn1.Marshal(tpmData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemBlock := &pem.Block{
		Type:  "TSS2 PRIVATE KEY",
		Bytes: asn1Bytes,
	}
	pemFile, err := os.Create(keyFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer pemFile.Close()
	err = pem.Encode(pemFile, pemBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}

func CreateEeTpmKey(eeTpmKeyFile string) crypto.PublicKey {
	rw, err := helper.OpenTPM()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	parentPermanentHandle := 0x40000001
	parentHandle, _, err := tpm2.CreatePrimary(rw, tpmutil.Handle(parentPermanentHandle), tpm2.PCRSelection{}, "", "", helper.PrimaryParams)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer tpm2.FlushContext(rw, parentHandle)

	// Make the transient object persistent
	parentPersistentHandle := 0x81000001
	tpm2.EvictControl(rw, "", tpmutil.Handle(parentPermanentHandle), parentHandle, tpmutil.Handle(parentPersistentHandle))

	var childParams = tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagNoDA | tpm2.FlagSensitiveDataOrigin,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg: tpm2.AlgNull,
			},
			Sign: &tpm2.SigScheme{
				Alg: tpm2.AlgNull,
			},
			CurveID: tpm2.CurveNISTP256,
			KDF: &tpm2.KDFScheme{
				Alg: tpm2.AlgNull,
			},
		},
	}

	// Create two key files from the same data - one with a persistent parent and another with a permanent parent
	privKeyBytes, pubKeyBytes, _, _, _, err := tpm2.CreateKey(rw, parentHandle, tpm2.PCRSelection{}, "", "", childParams)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	createTpmKeyWithParentHandle(parentPermanentHandle, "go-tpm-permanent-ec-key.pem", pubKeyBytes, privKeyBytes, true)
	createTpmKeyWithParentHandle(parentPersistentHandle, "go-tpm-persistent-ec-key.pem", pubKeyBytes, privKeyBytes, true)

	// This key pair will be created, but nothing else (it won't be used to create a certificate, for example)
	privKeyWPwBytes, pubKeyWPwBytes, _, _, _, err := tpm2.CreateKey(rw, parentHandle, tpm2.PCRSelection{}, "", "1234", childParams)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	createTpmKeyWithParentHandle(parentPermanentHandle, "go-tpm-permanent-ec-key-with-pw.pem", pubKeyWPwBytes, privKeyWPwBytes, false)

	tpmPublic, err := tpm2.DecodePublic(pubKeyBytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	publicKey, err := tpmPublic.Key()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return publicKey
}

func CreateIamRaCertificateHierarchy() {
	caCertFile := "ca-cert.pem"
	caKeyFile := "ca-key.pem"
	caCert, caKey, err := createCaCertificate(caCertFile, caKeyFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	eeTpmKeyFile := "ee-tpm-key.pem"
	eeCryptoPublicKey := CreateEeTpmKey(eeTpmKeyFile)

	eeCertFile := "ee-cert.pem"
	eePublicKey, ok := eeCryptoPublicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Failed to convert crypto.PublicKey to *ecdsa.PublicKey")
		os.Exit(1)
	}

	err = createEndEntityCertificate(eePublicKey, caCert, caKey, eeCertFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var tpmFixturesCmd = &cobra.Command{
	Use:   "tpm-fixtures",
	Short: "Generates fixture data within a TPM",
	Long:  "Generates fixture data within a TPM, including a certificate hierarchy; everything that's necessary to obtain temporary credentials",
	Run: func(cmd *cobra.Command, args []string) {
		CreateIamRaCertificateHierarchy()
	},
}
