package cmd

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(readCertificateDataCmd)
	readCertificateDataCmd.PersistentFlags().StringVar(&certificateId, "certificate", "", "Path to certificate file")
	readCertificateDataCmd.PersistentFlags().StringVar(&certSelector, "cert-selector", "", `JSON structure to identify 
a certificate from a certificate store. Can be passed in either as string or a file name (prefixed by "file://")`)
	readCertificateDataCmd.PersistentFlags().StringVar(&libPkcs11, "pkcs11-lib", "", "Library for smart card / cryptographic device (OpenSC or vendor specific)")
	readCertificateDataCmd.PersistentFlags().UintVar(&slotPkcs11, "pkcs11-slot", 0, "PKCS #11 slot in which to search for the certificate")
	readCertificateDataCmd.MarkFlagsRequiredTogether("pkcs11-lib")
}

var readCertificateDataCmd = &cobra.Command{
	Use:   "read-certificate-data [flags]",
	Short: "Diagnostic command to read certificate data",
	Long: `Diagnostic command to read certificate data, either from files or 
    from a certificate store`,
	Run: func(cmd *cobra.Command, args []string) {
		certIdentifier, err := PopulateCertIdentifier(certSelector)
		if err != nil {
			log.Println("unable to populate CertIdentifier")
			os.Exit(1)
		}

		if libPkcs11 == "" && certIdentifier == (helper.CertIdentifier{}) {
			data, _ := helper.ReadCertificateData(certificateId)
			buf, _ := json.Marshal(data)
			fmt.Print(string(buf[:]))
		} else {
			var certs []*x509.Certificate
			if libPkcs11 != "" {
				_, _, _, certs, err = helper.GetMatchingPKCSCerts(certIdentifier, libPkcs11, slotPkcs11)
				if err != nil {
					log.Println(err)
					os.Exit(1)
				}
			} else {
				certs, err = helper.GetMatchingCerts(certIdentifier)
				if err != nil {
					log.Println(err)
					os.Exit(1)
				}
			}
			for index, cert := range certs {
				fingerprint := sha1.Sum(cert.Raw) // nosemgrep
				fingerprintHex := hex.EncodeToString(fingerprint[:])
				fmt.Printf("Matching identities\n")
				fmt.Printf("%d) %s \"%s\"\n", index+1, fingerprintHex, cert.Subject.String())
			}
		}
	},
}
