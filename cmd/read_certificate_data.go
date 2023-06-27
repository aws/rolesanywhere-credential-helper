package cmd

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(readCertificateDataCmd)
	readCertificateDataCmd.PersistentFlags().StringVar(&certificateId, "certificate", "", "Path to certificate file")
	readCertificateDataCmd.PersistentFlags().StringVar(&certSelector, "cert-selector", "", `JSON structure to identify \ 
    a certificate from a certificate store. Can be passed in either as string or a file name (prefixed by "file://")`)
	readCertificateDataCmd.PersistentFlags().StringVar(&libPkcs11, "pkcs11-lib", "", "Library for smart card / cryptographic device (OpenSC or vendor specific)")
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

		var certs []*x509.Certificate

		if strings.HasPrefix(certificateId, "pkcs11:") {
			certs, err = helper.GetMatchingPKCSCerts(certIdentifier, certificateId, libPkcs11)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		} else if certificateId != "" && certIdentifier == (helper.CertIdentifier{}) {
			data, _ := helper.ReadCertificateData(certificateId)
			buf, _ := json.Marshal(data)
			fmt.Print(string(buf[:]))
			// Leaves 'certs' empty
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
	},
}
