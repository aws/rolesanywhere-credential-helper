package cmd

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"syscall"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(readCertificateDataCmd)
	readCertificateDataCmd.PersistentFlags().StringVar(&certificateId, "certificate", "", "Path to certificate file")
	readCertificateDataCmd.PersistentFlags().StringVar(&certSelector, "cert-selector", "", `JSON structure to identify 
a certificate from a certificate store. Can be passed in either as string or a file name (prefixed by \"file://\")`)
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
			syscall.Exit(1)
		}

		if certIdentifier == (helper.CertIdentifier{}) {
			data, _ := helper.ReadCertificateData(certificateId)
			buf, _ := json.Marshal(data)
			fmt.Print(string(buf[:]))
		} else {
			_, _, certs, err := helper.GetMatchingCerts(certIdentifier)
			if err != nil {
				log.Println("unable to get certificates from cert store")
				syscall.Exit(1)
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
