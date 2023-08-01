package cmd

import (
	"crypto/sha1"
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
	readCertificateDataCmd.PersistentFlags().StringVar(&certSelector, "cert-selector", "", "JSON structure to identify a certificate from a certificate store."+
		" Can be passed in either as string or a file name (prefixed by \"file://\")")
	readCertificateDataCmd.PersistentFlags().BoolVar(&debug, "debug", false, "To print debug output")
}

type PrintCertificate func(int, helper.CertificateContainer)

func DefaultPrintCertificate(index int, certContainer helper.CertificateContainer) {
	cert := certContainer.Cert

	fingerprint := sha1.Sum(cert.Raw) // nosemgrep
	fingerprintHex := hex.EncodeToString(fingerprint[:])
	fmt.Printf("%d) %s \"%s\"\n", index+1, fingerprintHex, cert.Subject.String())

	// Only for PKCS#11
	if certContainer.Uri != "" {
		fmt.Printf("\tURI: %s\n", certContainer.Uri)
	}
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

		var certContainers []helper.CertificateContainer
		// In case there is information that needs to be conditionally printed
		// based on the type of integration being used (which can't be taken
		// from the CertificateContainer), a function that implements the
		// PrintCertificate interface can be assigned to this variable.
		var printFunction PrintCertificate = DefaultPrintCertificate

		if strings.HasPrefix(certificateId, "pkcs11:") {
			certContainers, err = helper.GetMatchingPKCSCerts(certificateId, libPkcs11)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		} else if certificateId != "" && certIdentifier == (helper.CertIdentifier{}) {
			data, err := helper.ReadCertificateData(certificateId)
			if err != nil {
				os.Exit(1)
			}
			buf, err := json.Marshal(data)
			if err != nil {
				os.Exit(1)
			}

			fmt.Print(string(buf[:]))
			// Exit after printing out the certificate data
			os.Exit(0)
		} else {
			certContainers, err = helper.GetMatchingCerts(certIdentifier)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		}
		fmt.Printf("Matching identities\n")
		for index, certContainer := range certContainers {
			printFunction(index, certContainer)
		}
	},
}
